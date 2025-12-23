//! Integration with mprd-core orchestrator.
//!
//! **⚠️ EXPERIMENTAL - INTERNAL USE ONLY**
//!
//! Provides `MpbAttestor` and `MpbVerifier` implementations that can be
//! plugged into the MPRD orchestrator pipeline for high-frequency internal
//! policy checks.
//!
//! For production trustless verification, use Risc0 zkVM instead.

use crate::{
    prover::{MpbProof, MpbProver, ProverConfig},
    tracing_vm::{TracingResult, TracingVm},
    verifier::{MpbVerifier as ProofVerifier, VerificationResult},
    Hash256,
};
use bincode::{DefaultOptions, Options};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Proof bundle containing MPB custom proof.
///
/// This is a lightweight alternative to Risc0 receipts for internal use.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpbProofBundle {
    /// The proof of correct execution.
    pub proof: MpbProof,

    /// Original bytecode (for re-execution if needed).
    pub bytecode: Vec<u8>,

    /// Original register values.
    pub registers: Vec<i64>,
}

impl MpbProofBundle {
    /// Serialize to bytes for transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        // Use bincode for efficient serialization
        bincode::serialize(self)
    }

    /// Deserialize from bytes with bounded size (2 MiB max).
    ///
    /// # Security
    ///
    /// Uses bounded `bincode` deserialization to prevent DoS via memory exhaustion: attackers can
    /// craft small inputs with huge length prefixes that cause large allocations.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        const MAX_PROOF_BUNDLE_BYTES: usize = 2 * 1024 * 1024;

        // Fail-closed: reject oversized input before attempting deserialization.
        if bytes.len() > MAX_PROOF_BUNDLE_BYTES {
            return None;
        }

        bounded_bincode_deserialize(bytes, MAX_PROOF_BUNDLE_BYTES as u64).ok()
    }

    /// Get the proof size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.proof.size_bytes() + self.bytecode.len() + self.registers.len() * 8
    }
}

fn bounded_bincode_deserialize<T: DeserializeOwned>(bytes: &[u8], max_bytes: u64) -> Result<T, ()> {
    // Match bincode's default configuration while enforcing a hard size cap during decode.
    DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(max_bytes)
        .deserialize(bytes)
        .map_err(|_| ())
}

/// Configuration for the MPB attestor.
#[derive(Clone, Debug)]
pub struct MpbAttestorConfig {
    /// Number of spot checks for proofs.
    pub num_spot_checks: usize,

    /// Random seed for deterministic proofs (testing only).
    pub seed: Option<u64>,

    /// Custom fuel limit (default: 10,000).
    pub fuel_limit: u32,
}

impl Default for MpbAttestorConfig {
    fn default() -> Self {
        Self {
            num_spot_checks: 64, // ~64 bits security
            seed: None,
            fuel_limit: 10_000,
        }
    }
}

/// MPB-based attestor for generating proofs of policy execution.
///
/// **⚠️ EXPERIMENTAL - INTERNAL USE ONLY**
///
/// This attestor executes MPB bytecode with tracing and generates
/// a custom proof. It is designed for high-frequency internal checks
/// where full ZK overhead is not needed.
pub struct MpbAttestor {
    config: MpbAttestorConfig,
    prover: MpbProver,
}

impl MpbAttestor {
    /// Create a new attestor with default config.
    pub fn new() -> Self {
        Self::with_config(MpbAttestorConfig::default())
    }

    /// Create an attestor with custom config.
    pub fn with_config(config: MpbAttestorConfig) -> Self {
        let prover = MpbProver::with_config(ProverConfig {
            num_spot_checks: config.num_spot_checks,
            seed: config.seed,
        });

        Self { config, prover }
    }

    /// Execute bytecode and generate a proof.
    ///
    /// # Returns
    /// - `Ok(bundle)` with proof if execution succeeds
    /// - `Err(error)` if execution fails (fail-closed)
    pub fn attest(
        &self,
        bytecode: &[u8],
        registers: &[i64],
    ) -> Result<MpbProofBundle, AttestationError> {
        self.attest_with_context(bytecode, registers, [0u8; 32])
    }

    /// Execute bytecode and generate a proof, binding an external context hash into the statement.
    pub fn attest_with_context(
        &self,
        bytecode: &[u8],
        registers: &[i64],
        context_hash: Hash256,
    ) -> Result<MpbProofBundle, AttestationError> {
        // Execute with tracing
        let vm = TracingVm::with_fuel_and_context(
            bytecode,
            registers,
            self.config.fuel_limit,
            context_hash,
        );

        let trace = match vm.execute(bytecode) {
            TracingResult::Success { trace, .. } => trace,
            TracingResult::Error { status, .. } => {
                return Err(AttestationError::ExecutionFailed(format!("{:?}", status)));
            }
        };

        // Generate proof
        let proof = self
            .prover
            .prove(&trace)
            .map_err(|e| AttestationError::InvalidBytecode(format!("{:?}", e)))?;

        Ok(MpbProofBundle {
            proof,
            bytecode: bytecode.to_vec(),
            registers: registers.to_vec(),
        })
    }

    /// Execute and attest, returning the output value along with proof.
    pub fn attest_with_output(
        &self,
        bytecode: &[u8],
        registers: &[i64],
    ) -> Result<(i64, MpbProofBundle), AttestationError> {
        self.attest_with_output_and_context(bytecode, registers, [0u8; 32])
    }

    /// Execute and attest, returning the output value along with proof and binding an external context hash.
    pub fn attest_with_output_and_context(
        &self,
        bytecode: &[u8],
        registers: &[i64],
        context_hash: Hash256,
    ) -> Result<(i64, MpbProofBundle), AttestationError> {
        let vm = TracingVm::with_fuel_and_context(
            bytecode,
            registers,
            self.config.fuel_limit,
            context_hash,
        );

        let (result, trace) = match vm.execute(bytecode) {
            TracingResult::Success { result, trace } => (result, trace),
            TracingResult::Error { status, .. } => {
                return Err(AttestationError::ExecutionFailed(format!("{:?}", status)));
            }
        };

        let proof = self
            .prover
            .prove(&trace)
            .map_err(|e| AttestationError::InvalidBytecode(format!("{:?}", e)))?;

        Ok((
            result,
            MpbProofBundle {
                proof,
                bytecode: bytecode.to_vec(),
                registers: registers.to_vec(),
            },
        ))
    }
}

impl Default for MpbAttestor {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors during attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestationError {
    /// Bytecode execution failed.
    ExecutionFailed(String),

    /// Bytecode exceeded fuel limit.
    OutOfFuel,

    /// Invalid bytecode format.
    InvalidBytecode(String),
}

/// MPB proof verifier for the orchestrator.
///
/// **⚠️ EXPERIMENTAL - INTERNAL USE ONLY**
pub struct MpbLocalVerifier {
    verifier: ProofVerifier,
}

impl MpbLocalVerifier {
    /// Create a new verifier.
    pub fn new() -> Self {
        Self {
            verifier: ProofVerifier::new(),
        }
    }

    /// Verify a proof bundle.
    pub fn verify(&self, bundle: &MpbProofBundle) -> LocalVerificationResult {
        match self.verifier.verify(&bundle.proof) {
            VerificationResult::Valid => LocalVerificationResult::Success,
            VerificationResult::Invalid(err) => {
                LocalVerificationResult::Failure(format!("{:?}", err))
            }
        }
    }

    /// Verify proof and check expected output.
    pub fn verify_with_output(
        &self,
        bundle: &MpbProofBundle,
        expected_output: i64,
    ) -> LocalVerificationResult {
        // First verify the proof
        match self.verifier.verify(&bundle.proof) {
            VerificationResult::Valid => {}
            VerificationResult::Invalid(err) => {
                return LocalVerificationResult::Failure(format!("{:?}", err));
            }
        }

        // Then check output matches
        if bundle.proof.output != expected_output {
            return LocalVerificationResult::Failure(format!(
                "Output mismatch: expected {}, got {}",
                expected_output, bundle.proof.output
            ));
        }

        LocalVerificationResult::Success
    }

    /// Verify proof matches expected bytecode and inputs.
    pub fn verify_with_inputs(
        &self,
        bundle: &MpbProofBundle,
        expected_bytecode_hash: &Hash256,
        expected_input_hash: &Hash256,
    ) -> LocalVerificationResult {
        // Check hashes match
        if bundle.proof.bytecode_hash != *expected_bytecode_hash {
            return LocalVerificationResult::Failure("Bytecode hash mismatch".into());
        }

        if bundle.proof.input_hash != *expected_input_hash {
            return LocalVerificationResult::Failure("Input hash mismatch".into());
        }

        // Verify the proof itself
        self.verify(bundle)
    }

    /// Get security level (bits) for this proof.
    pub fn security_bits(&self, bundle: &MpbProofBundle) -> f64 {
        self.verifier.security_bits(&bundle.proof)
    }
}

impl Default for MpbLocalVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of local verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalVerificationResult {
    /// Proof verified successfully.
    Success,

    /// Proof failed verification.
    Failure(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct VecWrapper {
        v: Vec<u8>,
    }

    fn build_simple_program() -> Vec<u8> {
        // PUSH 10, PUSH 20, ADD, HALT -> result = 30
        let mut bytecode = vec![0x01];
        bytecode.extend_from_slice(&10i64.to_le_bytes());
        bytecode.push(0x01);
        bytecode.extend_from_slice(&20i64.to_le_bytes());
        bytecode.push(0x20); // ADD
        bytecode.push(0xFF); // HALT
        bytecode
    }

    fn build_risk_check_program() -> Vec<u8> {
        // LOAD_REG 0 (risk), LOAD_REG 1 (max), LE, HALT
        // Returns 1 if risk <= max, 0 otherwise
        vec![
            0x10, 0x00, // LOAD_REG 0
            0x10, 0x01, // LOAD_REG 1
            0x33, // LE
            0xFF, // HALT
        ]
    }

    #[test]
    fn bounded_bincode_deserialize_rejects_length_prefix_dos() {
        // bincode encodes Vec length prefixes; an attacker can claim a huge length with a tiny
        // input. The bounded decoder must fail without attempting to allocate enormous buffers.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());

        let res: Result<VecWrapper, _> = bounded_bincode_deserialize(&bytes, 1024);
        assert!(res.is_err());
    }

    #[test]
    fn attestor_generates_valid_proof() {
        let attestor = MpbAttestor::new();
        let bytecode = build_simple_program();

        let bundle = attestor.attest(&bytecode, &[]).expect("Should succeed");

        assert_eq!(bundle.proof.output, 30);
        assert!(bundle.size_bytes() < 10_000); // Should be small
    }

    #[test]
    fn verifier_accepts_valid_proof() {
        let attestor = MpbAttestor::new();
        let verifier = MpbLocalVerifier::new();
        let bytecode = build_simple_program();

        let bundle = attestor.attest(&bytecode, &[]).unwrap();
        let result = verifier.verify(&bundle);

        assert_eq!(result, LocalVerificationResult::Success);
    }

    #[test]
    fn risk_check_policy_allowed() {
        let attestor = MpbAttestor::new();
        let verifier = MpbLocalVerifier::new();
        let bytecode = build_risk_check_program();

        // Risk = 50, Max = 100 -> allowed (50 <= 100)
        let registers = [50, 100];
        let (output, bundle) = attestor.attest_with_output(&bytecode, &registers).unwrap();

        assert_eq!(output, 1); // Allowed
        assert_eq!(verifier.verify(&bundle), LocalVerificationResult::Success);
    }

    #[test]
    fn risk_check_policy_denied() {
        let attestor = MpbAttestor::new();
        let verifier = MpbLocalVerifier::new();
        let bytecode = build_risk_check_program();

        // Risk = 150, Max = 100 -> denied (150 > 100)
        let registers = [150, 100];
        let (output, bundle) = attestor.attest_with_output(&bytecode, &registers).unwrap();

        assert_eq!(output, 0); // Denied
        assert_eq!(verifier.verify(&bundle), LocalVerificationResult::Success);
    }

    #[test]
    fn verify_with_wrong_output_fails() {
        let attestor = MpbAttestor::new();
        let verifier = MpbLocalVerifier::new();
        let bytecode = build_simple_program();

        let bundle = attestor.attest(&bytecode, &[]).unwrap();
        let result = verifier.verify_with_output(&bundle, 999); // Wrong output

        assert!(matches!(result, LocalVerificationResult::Failure(_)));
    }

    #[test]
    fn deterministic_attestation() {
        let attestor = MpbAttestor::with_config(MpbAttestorConfig {
            num_spot_checks: 16,
            seed: Some(42), // Deterministic
            fuel_limit: 10_000,
        });

        let bytecode = build_simple_program();

        let bundle1 = attestor.attest(&bytecode, &[]).unwrap();
        let bundle2 = attestor.attest(&bytecode, &[]).unwrap();

        // Same seed, same bytecode -> same proof
        assert_eq!(bundle1.proof.trace_root, bundle2.proof.trace_root);
        assert_eq!(bundle1.proof.output, bundle2.proof.output);
    }

    #[test]
    fn proof_bundle_serialization_roundtrip() {
        let attestor = MpbAttestor::new();
        let bytecode = build_simple_program();

        let bundle = attestor.attest(&bytecode, &[]).unwrap();
        let bytes = bundle.to_bytes().expect("serialize");
        let restored = MpbProofBundle::from_bytes(&bytes).expect("Should deserialize");

        assert_eq!(bundle.proof.output, restored.proof.output);
        assert_eq!(bundle.proof.trace_root, restored.proof.trace_root);
    }
}
