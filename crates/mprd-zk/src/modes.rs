//! Deployment mode implementations for MPRD.
//!
//! # Deployment Modes
//!
//! | Mode | Trust Model | Proof Type | Performance |
//! |------|-------------|------------|-------------|
//! | A (Local) | Operator trusted | Signatures only | ~1ms |
//! | B-Lite | Computational | MPB proofs | ~1ms |
//! | B-Full | Cryptographic ZK | Risc0 receipts | ~minutes |
//! | C | Private + ZK | Encrypted + Risc0 | ~minutes |
//!
//! # Usage
//!
//! ```rust,ignore
//! use mprd_zk::modes::{DeploymentMode, ModeConfig};
//!
//! // Mode B-Lite: Fast computational proofs
//! let config = ModeConfig::mode_b_lite();
//! ```

#![allow(deprecated)]

use crate::abi::GovernorJournal;
pub use crate::verification::VerificationStep;
use mprd_core::{
    CandidateAction, Decision, DecisionToken, Hash32, MprdError, ProofBundle, Result,
    StateSnapshot, VerificationStatus, ZkAttestor, ZkLocalVerifier,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Deployment modes for MPRD.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentMode {
    /// Local mode: Signatures only, operator trusted.
    LocalTrusted,

    /// Mode B-Lite: Computational proofs using MPB.
    /// Provides execution trace verification without full ZK.
    TrustlessLite,

    /// Mode B-Full: Cryptographic ZK using Risc0.
    /// Provides trustless verification by any third party.
    TrustlessFull,

    /// Mode C: Private mode with encrypted inputs.
    /// Proves compliance without revealing sensitive data.
    Private,
}

impl Default for DeploymentMode {
    fn default() -> Self {
        Self::LocalTrusted
    }
}

/// Configuration for a deployment mode.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModeConfig {
    /// The deployment mode.
    pub mode: DeploymentMode,

    /// Number of spot checks for MPB proofs (Mode B-Lite).
    pub mpb_spot_checks: usize,

    /// Maximum fuel for MPB execution.
    pub mpb_max_fuel: u32,

    /// Risc0 image ID (Mode B-Full, Mode C).
    pub risc0_image_id: Option<[u8; 32]>,

    /// Whether to encrypt inputs (Mode C).
    pub encrypt_inputs: bool,

    /// Encryption key ID (Mode C).
    pub encryption_key_id: Option<String>,
}

impl Default for ModeConfig {
    fn default() -> Self {
        Self::mode_a()
    }
}

impl ModeConfig {
    /// Mode A: Local trusted operation.
    pub fn mode_a() -> Self {
        Self {
            mode: DeploymentMode::LocalTrusted,
            mpb_spot_checks: 0,
            mpb_max_fuel: 10_000,
            risc0_image_id: None,
            encrypt_inputs: false,
            encryption_key_id: None,
        }
    }

    /// Mode B-Lite: Computational proofs using MPB.
    pub fn mode_b_lite() -> Self {
        Self {
            mode: DeploymentMode::TrustlessLite,
            mpb_spot_checks: 64,
            mpb_max_fuel: 10_000,
            risc0_image_id: None,
            encrypt_inputs: false,
            encryption_key_id: None,
        }
    }

    /// Mode B-Full: Cryptographic ZK using Risc0.
    pub fn mode_b_full(image_id: [u8; 32]) -> Self {
        Self {
            mode: DeploymentMode::TrustlessFull,
            mpb_spot_checks: 0,
            mpb_max_fuel: 10_000,
            risc0_image_id: Some(image_id),
            encrypt_inputs: false,
            encryption_key_id: None,
        }
    }

    /// Mode C: Private mode with encrypted inputs.
    pub fn mode_c(image_id: [u8; 32], key_id: impl Into<String>) -> Self {
        Self {
            mode: DeploymentMode::Private,
            mpb_spot_checks: 0,
            mpb_max_fuel: 10_000,
            risc0_image_id: Some(image_id),
            encrypt_inputs: true,
            encryption_key_id: Some(key_id.into()),
        }
    }
}

/// Proof bundle extension for different modes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtendedProofBundle {
    /// Base proof bundle.
    pub base: ProofBundleData,

    /// Deployment mode used.
    pub mode: DeploymentMode,

    /// MPB proof data (Mode B-Lite).
    pub mpb_proof: Option<Vec<u8>>,

    /// Risc0 receipt (Mode B-Full, Mode C).
    pub risc0_receipt: Option<Vec<u8>>,

    /// Encrypted witness commitment (Mode C).
    pub encrypted_witness_hash: Option<[u8; 32]>,

    /// Journal from guest execution.
    pub journal: Option<GovernorJournal>,
}

/// Serializable proof bundle data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBundleData {
    pub policy_hash: [u8; 32],
    pub state_hash: [u8; 32],
    pub candidate_set_hash: [u8; 32],
    pub chosen_action_hash: [u8; 32],
}

impl From<&ProofBundle> for ProofBundleData {
    fn from(bundle: &ProofBundle) -> Self {
        Self {
            policy_hash: bundle.policy_hash.0,
            state_hash: bundle.state_hash.0,
            candidate_set_hash: bundle.candidate_set_hash.0,
            chosen_action_hash: bundle.chosen_action_hash.0,
        }
    }
}

/// Verification result with detailed information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtendedVerificationResult {
    /// Overall verification status.
    pub status: bool,

    /// Verification mode used.
    pub mode: DeploymentMode,

    /// Detailed verification steps.
    pub steps: Vec<VerificationStep>,

    /// Error message if verification failed.
    pub error: Option<String>,
}

impl ExtendedVerificationResult {
    /// Create a successful result.
    pub fn success(mode: DeploymentMode, steps: Vec<VerificationStep>) -> Self {
        Self {
            status: true,
            mode,
            steps,
            error: None,
        }
    }

    /// Create a failed result.
    pub fn failure(
        mode: DeploymentMode,
        error: impl Into<String>,
        steps: Vec<VerificationStep>,
    ) -> Self {
        Self {
            status: false,
            mode,
            steps,
            error: Some(error.into()),
        }
    }
}

// =============================================================================
// Mode B-Lite Attestor (MPB Proofs)
// =============================================================================

/// Attestor using MPB computational proofs.
///
/// This provides execution trace verification without the overhead of
/// full cryptographic ZK proofs. Suitable for high-frequency internal
/// operations where computational security is sufficient.
#[deprecated(
    note = "Legacy test-only attestor; use RobustMpbAttestor in mprd_zk::modes_v2 for production."
)]
pub struct MpbTrustlessAttestor {
    config: ModeConfig,
}

impl MpbTrustlessAttestor {
    pub fn new(config: ModeConfig) -> Self {
        Self { config }
    }

    pub fn default_config() -> Self {
        Self::new(ModeConfig::mode_b_lite())
    }
}

impl ZkAttestor for MpbTrustlessAttestor {
    fn attest(
        &self,
        _token: &DecisionToken,
        decision: &Decision,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<ProofBundle> {
        if self.config.mode != DeploymentMode::TrustlessLite {
            return Err(MprdError::ZkError(
                "MpbTrustlessAttestor requires TrustlessLite mode".into(),
            ));
        }

        // For Mode B-Lite, we use the MPB proof system
        // This is a placeholder - the actual implementation would use mprd-proof

        let candidate_set_hash = compute_candidate_set_hash(candidates);

        // Create proof bundle with MPB attestation marker
        let mut metadata = HashMap::new();
        metadata.insert("mode".into(), "B-Lite".into());
        metadata.insert("proof_type".into(), "MPB".into());
        metadata.insert(
            "spot_checks".into(),
            self.config.mpb_spot_checks.to_string(),
        );

        Ok(ProofBundle {
            policy_hash: decision.policy_hash.clone(),
            state_hash: state.state_hash.clone(),
            candidate_set_hash,
            chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
            limits_hash: mprd_core::limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: mprd_core::hash::candidate_hash_preimage(
                &decision.chosen_action,
            ),
            risc0_receipt: vec![], // No Risc0 receipt in B-Lite
            attestation_metadata: metadata,
        })
    }
}

/// Verifier for MPB computational proofs.
#[deprecated(
    note = "Legacy test-only verifier; use RobustMpbVerifier in mprd_zk::modes_v2 for production."
)]
pub struct MpbTrustlessVerifier {
    config: ModeConfig,
}

impl MpbTrustlessVerifier {
    pub fn new(config: ModeConfig) -> Self {
        Self { config }
    }

    pub fn default_config() -> Self {
        Self::new(ModeConfig::mode_b_lite())
    }
}

impl ZkLocalVerifier for MpbTrustlessVerifier {
    fn verify(&self, token: &DecisionToken, proof: &ProofBundle) -> VerificationStatus {
        if self.config.mode != DeploymentMode::TrustlessLite {
            return VerificationStatus::Failure(
                "MpbTrustlessVerifier requires TrustlessLite mode".into(),
            );
        }

        // Verify structural consistency
        if token.policy_hash != proof.policy_hash {
            return VerificationStatus::Failure("policy_hash mismatch".into());
        }
        if token.state_hash != proof.state_hash {
            return VerificationStatus::Failure("state_hash mismatch".into());
        }
        if token.chosen_action_hash != proof.chosen_action_hash {
            return VerificationStatus::Failure("chosen_action_hash mismatch".into());
        }

        // Verify mode marker
        match proof.attestation_metadata.get("mode") {
            Some(mode) if mode == "B-Lite" => {}
            _ => return VerificationStatus::Failure("Invalid proof mode".into()),
        }

        VerificationStatus::Success
    }
}

// =============================================================================
// Mode B-Full Attestor (Risc0 ZK)
// =============================================================================

/// Attestor using Risc0 cryptographic ZK proofs.
///
/// This provides trustless verification by any third party.
/// Requires Risc0 toolchain and guest program.
#[deprecated(
    note = "Legacy infrastructure-only attestor; use RobustRisc0Attestor in mprd_zk::modes_v2 or create_production_attestor for production."
)]
pub struct Risc0TrustlessAttestor {
    config: ModeConfig,
    #[allow(dead_code)]
    method_elf: Option<&'static [u8]>,
}

impl Risc0TrustlessAttestor {
    pub fn new(config: ModeConfig, method_elf: Option<&'static [u8]>) -> Self {
        Self { config, method_elf }
    }

    /// Check if Risc0 is available.
    pub fn is_risc0_available(&self) -> bool {
        self.method_elf.is_some() && self.config.risc0_image_id.is_some()
    }
}

impl ZkAttestor for Risc0TrustlessAttestor {
    fn attest(
        &self,
        _token: &DecisionToken,
        _decision: &Decision,
        _state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<ProofBundle> {
        if self.config.mode != DeploymentMode::TrustlessFull {
            return Err(MprdError::ZkError(
                "Risc0TrustlessAttestor requires TrustlessFull mode".into(),
            ));
        }

        if !self.is_risc0_available() {
            return Err(MprdError::ZkError(
                "Risc0 not configured. Set method_elf and image_id.".into(),
            ));
        }

        // TODO: When Risc0 is wired in:
        // 1. Serialize state, candidates, policy
        // 2. Create GovernorInput and GovernorWitness
        // 3. Invoke Risc0 prover
        // 4. Extract receipt and journal

        let _candidate_set_hash = compute_candidate_set_hash(candidates);

        // Placeholder until Risc0 is fully wired
        Err(MprdError::ZkError(
            "Risc0 proving not yet implemented. Use Mode B-Lite for computational proofs.".into(),
        ))
    }
}

/// Verifier for Risc0 cryptographic proofs.
#[deprecated(
    note = "Legacy infrastructure-only verifier; use RobustRisc0Verifier in mprd_zk::modes_v2 or create_production_verifier for production."
)]
pub struct Risc0TrustlessVerifier {
    config: ModeConfig,
}

impl Risc0TrustlessVerifier {
    pub fn new(config: ModeConfig) -> Self {
        Self { config }
    }

    /// Verify a Risc0 receipt.
    pub fn verify_receipt(
        &self,
        receipt: &[u8],
        _expected_journal: &GovernorJournal,
    ) -> Result<bool> {
        if receipt.is_empty() {
            return Err(MprdError::ZkError("Empty receipt".into()));
        }

        // TODO: When Risc0 is wired in:
        // 1. Deserialize receipt
        // 2. Verify against image_id
        // 3. Extract journal and compare with expected

        Err(MprdError::ZkError(
            "Risc0 verification not yet implemented.".into(),
        ))
    }
}

impl ZkLocalVerifier for Risc0TrustlessVerifier {
    fn verify(&self, token: &DecisionToken, proof: &ProofBundle) -> VerificationStatus {
        if self.config.mode != DeploymentMode::TrustlessFull {
            return VerificationStatus::Failure(
                "Risc0TrustlessVerifier requires TrustlessFull mode".into(),
            );
        }

        // Structural checks
        if token.policy_hash != proof.policy_hash {
            return VerificationStatus::Failure("policy_hash mismatch".into());
        }
        if token.state_hash != proof.state_hash {
            return VerificationStatus::Failure("state_hash mismatch".into());
        }
        if token.chosen_action_hash != proof.chosen_action_hash {
            return VerificationStatus::Failure("chosen_action_hash mismatch".into());
        }

        // Check for Risc0 receipt
        if proof.risc0_receipt.is_empty() {
            return VerificationStatus::Failure("No Risc0 receipt in proof".into());
        }

        // TODO: Verify receipt when Risc0 is wired
        VerificationStatus::Failure("Risc0 verification not yet implemented".into())
    }
}

// =============================================================================
// Mode C (Private) - Encrypted Inputs
// =============================================================================

/// Configuration for Mode C encryption.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Key ID for the encryption key.
    pub key_id: String,

    /// Algorithm identifier.
    pub algorithm: String,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            key_id: "default".into(),
            algorithm: "AES-256-GCM".into(),
        }
    }
}

/// Encrypted witness for Mode C.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedWitness {
    /// Encrypted state bytes.
    pub encrypted_state: Vec<u8>,

    /// Encrypted candidates bytes.
    pub encrypted_candidates: Vec<u8>,

    /// Nonce used for encryption.
    pub nonce: [u8; 12],

    /// Hash commitment to plaintext.
    pub plaintext_commitment: [u8; 32],
}

/// Attestor for Mode C (Private).
///
/// Encrypts inputs before proving, ensuring only commitments are revealed.
#[deprecated(
    note = "Legacy placeholder for Mode C; use RobustPrivateAttestor in mprd_zk::modes_v2 for production."
)]
pub struct PrivateAttestor {
    #[allow(dead_code)]
    config: ModeConfig,
    #[allow(dead_code)]
    encryption_config: EncryptionConfig,
}

impl PrivateAttestor {
    pub fn new(config: ModeConfig, encryption_config: EncryptionConfig) -> Self {
        Self {
            config,
            encryption_config,
        }
    }
}

impl ZkAttestor for PrivateAttestor {
    fn attest(
        &self,
        _token: &DecisionToken,
        _decision: &Decision,
        _state: &StateSnapshot,
        _candidates: &[CandidateAction],
    ) -> Result<ProofBundle> {
        // Mode C requires Risc0 + encryption
        // TODO: When implemented:
        // 1. Encrypt state and candidates
        // 2. Compute commitment to encrypted data
        // 3. Generate Risc0 proof with encrypted witness
        // 4. Include commitment in journal

        Err(MprdError::ZkError(
            "Mode C (Private) not yet implemented. Requires Risc0 + encryption layer.".into(),
        ))
    }
}

/// Verifier for Mode C (Private).
#[deprecated(
    note = "Legacy placeholder for Mode C; use RobustPrivateVerifier in mprd_zk::modes_v2 for production."
)]
pub struct PrivateVerifier {
    #[allow(dead_code)]
    config: ModeConfig,
}

impl PrivateVerifier {
    pub fn new(config: ModeConfig) -> Self {
        Self { config }
    }
}

impl ZkLocalVerifier for PrivateVerifier {
    fn verify(&self, _token: &DecisionToken, _proof: &ProofBundle) -> VerificationStatus {
        VerificationStatus::Failure("Mode C verification not yet implemented".into())
    }
}

// =============================================================================
// Factory Functions
// =============================================================================

/// Create an attestor for the specified mode.
#[deprecated(
    note = "Legacy factory; use create_robust_attestor or create_production_attestor instead."
)]
pub fn create_attestor(config: &ModeConfig) -> Box<dyn ZkAttestor> {
    match config.mode {
        DeploymentMode::LocalTrusted => Box::new(LegacyLocalTrustedAttestorDisabled),
        DeploymentMode::TrustlessLite => Box::new(MpbTrustlessAttestor::new(config.clone())),
        DeploymentMode::TrustlessFull => {
            Box::new(Risc0TrustlessAttestor::new(config.clone(), None))
        }
        DeploymentMode::Private => Box::new(PrivateAttestor::new(
            config.clone(),
            EncryptionConfig::default(),
        )),
    }
}

/// Create a verifier for the specified mode.
#[deprecated(
    note = "Legacy factory; use create_robust_verifier or create_production_verifier instead."
)]
pub fn create_verifier(config: &ModeConfig) -> Box<dyn ZkLocalVerifier> {
    match config.mode {
        DeploymentMode::LocalTrusted => Box::new(LegacyLocalTrustedVerifierDisabled),
        DeploymentMode::TrustlessLite => Box::new(MpbTrustlessVerifier::new(config.clone())),
        DeploymentMode::TrustlessFull => Box::new(Risc0TrustlessVerifier::new(config.clone())),
        DeploymentMode::Private => Box::new(PrivateVerifier::new(config.clone())),
    }
}

struct LegacyLocalTrustedAttestorDisabled;

impl ZkAttestor for LegacyLocalTrustedAttestorDisabled {
    fn attest(
        &self,
        _token: &DecisionToken,
        _decision: &Decision,
        _state: &StateSnapshot,
        _candidates: &[CandidateAction],
    ) -> Result<ProofBundle> {
        Err(MprdError::ZkError(
            "LocalTrusted is disabled in legacy factory; use mprd-core stub components explicitly for local demos/tests, or use mprd_zk::modes_v2 with an explicit strict_security opt-out".into(),
        ))
    }
}

struct LegacyLocalTrustedVerifierDisabled;

impl ZkLocalVerifier for LegacyLocalTrustedVerifierDisabled {
    fn verify(&self, _token: &DecisionToken, _proof: &ProofBundle) -> VerificationStatus {
        VerificationStatus::Failure(
            "LocalTrusted is disabled in legacy factory; use mprd-core stub components explicitly for local demos/tests, or use mprd_zk::modes_v2 with an explicit strict_security opt-out".into(),
        )
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

fn compute_candidate_set_hash(candidates: &[CandidateAction]) -> Hash32 {
    mprd_core::hash::hash_candidate_set(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mprd_core::PolicyRef;
    use mprd_core::Score;

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn dummy_policy_ref() -> PolicyRef {
        PolicyRef {
            policy_epoch: 1,
            registry_root: dummy_hash(99),
        }
    }

    #[test]
    fn mode_config_defaults() {
        let mode_a = ModeConfig::mode_a();
        assert_eq!(mode_a.mode, DeploymentMode::LocalTrusted);

        let mode_b_lite = ModeConfig::mode_b_lite();
        assert_eq!(mode_b_lite.mode, DeploymentMode::TrustlessLite);
        assert_eq!(mode_b_lite.mpb_spot_checks, 64);
    }

    #[test]
    fn mode_b_full_sets_expected_fields() {
        let image_id = [7u8; 32];
        let cfg = ModeConfig::mode_b_full(image_id);

        assert_eq!(cfg.mode, DeploymentMode::TrustlessFull);
        assert_eq!(cfg.mpb_spot_checks, 0);
        assert_eq!(cfg.risc0_image_id, Some(image_id));
        assert!(!cfg.encrypt_inputs);
        assert_eq!(cfg.encryption_key_id, None);
    }

    #[test]
    fn mode_c_sets_expected_fields() {
        let image_id = [9u8; 32];
        let cfg = ModeConfig::mode_c(image_id, "k1");

        assert_eq!(cfg.mode, DeploymentMode::Private);
        assert_eq!(cfg.mpb_spot_checks, 0);
        assert_eq!(cfg.risc0_image_id, Some(image_id));
        assert!(cfg.encrypt_inputs);
        assert_eq!(cfg.encryption_key_id.as_deref(), Some("k1"));
    }

    #[test]
    fn legacy_factory_fails_closed_for_local_trusted() {
        let config = ModeConfig::mode_a();
        let attestor = create_attestor(&config);
        let verifier = create_verifier(&config);

        let decision = Decision {
            chosen_index: 0,
            chosen_action: CandidateAction {
                action_type: "TEST".into(),
                params: HashMap::new(),
                score: Score(10),
                candidate_hash: dummy_hash(2),
            },
            policy_hash: dummy_hash(3),
            decision_commitment: dummy_hash(4),
        };

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(1),
            state_ref: mprd_core::StateRef::unknown(),
        };

        let token_for_attest = DecisionToken {
            policy_hash: decision.policy_hash.clone(),
            policy_ref: dummy_policy_ref(),
            state_hash: state.state_hash.clone(),
            state_ref: state.state_ref.clone(),
            chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
            nonce_or_tx_hash: dummy_hash(9),
            timestamp_ms: 0,
            signature: vec![],
        };
        let result = attestor.attest(&token_for_attest, &decision, &state, &[]);
        assert!(result.is_err());

        let token = DecisionToken {
            policy_hash: dummy_hash(1),
            policy_ref: dummy_policy_ref(),
            state_hash: dummy_hash(2),
            state_ref: mprd_core::StateRef::unknown(),
            chosen_action_hash: dummy_hash(3),
            nonce_or_tx_hash: dummy_hash(4),
            timestamp_ms: 0,
            signature: vec![],
        };
        let proof = ProofBundle {
            policy_hash: dummy_hash(1),
            state_hash: dummy_hash(2),
            candidate_set_hash: dummy_hash(5),
            chosen_action_hash: dummy_hash(3),
            limits_hash: dummy_hash(6),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };
        assert!(matches!(
            verifier.verify(&token, &proof),
            VerificationStatus::Failure(_)
        ));
    }

    #[test]
    fn mpb_attestor_creates_proof() {
        let attestor = MpbTrustlessAttestor::default_config();

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(1),
            state_ref: mprd_core::StateRef::unknown(),
        };

        let decision = Decision {
            chosen_index: 0,
            chosen_action: CandidateAction {
                action_type: "TEST".into(),
                params: HashMap::new(),
                score: Score(10),
                candidate_hash: dummy_hash(2),
            },
            policy_hash: dummy_hash(3),
            decision_commitment: dummy_hash(4),
        };

        let token = DecisionToken {
            policy_hash: decision.policy_hash.clone(),
            policy_ref: dummy_policy_ref(),
            state_hash: state.state_hash.clone(),
            state_ref: state.state_ref.clone(),
            chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
            nonce_or_tx_hash: dummy_hash(9),
            timestamp_ms: 0,
            signature: vec![],
        };

        let result = attestor.attest(&token, &decision, &state, &[]);
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert_eq!(
            proof.attestation_metadata.get("mode"),
            Some(&"B-Lite".to_string())
        );
    }

    #[test]
    fn mpb_verifier_checks_consistency() {
        let verifier = MpbTrustlessVerifier::default_config();

        let token = DecisionToken {
            policy_hash: dummy_hash(1),
            policy_ref: dummy_policy_ref(),
            state_hash: dummy_hash(2),
            state_ref: mprd_core::StateRef::unknown(),
            chosen_action_hash: dummy_hash(3),
            nonce_or_tx_hash: dummy_hash(4),
            timestamp_ms: 0,
            signature: vec![],
        };

        let mut metadata = HashMap::new();
        metadata.insert("mode".into(), "B-Lite".into());

        let proof = ProofBundle {
            policy_hash: dummy_hash(1),
            state_hash: dummy_hash(2),
            candidate_set_hash: dummy_hash(5),
            chosen_action_hash: dummy_hash(3),
            limits_hash: dummy_hash(6),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![],
            attestation_metadata: metadata,
        };

        assert_eq!(verifier.verify(&token, &proof), VerificationStatus::Success);
    }

    #[test]
    fn mpb_verifier_rejects_mismatch() {
        let verifier = MpbTrustlessVerifier::default_config();

        let token = DecisionToken {
            policy_hash: dummy_hash(1),
            policy_ref: dummy_policy_ref(),
            state_hash: dummy_hash(2),
            state_ref: mprd_core::StateRef::unknown(),
            chosen_action_hash: dummy_hash(3),
            nonce_or_tx_hash: dummy_hash(4),
            timestamp_ms: 0,
            signature: vec![],
        };

        let mut metadata = HashMap::new();
        metadata.insert("mode".into(), "B-Lite".into());

        let proof = ProofBundle {
            policy_hash: dummy_hash(99), // Mismatch!
            state_hash: dummy_hash(2),
            candidate_set_hash: dummy_hash(5),
            chosen_action_hash: dummy_hash(3),
            limits_hash: dummy_hash(6),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![],
            attestation_metadata: metadata,
        };

        assert!(matches!(
            verifier.verify(&token, &proof),
            VerificationStatus::Failure(_)
        ));
    }

    #[test]
    fn risc0_attestor_requires_config() {
        let config = ModeConfig::mode_b_full([0u8; 32]);
        let attestor = Risc0TrustlessAttestor::new(config, None);

        assert!(!attestor.is_risc0_available());
    }
}
