//! Robust deployment mode implementations for MPRD.
//!
//! This module provides production-ready attestor and verifier implementations
//! for all MPRD deployment modes, with proper integration to the mprd-proof crate.
//!
//! # Security Properties
//!
//! All modes enforce:
//! - **S5 Binding**: Proof cryptographically binds policy_hash + state_hash + action_hash
//! - **Validation**: All inputs are validated before processing
//! - **Fail-closed**: Any error results in rejection
//!
//! # Deployment Modes
//!
//! | Mode | Trust Model | Proof Type | Performance |
//! |------|-------------|------------|-------------|
//! | A (Local) | Operator trusted | Signatures only | ~1ms |
//! | B-Lite | Computational | MPB proofs | ~1ms |
//! | B-Full | Cryptographic ZK | Risc0 receipts | ~minutes |
//! | C | Private + ZK | Encrypted + Risc0 | ~minutes |

use crate::error::{ModeError, ModeResult};
use crate::privacy::{
    EncryptedState, EncryptionConfig as ModeCEncryptionConfig,
    StateEncryptor as ModeCStateEncryptor,
};
use crate::risc0_host::{
    MpbPolicyProvider, Risc0Attestor as DecisionRisc0Attestor, Risc0MpbAttestor,
};
use crate::security::SecurityChecker;
use mprd_core::{
    CandidateAction, Decision, DecisionToken, Hash32, MprdError, ProofBundle, Result, RuleVerdict,
    StateSnapshot, VerificationStatus, ZkAttestor, ZkLocalVerifier,
};
use mprd_proof::integration::MpbLocalVerifier as ProofVerifier;
use mprd_risc0_methods::{MPRD_GUEST_ELF, MPRD_MPB_GUEST_ELF};
use mprd_risc0_shared::{
    action_encoding_id_v1, compute_decision_commitment_v3, limits_hash, limits_hash_mpb_v1,
    policy_exec_kind_host_trusted_id_v0, policy_exec_kind_mpb_id_v1, policy_exec_version_id_v1,
    state_encoding_id_v1, GuestJournalV3, JOURNAL_VERSION, MPB_FUEL_LIMIT_V1,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, instrument, warn};

// =============================================================================
// Deployment Modes
// =============================================================================

/// Deployment modes for MPRD.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentMode {
    /// Local mode: Signatures only, operator trusted.
    LocalTrusted,

    /// Mode B-Lite: Computational proofs using MPB.
    TrustlessLite,

    /// Mode B-Full: Cryptographic ZK using Risc0.
    TrustlessFull,

    /// Mode C: Private mode with encrypted inputs.
    Private,
}

impl Default for DeploymentMode {
    fn default() -> Self {
        Self::LocalTrusted
    }
}

impl DeploymentMode {
    /// Get the mode identifier for metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LocalTrusted => "A",
            Self::TrustlessLite => "B-Lite",
            Self::TrustlessFull => "B-Full",
            Self::Private => "C",
        }
    }

    /// Check if this mode requires ZK proofs.
    pub fn requires_zk(&self) -> bool {
        matches!(self, Self::TrustlessFull | Self::Private)
    }

    /// Check if this mode requires encryption.
    pub fn requires_encryption(&self) -> bool {
        matches!(self, Self::Private)
    }
}

// =============================================================================
// Mode Configuration
// =============================================================================

/// Configuration for a deployment mode.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModeConfig {
    /// The deployment mode.
    pub mode: DeploymentMode,

    /// Number of spot checks for MPB proofs (Mode B-Lite).
    /// More checks = higher security but slower verification.
    pub mpb_spot_checks: usize,

    /// Maximum fuel for MPB execution.
    pub mpb_max_fuel: u32,

    /// MPB policy bytecode (required for Mode B-Full mpb-in-guest).
    pub mpb_policy_bytecode: Option<Vec<u8>>,

    /// MPB policy variable bindings `(name, reg)` (required for Mode B-Full mpb-in-guest).
    pub mpb_policy_variables: Option<Vec<(String, u8)>>,

    /// Risc0 image ID for the transitional host-trusted guest (Mode C).
    pub risc0_image_id_host_trusted: Option<[u8; 32]>,

    /// Risc0 image ID for the MPB-in-guest program (Mode B-Full).
    pub risc0_image_id_mpb: Option<[u8; 32]>,

    /// Whether to encrypt inputs (Mode C).
    pub encrypt_inputs: bool,

    /// Encryption key ID (Mode C).
    pub encryption_key_id: Option<String>,

    /// Whether to use strict security checks.
    pub strict_security: bool,
}

impl Default for ModeConfig {
    fn default() -> Self {
        Self::mode_b_lite()
    }
}

impl ModeConfig {
    /// Mode A: Local trusted operation.
    pub fn mode_a() -> Self {
        Self {
            mode: DeploymentMode::LocalTrusted,
            mpb_spot_checks: 0,
            mpb_max_fuel: 10_000,
            mpb_policy_bytecode: None,
            mpb_policy_variables: None,
            risc0_image_id_host_trusted: None,
            risc0_image_id_mpb: None,
            encrypt_inputs: false,
            encryption_key_id: None,
            strict_security: true,
        }
    }

    /// Mode B-Lite: Computational proofs using MPB.
    pub fn mode_b_lite() -> Self {
        Self {
            mode: DeploymentMode::TrustlessLite,
            mpb_spot_checks: 64, // ~64 bits security
            mpb_max_fuel: 10_000,
            mpb_policy_bytecode: None,
            mpb_policy_variables: None,
            risc0_image_id_host_trusted: None,
            risc0_image_id_mpb: None,
            encrypt_inputs: false,
            encryption_key_id: None,
            strict_security: true,
        }
    }

    /// Mode B-Lite with custom spot checks.
    pub fn mode_b_lite_with_checks(spot_checks: usize) -> Self {
        let mut config = Self::mode_b_lite();
        config.mpb_spot_checks = spot_checks;
        config
    }

    /// Mode B-Full: Cryptographic ZK using Risc0.
    pub fn mode_b_full(image_id: [u8; 32]) -> Self {
        Self {
            mode: DeploymentMode::TrustlessFull,
            mpb_spot_checks: 0,
            mpb_max_fuel: 10_000,
            mpb_policy_bytecode: None,
            mpb_policy_variables: None,
            risc0_image_id_host_trusted: None,
            risc0_image_id_mpb: Some(image_id),
            encrypt_inputs: false,
            encryption_key_id: None,
            strict_security: true,
        }
    }

    /// Mode C: Private mode with encrypted inputs.
    pub fn mode_c(image_id: [u8; 32], key_id: impl Into<String>) -> Self {
        Self {
            mode: DeploymentMode::Private,
            mpb_spot_checks: 0,
            mpb_max_fuel: 10_000,
            mpb_policy_bytecode: None,
            mpb_policy_variables: None,
            risc0_image_id_host_trusted: Some(image_id),
            risc0_image_id_mpb: None,
            encrypt_inputs: true,
            encryption_key_id: Some(key_id.into()),
            strict_security: true,
        }
    }

    /// Validate configuration for producing proofs (attestors).
    pub fn validate(&self) -> ModeResult<()> {
        self.validate_internal(true)
    }

    /// Validate configuration for verifying proofs (verifiers).
    pub fn validate_for_verifier(&self) -> ModeResult<()> {
        self.validate_internal(false)
    }

    fn validate_internal(&self, require_policy_artifact: bool) -> ModeResult<()> {
        if self.strict_security && self.mode == DeploymentMode::LocalTrusted {
            return Err(ModeError::InvariantViolation {
                invariant: "strict_security".into(),
                details: "LocalTrusted mode is not trustless; set strict_security=false to explicitly allow stub verification/attestation".into(),
            });
        }

        let is_all_zero_image_id = |image_id: [u8; 32]| image_id == [0u8; 32];

        match self.mode {
            DeploymentMode::LocalTrusted => {
                // No special requirements
            }
            DeploymentMode::TrustlessLite => {
                if self.mpb_spot_checks < 16 {
                    return Err(ModeError::InvalidConfig(
                        "Mode B-Lite requires at least 16 spot checks for security".into(),
                    ));
                }
                if self.mpb_max_fuel == 0 {
                    return Err(ModeError::InvalidConfig(
                        "Mode B-Lite requires mpb_max_fuel > 0".into(),
                    ));
                }

                if require_policy_artifact {
                    if self
                        .mpb_policy_bytecode
                        .as_ref()
                        .map(|b| b.is_empty())
                        .unwrap_or(true)
                    {
                        return Err(ModeError::MissingConfig {
                            mode: "B-Lite".into(),
                            field: "mpb_policy_bytecode".into(),
                        });
                    }

                    if self.mpb_policy_variables.is_none() {
                        return Err(ModeError::MissingConfig {
                            mode: "B-Lite".into(),
                            field: "mpb_policy_variables".into(),
                        });
                    }
                }
            }
            DeploymentMode::TrustlessFull => {
                if self.mpb_max_fuel != MPB_FUEL_LIMIT_V1 {
                    return Err(ModeError::InvalidConfig(format!(
                        "Mode B-Full (mpb-v1) requires mpb_max_fuel == {}; got {}",
                        MPB_FUEL_LIMIT_V1, self.mpb_max_fuel
                    )));
                }

                if require_policy_artifact {
                    if self
                        .mpb_policy_bytecode
                        .as_ref()
                        .map(|b| b.is_empty())
                        .unwrap_or(true)
                    {
                        return Err(ModeError::MissingConfig {
                            mode: "B-Full".into(),
                            field: "mpb_policy_bytecode".into(),
                        });
                    }

                    if self.mpb_policy_variables.is_none() {
                        return Err(ModeError::MissingConfig {
                            mode: "B-Full".into(),
                            field: "mpb_policy_variables".into(),
                        });
                    }
                }

                if self.risc0_image_id_mpb.is_none() {
                    return Err(ModeError::MissingConfig {
                        mode: "B-Full".into(),
                        field: "risc0_image_id_mpb".into(),
                    });
                }

                if self.risc0_image_id_mpb.is_some_and(is_all_zero_image_id) {
                    return Err(ModeError::InvalidConfig(
                        "Mode B-Full risc0_image_id_mpb is all-zero; refusing to run with an unspecified guest".into(),
                    ));
                }
            }
            DeploymentMode::Private => {
                if self.risc0_image_id_host_trusted.is_none() {
                    return Err(ModeError::MissingConfig {
                        mode: "C".into(),
                        field: "risc0_image_id_host_trusted".into(),
                    });
                }

                if self
                    .risc0_image_id_host_trusted
                    .is_some_and(is_all_zero_image_id)
                {
                    return Err(ModeError::InvalidConfig(
                        "Mode C risc0_image_id_host_trusted is all-zero; refusing to run with an unspecified guest".into(),
                    ));
                }
                if self.encryption_key_id.is_none() {
                    return Err(ModeError::MissingConfig {
                        mode: "C".into(),
                        field: "encryption_key_id".into(),
                    });
                }
            }
        }
        Ok(())
    }
}

// =============================================================================
// Mode B-Lite: Robust MPB Integration
// =============================================================================

/// Robust attestor using real MPB computational proofs.
///
/// This integrates with the `mprd-proof` crate to generate actual
/// execution trace proofs with Merkle commitments.
pub struct RobustMpbAttestor {
    config: ModeConfig,
    security_checker: SecurityChecker,
    policy_bytecode: Vec<u8>,
    policy_variables: Vec<mprd_risc0_shared::MpbVarBindingV1>,
}

impl RobustMpbAttestor {
    /// Create a new attestor with configuration.
    pub fn new(config: ModeConfig) -> ModeResult<Self> {
        if config.mode != DeploymentMode::TrustlessLite {
            return Err(ModeError::InvalidConfig(format!(
                "RobustMpbAttestor requires TrustlessLite mode, got {:?}",
                config.mode
            )));
        }

        config.validate()?;

        let security_checker = if config.strict_security {
            SecurityChecker::strict()
        } else {
            SecurityChecker::permissive()
        };

        let policy_bytecode =
            config
                .mpb_policy_bytecode
                .clone()
                .ok_or(ModeError::MissingConfig {
                    mode: "B-Lite".into(),
                    field: "mpb_policy_bytecode".into(),
                })?;

        let mut vars = config
            .mpb_policy_variables
            .clone()
            .ok_or(ModeError::MissingConfig {
                mode: "B-Lite".into(),
                field: "mpb_policy_variables".into(),
            })?;
        vars.sort_by(|a, b| a.0.cmp(&b.0));
        for w in vars.windows(2) {
            if w[0].0 >= w[1].0 {
                return Err(ModeError::InvalidConfig(
                    "mpb_policy_variables must be unique and sorted".into(),
                ));
            }
        }

        let policy_variables: Vec<mprd_risc0_shared::MpbVarBindingV1> = vars
            .into_iter()
            .map(|(name, reg)| mprd_risc0_shared::MpbVarBindingV1 {
                name: name.into_bytes(),
                reg,
            })
            .collect();

        Ok(Self {
            config,
            security_checker,
            policy_bytecode,
            policy_variables,
        })
    }

    /// Create with default configuration.
    pub fn default_config() -> ModeResult<Self> {
        let mut cfg = ModeConfig::mode_b_lite();
        // Default allow-all policy (MPB): PUSH 1, HALT.
        cfg.mpb_policy_bytecode = Some(
            mprd_core::mpb::BytecodeBuilder::new()
                .push_i64(1)
                .halt()
                .build(),
        );
        cfg.mpb_policy_variables = Some(vec![]);
        Self::new(cfg)
    }

    /// Get the number of spot checks.
    pub fn spot_checks(&self) -> usize {
        self.config.mpb_spot_checks
    }

    /// Compute security level in bits.
    pub fn security_bits(&self) -> f64 {
        // Each spot check provides ~1 bit of security
        self.config.mpb_spot_checks as f64
    }
}

impl ZkAttestor for RobustMpbAttestor {
    #[instrument(skip(self, decision, state, candidates), fields(mode = "B-Lite"))]
    fn attest(
        &self,
        token: &DecisionToken,
        decision: &Decision,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<ProofBundle> {
        info!(
            policy = %hex::encode(&decision.policy_hash.0[..8]),
            candidates = candidates.len(),
            "Generating MPB attestation"
        );

        // Validate inputs
        self.security_checker
            .check_hash_validity(&decision.policy_hash, "policy_hash")
            .map_err(|e| MprdError::ZkError(e.to_string()))?;
        self.security_checker
            .check_hash_validity(&state.state_hash, "state_hash")
            .map_err(|e| MprdError::ZkError(e.to_string()))?;

        // Candidate set commitment (must match mprd-core canonical hashing).
        let candidate_set_hash = compute_candidate_set_hash(candidates);

        let chosen_action_preimage =
            mprd_core::hash::candidate_hash_preimage(&decision.chosen_action);

        // Commit MPB evaluation fuel limit as canonical limits bytes.
        let mut limits_bytes = Vec::with_capacity(1 + 4);
        limits_bytes.push(mprd_core::limits::tags::MPB_FUEL_LIMIT);
        limits_bytes.extend_from_slice(&self.config.mpb_max_fuel.to_le_bytes());
        let limits_hash = mprd_core::limits::limits_hash_v1(&limits_bytes);

        // Build a deterministic MPB proof context binding this proof to the signed token fields.
        let context_hash = crate::mpb_lite::mpb_lite_context_hash_parts_v1(
            token,
            &candidate_set_hash,
            &limits_hash,
        );

        // Verify policy hash matches the configured MPB artifact (fail-closed).
        let policy_hash = crate::mpb_lite::policy_hash_from_artifact_v1(
            &self.policy_bytecode,
            &self.policy_variables,
        );
        if policy_hash != token.policy_hash || policy_hash != decision.policy_hash {
            return Err(MprdError::ZkError(
                "policy_hash mismatch vs configured MPB policy".into(),
            ));
        }

        // Verify state preimage binds to the state hash.
        let state_preimage = mprd_core::hash::state_hash_preimage(state);
        let state_hash = mprd_core::hash::hash_state_preimage_v1(&state_preimage);
        if state_hash != token.state_hash || state_hash != state.state_hash {
            return Err(MprdError::ZkError("state_hash mismatch".into()));
        }

        // Verify chosen action binds to token.
        let chosen_action_hash =
            mprd_core::hash::hash_candidate_preimage_v1(&chosen_action_preimage);
        if chosen_action_hash != token.chosen_action_hash
            || chosen_action_hash != decision.chosen_action.candidate_hash
        {
            return Err(MprdError::ZkError("chosen_action_hash mismatch".into()));
        }

        // Candidate membership: chosen_index must match candidate list ordering.
        let chosen_index: u32 = decision
            .chosen_index
            .try_into()
            .map_err(|_| MprdError::InvalidInput("chosen_index overflow".into()))?;
        if chosen_index as usize >= candidates.len() {
            return Err(MprdError::InvalidInput("chosen_index out of bounds".into()));
        }
        if candidates[chosen_index as usize].candidate_hash != token.chosen_action_hash {
            return Err(MprdError::ZkError(
                "chosen_action_hash not at chosen_index".into(),
            ));
        }

        // Compute registers from canonical preimages (single source of truth mapping).
        let bindings: Vec<(&[u8], u8)> = self
            .policy_variables
            .iter()
            .map(|v| (v.name.as_slice(), v.reg))
            .collect();
        let regs = mprd_mpb::registers_from_preimages_v1(
            &state_preimage,
            &chosen_action_preimage,
            &bindings,
        )
        .map_err(|e| MprdError::InvalidInput(format!("register mapping failed: {e:?}")))?;
        let registers: Vec<i64> = regs.to_vec();

        // Generate computational proof of MPB execution.
        let attestor = mprd_proof::MpbAttestor::with_config(mprd_proof::MpbAttestorConfig {
            num_spot_checks: self.config.mpb_spot_checks,
            seed: None,
            fuel_limit: self.config.mpb_max_fuel,
        });

        let (output, mpb_proof_bundle) = attestor
            .attest_with_output_and_context(&self.policy_bytecode, &registers, context_hash)
            .map_err(|e| MprdError::ZkError(format!("mpb proof generation failed: {e:?}")))?;

        if output == 0 {
            return Err(MprdError::ZkError("MPB policy denied chosen action".into()));
        }

        // Record candidate hashes (enables verifier recomputation of candidate_set_hash).
        let candidate_hashes: Vec<[u8; 32]> =
            candidates.iter().map(|c| c.candidate_hash.0).collect();

        let artifact = crate::mpb_lite::MpbLiteArtifactV1 {
            version: crate::mpb_lite::MPB_LITE_ARTIFACT_VERSION_V1,
            mpb_register_mapping_id: mprd_risc0_shared::mpb_register_mapping_id_v1(),
            policy_variables: self.policy_variables.clone(),
            state_preimage,
            candidate_hashes,
            chosen_index,
            mpb_proof_bundle,
            limits_bytes: limits_bytes.clone(),
            chosen_action_preimage: chosen_action_preimage.clone(),
        };

        let artifact_bytes = bincode::serialize(&artifact)
            .map_err(|e| MprdError::ZkError(format!("mpb artifact serialization failed: {e}")))?;

        let mut metadata = HashMap::new();
        metadata.insert("mode".into(), self.config.mode.as_str().into());
        metadata.insert("proof_type".into(), "MPB".into());
        metadata.insert("proof_backend".into(), "mpb_lite_v1".into());
        metadata.insert(
            "spot_checks".into(),
            self.config.mpb_spot_checks.to_string(),
        );
        metadata.insert("fuel_limit".into(), self.config.mpb_max_fuel.to_string());
        metadata.insert(
            "nonce_or_tx_hash".into(),
            hex::encode(token.nonce_or_tx_hash.0),
        );
        metadata.insert("artifact_bytes".into(), artifact_bytes.len().to_string());

        debug!(
            candidate_set_hash = %hex::encode(&candidate_set_hash.0[..8]),
            "MPB attestation complete"
        );

        Ok(ProofBundle {
            policy_hash,
            state_hash,
            candidate_set_hash,
            chosen_action_hash,
            limits_hash,
            limits_bytes,
            chosen_action_preimage,
            risc0_receipt: artifact_bytes,
            attestation_metadata: metadata,
        })
    }
}

// =============================================================================
// MPB Verification Helper Functions (Cyclomatic Complexity Reduction)
// =============================================================================

/// Verify basic binding checks between token and proof (fail-closed).
fn verify_mpb_token_binding(
    token: &DecisionToken,
    proof: &ProofBundle,
) -> std::result::Result<(), VerificationStatus> {
    if token.policy_hash != proof.policy_hash {
        return Err(VerificationStatus::Failure("policy_hash mismatch".into()));
    }
    if token.state_hash != proof.state_hash {
        return Err(VerificationStatus::Failure("state_hash mismatch".into()));
    }
    if token.chosen_action_hash != proof.chosen_action_hash {
        return Err(VerificationStatus::Failure(
            "chosen_action_hash mismatch".into(),
        ));
    }
    Ok(())
}

/// Verify limits binding and parsing (fail-closed).
fn verify_mpb_limits(
    proof: &ProofBundle,
    expected_fuel: u32,
) -> std::result::Result<(), VerificationStatus> {
    if let Err(e) =
        mprd_core::limits::verify_limits_binding_v1(&proof.limits_hash, &proof.limits_bytes)
    {
        return Err(VerificationStatus::Failure(format!(
            "limits binding failed: {e}"
        )));
    }
    let limits = match mprd_core::limits::parse_limits_v1(&proof.limits_bytes) {
        Ok(l) => l,
        Err(e) => {
            return Err(VerificationStatus::Failure(format!(
                "limits parse failed: {e}"
            )))
        }
    };
    if limits.mpb_fuel_limit != Some(expected_fuel) {
        return Err(VerificationStatus::Failure(
            "mpb_fuel_limit mismatch".into(),
        ));
    }
    Ok(())
}

/// Decode and validate MPB artifact from proof bundle.
fn decode_mpb_artifact(
    proof: &ProofBundle,
) -> std::result::Result<crate::mpb_lite::MpbLiteArtifactV1, VerificationStatus> {
    if proof.risc0_receipt.is_empty() {
        return Err(VerificationStatus::Failure(
            "missing mpb lite proof artifact".into(),
        ));
    }
    let artifact: crate::mpb_lite::MpbLiteArtifactV1 =
        match crate::bounded_deser::deserialize_mpb_artifact(&proof.risc0_receipt) {
            Ok(a) => a,
            Err(e) => {
                return Err(VerificationStatus::Failure(format!(
                    "mpb artifact decode failed: {e}"
                )))
            }
        };
    if let Err(e) = crate::mpb_lite::verify_artifact_header(&artifact) {
        return Err(VerificationStatus::Failure(format!(
            "mpb artifact invalid: {e}"
        )));
    }
    Ok(artifact)
}

/// Verify preimage hashes match token/proof commitments.
fn verify_mpb_preimage_hashes(
    token: &DecisionToken,
    proof: &ProofBundle,
    artifact: &crate::mpb_lite::MpbLiteArtifactV1,
) -> std::result::Result<(), VerificationStatus> {
    // Fail-closed: artifact must carry the same execution-affecting bytes the proof bundle
    // exposes for executor derivation / auditing.
    if artifact.limits_bytes != proof.limits_bytes {
        return Err(VerificationStatus::Failure(
            "limits_bytes mismatch vs artifact".into(),
        ));
    }
    if mprd_core::limits::limits_hash_v1(&artifact.limits_bytes) != proof.limits_hash {
        return Err(VerificationStatus::Failure(
            "limits_hash mismatch vs limits_bytes".into(),
        ));
    }

    if artifact.chosen_action_preimage != proof.chosen_action_preimage {
        return Err(VerificationStatus::Failure(
            "chosen_action_preimage mismatch vs artifact".into(),
        ));
    }
    let chosen_action_hash =
        mprd_core::hash::hash_candidate_preimage_v1(&artifact.chosen_action_preimage);
    if chosen_action_hash != token.chosen_action_hash
        || chosen_action_hash != proof.chosen_action_hash
    {
        return Err(VerificationStatus::Failure(
            "chosen_action_hash mismatch vs preimage".into(),
        ));
    }

    // Verify state hash
    let state_hash = mprd_core::hash::hash_state_preimage_v1(&artifact.state_preimage);
    if state_hash != token.state_hash || state_hash != proof.state_hash {
        return Err(VerificationStatus::Failure(
            "state_hash mismatch vs preimage".into(),
        ));
    }

    // Verify candidate set hash
    let mut set_preimage = Vec::with_capacity(4 + artifact.candidate_hashes.len() * 32);
    set_preimage.extend_from_slice(&(artifact.candidate_hashes.len() as u32).to_le_bytes());
    for h in &artifact.candidate_hashes {
        set_preimage.extend_from_slice(h);
    }
    let candidate_set_hash = mprd_core::hash::hash_candidate_set_preimage_v1(&set_preimage);
    if candidate_set_hash != proof.candidate_set_hash {
        return Err(VerificationStatus::Failure(
            "candidate_set_hash mismatch".into(),
        ));
    }

    // Verify chosen index + membership
    let idx = artifact.chosen_index as usize;
    if idx >= artifact.candidate_hashes.len() {
        return Err(VerificationStatus::Failure(
            "chosen_index out of bounds".into(),
        ));
    }
    if Hash32(artifact.candidate_hashes[idx]) != token.chosen_action_hash {
        return Err(VerificationStatus::Failure(
            "chosen_action_hash not at chosen_index".into(),
        ));
    }
    if Hash32(artifact.candidate_hashes[idx]) != chosen_action_hash {
        return Err(VerificationStatus::Failure(
            "chosen_action_preimage does not match chosen_index".into(),
        ));
    }

    // Verify policy hash binds to bytecode + variable mapping
    let policy_hash = crate::mpb_lite::policy_hash_from_artifact_v1(
        &artifact.mpb_proof_bundle.bytecode,
        &artifact.policy_variables,
    );
    if policy_hash != token.policy_hash || policy_hash != proof.policy_hash {
        return Err(VerificationStatus::Failure(
            "policy_hash mismatch vs artifact".into(),
        ));
    }

    Ok(())
}

/// Verify MPB proof correctness and context binding.
fn verify_mpb_proof_correctness(
    token: &DecisionToken,
    proof: &ProofBundle,
    artifact: &crate::mpb_lite::MpbLiteArtifactV1,
    expected_spot_checks: usize,
) -> std::result::Result<(), VerificationStatus> {
    // Recompute expected registers
    let bindings: Vec<(&[u8], u8)> = artifact
        .policy_variables
        .iter()
        .map(|v| (v.name.as_slice(), v.reg))
        .collect();
    let regs = match mprd_mpb::registers_from_preimages_v1(
        &artifact.state_preimage,
        &artifact.chosen_action_preimage,
        &bindings,
    ) {
        Ok(r) => r,
        Err(e) => {
            return Err(VerificationStatus::Failure(format!(
                "register mapping failed: {e:?}"
            )));
        }
    };
    let expected_registers: Vec<i64> = regs.to_vec();
    if artifact.mpb_proof_bundle.registers != expected_registers {
        return Err(VerificationStatus::Failure("mpb registers mismatch".into()));
    }

    // Verify the computational proof
    let expected_bytecode_hash = mprd_proof::sha256(&artifact.mpb_proof_bundle.bytecode);
    let expected_input_hash = crate::mpb_lite::registers_input_hash(&expected_registers);
    if let Err(e) = crate::mpb_lite::verify_mpb_proof_bundle_with_inputs(
        &artifact.mpb_proof_bundle,
        &expected_bytecode_hash,
        &expected_input_hash,
    ) {
        return Err(VerificationStatus::Failure(e.to_string()));
    }

    // Verify context binding
    let expected_context = crate::mpb_lite::mpb_lite_context_hash_parts_v1(
        token,
        &proof.candidate_set_hash,
        &proof.limits_hash,
    );
    if artifact.mpb_proof_bundle.proof.context_hash != expected_context {
        return Err(VerificationStatus::Failure(
            "mpb proof context_hash mismatch".into(),
        ));
    }

    // Enforce spot check count
    let max = artifact.mpb_proof_bundle.proof.num_steps.saturating_sub(2);
    let actual_checks = expected_spot_checks.min(max);
    if artifact.mpb_proof_bundle.proof.spot_checks.len() != actual_checks {
        return Err(VerificationStatus::Failure(
            "spot_checks count mismatch".into(),
        ));
    }

    // Check policy verdict
    if artifact.mpb_proof_bundle.proof.output == 0 {
        return Err(VerificationStatus::Failure(
            "policy denied chosen action".into(),
        ));
    }

    Ok(())
}

/// Robust verifier for MPB computational proofs.
pub struct RobustMpbVerifier {
    config: ModeConfig,
    #[allow(dead_code)]
    proof_verifier: ProofVerifier,
}

impl RobustMpbVerifier {
    /// Create a new verifier with configuration.
    pub fn new(config: ModeConfig) -> ModeResult<Self> {
        if config.mode != DeploymentMode::TrustlessLite {
            return Err(ModeError::InvalidConfig(format!(
                "RobustMpbVerifier requires TrustlessLite mode, got {:?}",
                config.mode
            )));
        }

        config.validate_for_verifier()?;

        Ok(Self {
            config,
            proof_verifier: ProofVerifier::new(),
        })
    }

    /// Create with default configuration.
    pub fn default_config() -> ModeResult<Self> {
        Self::new(ModeConfig::mode_b_lite())
    }
}

impl ZkLocalVerifier for RobustMpbVerifier {
    #[instrument(skip(self, token, proof), fields(mode = "B-Lite"))]
    fn verify(&self, token: &DecisionToken, proof: &ProofBundle) -> VerificationStatus {
        debug!("Starting MPB proof verification");

        // Step 1: Mode check
        if self.config.mode != DeploymentMode::TrustlessLite {
            return VerificationStatus::Failure(
                "RobustMpbVerifier requires TrustlessLite mode".into(),
            );
        }

        // Step 2: Token-proof binding (extracted helper, CC reduction)
        if let Err(status) = verify_mpb_token_binding(token, proof) {
            return status;
        }

        // Step 3: Limits verification (extracted helper, CC reduction)
        if let Err(status) = verify_mpb_limits(proof, self.config.mpb_max_fuel) {
            return status;
        }

        // Step 4: Decode artifact (extracted helper, CC reduction)
        let artifact = match decode_mpb_artifact(proof) {
            Ok(a) => a,
            Err(status) => return status,
        };

        // Step 5: Preimage hash verification (extracted helper, CC reduction)
        if let Err(status) = verify_mpb_preimage_hashes(token, proof, &artifact) {
            return status;
        }

        // Step 6: Proof correctness (extracted helper, CC reduction)
        if let Err(status) =
            verify_mpb_proof_correctness(token, proof, &artifact, self.config.mpb_spot_checks)
        {
            return status;
        }

        info!("MPB proof verification successful");
        VerificationStatus::Success
    }
}

// =============================================================================
// Mode B-Full: Risc0 Infrastructure
// =============================================================================

/// Robust attestor using Risc0 cryptographic ZK proofs.
pub struct RobustRisc0Attestor {
    config: ModeConfig,
    #[allow(dead_code)]
    method_elf: Option<&'static [u8]>,
    mpb_policy_provider: Option<Arc<dyn MpbPolicyProvider>>,
    security_checker: SecurityChecker,
}

impl RobustRisc0Attestor {
    /// Create a new attestor.
    pub fn new(
        config: ModeConfig,
        method_elf: Option<&'static [u8]>,
        mpb_policy_provider: Option<Arc<dyn MpbPolicyProvider>>,
    ) -> ModeResult<Self> {
        if config.mode != DeploymentMode::TrustlessFull {
            return Err(ModeError::InvalidConfig(format!(
                "RobustRisc0Attestor requires TrustlessFull mode, got {:?}",
                config.mode
            )));
        }

        // Don't validate config here - allow partial setup
        let security_checker = SecurityChecker::strict();

        Ok(Self {
            config,
            method_elf,
            mpb_policy_provider,
            security_checker,
        })
    }

    /// Check if Risc0 is fully configured.
    pub fn is_available(&self) -> bool {
        self.method_elf.is_some()
            && self.config.risc0_image_id_mpb.is_some()
            && self.mpb_policy_provider.is_some()
    }

    /// Get availability status with reason.
    pub fn availability_status(&self) -> (bool, &'static str) {
        if self.method_elf.is_none() {
            return (false, "method_elf not provided");
        }
        if self.config.risc0_image_id_mpb.is_none() {
            return (false, "risc0_image_id_mpb not configured");
        }
        if self.mpb_policy_provider.is_none() {
            return (false, "mpb_policy_provider not provided");
        }
        (true, "ready")
    }
}

impl ZkAttestor for RobustRisc0Attestor {
    #[instrument(skip(self, decision, state, candidates), fields(mode = "B-Full"))]
    fn attest(
        &self,
        token: &DecisionToken,
        decision: &Decision,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<ProofBundle> {
        let (available, reason) = self.availability_status();
        if !available {
            error!(reason = reason, "Risc0 not available");
            return Err(MprdError::ZkError(format!(
                "Risc0 not available: {}. Use Mode B-Lite for computational proofs.",
                reason
            )));
        }

        // Validate inputs (basic hash sanity)
        self.security_checker
            .check_hash_validity(&decision.policy_hash, "policy_hash")
            .map_err(|e| MprdError::ZkError(e.to_string()))?;
        self.security_checker
            .check_hash_validity(&state.state_hash, "state_hash")
            .map_err(|e| MprdError::ZkError(e.to_string()))?;

        let Some(image_id) = self.config.risc0_image_id_mpb else {
            return Err(MprdError::ZkError(
                "Risc0 not available: risc0_image_id_mpb not configured. Use Mode B-Lite for computational proofs.".into(),
            ));
        };
        let Some(guest_elf) = self.method_elf else {
            return Err(MprdError::ZkError(
                "Risc0 not available: method_elf not provided. Use Mode B-Lite for computational proofs.".into(),
            ));
        };
        let Some(policy_provider) = self.mpb_policy_provider.as_ref() else {
            return Err(MprdError::ZkError(
                "Risc0 not available: mpb_policy_provider not provided".into(),
            ));
        };

        let inner = Risc0MpbAttestor::new(
            guest_elf,
            image_id,
            self.config.mpb_max_fuel,
            Arc::clone(policy_provider),
        );
        inner.attest(token, decision, state, candidates)
    }
}

/// Robust verifier for Risc0 proofs.
pub struct RobustRisc0Verifier {
    config: ModeConfig,
    security_checker: SecurityChecker,
}

impl RobustRisc0Verifier {
    /// Create a new verifier.
    pub fn new(config: ModeConfig) -> ModeResult<Self> {
        if config.mode != DeploymentMode::TrustlessFull {
            return Err(ModeError::InvalidConfig(format!(
                "RobustRisc0Verifier requires TrustlessFull mode, got {:?}",
                config.mode
            )));
        }

        Ok(Self {
            config,
            security_checker: SecurityChecker::strict(),
        })
    }

    /// Verify a Risc0 receipt and extract the committed journal.
    pub fn verify_receipt(&self, receipt: &[u8]) -> ModeResult<GuestJournalV3> {
        if receipt.is_empty() {
            return Err(ModeError::VerificationFailed("Empty Risc0 receipt".into()));
        }

        let image_id = self
            .config
            .risc0_image_id_mpb
            .ok_or_else(|| ModeError::MissingConfig {
                mode: "B-Full".into(),
                field: "risc0_image_id_mpb".into(),
            })?;

        // Deserialize the zkVM receipt (bounded to prevent DoS)
        let receipt: risc0_zkvm::Receipt = crate::bounded_deser::deserialize_receipt(receipt)
            .map_err(|e| {
                ModeError::VerificationFailed(format!("Failed to deserialize receipt: {}", e))
            })?;

        // Verify against image ID
        let digest = risc0_zkvm::sha::Digest::from_bytes(image_id);
        receipt.verify(digest).map_err(|e| {
            ModeError::VerificationFailed(format!("Receipt verification failed: {}", e))
        })?;

        // Decode guest journal
        let journal: GuestJournalV3 = receipt.journal.decode().map_err(|e| {
            ModeError::VerificationFailed(format!("Failed to decode journal: {}", e))
        })?;
        Ok(journal)
    }
}

impl ZkLocalVerifier for RobustRisc0Verifier {
    #[instrument(skip(self, token, proof), fields(mode = "B-Full"))]
    fn verify(&self, token: &DecisionToken, proof: &ProofBundle) -> VerificationStatus {
        // Step 1: Verify binding
        if let Err(e) = self.security_checker.check_binding(token, proof) {
            return VerificationStatus::Failure(e.to_string());
        }

        // Step 2: Check for receipt
        if proof.risc0_receipt.is_empty() {
            return VerificationStatus::Failure("No Risc0 receipt in proof bundle".into());
        }

        // Step 3: Verify receipt (TODO)
        match self.verify_receipt(&proof.risc0_receipt) {
            Ok(journal) => {
                if journal.journal_version != JOURNAL_VERSION {
                    return VerificationStatus::Failure("Unsupported journal_version".into());
                }

                if journal.state_encoding_id != state_encoding_id_v1()
                    || journal.action_encoding_id != action_encoding_id_v1()
                {
                    return VerificationStatus::Failure("Unsupported encoding_id".into());
                }

                if journal.policy_exec_kind_id != policy_exec_kind_mpb_id_v1()
                    || journal.policy_exec_version_id != policy_exec_version_id_v1()
                {
                    return VerificationStatus::Failure(
                        "Unsupported policy_exec_kind/version".into(),
                    );
                }

                let expected_commitment = compute_decision_commitment_v3(&journal);
                if journal.decision_commitment != expected_commitment {
                    return VerificationStatus::Failure("decision_commitment mismatch".into());
                }

                if Hash32(journal.policy_hash) != token.policy_hash {
                    return VerificationStatus::Failure("Policy hash mismatch in journal".into());
                }
                if journal.policy_epoch != token.policy_ref.policy_epoch {
                    return VerificationStatus::Failure("policy_epoch mismatch in journal".into());
                }
                if Hash32(journal.registry_root) != token.policy_ref.registry_root {
                    return VerificationStatus::Failure("registry_root mismatch in journal".into());
                }

                if Hash32(journal.state_source_id) != token.state_ref.state_source_id {
                    return VerificationStatus::Failure(
                        "state_source_id mismatch in journal".into(),
                    );
                }
                if journal.state_epoch != token.state_ref.state_epoch {
                    return VerificationStatus::Failure("state_epoch mismatch in journal".into());
                }
                if Hash32(journal.state_attestation_hash) != token.state_ref.state_attestation_hash
                {
                    return VerificationStatus::Failure(
                        "state_attestation_hash mismatch in journal".into(),
                    );
                }

                if Hash32(journal.state_hash) != token.state_hash {
                    return VerificationStatus::Failure("State hash mismatch in journal".into());
                }

                if Hash32(journal.candidate_set_hash) != proof.candidate_set_hash {
                    return VerificationStatus::Failure(
                        "Candidate set hash mismatch in journal".into(),
                    );
                }

                if Hash32(journal.chosen_action_hash) != token.chosen_action_hash {
                    return VerificationStatus::Failure(
                        "Chosen action hash mismatch in journal".into(),
                    );
                }

                if Hash32(journal.nonce_or_tx_hash) != token.nonce_or_tx_hash {
                    return VerificationStatus::Failure(
                        "nonce_or_tx_hash mismatch in journal".into(),
                    );
                }

                if journal.limits_hash != limits_hash_mpb_v1() {
                    return VerificationStatus::Failure("limits_hash mismatch".into());
                }

                if !journal.allowed {
                    return VerificationStatus::Failure(
                        "Selector contract not satisfied in journal".into(),
                    );
                }

                VerificationStatus::Success
            }
            Err(e) => VerificationStatus::Failure(e.to_string()),
        }
    }
}
// Mode C: Private (Encrypted)
// =============================================================================

/// Encryption configuration for Mode C.
///
/// # Security
///
/// The `master_key` field MUST be set with actual secret key material
/// from a secure source (HSM, KMS, secure key file) before use.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Key identifier for key management.
    pub key_id: String,

    /// Encryption algorithm (default: AES-256-GCM).
    pub algorithm: String,

    /// Master key for encryption. MUST be set before use.
    /// This is NOT serialized to avoid accidental exposure.
    #[serde(skip)]
    pub master_key: Option<[u8; 32]>,
}

impl std::fmt::Debug for EncryptionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionConfig")
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .field("master_key", &"[REDACTED]")
            .finish()
    }
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            key_id: "default".into(),
            algorithm: "AES-256-GCM".into(),
            master_key: None,
        }
    }
}

impl EncryptionConfig {
    /// Create config with a master key.
    pub fn with_master_key(key_id: impl Into<String>, master_key: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            algorithm: "AES-256-GCM".into(),
            master_key: Some(master_key),
        }
    }
}

/// Robust attestor for Mode C (Private).
pub struct RobustPrivateAttestor {
    config: ModeConfig,
    encryption_config: EncryptionConfig,
    #[allow(dead_code)]
    security_checker: SecurityChecker,
}

impl RobustPrivateAttestor {
    /// Create a new private attestor.
    pub fn new(config: ModeConfig, encryption_config: EncryptionConfig) -> ModeResult<Self> {
        if config.mode != DeploymentMode::Private {
            return Err(ModeError::InvalidConfig(format!(
                "RobustPrivateAttestor requires Private mode, got {:?}",
                config.mode
            )));
        }

        Ok(Self {
            config,
            encryption_config,
            security_checker: SecurityChecker::strict(),
        })
    }
}

impl ZkAttestor for RobustPrivateAttestor {
    #[instrument(skip(self, decision, state, candidates), fields(mode = "C"))]
    fn attest(
        &self,
        token: &DecisionToken,
        decision: &Decision,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<ProofBundle> {
        let image_id = match self.config.risc0_image_id_host_trusted {
            Some(id) => id,
            None => return Err(MprdError::ZkError("Mode C requires Risc0 image_id".into())),
        };

        let key_id = match &self.config.encryption_key_id {
            Some(id) => id.clone(),
            None => self.encryption_config.key_id.clone(),
        };

        // Fail-closed algorithm allowlist.
        if self.encryption_config.algorithm != "AES-256-GCM" {
            return Err(MprdError::ZkError(
                "Mode C currently only supports AES-256-GCM".into(),
            ));
        }

        let committed_fields: Vec<String> = state.fields.keys().cloned().collect();

        let enc_config = ModeCEncryptionConfig {
            key_id: key_id.clone(),
            master_key: self.encryption_config.master_key,
            committed_fields,
            encrypted_fields: Vec::new(),
            revealed_fields: Vec::new(),
        };

        let encryptor = ModeCStateEncryptor::new(enc_config);

        let (encrypted_state, _witness) = encryptor
            .encrypt(state)
            .map_err(|e| MprdError::ZkError(e.to_string()))?;

        let attestor = DecisionRisc0Attestor::new(MPRD_GUEST_ELF, image_id);

        let verdict = RuleVerdict {
            allowed: true,
            reasons: Vec::new(),
            limits: HashMap::new(),
        };

        // Bind the encrypted payload to the receipt transcript via committed `limits_hash/limits_bytes`.
        let ctx_hash = mprd_core::limits::mode_c_encryption_ctx_hash_v1(
            &token.state_hash,
            &token.nonce_or_tx_hash,
            &key_id,
            &self.encryption_config.algorithm,
            &encrypted_state.nonce,
            &encrypted_state.ciphertext,
        );
        let limits_bytes = mprd_core::limits::limits_bytes_mode_c_encryption_ctx_v1(&ctx_hash);

        let mut bundle = attestor.attest_with_verdict_and_limits_bytes(
            token,
            decision,
            state,
            candidates,
            &verdict,
            limits_bytes,
        )?;

        let encrypted_json = serde_json::to_string(&encrypted_state).map_err(|e| {
            MprdError::ZkError(format!("Failed to serialize encrypted state: {}", e))
        })?;

        bundle
            .attestation_metadata
            .insert("mode".into(), DeploymentMode::Private.as_str().into());
        bundle
            .attestation_metadata
            .insert("encryption_key_id".into(), key_id);
        bundle.attestation_metadata.insert(
            "nonce_or_tx_hash".into(),
            hex::encode(token.nonce_or_tx_hash.0),
        );
        bundle.attestation_metadata.insert(
            "encryption_algorithm".into(),
            self.encryption_config.algorithm.clone(),
        );
        bundle
            .attestation_metadata
            .insert("encrypted_state".into(), encrypted_json);

        Ok(bundle)
    }
}

/// Robust verifier for Mode C.
pub struct RobustPrivateVerifier {
    config: ModeConfig,
}

impl RobustPrivateVerifier {
    pub fn new(config: ModeConfig) -> ModeResult<Self> {
        if config.mode != DeploymentMode::Private {
            return Err(ModeError::InvalidConfig(format!(
                "RobustPrivateVerifier requires Private mode, got {:?}",
                config.mode
            )));
        }
        Ok(Self { config })
    }
}

impl ZkLocalVerifier for RobustPrivateVerifier {
    fn verify(&self, token: &DecisionToken, proof: &ProofBundle) -> VerificationStatus {
        let image_id = match self.config.risc0_image_id_host_trusted {
            Some(id) => id,
            None => return VerificationStatus::Failure("Mode C requires Risc0 image_id".into()),
        };

        if proof.risc0_receipt.is_empty() {
            return VerificationStatus::Failure("No Risc0 receipt in proof".into());
        }
        // Verify receipt + journal bindings (fail-closed, bounded deserialization).
        let receipt: risc0_zkvm::Receipt =
            match crate::bounded_deser::deserialize_receipt(&proof.risc0_receipt) {
                Ok(r) => r,
                Err(e) => {
                    return VerificationStatus::Failure(format!(
                        "Failed to deserialize receipt: {}",
                        e
                    ))
                }
            };

        let digest = risc0_zkvm::sha::Digest::from_bytes(image_id);
        if let Err(e) = receipt.verify(digest) {
            return VerificationStatus::Failure(format!("Receipt verification failed: {}", e));
        }

        let journal: GuestJournalV3 = match receipt.journal.decode() {
            Ok(j) => j,
            Err(e) => {
                return VerificationStatus::Failure(format!("Failed to decode journal: {}", e))
            }
        };

        if journal.journal_version != JOURNAL_VERSION {
            return VerificationStatus::Failure("Unsupported journal_version".into());
        }
        if journal.state_encoding_id != state_encoding_id_v1()
            || journal.action_encoding_id != action_encoding_id_v1()
        {
            return VerificationStatus::Failure("Unsupported encoding_id".into());
        }
        if journal.policy_exec_kind_id != policy_exec_kind_host_trusted_id_v0()
            || journal.policy_exec_version_id != policy_exec_version_id_v1()
        {
            return VerificationStatus::Failure("Unsupported policy_exec_kind/version".into());
        }
        if journal.decision_commitment != compute_decision_commitment_v3(&journal) {
            return VerificationStatus::Failure("decision_commitment mismatch".into());
        }

        // Fail-closed: bind journal commitments to token/proof.
        if Hash32(journal.policy_hash) != token.policy_hash {
            return VerificationStatus::Failure("Policy hash mismatch".into());
        }
        if journal.policy_epoch != token.policy_ref.policy_epoch {
            return VerificationStatus::Failure("policy_epoch mismatch".into());
        }
        if Hash32(journal.registry_root) != token.policy_ref.registry_root {
            return VerificationStatus::Failure("registry_root mismatch".into());
        }
        if Hash32(journal.state_source_id) != token.state_ref.state_source_id {
            return VerificationStatus::Failure("state_source_id mismatch".into());
        }
        if journal.state_epoch != token.state_ref.state_epoch {
            return VerificationStatus::Failure("state_epoch mismatch".into());
        }
        if Hash32(journal.state_attestation_hash) != token.state_ref.state_attestation_hash {
            return VerificationStatus::Failure("state_attestation_hash mismatch".into());
        }
        if Hash32(journal.state_hash) != token.state_hash {
            return VerificationStatus::Failure("State hash mismatch".into());
        }
        if Hash32(journal.candidate_set_hash) != proof.candidate_set_hash {
            return VerificationStatus::Failure("Candidate set hash mismatch".into());
        }
        if Hash32(journal.chosen_action_hash) != token.chosen_action_hash {
            return VerificationStatus::Failure("Chosen action hash mismatch".into());
        }
        if Hash32(journal.nonce_or_tx_hash) != token.nonce_or_tx_hash {
            return VerificationStatus::Failure("nonce_or_tx_hash mismatch".into());
        }
        if !journal.allowed {
            return VerificationStatus::Failure(
                "Selector contract not satisfied in journal".into(),
            );
        }

        // Limits hash must bind to the provided limits_bytes (fail-closed).
        let expected_limits_hash = limits_hash(&proof.limits_bytes);
        if journal.limits_hash != expected_limits_hash {
            return VerificationStatus::Failure("limits_hash mismatch".into());
        }
        if proof.limits_hash != Hash32(journal.limits_hash) {
            return VerificationStatus::Failure("limits_hash mismatch vs proof".into());
        }
        if let Err(e) =
            mprd_core::limits::verify_limits_binding_v1(&proof.limits_hash, &proof.limits_bytes)
        {
            return VerificationStatus::Failure(format!("limits binding failed: {e}"));
        }
        let parsed = match mprd_core::limits::parse_limits_v1(&proof.limits_bytes) {
            Ok(l) => l,
            Err(e) => return VerificationStatus::Failure(format!("limits parse failed: {e}")),
        };
        let Some(committed_ctx) = parsed.mode_c_encryption_ctx_hash else {
            return VerificationStatus::Failure(
                "Mode C missing encryption ctx hash in limits".into(),
            );
        };

        match proof.attestation_metadata.get("mode") {
            Some(mode) if mode == DeploymentMode::Private.as_str() => {}
            _ => {
                return VerificationStatus::Failure(
                    "Mode C proof missing or invalid mode marker".into(),
                )
            }
        }

        // Fail-closed algorithm allowlist.
        let alg = match proof.attestation_metadata.get("encryption_algorithm") {
            Some(a) if a == "AES-256-GCM" => a.clone(),
            _ => {
                return VerificationStatus::Failure(
                    "Mode C unsupported encryption algorithm".into(),
                )
            }
        };

        if let Some(expected_key_id) = &self.config.encryption_key_id {
            match proof.attestation_metadata.get("encryption_key_id") {
                Some(actual) if actual == expected_key_id => {}
                _ => {
                    return VerificationStatus::Failure("Mode C encryption key_id mismatch".into())
                }
            }
        }

        let enc_json = match proof.attestation_metadata.get("encrypted_state") {
            Some(v) => v,
            None => {
                return VerificationStatus::Failure(
                    "Mode C proof missing encrypted_state metadata".into(),
                )
            }
        };
        let encrypted_state: EncryptedState = match serde_json::from_str(enc_json) {
            Ok(v) => v,
            Err(e) => {
                return VerificationStatus::Failure(format!(
                    "Invalid encrypted_state metadata: {}",
                    e,
                ))
            }
        };

        // Bind the encrypted payload metadata to the committed limits hash (fail-closed).
        let key_id = proof
            .attestation_metadata
            .get("encryption_key_id")
            .cloned()
            .unwrap_or_else(|| encrypted_state.key_id.clone());
        if encrypted_state.key_id != key_id {
            return VerificationStatus::Failure("Mode C encrypted_state key_id mismatch".into());
        }
        let expected_ctx = mprd_core::limits::mode_c_encryption_ctx_hash_v1(
            &token.state_hash,
            &token.nonce_or_tx_hash,
            &key_id,
            &alg,
            &encrypted_state.nonce,
            &encrypted_state.ciphertext,
        );
        if committed_ctx != expected_ctx {
            return VerificationStatus::Failure("Mode C encryption binding mismatch".into());
        }

        VerificationStatus::Success
    }
}

// =============================================================================
// Factory Functions
// =============================================================================

/// Create an attestor for the specified mode.
pub fn create_robust_attestor(config: &ModeConfig) -> Result<Box<dyn ZkAttestor>> {
    config
        .validate()
        .map_err(|e| MprdError::ZkError(e.to_string()))?;

    match config.mode {
        DeploymentMode::LocalTrusted => {
            // Mode A uses the core stub attestor
            Ok(Box::new(mprd_core::components::StubZkAttestor::new()))
        }
        DeploymentMode::TrustlessLite => {
            let attestor = RobustMpbAttestor::new(config.clone())
                .map_err(|e| MprdError::ZkError(e.to_string()))?;
            Ok(Box::new(attestor))
        }
        DeploymentMode::TrustlessFull => {
            let bytecode = config.mpb_policy_bytecode.clone().ok_or_else(|| {
                MprdError::ZkError("Mode B-Full requires mpb_policy_bytecode".into())
            })?;
            let mut vars = config.mpb_policy_variables.clone().ok_or_else(|| {
                MprdError::ZkError("Mode B-Full requires mpb_policy_variables".into())
            })?;
            vars.sort_by(|a, b| a.0.cmp(&b.0));
            for w in vars.windows(2) {
                if w[0].0 >= w[1].0 {
                    return Err(MprdError::ZkError(
                        "mpb_policy_variables must be unique and sorted".into(),
                    ));
                }
            }

            let refs: Vec<(&[u8], u8)> = vars
                .iter()
                .map(|(name, reg)| (name.as_bytes(), *reg))
                .collect();
            let policy_hash = Hash32(mprd_mpb::policy_hash_v1(&bytecode, &refs));

            let mut store: HashMap<mprd_core::PolicyHash, crate::risc0_host::MpbPolicyArtifactV1> =
                HashMap::new();
            store.insert(
                policy_hash.clone(),
                crate::risc0_host::MpbPolicyArtifactV1 {
                    bytecode,
                    variables: vars,
                },
            );

            let policy_provider = Arc::new(store) as Arc<dyn MpbPolicyProvider>;
            let attestor = RobustRisc0Attestor::new(
                config.clone(),
                Some(MPRD_MPB_GUEST_ELF),
                Some(policy_provider),
            )
            .map_err(|e| MprdError::ZkError(e.to_string()))?;
            Ok(Box::new(attestor))
        }
        DeploymentMode::Private => {
            let attestor = RobustPrivateAttestor::new(config.clone(), EncryptionConfig::default())
                .map_err(|e| MprdError::ZkError(e.to_string()))?;
            Ok(Box::new(attestor))
        }
    }
}

/// Create a verifier for the specified mode.
pub fn create_robust_verifier(config: &ModeConfig) -> Result<Box<dyn ZkLocalVerifier>> {
    config
        .validate_for_verifier()
        .map_err(|e| MprdError::ZkError(e.to_string()))?;

    match config.mode {
        DeploymentMode::LocalTrusted => {
            Ok(Box::new(mprd_core::components::StubZkLocalVerifier::new()))
        }
        DeploymentMode::TrustlessLite => {
            let verifier = RobustMpbVerifier::new(config.clone())
                .map_err(|e| MprdError::ZkError(e.to_string()))?;
            Ok(Box::new(verifier))
        }
        DeploymentMode::TrustlessFull => {
            let verifier = RobustRisc0Verifier::new(config.clone())
                .map_err(|e| MprdError::ZkError(e.to_string()))?;
            Ok(Box::new(verifier))
        }
        DeploymentMode::Private => {
            let verifier = RobustPrivateVerifier::new(config.clone())
                .map_err(|e| MprdError::ZkError(e.to_string()))?;
            Ok(Box::new(verifier))
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Compute the candidate set hash.
pub fn compute_candidate_set_hash(candidates: &[CandidateAction]) -> Hash32 {
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
    fn mode_config_validation() {
        // Mode A is only valid when strict_security is explicitly disabled.
        assert!(ModeConfig::mode_a().validate().is_err());

        let mut mode_a = ModeConfig::mode_a();
        mode_a.strict_security = false;
        assert!(mode_a.validate().is_ok());

        // Mode B-Lite needs enough spot checks
        let mut config = ModeConfig::mode_b_lite();
        config.mpb_policy_bytecode = Some(
            mprd_core::mpb::BytecodeBuilder::new()
                .push_i64(1)
                .halt()
                .build(),
        );
        config.mpb_policy_variables = Some(vec![]);
        config.mpb_spot_checks = 8; // Too low
        assert!(config.validate().is_err());

        config.mpb_spot_checks = 64;
        assert!(config.validate().is_ok());

        // Mode B-Full needs image_id
        assert!(ModeConfig::mode_b_full([0u8; 32]).validate().is_err());

        let mut config = ModeConfig::mode_b_full([1u8; 32]);
        config.risc0_image_id_mpb = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn robust_mpb_attestor_creates_valid_proof() {
        let policy_bytecode = mprd_core::mpb::BytecodeBuilder::new()
            .push_i64(1)
            .halt()
            .build();
        let policy_hash = Hash32(mprd_mpb::policy_hash_v1(&policy_bytecode, &[]));

        let mut cfg = ModeConfig::mode_b_lite();
        cfg.mpb_policy_bytecode = Some(policy_bytecode);
        cfg.mpb_policy_variables = Some(vec![]);
        let attestor = RobustMpbAttestor::new(cfg).expect("Should create");

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: mprd_core::hash::hash_state(&StateSnapshot {
                fields: HashMap::new(),
                policy_inputs: HashMap::new(),
                state_hash: dummy_hash(0),
                state_ref: mprd_core::StateRef::unknown(),
            }),
            state_ref: mprd_core::StateRef::unknown(),
        };

        let mut candidate = CandidateAction {
            action_type: "TEST".into(),
            params: HashMap::new(),
            score: Score(10),
            candidate_hash: dummy_hash(0),
        };
        candidate.candidate_hash = mprd_core::hash::hash_candidate(&candidate);

        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate.clone(),
            policy_hash: policy_hash.clone(),
            decision_commitment: dummy_hash(4),
        };

        let token = DecisionToken {
            policy_hash: policy_hash.clone(),
            policy_ref: dummy_policy_ref(),
            state_hash: state.state_hash.clone(),
            state_ref: state.state_ref.clone(),
            chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
            nonce_or_tx_hash: dummy_hash(9),
            timestamp_ms: 0,
            signature: vec![],
        };

        let candidates = vec![candidate];
        let result = attestor.attest(&token, &decision, &state, &candidates);
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert_eq!(
            proof.attestation_metadata.get("mode"),
            Some(&"B-Lite".to_string())
        );
        assert_eq!(
            proof.attestation_metadata.get("proof_backend"),
            Some(&"mpb_lite_v1".to_string())
        );
        assert!(!proof.risc0_receipt.is_empty());
    }

    #[test]
    fn robust_mpb_verifier_accepts_valid_proof() {
        let verifier = RobustMpbVerifier::default_config().expect("Should create");

        let policy_bytecode = mprd_core::mpb::BytecodeBuilder::new()
            .push_i64(1)
            .halt()
            .build();
        let policy_hash = Hash32(mprd_mpb::policy_hash_v1(&policy_bytecode, &[]));
        let mut cfg = ModeConfig::mode_b_lite();
        cfg.mpb_policy_bytecode = Some(policy_bytecode);
        cfg.mpb_policy_variables = Some(vec![]);
        let attestor = RobustMpbAttestor::new(cfg).expect("attestor");

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: mprd_core::hash::hash_state(&StateSnapshot {
                fields: HashMap::new(),
                policy_inputs: HashMap::new(),
                state_hash: dummy_hash(0),
                state_ref: mprd_core::StateRef::unknown(),
            }),
            state_ref: mprd_core::StateRef::unknown(),
        };

        let mut candidate = CandidateAction {
            action_type: "TEST".into(),
            params: HashMap::new(),
            score: Score(10),
            candidate_hash: dummy_hash(0),
        };
        candidate.candidate_hash = mprd_core::hash::hash_candidate(&candidate);
        let candidates = vec![candidate.clone()];

        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate,
            policy_hash: policy_hash.clone(),
            decision_commitment: dummy_hash(4),
        };

        let token = DecisionToken {
            policy_hash,
            policy_ref: dummy_policy_ref(),
            state_hash: state.state_hash.clone(),
            state_ref: state.state_ref.clone(),
            chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
            nonce_or_tx_hash: dummy_hash(4),
            timestamp_ms: 0,
            signature: vec![],
        };

        let proof = attestor
            .attest(&token, &decision, &state, &candidates)
            .expect("proof");
        assert_eq!(verifier.verify(&token, &proof), VerificationStatus::Success);
    }

    #[test]
    fn robust_mpb_verifier_rejects_missing_artifact() {
        let verifier = RobustMpbVerifier::default_config().expect("Should create");

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
    fn factory_validates_config() {
        // Valid config works
        let mut config = ModeConfig::mode_b_lite();
        config.mpb_policy_bytecode = Some(
            mprd_core::mpb::BytecodeBuilder::new()
                .push_i64(1)
                .halt()
                .build(),
        );
        config.mpb_policy_variables = Some(vec![]);
        assert!(create_robust_attestor(&config).is_ok());

        // Invalid config fails
        let mut config = ModeConfig::mode_b_lite();
        config.mpb_policy_bytecode = Some(
            mprd_core::mpb::BytecodeBuilder::new()
                .push_i64(1)
                .halt()
                .build(),
        );
        config.mpb_policy_variables = Some(vec![]);
        config.mpb_spot_checks = 4; // Too low
        assert!(create_robust_attestor(&config).is_err());
    }

    #[test]
    fn deployment_mode_properties() {
        assert!(!DeploymentMode::LocalTrusted.requires_zk());
        assert!(!DeploymentMode::TrustlessLite.requires_zk());
        assert!(DeploymentMode::TrustlessFull.requires_zk());
        assert!(DeploymentMode::Private.requires_zk());
        assert!(DeploymentMode::Private.requires_encryption());
    }
}
