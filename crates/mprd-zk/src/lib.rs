//! MPRD ZK and Deployment Mode Library
//!
//! This crate provides zero-knowledge proof infrastructure and deployment modes
//! for the MPRD (Model Proposes, Rules Decide) system.
//!
//! # Recommended Production Configuration
//!
//! **Risc0 is the recommended default** for production deployments requiring
//! trustless verification. MPB (Mode B-Lite) is experimental and should only
//! be used for internal high-frequency checks where full ZK is not required.
//!
//! ```rust,ignore
//! use mprd_zk::{ProductionConfig, create_production_attestor};
//!
//! // Production: Use Risc0 (Mode B-Full)
//! let config = ProductionConfig::risc0_default(image_id);
//! let attestor = create_production_attestor(&config)?;
//!
//! // Development/Testing: Use MPB (experimental)
//! let config = ProductionConfig::experimental_mpb();
//! let attestor = create_production_attestor(&config)?;
//! ```
//!
//! # Deployment Modes
//!
//! | Mode | Trust | Default | Use Case |
//! |------|-------|---------|----------|
//! | A (Local) | Operator | ❌ | Internal testing only |
//! | B-Full (Risc0) | Trustless | ✅ | **Production default** |
//! | B-Lite (MPB) | Computational | ❌ | Experimental, internal |
//! | C (Private) | Trustless + Private | ❌ | Privacy-required scenarios |
//!
//! # Decentralization Features
//!
//! - **Multi-Attestor**: K-of-N quorum for attestation
//! - **Threshold Verification**: Multiple verifiers must agree
//! - **Distributed Policy Storage**: IPFS/Arweave interfaces
//!
//! # Privacy Features
//!
//! - **Commitment Schemes**: Hide values while proving properties
//! - **Encrypted State**: AES-256-GCM encryption
//! - **Selective Disclosure**: Reveal only necessary fields

pub mod abi;
pub mod decentralization;
pub mod error;
pub mod external_verifier;
pub mod modes;
pub mod modes_v2;
pub mod privacy;
pub mod risc0_host;
pub mod security;

// Re-export legacy modes for backwards compatibility
pub use modes::{
    DeploymentMode, ModeConfig, ExtendedProofBundle, ExtendedVerificationResult,
    MpbTrustlessAttestor, MpbTrustlessVerifier,
    Risc0TrustlessAttestor, Risc0TrustlessVerifier,
    PrivateAttestor, PrivateVerifier,
    create_attestor, create_verifier,
};

// Re-export robust implementations (v2)
pub use modes_v2::{
    RobustMpbAttestor, RobustMpbVerifier,
    RobustRisc0Attestor, RobustRisc0Verifier,
    RobustPrivateAttestor, RobustPrivateVerifier,
    create_robust_attestor, create_robust_verifier,
    compute_candidate_set_hash,
};

// Re-export error types
pub use error::{ModeError, ModeResult};

// Re-export security utilities
pub use security::{SecurityChecker, Invariant, validate_decision_allowed, validate_timestamp};

// Re-export external verifier
pub use external_verifier::{
    ExternalVerifier, VerificationRequest, VerificationResponse,
};

// Re-export decentralization primitives
pub use decentralization::{
    ThresholdConfig, MultiAttestor, ThresholdVerifier,
    AggregatedAttestation, ThresholdVerificationResult,
    DistributedPolicyStore, IpfsPolicyStore,
    CommitmentAnchor, AnchorType,
    // Governance profile types
    UpdateKind, GovernanceMode, ProfileConfig,
    GovernanceProfile, GovernanceGateInput,
    TauGovernanceRunner,
};

// Re-export privacy primitives
pub use privacy::{
    Commitment, CommitmentScheme, CommitmentOpening, CommitmentGenerator,
    EncryptedState, StateEncryptor, EncryptionConfig, EncryptionWitness,
    SelectiveDisclosure, SelectiveDisclosureBuilder, Property, PropertyProof,
    PrivateAttestationConfig, PrivateAttestationResult,
};

// Re-export Risc0 host integration (real proofs only)
pub use risc0_host::{
    Risc0Attestor, Risc0Verifier,
    Risc0HostConfig, GuestInput, GuestOutput,
    create_risc0_attestor, create_risc0_verifier,
    compute_expected_hashes,
};

// =============================================================================
// Production Configuration (Risc0 Default)
// =============================================================================

use serde::{Deserialize, Serialize};

/// Production configuration with Risc0 as default.
///
/// **Risc0 is the recommended production backend.**
/// MPB is experimental and should only be used for development/testing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProductionConfig {
    /// The backend to use.
    pub backend: ProductionBackend,

    /// Risc0 image ID (required for Risc0 backend).
    pub risc0_image_id: Option<[u8; 32]>,

    /// Number of spot checks (MPB only).
    pub mpb_spot_checks: usize,

    /// Decentralization config (optional).
    pub decentralization: Option<ThresholdConfig>,

    /// Privacy config (optional).
    pub privacy: Option<PrivateAttestationConfig>,
}

/// Production backend selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProductionBackend {
    /// Risc0 ZK (recommended for production).
    Risc0,

    /// MPB computational proofs (experimental, internal only).
    #[deprecated(note = "MPB is experimental. Use Risc0 for production.")]
    MpbExperimental,

    /// Local mode (no proofs, testing only).
    #[deprecated(note = "Local mode provides no trustless guarantees.")]
    LocalTesting,
}

impl ProductionConfig {
    /// Create a Risc0 production config (recommended).
    pub fn risc0_default(image_id: [u8; 32]) -> Self {
        Self {
            backend: ProductionBackend::Risc0,
            risc0_image_id: Some(image_id),
            mpb_spot_checks: 0,
            decentralization: None,
            privacy: None,
        }
    }

    /// Create an experimental MPB config (NOT for production).
    #[deprecated(note = "MPB is experimental. Use risc0_default() for production.")]
    pub fn experimental_mpb() -> Self {
        Self {
            backend: ProductionBackend::MpbExperimental,
            risc0_image_id: None,
            mpb_spot_checks: 64,
            decentralization: None,
            privacy: None,
        }
    }

    /// Create a local testing config (NO trustless guarantees).
    #[deprecated(note = "Local mode provides no trustless guarantees.")]
    pub fn local_testing() -> Self {
        Self {
            backend: ProductionBackend::LocalTesting,
            risc0_image_id: None,
            mpb_spot_checks: 0,
            decentralization: None,
            privacy: None,
        }
    }

    /// Add decentralization (multi-attestor).
    pub fn with_decentralization(mut self, config: ThresholdConfig) -> Self {
        self.decentralization = Some(config);
        self
    }

    /// Add privacy features.
    pub fn with_privacy(mut self, config: PrivateAttestationConfig) -> Self {
        self.privacy = Some(config);
        self
    }

    /// Check if this is a production-ready config.
    pub fn is_production_ready(&self) -> bool {
        matches!(self.backend, ProductionBackend::Risc0)
            && self.risc0_image_id.is_some()
    }

    /// Get warnings for non-production configs.
    pub fn get_warnings(&self) -> Vec<&'static str> {
        let mut warnings = Vec::new();

        #[allow(deprecated)]
        match self.backend {
            ProductionBackend::Risc0 => {
                if self.risc0_image_id.is_none() {
                    warnings.push("Risc0 image_id not set - attestation will fail");
                }
            }
            ProductionBackend::MpbExperimental => {
                warnings.push("⚠️ MPB is EXPERIMENTAL - not suitable for production");
                warnings.push("⚠️ MPB provides computational security only, not cryptographic ZK");
            }
            ProductionBackend::LocalTesting => {
                warnings.push("⚠️ Local mode provides NO trustless guarantees");
                warnings.push("⚠️ This mode is for testing ONLY");
            }
        }

        warnings
    }
}

/// Create a production attestor.
///
/// **Risc0 is required for production.** This function will emit warnings
/// for non-production configurations.
pub fn create_production_attestor(
    config: &ProductionConfig,
) -> mprd_core::Result<Box<dyn mprd_core::ZkAttestor>> {
    // Emit warnings
    for warning in config.get_warnings() {
        tracing::warn!("{}", warning);
    }

    #[allow(deprecated)]
    match config.backend {
        ProductionBackend::Risc0 => {
            let mode_config = modes_v2::ModeConfig::mode_b_full(
                config.risc0_image_id.unwrap_or([0u8; 32])
            );
            create_robust_attestor(&mode_config)
        }
        ProductionBackend::MpbExperimental => {
            tracing::warn!("Using EXPERIMENTAL MPB backend - not for production!");
            let mut mode_config = modes_v2::ModeConfig::mode_b_lite();
            mode_config.mpb_spot_checks = config.mpb_spot_checks;
            create_robust_attestor(&mode_config)
        }
        ProductionBackend::LocalTesting => {
            tracing::warn!("Using LOCAL testing mode - NO trustless guarantees!");
            let mode_config = modes_v2::ModeConfig::mode_a();
            create_robust_attestor(&mode_config)
        }
    }
}

/// Create a production verifier.
pub fn create_production_verifier(
    config: &ProductionConfig,
) -> mprd_core::Result<Box<dyn mprd_core::ZkLocalVerifier>> {
    for warning in config.get_warnings() {
        tracing::warn!("{}", warning);
    }

    #[allow(deprecated)]
    match config.backend {
        ProductionBackend::Risc0 => {
            let mode_config = modes_v2::ModeConfig::mode_b_full(
                config.risc0_image_id.unwrap_or([0u8; 32])
            );
            create_robust_verifier(&mode_config)
        }
        ProductionBackend::MpbExperimental => {
            let mut mode_config = modes_v2::ModeConfig::mode_b_lite();
            mode_config.mpb_spot_checks = config.mpb_spot_checks;
            create_robust_verifier(&mode_config)
        }
        ProductionBackend::LocalTesting => {
            let mode_config = modes_v2::ModeConfig::mode_a();
            create_robust_verifier(&mode_config)
        }
    }
}

use mprd_core::{
    CandidateAction, Decision, DecisionToken, MprdError, ProofBundle, Result, StateSnapshot,
    VerificationStatus, ZkAttestor, ZkLocalVerifier,
};

/// Configuration for the Risc0-based ZK pipeline.
///
/// This is a placeholder; additional fields (e.g. image ID, method ID) will be
/// added when Risc0 is fully wired in.
#[derive(Clone)]
pub struct Risc0Config {
    pub method_elf: &'static [u8],
}

pub struct Risc0ZkAttestor {
    config: Risc0Config,
}

impl Risc0ZkAttestor {
    pub fn new(config: Risc0Config) -> Self {
        Self { config }
    }
}

impl ZkAttestor for Risc0ZkAttestor {
    /// Current behavior:
    /// - Always returns `MprdError::ZkError("ZK attestation not implemented")`.
    ///
    /// This is deliberate to avoid silent insecure operation before the
    /// Risc0 pipeline is fully implemented.
    fn attest(
        &self,
        _decision: &Decision,
        _state: &StateSnapshot,
        _candidates: &[CandidateAction],
    ) -> Result<ProofBundle> {
        Err(MprdError::ZkError(
            "ZK attestation not implemented; wire Risc0 before use".into(),
        ))
    }
}

/// Local verifier backed by Risc0 receipts.
pub struct Risc0ZkLocalVerifier {
    config: Risc0Config,
}

impl Risc0ZkLocalVerifier {
    pub fn new(config: Risc0Config) -> Self {
        Self { config }
    }
}

impl ZkLocalVerifier for Risc0ZkLocalVerifier {
    /// Current behavior:
    /// - Always returns `VerificationStatus::Failure` with a descriptive
    ///   message.
    ///
    /// This prevents accidental acceptance of unverified actions while the
    /// ZK pipeline is still under construction.
    fn verify(&self, _token: &DecisionToken, _proof: &ProofBundle) -> VerificationStatus {
        VerificationStatus::Failure(
            "ZK local verification not implemented; wire Risc0 before use".into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mprd_core::{Hash32, PolicyHash, StateHash};
    use std::collections::HashMap;

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn dummy_config() -> Risc0Config {
        Risc0Config { method_elf: &[] }
    }

    #[test]
    fn attestor_returns_explicit_error() {
        let attestor = Risc0ZkAttestor::new(dummy_config());

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(1),
        };

        let decision = Decision {
            chosen_index: 0,
            chosen_action: CandidateAction {
                action_type: "A".into(),
                params: HashMap::new(),
                score: mprd_core::Score(0),
                candidate_hash: dummy_hash(2),
            },
            policy_hash: dummy_hash(3),
            decision_commitment: dummy_hash(4),
        };

        let result = attestor.attest(&decision, &state, &[]);
        assert!(matches!(result, Err(MprdError::ZkError(_))));
    }

    #[test]
    fn verifier_always_fails_in_stub_mode() {
        let verifier = Risc0ZkLocalVerifier::new(dummy_config());

        let token = DecisionToken {
            policy_hash: dummy_hash(5),
            state_hash: dummy_hash(6),
            chosen_action_hash: dummy_hash(7),
            nonce_or_tx_hash: dummy_hash(8),
            timestamp_ms: 0,
            signature: vec![],
        };

        let proof = ProofBundle {
            policy_hash: dummy_hash(9),
            state_hash: dummy_hash(10),
            candidate_set_hash: dummy_hash(11),
            chosen_action_hash: dummy_hash(12),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };

        let status = verifier.verify(&token, &proof);
        assert!(matches!(status, VerificationStatus::Failure(_)));
    }
}

