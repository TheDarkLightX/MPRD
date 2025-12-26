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
pub mod artifact_repo_integration;
pub mod bounded_deser;
pub mod decentralization;
pub mod error;
pub mod external_verifier;
pub mod manifest;
pub mod manifest_verifier;
#[deprecated(note = "Legacy deployment modes; use mprd_zk::modes_v2 or top-level v2 exports.")]
pub mod modes;
pub mod modes_v2;
pub mod mpb_lite;
pub mod policy_artifacts;
pub mod policy_fetch;
pub mod privacy;
pub mod registry_bound_attestor;
pub mod registry_state;
pub mod risc0_host;
pub mod security;
pub mod verification;

use std::sync::Arc;

// Re-export robust implementations (v2)
pub use modes_v2::{
    compute_candidate_set_hash, create_robust_attestor, create_robust_private_attestor,
    create_robust_verifier, DeploymentMode, ModeConfig, RobustMpbAttestor, RobustMpbVerifier,
    RobustPrivateAttestor, RobustPrivateVerifier, RobustRisc0Attestor, RobustRisc0Verifier,
};

// Re-export error types
pub use error::{ModeError, ModeResult};

// Re-export security utilities
pub use security::{validate_decision_allowed, validate_timestamp, Invariant, SecurityChecker};

// Re-export external verifier
pub use external_verifier::{ExternalVerifier, VerificationRequest, VerificationResponse};

// Re-export verification step type
pub use verification::VerificationStep;

// Re-export MPB B-Lite proof artifact
pub use mpb_lite::{MpbLiteArtifactV1, MPB_LITE_ARTIFACT_VERSION_V1};

// Re-export decentralization primitives
pub use decentralization::{
    AggregatedAttestation,
    AnchorType,
    CommitmentAnchor,
    DistributedPolicyStore,
    GovernanceGateInput,
    GovernanceMode,
    GovernanceProfile,
    IpfsPolicyStore,
    MultiAttestor,
    ProfileConfig,
    TauGovernanceRunner,
    ThresholdConfig,
    ThresholdVerificationResult,
    ThresholdVerifier,
    // Governance profile types
    UpdateKind,
};

// Re-export policy fetching primitives (production wiring)
pub use policy_fetch::{DirPolicyArtifactStore, InMemoryPolicyArtifactStore, PolicyArtifactStore};
pub use registry_bound_attestor::{
    RegistryBoundRisc0MpbAttestor, RegistryBoundRisc0TauCompiledAttestor,
};

// Re-export privacy primitives
pub use privacy::{
    Commitment, CommitmentGenerator, CommitmentOpening, CommitmentScheme, EncryptedState,
    EncryptionConfig, EncryptionWitness, PrivateAttestationConfig, PrivateAttestationResult,
    Property, PropertyProof, SelectiveDisclosure, SelectiveDisclosureBuilder, StateEncryptor,
};

// Re-export Risc0 host integration (real proofs only)
pub use risc0_host::{
    create_risc0_attestor, create_risc0_verifier, MpbPolicyArtifactV1, MpbPolicyProvider,
    Risc0Attestor, Risc0HostConfig, Risc0MpbAttestor, Risc0Verifier,
};

// Re-export the decision-level Risc0 ABI
pub use mprd_risc0_shared::{
    GuestInputV1, GuestInputV2, GuestInputV3, GuestJournalV1, GuestJournalV2, GuestJournalV3,
    MpbGuestInputV1, MpbGuestInputV2, MpbGuestInputV3, MpbVarBindingV1, JOURNAL_VERSION,
    JOURNAL_VERSION_V1, JOURNAL_VERSION_V2, JOURNAL_VERSION_V3,
};

pub type RegistryBoundAttestorAndVerifier = (
    mprd_core::PolicyRef,
    Box<dyn mprd_core::ZkAttestor>,
    Box<dyn mprd_core::ZkLocalVerifier>,
);

/// Create a registry-bound Risc0 MPB attestor that fetches policy artifacts by `policy_hash`.
///
/// This is the production-grade proving path for mpb-v1:
/// - policy authorization is checked against verifier-trusted registry state (epoch/root pinned),
/// - guest image routing uses the signed guest-image manifest,
/// - policy bytes are fetched by content ID and fail-closed validated.
pub fn create_registry_bound_mpb_v1_attestor_from_signed_registry_state<
    S: PolicyArtifactStore + 'static,
>(
    signed_registry_state: crate::registry_state::SignedRegistryStateV1,
    registry_state_verifying_key: mprd_core::TokenVerifyingKey,
    manifest_verifying_key: mprd_core::TokenVerifyingKey,
    store: S,
    mpb_fuel_limit: u32,
) -> mprd_core::Result<(mprd_core::PolicyRef, Box<dyn mprd_core::ZkAttestor>)> {
    use crate::registry_state::{
        RegistryStatePolicyAuthorizationProvider, RegistryStateProvider,
        SignedStaticRegistryStateProvider,
    };
    use mprd_risc0_methods::MPRD_MPB_GUEST_ELF;

    let provider = Arc::new(SignedStaticRegistryStateProvider::new(
        signed_registry_state,
        registry_state_verifying_key,
    ));
    let state = RegistryStateProvider::get(provider.as_ref())?;
    state.verify_manifest(&manifest_verifying_key)?;

    let policy_ref = mprd_core::PolicyRef {
        policy_epoch: state.policy_epoch,
        registry_root: state.registry_root,
    };

    let authorization: Arc<dyn crate::registry_state::PolicyAuthorizationProvider> = Arc::new(
        RegistryStatePolicyAuthorizationProvider::new(provider, manifest_verifying_key),
    );

    let attestor = crate::registry_bound_attestor::RegistryBoundRisc0MpbAttestor::new(
        MPRD_MPB_GUEST_ELF,
        policy_ref.clone(),
        mpb_fuel_limit,
        authorization,
        Arc::new(store),
    );
    Ok((policy_ref, Box::new(attestor)))
}

/// Create a registry-bound Risc0 Tau-compiled (TCV) attestor that fetches policy artifacts by `policy_hash`.
///
/// This is the production-grade proving path for tau_compiled_v1:
/// - policy authorization is checked against verifier-trusted registry state (epoch/root pinned),
/// - guest image routing uses the signed guest-image manifest,
/// - policy bytes are fetched by content ID and fail-closed validated.
pub fn create_registry_bound_tau_compiled_v1_attestor_from_signed_registry_state<
    S: PolicyArtifactStore + 'static,
>(
    signed_registry_state: crate::registry_state::SignedRegistryStateV1,
    registry_state_verifying_key: mprd_core::TokenVerifyingKey,
    manifest_verifying_key: mprd_core::TokenVerifyingKey,
    store: S,
) -> mprd_core::Result<(mprd_core::PolicyRef, Box<dyn mprd_core::ZkAttestor>)> {
    use crate::policy_fetch::RegistryBoundTauCompiledPolicyProviderAdapter;
    use crate::registry_state::{
        RegistryStatePolicyAuthorizationProvider, RegistryStateProvider,
        SignedStaticRegistryStateProvider,
    };
    use mprd_risc0_methods::MPRD_TAU_COMPILED_GUEST_ELF;

    let provider = Arc::new(SignedStaticRegistryStateProvider::new(
        signed_registry_state,
        registry_state_verifying_key,
    ));
    let state = RegistryStateProvider::get(provider.as_ref())?;
    state.verify_manifest(&manifest_verifying_key)?;

    let policy_ref = mprd_core::PolicyRef {
        policy_epoch: state.policy_epoch,
        registry_root: state.registry_root,
    };

    let authorization: Arc<dyn crate::registry_state::PolicyAuthorizationProvider> = Arc::new(
        RegistryStatePolicyAuthorizationProvider::new(provider, manifest_verifying_key),
    );

    let policy_provider = Arc::new(RegistryBoundTauCompiledPolicyProviderAdapter::new(
        policy_ref.clone(),
        Arc::clone(&authorization),
        Arc::new(store),
    ));

    let attestor = crate::registry_bound_attestor::RegistryBoundRisc0TauCompiledAttestor::new(
        MPRD_TAU_COMPILED_GUEST_ELF,
        policy_ref.clone(),
        authorization,
        policy_provider,
    );
    Ok((policy_ref, Box::new(attestor)))
}

/// Create registry-bound mpb-v1 attestor + verifier from a signed registry checkpoint.
///
/// This is the safest wiring for production deployments:
/// - uses the verifier-trusted registry snapshot for both proving and verifying,
/// - routes guest image IDs via the signed manifest,
/// - and fetches policy artifacts by `policy_hash` from the provided store.
pub fn create_registry_bound_mpb_v1_attestor_and_verifier_from_signed_registry_state<
    S: PolicyArtifactStore + 'static,
>(
    signed_registry_state: crate::registry_state::SignedRegistryStateV1,
    registry_state_verifying_key: mprd_core::TokenVerifyingKey,
    manifest_verifying_key: mprd_core::TokenVerifyingKey,
    store: S,
    mpb_fuel_limit: u32,
) -> mprd_core::Result<RegistryBoundAttestorAndVerifier> {
    // Clone the signed checkpoint so both sides verify the exact same bytes.
    let signed_for_attestor = signed_registry_state.clone();
    let signed_for_verifier = signed_registry_state;

    let (policy_ref, attestor) = create_registry_bound_mpb_v1_attestor_from_signed_registry_state(
        signed_for_attestor,
        registry_state_verifying_key.clone(),
        manifest_verifying_key.clone(),
        store,
        mpb_fuel_limit,
    )?;

    let verifier = create_production_verifier_from_signed_registry_state_with_manifest_key(
        signed_for_verifier,
        &registry_state_verifying_key,
        &manifest_verifying_key,
    )?;

    Ok((policy_ref, attestor, verifier))
}

/// Create registry-bound tau_compiled_v1 attestor + verifier from a signed registry checkpoint.
pub fn create_registry_bound_tau_compiled_v1_attestor_and_verifier_from_signed_registry_state<
    S: PolicyArtifactStore + 'static,
>(
    signed_registry_state: crate::registry_state::SignedRegistryStateV1,
    registry_state_verifying_key: mprd_core::TokenVerifyingKey,
    manifest_verifying_key: mprd_core::TokenVerifyingKey,
    store: S,
) -> mprd_core::Result<RegistryBoundAttestorAndVerifier> {
    let signed_for_attestor = signed_registry_state.clone();
    let signed_for_verifier = signed_registry_state;

    let (policy_ref, attestor) =
        create_registry_bound_tau_compiled_v1_attestor_from_signed_registry_state(
            signed_for_attestor,
            registry_state_verifying_key.clone(),
            manifest_verifying_key.clone(),
            store,
        )?;

    let verifier = create_production_verifier_from_signed_registry_state_with_manifest_key(
        signed_for_verifier,
        &registry_state_verifying_key,
        &manifest_verifying_key,
    )?;

    Ok((policy_ref, attestor, verifier))
}

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

    /// Risc0 image ID for the mpb-v1 guest (required for Risc0 backend).
    pub risc0_image_id_mpb: Option<[u8; 32]>,

    /// Risc0 image ID for the host-trusted guest (required for Mode C).
    pub risc0_image_id_host_trusted: Option<[u8; 32]>,

    /// MPB policy bytecode (required for mpb-v1 guest attestation).
    pub mpb_policy_bytecode: Option<Vec<u8>>,

    /// MPB policy variable bindings `(name, reg)` (required for mpb-v1 guest attestation).
    pub mpb_policy_variables: Option<Vec<(String, u8)>>,

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
    /// Create a Risc0 production config using the mpb-v1 guest.
    pub fn risc0_mpb_v1(
        image_id: [u8; 32],
        policy_bytecode: Vec<u8>,
        policy_variables: Vec<(String, u8)>,
    ) -> Self {
        Self {
            backend: ProductionBackend::Risc0,
            risc0_image_id_mpb: Some(image_id),
            risc0_image_id_host_trusted: None,
            mpb_policy_bytecode: Some(policy_bytecode),
            mpb_policy_variables: Some(policy_variables),
            mpb_spot_checks: 0,
            decentralization: None,
            privacy: None,
        }
    }

    /// Create a Risc0 production config (deprecated; use `risc0_mpb_v1`).
    #[deprecated(note = "Use risc0_mpb_v1(image_id, policy_bytecode, policy_variables)")]
    pub fn risc0_default(image_id: [u8; 32]) -> Self {
        Self {
            backend: ProductionBackend::Risc0,
            risc0_image_id_mpb: Some(image_id),
            risc0_image_id_host_trusted: None,
            mpb_policy_bytecode: None,
            mpb_policy_variables: None,
            mpb_spot_checks: 0,
            decentralization: None,
            privacy: None,
        }
    }

    /// Create an experimental MPB config (NOT for production).
    #[deprecated(note = "MPB is experimental. Use risc0_default() for production.")]
    #[allow(deprecated)]
    pub fn experimental_mpb() -> Self {
        Self {
            backend: ProductionBackend::MpbExperimental,
            risc0_image_id_mpb: None,
            risc0_image_id_host_trusted: None,
            mpb_policy_bytecode: None,
            mpb_policy_variables: None,
            mpb_spot_checks: 64,
            decentralization: None,
            privacy: None,
        }
    }

    /// Create a local testing config (NO trustless guarantees).
    #[deprecated(note = "Local mode provides no trustless guarantees.")]
    #[allow(deprecated)]
    pub fn local_testing() -> Self {
        Self {
            backend: ProductionBackend::LocalTesting,
            risc0_image_id_mpb: None,
            risc0_image_id_host_trusted: None,
            mpb_policy_bytecode: None,
            mpb_policy_variables: None,
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
        if let Some(privacy) = &self.privacy {
            return matches!(self.backend, ProductionBackend::Risc0)
                && self
                    .risc0_image_id_host_trusted
                    .is_some_and(|id| id != [0u8; 32])
                && privacy.encryption.master_key.is_some()
                && !privacy.encryption.key_id.is_empty();
        }

        matches!(self.backend, ProductionBackend::Risc0)
            && self.risc0_image_id_mpb.is_some()
            && self
                .mpb_policy_bytecode
                .as_ref()
                .is_some_and(|b| !b.is_empty())
            && self.mpb_policy_variables.is_some()
    }

    /// Get warnings for non-production configs.
    pub fn get_warnings(&self) -> Vec<&'static str> {
        let mut warnings = Vec::new();

        if let Some(privacy) = &self.privacy {
            if !matches!(self.backend, ProductionBackend::Risc0) {
                warnings.push("Mode C requires Risc0 backend");
            }
            if self.risc0_image_id_host_trusted.is_none() {
                warnings.push("Mode C host-trusted image_id not set - attestation will fail");
            }
            if self
                .risc0_image_id_host_trusted
                .is_some_and(|id| id == [0u8; 32])
            {
                warnings.push("Mode C host-trusted image_id is all-zero - attestation will fail");
            }
            if privacy.encryption.master_key.is_none() {
                warnings.push("Mode C master_key not set - attestation will fail");
            }
            if privacy.encryption.key_id.is_empty() {
                warnings.push("Mode C key_id not set - attestation will fail");
            }
            return warnings;
        }

        #[allow(deprecated)]
        match self.backend {
            ProductionBackend::Risc0 => {
                if self.risc0_image_id_mpb.is_none() {
                    warnings.push("Risc0 mpb guest image_id not set - attestation will fail");
                }
                if self
                    .mpb_policy_bytecode
                    .as_ref()
                    .map(|b| b.is_empty())
                    .unwrap_or(true)
                {
                    warnings.push("MPB policy bytecode not set - attestation will fail");
                }
                if self.mpb_policy_variables.is_none() {
                    warnings.push("MPB policy variables not set - attestation will fail");
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

    if let Some(privacy) = &config.privacy {
        if !matches!(config.backend, ProductionBackend::Risc0) {
            return Err(mprd_core::MprdError::ZkError(
                "Mode C requires the Risc0 backend".into(),
            ));
        }

        let Some(image_id) = config.risc0_image_id_host_trusted else {
            return Err(mprd_core::MprdError::ZkError(
                "Mode C requires risc0_image_id_host_trusted; refusing to default to an unspecified guest".into(),
            ));
        };

        if image_id == [0u8; 32] {
            return Err(mprd_core::MprdError::ZkError(
                "Mode C configured with all-zero risc0_image_id_host_trusted; refusing to run with an unspecified guest".into(),
            ));
        }

        if privacy.encryption.key_id.is_empty() {
            return Err(mprd_core::MprdError::ZkError(
                "Mode C requires a non-empty encryption key_id".into(),
            ));
        }

        let master_key = privacy.encryption.master_key.ok_or_else(|| {
            mprd_core::MprdError::ZkError(
                "Mode C requires encryption master_key; refusing to run without key material"
                    .into(),
            )
        })?;

        let revealed_fields = if !privacy.encryption.revealed_fields.is_empty() {
            privacy.encryption.revealed_fields.clone()
        } else {
            privacy.disclosed_fields.clone()
        };

        let mode_config = modes_v2::ModeConfig::mode_c(image_id, privacy.encryption.key_id.clone());
        let encryption_config = modes_v2::EncryptionConfig {
            key_id: privacy.encryption.key_id.clone(),
            algorithm: "AES-256-GCM".into(),
            master_key: Some(master_key),
            commitment_scheme: privacy.commitment_scheme,
            committed_fields: privacy.encryption.committed_fields.clone(),
            encrypted_fields: privacy.encryption.encrypted_fields.clone(),
            revealed_fields,
        };

        return modes_v2::create_robust_private_attestor(&mode_config, encryption_config);
    }

    #[allow(deprecated)]
    match config.backend {
        ProductionBackend::Risc0 => {
            let Some(image_id) = config.risc0_image_id_mpb else {
                return Err(mprd_core::MprdError::ZkError(
                    "Risc0 backend requires risc0_image_id; refusing to default to an unspecified guest".into(),
                ));
            };

            if image_id == [0u8; 32] {
                return Err(mprd_core::MprdError::ZkError(
                    "Risc0 backend configured with all-zero risc0_image_id; refusing to run with an unspecified guest".into(),
                ));
            }

            let mut mode_config = modes_v2::ModeConfig::mode_b_full(image_id);
            mode_config.mpb_policy_bytecode = config.mpb_policy_bytecode.clone();
            mode_config.mpb_policy_variables = config.mpb_policy_variables.clone();
            create_robust_attestor(&mode_config)
        }
        ProductionBackend::MpbExperimental => {
            tracing::warn!("Using EXPERIMENTAL MPB backend - not for production!");
            let mut mode_config = modes_v2::ModeConfig::mode_b_lite();
            mode_config.mpb_spot_checks = config.mpb_spot_checks;
            mode_config.mpb_policy_bytecode = config.mpb_policy_bytecode.clone();
            mode_config.mpb_policy_variables = config.mpb_policy_variables.clone();
            create_robust_attestor(&mode_config)
        }
        ProductionBackend::LocalTesting => {
            tracing::warn!("Using LOCAL testing mode - NO trustless guarantees!");
            let mut mode_config = modes_v2::ModeConfig::mode_a();
            mode_config.strict_security = false;
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

    if let Some(privacy) = &config.privacy {
        if !matches!(config.backend, ProductionBackend::Risc0) {
            return Err(mprd_core::MprdError::ZkError(
                "Mode C requires the Risc0 backend".into(),
            ));
        }

        let Some(image_id) = config.risc0_image_id_host_trusted else {
            return Err(mprd_core::MprdError::ZkError(
                "Mode C requires risc0_image_id_host_trusted; refusing to default to an unspecified guest".into(),
            ));
        };

        if image_id == [0u8; 32] {
            return Err(mprd_core::MprdError::ZkError(
                "Mode C configured with all-zero risc0_image_id_host_trusted; refusing to run with an unspecified guest".into(),
            ));
        }

        if privacy.encryption.key_id.is_empty() {
            return Err(mprd_core::MprdError::ZkError(
                "Mode C requires a non-empty encryption key_id".into(),
            ));
        }

        let mode_config = modes_v2::ModeConfig::mode_c(image_id, privacy.encryption.key_id.clone());
        return modes_v2::create_robust_verifier(&mode_config);
    }

    #[allow(deprecated)]
    match config.backend {
        ProductionBackend::Risc0 => {
            let Some(image_id) = config.risc0_image_id_mpb else {
                return Err(mprd_core::MprdError::ZkError(
                    "Risc0 backend requires risc0_image_id; refusing to default to an unspecified guest".into(),
                ));
            };

            if image_id == [0u8; 32] {
                return Err(mprd_core::MprdError::ZkError(
                    "Risc0 backend configured with all-zero risc0_image_id; refusing to run with an unspecified guest".into(),
                ));
            }

            let mode_config = modes_v2::ModeConfig::mode_b_full(image_id);
            create_robust_verifier(&mode_config)
        }
        ProductionBackend::MpbExperimental => {
            let mut mode_config = modes_v2::ModeConfig::mode_b_lite();
            mode_config.mpb_spot_checks = config.mpb_spot_checks;
            mode_config.mpb_policy_bytecode = config.mpb_policy_bytecode.clone();
            mode_config.mpb_policy_variables = config.mpb_policy_variables.clone();
            create_robust_verifier(&mode_config)
        }
        ProductionBackend::LocalTesting => {
            let mut mode_config = modes_v2::ModeConfig::mode_a();
            mode_config.strict_security = false;
            create_robust_verifier(&mode_config)
        }
    }
}

/// Create a production verifier using a signed guest image manifest.
///
/// This is the recommended production pattern: verifiers route receipts to an allowlisted image ID
/// derived from a pinned manifest, rather than relying on any untrusted hint.
pub fn create_production_verifier_from_manifest(
    manifest: crate::manifest::GuestImageManifestV1,
    verifying_key: &mprd_core::TokenVerifyingKey,
) -> mprd_core::Result<Box<dyn mprd_core::ZkLocalVerifier>> {
    let verifier =
        crate::manifest_verifier::ManifestBoundRisc0Verifier::new_verified(manifest, verifying_key)
            .map_err(|e| {
                mprd_core::MprdError::ZkError(format!("Invalid guest image manifest: {e}"))
            })?;
    Ok(Box::new(verifier))
}

/// Create a production verifier using a signed registry checkpoint.
///
/// This enables verifiers to:
/// - fail-closed validate a verifier-trusted registry snapshot (trust anchor),
/// - authorize `policy_hash` at a specific `(policy_epoch, registry_root)`,
/// - route receipts to an allowlisted image ID before verification.
pub fn create_production_verifier_from_signed_registry_state(
    signed_registry_state: crate::registry_state::SignedRegistryStateV1,
    verifying_key: &mprd_core::TokenVerifyingKey,
) -> mprd_core::Result<Box<dyn mprd_core::ZkLocalVerifier>> {
    create_production_verifier_from_signed_registry_state_with_manifest_key(
        signed_registry_state,
        verifying_key,
        verifying_key,
    )
}

/// Create a production verifier using a signed registry checkpoint, with a separate manifest
/// verifying key.
///
/// Use this when registry checkpoints and guest-image manifests are signed by different keys.
pub fn create_production_verifier_from_signed_registry_state_with_manifest_key(
    signed_registry_state: crate::registry_state::SignedRegistryStateV1,
    registry_state_verifying_key: &mprd_core::TokenVerifyingKey,
    manifest_verifying_key: &mprd_core::TokenVerifyingKey,
) -> mprd_core::Result<Box<dyn mprd_core::ZkLocalVerifier>> {
    use crate::registry_state::{RegistryBoundRisc0Verifier, SignedStaticRegistryStateProvider};
    use std::sync::Arc;

    signed_registry_state
        .verify_with_key(registry_state_verifying_key)
        .map_err(|e| {
            mprd_core::MprdError::ZkError(format!("Invalid registry_state checkpoint: {e}"))
        })?;

    let provider = Arc::new(SignedStaticRegistryStateProvider::new(
        signed_registry_state,
        registry_state_verifying_key.clone(),
    ));

    let verifier = RegistryBoundRisc0Verifier::new(provider, manifest_verifying_key.clone())
        .with_required_policy_source_mapping(true);
    Ok(Box::new(verifier))
}

/// Create a production verifier using a weighted-quorum signed registry checkpoint.
///
/// This enables "weighted voting" committees to authorize registry snapshots:
/// a checkpoint is accepted if the sum of weights of distinct trusted signers who signed it meets
/// or exceeds `required_weight`.
///
/// Verifiers still evaluate `ValidDecision(bundle, registry_state)` fail-closed:
/// - registry checkpoint signatures are validated against `trusted_signer_weights`
/// - the embedded guest image manifest is validated against `manifest_verifying_key`
/// - policy authorization is enforced at `(policy_epoch, registry_root)`
/// - receipt verification is routed to an allowlisted image ID chosen from the registry state
pub fn create_production_verifier_from_weighted_quorum_registry_state(
    signed_registry_state: crate::registry_state::WeightedQuorumSignedRegistryStateV1,
    trusted_signer_weights: std::collections::HashMap<[u8; 32], u32>,
    manifest_verifying_key: &mprd_core::TokenVerifyingKey,
) -> mprd_core::Result<Box<dyn mprd_core::ZkLocalVerifier>> {
    use crate::registry_state::{
        RegistryBoundRisc0Verifier, WeightedQuorumSignedRegistryStateProvider,
    };
    use std::sync::Arc;

    signed_registry_state
        .verify_with_trusted_signer_weights(&trusted_signer_weights)
        .map_err(|e| {
            mprd_core::MprdError::ZkError(format!(
                "Invalid weighted-quorum registry_state checkpoint: {e}"
            ))
        })?;

    let provider = Arc::new(WeightedQuorumSignedRegistryStateProvider::new(
        signed_registry_state,
        trusted_signer_weights,
        manifest_verifying_key.clone(),
    ));

    let verifier = RegistryBoundRisc0Verifier::new(provider, manifest_verifying_key.clone())
        .with_required_policy_source_mapping(true);
    Ok(Box::new(verifier))
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
    #[allow(dead_code)]
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
        _token: &DecisionToken,
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
    #[allow(dead_code)]
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
    use mprd_core::Hash32;
    use mprd_core::PolicyRef;
    use std::collections::HashMap;

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn dummy_policy_ref() -> PolicyRef {
        PolicyRef {
            policy_epoch: 1,
            registry_root: dummy_hash(99),
        }
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
            state_ref: mprd_core::StateRef::unknown(),
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

        let token = DecisionToken {
            policy_hash: dummy_hash(5),
            policy_ref: dummy_policy_ref(),
            state_hash: dummy_hash(6),
            state_ref: mprd_core::StateRef::unknown(),
            chosen_action_hash: dummy_hash(7),
            nonce_or_tx_hash: dummy_hash(8),
            timestamp_ms: 0,
            signature: vec![],
        };

        let result = attestor.attest(&token, &decision, &state, &[]);
        assert!(matches!(result, Err(MprdError::ZkError(_))));
    }

    #[test]
    fn verifier_always_fails_in_stub_mode() {
        let verifier = Risc0ZkLocalVerifier::new(dummy_config());

        let token = DecisionToken {
            policy_hash: dummy_hash(5),
            policy_ref: dummy_policy_ref(),
            state_hash: dummy_hash(6),
            state_ref: mprd_core::StateRef::unknown(),
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
            limits_hash: dummy_hash(13),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };

        let status = verifier.verify(&token, &proof);
        assert!(matches!(status, VerificationStatus::Failure(_)));
    }
}
