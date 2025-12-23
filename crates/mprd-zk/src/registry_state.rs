//! Verifier-trusted registry state.
//!
//! The production checklist requires verifiers to evaluate:
//! `ValidDecision(bundle, registry_state)` fail-closed.
//!
//! This module defines the minimal data model needed to route image IDs and authorize policies.
//! Binding `policy_epoch/registry_root` into the verified statement is implemented by:
//! - `mprd-core::DecisionToken::policy_ref`
//! - `mprd-risc0-shared::GuestJournalV3::{policy_epoch, registry_root}`
//! - verifier checks that compare token/journal/registry_state (fail-closed).
//!
//! # Trust Modes
//!
//! - **High-Trust Mode**: Single signer (`SignedRegistryStateV1`) - suitable for operator-controlled
//!   deployments where one key controls the registry.
//! - **Low-Trust Mode**: Quorum signatures (`QuorumSignedRegistryStateV1`) - requires k-of-n
//!   signatures from independent signers, eliminating single points of failure.

use crate::manifest::GuestImageManifestV1;
use crate::risc0_host::Risc0Verifier;
use mprd_core::{
    DecisionToken, Hash32, PolicyRef, Result, TokenSigningKey, TokenVerifyingKey,
    VerificationStatus, ZkLocalVerifier,
};
use mprd_risc0_shared::Id32;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizedPolicyV1 {
    pub policy_hash: Hash32,
    pub policy_exec_kind_id: Id32,
    pub policy_exec_version_id: Id32,
    /// Optional mapping to a governed policy *source* hash (e.g. Tau source bytes), for auditability.
    ///
    /// If a deployment treats Tau as source-of-truth while executing MPB bytecode, verifiers can
    /// require this mapping to be present (fail-closed) to close the "compiler middleman" gap.
    pub policy_source_kind_id: Option<Id32>,
    pub policy_source_hash: Option<Hash32>,
}

/// Verifier-trusted registry snapshot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryStateV1 {
    pub policy_epoch: u64,
    pub registry_root: Hash32,
    pub authorized_policies: Vec<AuthorizedPolicyV1>,
    pub guest_image_manifest: GuestImageManifestV1,
}

/// Signed registry snapshot schema version.
pub const REGISTRY_STATE_VERSION: u32 = 2;

/// Domain separation for registry snapshot signatures.
pub const REGISTRY_STATE_DOMAIN_V2: &[u8] = b"MPRD_REGISTRY_STATE_V2";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedRegistryStateV1 {
    pub registry_state_version: u32,
    pub state: RegistryStateV1,
    pub signed_at_ms: i64,
    /// Public key used to sign this registry checkpoint (ed25519).
    pub signer_pubkey: [u8; 32],
    /// Signature over canonical `signing_bytes_v1()`.
    pub signature: Vec<u8>,
}

impl SignedRegistryStateV1 {
    pub fn signing_bytes_v1(&self) -> Result<Vec<u8>> {
        if self.registry_state_version != REGISTRY_STATE_VERSION {
            return Err(mprd_core::MprdError::InvalidInput(
                "unsupported registry_state_version".into(),
            ));
        }

        let mut policies = self.state.authorized_policies.clone();
        policies.sort_by(|a, b| a.policy_hash.0.cmp(&b.policy_hash.0));

        // Fail-closed: require policies already canonical (sorted, unique).
        if policies != self.state.authorized_policies {
            return Err(mprd_core::MprdError::InvalidInput(
                "authorized_policies must be sorted and canonical".into(),
            ));
        }
        for w in policies.windows(2) {
            if w[0].policy_hash == w[1].policy_hash {
                return Err(mprd_core::MprdError::InvalidInput(
                    "duplicate policy_hash in authorized_policies".into(),
                ));
            }
        }

        // Bind to the exact signed manifest contents (not just its image IDs).
        let manifest_bytes = self.state.guest_image_manifest.signing_bytes_v1()?;
        let manifest_digest: [u8; 32] = Sha256::digest(&manifest_bytes).into();

        let mut out = Vec::with_capacity(64 + policies.len() * 160);
        out.extend_from_slice(REGISTRY_STATE_DOMAIN_V2);
        out.extend_from_slice(&self.registry_state_version.to_le_bytes());
        out.extend_from_slice(&self.state.policy_epoch.to_le_bytes());
        out.extend_from_slice(&self.state.registry_root.0);
        out.extend_from_slice(&self.signed_at_ms.to_le_bytes());
        out.extend_from_slice(&(policies.len() as u32).to_le_bytes());
        for p in policies {
            out.extend_from_slice(&p.policy_hash.0);
            out.extend_from_slice(&p.policy_exec_kind_id);
            out.extend_from_slice(&p.policy_exec_version_id);
            match (&p.policy_source_kind_id, &p.policy_source_hash) {
                (None, None) => out.push(0u8),
                (Some(kind), Some(hash)) => {
                    out.push(1u8);
                    out.extend_from_slice(kind);
                    out.extend_from_slice(&hash.0);
                }
                _ => return Err(mprd_core::MprdError::InvalidInput(
                    "policy_source_kind_id and policy_source_hash must be both set or both unset"
                        .into(),
                )),
            }
        }
        out.extend_from_slice(&manifest_digest);
        Ok(out)
    }

    pub fn verify_with_key(&self, vk: &TokenVerifyingKey) -> Result<()> {
        if vk.to_bytes() != self.signer_pubkey {
            return Err(mprd_core::MprdError::SignatureInvalid(
                "registry_state signer_pubkey does not match expected key".into(),
            ));
        }
        let msg = self.signing_bytes_v1()?;
        vk.verify_bytes(&msg, &self.signature)?;
        Ok(())
    }

    pub fn sign(
        signing_key: &TokenSigningKey,
        signed_at_ms: i64,
        mut state: RegistryStateV1,
    ) -> Result<Self> {
        state
            .authorized_policies
            .sort_by(|a, b| a.policy_hash.0.cmp(&b.policy_hash.0));
        let signer_pubkey = signing_key.verifying_key().to_bytes();
        let mut out = Self {
            registry_state_version: REGISTRY_STATE_VERSION,
            state,
            signed_at_ms,
            signer_pubkey,
            signature: Vec::new(),
        };
        let msg = out.signing_bytes_v1()?;
        out.signature = signing_key.sign_bytes(&msg).to_vec();
        Ok(out)
    }
}

// =============================================================================
// Low-Trust Mode: Quorum-Signed Registry State (k-of-n threshold)
// =============================================================================

/// Schema version for quorum-signed registry snapshots.
pub const QUORUM_REGISTRY_STATE_VERSION: u32 = 1;

/// Domain separation for quorum registry snapshot signatures.
pub const QUORUM_REGISTRY_STATE_DOMAIN_V1: &[u8] = b"MPRD_QUORUM_REGISTRY_STATE_V1";

/// Individual signer's contribution to a quorum-signed registry state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumSignerContribution {
    /// Public key of this signer (ed25519).
    pub signer_pubkey: [u8; 32],
    /// Signature over the canonical signing bytes.
    pub signature: Vec<u8>,
}

/// Quorum-signed registry snapshot for low-trust mode.
///
/// Requires k-of-n signatures from independent signers to be valid,
/// eliminating single points of failure in policy authorization.
///
/// # Security
///
/// - `quorum_threshold`: Minimum number of valid signatures required (k).
/// - `signers`: The set of trusted signer public keys (n).
/// - Verification fails closed if fewer than k valid signatures are present.
/// - All signers must sign the exact same `RegistryStateV1` content.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumSignedRegistryStateV1 {
    pub registry_state_version: u32,
    pub state: RegistryStateV1,
    pub signed_at_ms: i64,
    /// Minimum number of valid signatures required (k in k-of-n).
    pub quorum_threshold: u8,
    /// Signatures from contributing signers.
    pub contributions: Vec<QuorumSignerContribution>,
}

impl QuorumSignedRegistryStateV1 {
    /// Compute the canonical signing bytes (same format as single-signer, for compatibility).
    pub fn signing_bytes_v1(&self) -> Result<Vec<u8>> {
        if self.registry_state_version != QUORUM_REGISTRY_STATE_VERSION {
            return Err(mprd_core::MprdError::InvalidInput(
                "unsupported quorum registry_state_version".into(),
            ));
        }

        let mut policies = self.state.authorized_policies.clone();
        policies.sort_by(|a, b| a.policy_hash.0.cmp(&b.policy_hash.0));

        // Fail-closed: require policies already canonical (sorted, unique).
        if policies != self.state.authorized_policies {
            return Err(mprd_core::MprdError::InvalidInput(
                "authorized_policies must be sorted and canonical".into(),
            ));
        }
        for w in policies.windows(2) {
            if w[0].policy_hash == w[1].policy_hash {
                return Err(mprd_core::MprdError::InvalidInput(
                    "duplicate policy_hash in authorized_policies".into(),
                ));
            }
        }

        let manifest_bytes = self.state.guest_image_manifest.signing_bytes_v1()?;
        let manifest_digest: [u8; 32] = Sha256::digest(&manifest_bytes).into();

        let mut out = Vec::with_capacity(128 + policies.len() * 160);
        out.extend_from_slice(QUORUM_REGISTRY_STATE_DOMAIN_V1);
        out.extend_from_slice(&self.registry_state_version.to_le_bytes());
        out.extend_from_slice(&self.state.policy_epoch.to_le_bytes());
        out.extend_from_slice(&self.state.registry_root.0);
        out.extend_from_slice(&self.signed_at_ms.to_le_bytes());
        out.extend_from_slice(&self.quorum_threshold.to_le_bytes());
        out.extend_from_slice(&(policies.len() as u32).to_le_bytes());
        for p in policies {
            out.extend_from_slice(&p.policy_hash.0);
            out.extend_from_slice(&p.policy_exec_kind_id);
            out.extend_from_slice(&p.policy_exec_version_id);
            match (&p.policy_source_kind_id, &p.policy_source_hash) {
                (None, None) => out.push(0u8),
                (Some(kind), Some(hash)) => {
                    out.push(1u8);
                    out.extend_from_slice(kind);
                    out.extend_from_slice(&hash.0);
                }
                _ => return Err(mprd_core::MprdError::InvalidInput(
                    "policy_source_kind_id and policy_source_hash must be both set or both unset"
                        .into(),
                )),
            }
        }
        out.extend_from_slice(&manifest_digest);
        Ok(out)
    }

    /// Verify the quorum signature against a set of trusted signer public keys.
    ///
    /// # Arguments
    ///
    /// * `trusted_signers` - The set of public keys that are trusted to sign registry state.
    ///
    /// # Security
    ///
    /// - Fails closed if fewer than `quorum_threshold` valid signatures from trusted signers.
    /// - Each signer can only contribute one signature (deduplication enforced).
    /// - Signers not in `trusted_signers` are ignored.
    pub fn verify_with_trusted_signers(&self, trusted_signers: &[[u8; 32]]) -> Result<()> {
        if self.quorum_threshold == 0 {
            return Err(mprd_core::MprdError::InvalidInput(
                "quorum_threshold must be at least 1".into(),
            ));
        }

        let msg = self.signing_bytes_v1()?;
        let mut valid_signers: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::new();

        for contrib in &self.contributions {
            // Skip if not a trusted signer
            if !trusted_signers.contains(&contrib.signer_pubkey) {
                continue;
            }

            // Skip if this signer already contributed (prevent double-counting)
            if valid_signers.contains(&contrib.signer_pubkey) {
                continue;
            }

            // Verify signature
            let vk = TokenVerifyingKey::from_bytes(&contrib.signer_pubkey).map_err(|_| {
                mprd_core::MprdError::SignatureInvalid("invalid signer pubkey".into())
            })?;

            if vk.verify_bytes(&msg, &contrib.signature).is_ok() {
                valid_signers.insert(contrib.signer_pubkey);
            }
        }

        let valid_count = valid_signers.len();
        if valid_count < self.quorum_threshold as usize {
            return Err(mprd_core::MprdError::SignatureInvalid(format!(
                "insufficient quorum: {} valid signatures, {} required",
                valid_count, self.quorum_threshold
            )));
        }

        Ok(())
    }

    /// Sign a registry state as one member of a quorum.
    ///
    /// Returns a contribution that can be aggregated with others.
    pub fn sign_contribution(
        signing_key: &TokenSigningKey,
        state: &RegistryStateV1,
        signed_at_ms: i64,
        quorum_threshold: u8,
    ) -> Result<QuorumSignerContribution> {
        // Create a temporary struct to compute signing bytes
        let mut sorted_state = state.clone();
        sorted_state
            .authorized_policies
            .sort_by(|a, b| a.policy_hash.0.cmp(&b.policy_hash.0));

        let temp = Self {
            registry_state_version: QUORUM_REGISTRY_STATE_VERSION,
            state: sorted_state,
            signed_at_ms,
            quorum_threshold,
            contributions: vec![],
        };

        let msg = temp.signing_bytes_v1()?;
        let signature = signing_key.sign_bytes(&msg).to_vec();
        let signer_pubkey = signing_key.verifying_key().to_bytes();

        Ok(QuorumSignerContribution {
            signer_pubkey,
            signature,
        })
    }

    /// Aggregate contributions into a complete quorum-signed registry state.
    pub fn aggregate(
        state: RegistryStateV1,
        signed_at_ms: i64,
        quorum_threshold: u8,
        contributions: Vec<QuorumSignerContribution>,
    ) -> Result<Self> {
        let mut sorted_state = state;
        sorted_state
            .authorized_policies
            .sort_by(|a, b| a.policy_hash.0.cmp(&b.policy_hash.0));

        Ok(Self {
            registry_state_version: QUORUM_REGISTRY_STATE_VERSION,
            state: sorted_state,
            signed_at_ms,
            quorum_threshold,
            contributions,
        })
    }
}

// =============================================================================
// Low-Trust Mode: Weighted-Quorum Registry State (sum of weights threshold)
// =============================================================================

/// Schema version for weighted quorum-signed registry snapshots.
pub const WEIGHTED_QUORUM_REGISTRY_STATE_VERSION: u32 = 1;

/// Domain separation for weighted quorum registry snapshot signatures.
pub const WEIGHTED_QUORUM_REGISTRY_STATE_DOMAIN_V1: &[u8] =
    b"MPRD_WEIGHTED_QUORUM_REGISTRY_STATE_V1";

/// Weighted quorum-signed registry snapshot.
///
/// This is a governance authorization primitive intended for "weighted voting" committees:
/// a checkpoint is valid if the sum of weights of distinct trusted signers who signed it meets or
/// exceeds `required_weight`.
///
/// # Security
///
/// - Weights are verifier-trusted configuration (not host-provided).
/// - The signed message commits to `required_weight` (so the threshold cannot be modified).
/// - Verification fails closed if total valid weight is insufficient.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WeightedQuorumSignedRegistryStateV1 {
    pub registry_state_version: u32,
    pub state: RegistryStateV1,
    pub signed_at_ms: i64,
    /// Minimum total signer weight required to accept this checkpoint.
    pub required_weight: u32,
    /// Signatures from contributing signers.
    pub contributions: Vec<QuorumSignerContribution>,
}

impl WeightedQuorumSignedRegistryStateV1 {
    /// Compute canonical signing bytes.
    pub fn signing_bytes_v1(&self) -> Result<Vec<u8>> {
        if self.registry_state_version != WEIGHTED_QUORUM_REGISTRY_STATE_VERSION {
            return Err(mprd_core::MprdError::InvalidInput(
                "unsupported weighted quorum registry_state_version".into(),
            ));
        }
        if self.required_weight == 0 {
            return Err(mprd_core::MprdError::InvalidInput(
                "required_weight must be at least 1".into(),
            ));
        }

        let mut policies = self.state.authorized_policies.clone();
        policies.sort_by(|a, b| a.policy_hash.0.cmp(&b.policy_hash.0));

        // Fail-closed: require policies already canonical (sorted, unique).
        if policies != self.state.authorized_policies {
            return Err(mprd_core::MprdError::InvalidInput(
                "authorized_policies must be sorted and canonical".into(),
            ));
        }
        for w in policies.windows(2) {
            if w[0].policy_hash == w[1].policy_hash {
                return Err(mprd_core::MprdError::InvalidInput(
                    "duplicate policy_hash in authorized_policies".into(),
                ));
            }
        }

        // Bind to the exact signed manifest contents (not just its image IDs).
        let manifest_bytes = self.state.guest_image_manifest.signing_bytes_v1()?;
        let manifest_digest: [u8; 32] = Sha256::digest(&manifest_bytes).into();

        let mut out = Vec::with_capacity(64 + policies.len() * 160);
        out.extend_from_slice(WEIGHTED_QUORUM_REGISTRY_STATE_DOMAIN_V1);
        out.extend_from_slice(&self.registry_state_version.to_le_bytes());
        out.extend_from_slice(&self.state.policy_epoch.to_le_bytes());
        out.extend_from_slice(&self.state.registry_root.0);
        out.extend_from_slice(&self.signed_at_ms.to_le_bytes());
        out.extend_from_slice(&self.required_weight.to_le_bytes());
        out.extend_from_slice(&(policies.len() as u32).to_le_bytes());
        for p in policies {
            out.extend_from_slice(&p.policy_hash.0);
            out.extend_from_slice(&p.policy_exec_kind_id);
            out.extend_from_slice(&p.policy_exec_version_id);
            match (&p.policy_source_kind_id, &p.policy_source_hash) {
                (None, None) => out.push(0u8),
                (Some(kind), Some(hash)) => {
                    out.push(1u8);
                    out.extend_from_slice(kind);
                    out.extend_from_slice(&hash.0);
                }
                _ => return Err(mprd_core::MprdError::InvalidInput(
                    "policy_source_kind_id and policy_source_hash must be both set or both unset"
                        .into(),
                )),
            }
        }
        out.extend_from_slice(&manifest_digest);
        Ok(out)
    }

    /// Verify the weighted quorum signature against a verifier-trusted signer weight map.
    ///
    /// Signers not present in `trusted_signer_weights` are ignored.
    pub fn verify_with_trusted_signer_weights(
        &self,
        trusted_signer_weights: &std::collections::HashMap<[u8; 32], u32>,
    ) -> Result<()> {
        if self.required_weight == 0 {
            return Err(mprd_core::MprdError::InvalidInput(
                "required_weight must be at least 1".into(),
            ));
        }

        let msg = self.signing_bytes_v1()?;
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut total_weight: u64 = 0;
        let required: u64 = self.required_weight as u64;

        for contrib in &self.contributions {
            let Some(weight) = trusted_signer_weights.get(&contrib.signer_pubkey) else {
                continue;
            };
            if *weight == 0 {
                continue;
            }

            // Prevent double-counting.
            if !seen.insert(contrib.signer_pubkey) {
                continue;
            }

            let vk = TokenVerifyingKey::from_bytes(&contrib.signer_pubkey).map_err(|_| {
                mprd_core::MprdError::SignatureInvalid("invalid signer pubkey".into())
            })?;
            if vk.verify_bytes(&msg, &contrib.signature).is_ok() {
                total_weight = total_weight.saturating_add(*weight as u64);
                if total_weight >= required {
                    return Ok(());
                }
            }
        }

        Err(mprd_core::MprdError::SignatureInvalid(format!(
            "insufficient weighted quorum: {} total weight, {} required",
            total_weight, self.required_weight
        )))
    }

    /// Sign a registry state as one member of a weighted quorum.
    pub fn sign_contribution(
        signing_key: &TokenSigningKey,
        state: &RegistryStateV1,
        signed_at_ms: i64,
        required_weight: u32,
    ) -> Result<QuorumSignerContribution> {
        let mut sorted_state = state.clone();
        sorted_state
            .authorized_policies
            .sort_by(|a, b| a.policy_hash.0.cmp(&b.policy_hash.0));

        let temp = Self {
            registry_state_version: WEIGHTED_QUORUM_REGISTRY_STATE_VERSION,
            state: sorted_state,
            signed_at_ms,
            required_weight,
            contributions: vec![],
        };

        let msg = temp.signing_bytes_v1()?;
        let signature = signing_key.sign_bytes(&msg).to_vec();
        let signer_pubkey = signing_key.verifying_key().to_bytes();

        Ok(QuorumSignerContribution {
            signer_pubkey,
            signature,
        })
    }

    /// Aggregate contributions into a complete weighted quorum-signed registry state.
    pub fn aggregate(
        state: RegistryStateV1,
        signed_at_ms: i64,
        required_weight: u32,
        contributions: Vec<QuorumSignerContribution>,
    ) -> Result<Self> {
        let mut sorted_state = state;
        sorted_state
            .authorized_policies
            .sort_by(|a, b| a.policy_hash.0.cmp(&b.policy_hash.0));

        Ok(Self {
            registry_state_version: WEIGHTED_QUORUM_REGISTRY_STATE_VERSION,
            state: sorted_state,
            signed_at_ms,
            required_weight,
            contributions,
        })
    }
}

/// Provider for a weighted quorum-signed registry checkpoint (low-trust weighted mode).
pub struct WeightedQuorumSignedRegistryStateProvider {
    signed: WeightedQuorumSignedRegistryStateV1,
    trusted_signer_weights: std::collections::HashMap<[u8; 32], u32>,
    manifest_verifying_key: TokenVerifyingKey,
}

impl WeightedQuorumSignedRegistryStateProvider {
    pub fn new(
        signed: WeightedQuorumSignedRegistryStateV1,
        trusted_signer_weights: std::collections::HashMap<[u8; 32], u32>,
        manifest_verifying_key: TokenVerifyingKey,
    ) -> Self {
        Self {
            signed,
            trusted_signer_weights,
            manifest_verifying_key,
        }
    }
}

impl RegistryStateProvider for WeightedQuorumSignedRegistryStateProvider {
    fn get(&self) -> Result<RegistryStateV1> {
        self.signed
            .verify_with_trusted_signer_weights(&self.trusted_signer_weights)?;
        self.signed
            .state
            .verify_manifest(&self.manifest_verifying_key)?;
        Ok(self.signed.state.clone())
    }
}

/// Provider for a quorum-signed registry checkpoint (low-trust mode).
pub struct QuorumSignedRegistryStateProvider {
    signed: QuorumSignedRegistryStateV1,
    trusted_signers: Vec<[u8; 32]>,
    manifest_verifying_key: TokenVerifyingKey,
}

impl QuorumSignedRegistryStateProvider {
    pub fn new(
        signed: QuorumSignedRegistryStateV1,
        trusted_signers: Vec<[u8; 32]>,
        manifest_verifying_key: TokenVerifyingKey,
    ) -> Self {
        Self {
            signed,
            trusted_signers,
            manifest_verifying_key,
        }
    }
}

impl RegistryStateProvider for QuorumSignedRegistryStateProvider {
    fn get(&self) -> Result<RegistryStateV1> {
        // Verify quorum signatures
        self.signed
            .verify_with_trusted_signers(&self.trusted_signers)?;
        // Verify manifest signature
        self.signed
            .state
            .verify_manifest(&self.manifest_verifying_key)?;
        Ok(self.signed.state.clone())
    }
}

impl RegistryStateV1 {
    pub fn verify_manifest(&self, verifying_key: &TokenVerifyingKey) -> Result<()> {
        self.guest_image_manifest.verify_with_key(verifying_key)
    }

    pub fn image_id_for_policy(&self, policy_hash: &Hash32) -> Option<Id32> {
        let p = self
            .authorized_policies
            .iter()
            .find(|p| &p.policy_hash == policy_hash)?;
        self.guest_image_manifest
            .image_id_for(&p.policy_exec_kind_id, &p.policy_exec_version_id)
    }

    pub fn authorized_policy(&self, policy_hash: &Hash32) -> Option<&AuthorizedPolicyV1> {
        self.authorized_policies
            .iter()
            .find(|p| &p.policy_hash == policy_hash)
    }
}

/// Provider for verifier-trusted registry snapshots.
pub trait RegistryStateProvider: Send + Sync {
    fn get(&self) -> Result<RegistryStateV1>;
}

/// Pluggable policy authorization provider.
///
/// This can be used by pipeline components to fail-fast before running an expensive proving step,
/// while still treating the verifier-trusted registry state as the ultimate source of truth.
pub trait PolicyAuthorizationProvider: Send + Sync {
    fn resolve(
        &self,
        policy_hash: &Hash32,
        policy_ref: &PolicyRef,
    ) -> Result<AuthorizedPolicyResolutionV1>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedPolicyResolutionV1 {
    pub authorized_policy: AuthorizedPolicyV1,
    pub image_id: Id32,
}

/// Policy authorization provider backed by a verifier-trusted registry state provider.
///
/// This enforces the same epoch/root pinning and manifest verification rules used by
/// `RegistryBoundRisc0Verifier`, but exposes the result as a reusable resolution object.
pub struct RegistryStatePolicyAuthorizationProvider {
    registry_state: Arc<dyn RegistryStateProvider>,
    manifest_verifying_key: TokenVerifyingKey,
    require_policy_source_mapping: bool,
}

impl RegistryStatePolicyAuthorizationProvider {
    pub fn new(
        registry_state: Arc<dyn RegistryStateProvider>,
        manifest_verifying_key: TokenVerifyingKey,
    ) -> Self {
        Self {
            registry_state,
            manifest_verifying_key,
            require_policy_source_mapping: false,
        }
    }

    pub fn with_required_policy_source_mapping(mut self, required: bool) -> Self {
        self.require_policy_source_mapping = required;
        self
    }
}

impl PolicyAuthorizationProvider for RegistryStatePolicyAuthorizationProvider {
    fn resolve(
        &self,
        policy_hash: &Hash32,
        policy_ref: &PolicyRef,
    ) -> Result<AuthorizedPolicyResolutionV1> {
        let state = self.registry_state.get()?;
        state.verify_manifest(&self.manifest_verifying_key)?;

        if state.policy_epoch != policy_ref.policy_epoch {
            return Err(mprd_core::MprdError::InvalidInput(
                "policy_epoch mismatch vs registry_state".into(),
            ));
        }
        if state.registry_root != policy_ref.registry_root {
            return Err(mprd_core::MprdError::InvalidInput(
                "registry_root mismatch vs registry_state".into(),
            ));
        }

        let authorized = state.authorized_policy(policy_hash).ok_or_else(|| {
            mprd_core::MprdError::InvalidInput("policy_hash not authorized".into())
        })?;

        if self.require_policy_source_mapping
            && (authorized.policy_source_kind_id.is_none()
                || authorized.policy_source_hash.is_none())
        {
            return Err(mprd_core::MprdError::InvalidInput(
                "authorized policy missing required policy_source mapping".into(),
            ));
        }

        let image_id = state
            .guest_image_manifest
            .image_id_for(
                &authorized.policy_exec_kind_id,
                &authorized.policy_exec_version_id,
            )
            .ok_or_else(|| {
                mprd_core::MprdError::InvalidInput("missing image_id for exec kind/version".into())
            })?;

        Ok(AuthorizedPolicyResolutionV1 {
            authorized_policy: authorized.clone(),
            image_id,
        })
    }
}

/// Simple in-memory provider for a fixed registry snapshot.
#[derive(Clone)]
pub struct StaticRegistryStateProvider(pub RegistryStateV1);

impl RegistryStateProvider for StaticRegistryStateProvider {
    fn get(&self) -> Result<RegistryStateV1> {
        Ok(self.0.clone())
    }
}

/// Provider for a fixed signed registry checkpoint, verified on every access (fail-closed).
pub struct SignedStaticRegistryStateProvider {
    signed: SignedRegistryStateV1,
    verifying_key: TokenVerifyingKey,
}

impl SignedStaticRegistryStateProvider {
    pub fn new(signed: SignedRegistryStateV1, verifying_key: TokenVerifyingKey) -> Self {
        Self {
            signed,
            verifying_key,
        }
    }
}

impl RegistryStateProvider for SignedStaticRegistryStateProvider {
    fn get(&self) -> Result<RegistryStateV1> {
        self.signed.verify_with_key(&self.verifying_key)?;
        Ok(self.signed.state.clone())
    }
}

/// Fail-closed verifier that evaluates `ValidDecision(bundle, registry_state)` by:
/// - selecting the expected ImageID from verifier-trusted `registry_state` before receipt verification
/// - enforcing policy authorization at a specific `(policy_epoch, registry_root)`
pub struct RegistryBoundRisc0Verifier {
    registry_state: Arc<dyn RegistryStateProvider>,
    manifest_verifying_key: TokenVerifyingKey,
    /// If true, require that every authorized policy entry includes a source-hash mapping.
    require_policy_source_mapping: bool,
}

impl RegistryBoundRisc0Verifier {
    pub fn new(
        registry_state: Arc<dyn RegistryStateProvider>,
        manifest_verifying_key: TokenVerifyingKey,
    ) -> Self {
        Self {
            registry_state,
            manifest_verifying_key,
            require_policy_source_mapping: false,
        }
    }

    /// Require that the registry provides a `policy_source_*` mapping (fail-closed).
    pub fn with_required_policy_source_mapping(
        mut self,
        require_policy_source_mapping: bool,
    ) -> Self {
        self.require_policy_source_mapping = require_policy_source_mapping;
        self
    }
}

impl ZkLocalVerifier for RegistryBoundRisc0Verifier {
    fn verify(&self, token: &DecisionToken, proof: &mprd_core::ProofBundle) -> VerificationStatus {
        let state = match self.registry_state.get() {
            Ok(s) => s,
            Err(e) => {
                return VerificationStatus::Failure(format!("registry_state unavailable: {e}"))
            }
        };

        if let Err(e) = state.verify_manifest(&self.manifest_verifying_key) {
            return VerificationStatus::Failure(format!("invalid guest image manifest: {e}"));
        }

        // Fail-closed epoch/root pinning.
        if state.policy_epoch != token.policy_ref.policy_epoch {
            return VerificationStatus::Failure("policy_epoch mismatch vs registry_state".into());
        }
        if state.registry_root != token.policy_ref.registry_root {
            return VerificationStatus::Failure("registry_root mismatch vs registry_state".into());
        }

        let authorized = match state.authorized_policy(&token.policy_hash) {
            Some(p) => p,
            None => return VerificationStatus::Failure("policy_hash not authorized".into()),
        };

        if self.require_policy_source_mapping
            && (authorized.policy_source_kind_id.is_none()
                || authorized.policy_source_hash.is_none())
        {
            return VerificationStatus::Failure(
                "authorized policy missing required policy_source mapping".into(),
            );
        }

        let image_id = match state.guest_image_manifest.image_id_for(
            &authorized.policy_exec_kind_id,
            &authorized.policy_exec_version_id,
        ) {
            Some(id) => id,
            None => {
                return VerificationStatus::Failure(
                    "registry_state missing image_id for authorized exec kind/version".into(),
                )
            }
        };

        // Receipt verification is performed against the selected image ID (fail-closed).
        let verifier = Risc0Verifier::new(
            image_id,
            authorized.policy_exec_kind_id,
            authorized.policy_exec_version_id,
        );
        verifier.verify(token, proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{GuestImageEntryV1, GuestImageManifestV1};
    use mprd_risc0_shared::{policy_exec_kind_mpb_id_v1, policy_exec_version_id_v1};

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    #[test]
    fn signed_registry_state_roundtrip_sign_and_verify() {
        let key = TokenSigningKey::from_seed(&[41u8; 32]);
        let vk = key.verifying_key();

        let manifest = GuestImageManifestV1::sign(
            &key,
            123,
            vec![GuestImageEntryV1 {
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                image_id: [7u8; 32],
            }],
        )
        .expect("manifest");

        let state = RegistryStateV1 {
            policy_epoch: 1,
            registry_root: dummy_hash(9),
            authorized_policies: vec![AuthorizedPolicyV1 {
                policy_hash: dummy_hash(3),
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: None,
                policy_source_hash: None,
            }],
            guest_image_manifest: manifest,
        };

        let signed = SignedRegistryStateV1::sign(&key, 456, state).expect("sign");
        signed.verify_with_key(&vk).expect("verify");
    }

    #[test]
    fn signed_registry_state_rejects_unsorted_policies() {
        let key = TokenSigningKey::from_seed(&[42u8; 32]);
        let vk = key.verifying_key();

        let manifest = GuestImageManifestV1::sign(&key, 123, vec![]).expect("manifest");
        let state = RegistryStateV1 {
            policy_epoch: 1,
            registry_root: dummy_hash(9),
            authorized_policies: vec![
                AuthorizedPolicyV1 {
                    policy_hash: dummy_hash(3),
                    policy_exec_kind_id: [1u8; 32],
                    policy_exec_version_id: [1u8; 32],
                    policy_source_kind_id: None,
                    policy_source_hash: None,
                },
                AuthorizedPolicyV1 {
                    policy_hash: dummy_hash(2), // out of order
                    policy_exec_kind_id: [1u8; 32],
                    policy_exec_version_id: [1u8; 32],
                    policy_source_kind_id: None,
                    policy_source_hash: None,
                },
            ],
            guest_image_manifest: manifest,
        };

        let signed = SignedRegistryStateV1::sign(&key, 456, state).expect("sign");
        signed.verify_with_key(&vk).expect("verify");

        let mut malformed = signed.clone();
        malformed.state.authorized_policies.reverse(); // non-canonical
        assert!(malformed.verify_with_key(&vk).is_err());
    }

    #[test]
    fn registry_bound_verifier_can_require_policy_source_mapping() {
        let key = TokenSigningKey::from_seed(&[43u8; 32]);
        let vk = key.verifying_key();

        let manifest = GuestImageManifestV1::sign(&key, 123, vec![]).expect("manifest");
        let policy_hash = dummy_hash(3);

        let state = RegistryStateV1 {
            policy_epoch: 7,
            registry_root: dummy_hash(9),
            authorized_policies: vec![AuthorizedPolicyV1 {
                policy_hash: policy_hash.clone(),
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: None,
                policy_source_hash: None,
            }],
            guest_image_manifest: manifest,
        };

        let signed = SignedRegistryStateV1::sign(&key, 456, state).expect("sign");
        signed.verify_with_key(&vk).expect("verify");

        let provider = Arc::new(SignedStaticRegistryStateProvider::new(signed, vk.clone()))
            as Arc<dyn RegistryStateProvider>;

        let verifier =
            RegistryBoundRisc0Verifier::new(provider, vk).with_required_policy_source_mapping(true);

        let token = DecisionToken {
            policy_hash,
            policy_ref: mprd_core::PolicyRef {
                policy_epoch: 7,
                registry_root: dummy_hash(9),
            },
            state_hash: dummy_hash(2),
            state_ref: mprd_core::StateRef::unknown(),
            chosen_action_hash: dummy_hash(4),
            nonce_or_tx_hash: dummy_hash(5),
            timestamp_ms: 0,
            signature: vec![],
        };
        let proof = mprd_core::ProofBundle {
            policy_hash: dummy_hash(0),
            state_hash: dummy_hash(0),
            candidate_set_hash: dummy_hash(0),
            chosen_action_hash: dummy_hash(0),
            limits_hash: dummy_hash(0),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![],
            attestation_metadata: Default::default(),
        };

        let status = verifier.verify(&token, &proof);
        assert!(
            matches!(status, VerificationStatus::Failure(msg) if msg == "authorized policy missing required policy_source mapping")
        );
    }

    // =========================================================================
    // Low-Trust Mode: Quorum-Signed Registry State Tests
    // =========================================================================

    #[test]
    fn quorum_signed_registry_state_2_of_3() {
        let key1 = TokenSigningKey::from_seed(&[51u8; 32]);
        let key2 = TokenSigningKey::from_seed(&[52u8; 32]);
        let key3 = TokenSigningKey::from_seed(&[53u8; 32]);

        let trusted_signers = vec![
            key1.verifying_key().to_bytes(),
            key2.verifying_key().to_bytes(),
            key3.verifying_key().to_bytes(),
        ];

        let manifest = GuestImageManifestV1::sign(&key1, 123, vec![]).expect("manifest");
        let state = RegistryStateV1 {
            policy_epoch: 1,
            registry_root: dummy_hash(9),
            authorized_policies: vec![],
            guest_image_manifest: manifest,
        };

        // Get contributions from 2 signers (meeting 2-of-3 threshold)
        let contrib1 =
            QuorumSignedRegistryStateV1::sign_contribution(&key1, &state, 456, 2).expect("c1");
        let contrib2 =
            QuorumSignedRegistryStateV1::sign_contribution(&key2, &state, 456, 2).expect("c2");

        let signed =
            QuorumSignedRegistryStateV1::aggregate(state, 456, 2, vec![contrib1, contrib2])
                .expect("aggregate");

        // Should verify with 2 valid signatures
        signed
            .verify_with_trusted_signers(&trusted_signers)
            .expect("quorum met");
    }

    #[test]
    fn quorum_signed_registry_state_fails_below_threshold() {
        let key1 = TokenSigningKey::from_seed(&[61u8; 32]);
        let key2 = TokenSigningKey::from_seed(&[62u8; 32]);
        let key3 = TokenSigningKey::from_seed(&[63u8; 32]);

        let trusted_signers = vec![
            key1.verifying_key().to_bytes(),
            key2.verifying_key().to_bytes(),
            key3.verifying_key().to_bytes(),
        ];

        let manifest = GuestImageManifestV1::sign(&key1, 123, vec![]).expect("manifest");
        let state = RegistryStateV1 {
            policy_epoch: 1,
            registry_root: dummy_hash(9),
            authorized_policies: vec![],
            guest_image_manifest: manifest,
        };

        // Get only 1 contribution (below 2-of-3 threshold)
        let contrib1 =
            QuorumSignedRegistryStateV1::sign_contribution(&key1, &state, 456, 2).expect("c1");

        let signed = QuorumSignedRegistryStateV1::aggregate(state, 456, 2, vec![contrib1])
            .expect("aggregate");

        // Should fail - insufficient quorum
        let result = signed.verify_with_trusted_signers(&trusted_signers);
        match result {
            Ok(_) => panic!("expected insufficient quorum"),
            Err(mprd_core::MprdError::SignatureInvalid(msg)) => {
                assert!(msg.starts_with("insufficient quorum:"));
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn quorum_signed_registry_state_ignores_untrusted_signers() {
        let key1 = TokenSigningKey::from_seed(&[71u8; 32]);
        let untrusted_key = TokenSigningKey::from_seed(&[72u8; 32]);

        // Only key1 is trusted
        let trusted_signers = vec![key1.verifying_key().to_bytes()];

        let manifest = GuestImageManifestV1::sign(&key1, 123, vec![]).expect("manifest");
        let state = RegistryStateV1 {
            policy_epoch: 1,
            registry_root: dummy_hash(9),
            authorized_policies: vec![],
            guest_image_manifest: manifest,
        };

        // Get contributions from trusted and untrusted signers
        let contrib1 =
            QuorumSignedRegistryStateV1::sign_contribution(&key1, &state, 456, 2).expect("c1");
        let contrib_untrusted =
            QuorumSignedRegistryStateV1::sign_contribution(&untrusted_key, &state, 456, 2)
                .expect("untrusted");

        let signed = QuorumSignedRegistryStateV1::aggregate(
            state,
            456,
            2,
            vec![contrib1, contrib_untrusted],
        )
        .expect("aggregate");

        // Should fail - only 1 trusted signer, threshold is 2
        let result = signed.verify_with_trusted_signers(&trusted_signers);
        assert!(result.is_err());
    }

    #[test]
    fn quorum_signed_registry_state_prevents_double_counting() {
        let key1 = TokenSigningKey::from_seed(&[73u8; 32]);

        let trusted_signers = vec![key1.verifying_key().to_bytes()];

        let manifest = GuestImageManifestV1::sign(&key1, 123, vec![]).expect("manifest");
        let state = RegistryStateV1 {
            policy_epoch: 1,
            registry_root: dummy_hash(9),
            authorized_policies: vec![],
            guest_image_manifest: manifest,
        };

        // Same signer contributes twice
        let contrib1 =
            QuorumSignedRegistryStateV1::sign_contribution(&key1, &state, 456, 2).expect("c1");
        let contrib1_dup =
            QuorumSignedRegistryStateV1::sign_contribution(&key1, &state, 456, 2).expect("c1_dup");

        let signed =
            QuorumSignedRegistryStateV1::aggregate(state, 456, 2, vec![contrib1, contrib1_dup])
                .expect("aggregate");

        // Should fail - same signer counted only once, threshold is 2
        let result = signed.verify_with_trusted_signers(&trusted_signers);
        assert!(result.is_err());
    }

    // =========================================================================
    // Weighted Quorum Registry State Tests
    // =========================================================================

    #[test]
    fn weighted_quorum_registry_state_meets_required_weight() {
        let key1 = TokenSigningKey::from_seed(&[81u8; 32]);
        let key2 = TokenSigningKey::from_seed(&[82u8; 32]);
        let key3 = TokenSigningKey::from_seed(&[83u8; 32]);

        let mut weights: std::collections::HashMap<[u8; 32], u32> =
            std::collections::HashMap::new();
        weights.insert(key1.verifying_key().to_bytes(), 5);
        weights.insert(key2.verifying_key().to_bytes(), 3);
        weights.insert(key3.verifying_key().to_bytes(), 1);

        let manifest = GuestImageManifestV1::sign(&key1, 123, vec![]).expect("manifest");
        let state = RegistryStateV1 {
            policy_epoch: 1,
            registry_root: dummy_hash(9),
            authorized_policies: vec![],
            guest_image_manifest: manifest,
        };

        // Required weight 8: key1 + key2 should satisfy.
        let c1 = WeightedQuorumSignedRegistryStateV1::sign_contribution(&key1, &state, 456, 8)
            .expect("c1");
        let c2 = WeightedQuorumSignedRegistryStateV1::sign_contribution(&key2, &state, 456, 8)
            .expect("c2");
        let signed = WeightedQuorumSignedRegistryStateV1::aggregate(state, 456, 8, vec![c1, c2])
            .expect("agg");

        signed
            .verify_with_trusted_signer_weights(&weights)
            .expect("weighted quorum met");
    }

    #[test]
    fn weighted_quorum_registry_state_fails_below_required_weight() {
        let key1 = TokenSigningKey::from_seed(&[91u8; 32]);
        let key2 = TokenSigningKey::from_seed(&[92u8; 32]);

        let mut weights: std::collections::HashMap<[u8; 32], u32> =
            std::collections::HashMap::new();
        weights.insert(key1.verifying_key().to_bytes(), 5);
        weights.insert(key2.verifying_key().to_bytes(), 3);

        let manifest = GuestImageManifestV1::sign(&key1, 123, vec![]).expect("manifest");
        let state = RegistryStateV1 {
            policy_epoch: 1,
            registry_root: dummy_hash(9),
            authorized_policies: vec![],
            guest_image_manifest: manifest,
        };

        // Required weight 6: key1 alone (weight 5) should fail.
        let c1 = WeightedQuorumSignedRegistryStateV1::sign_contribution(&key1, &state, 456, 6)
            .expect("c1");
        let signed =
            WeightedQuorumSignedRegistryStateV1::aggregate(state, 456, 6, vec![c1]).expect("agg");

        assert!(signed.verify_with_trusted_signer_weights(&weights).is_err());
    }

    #[test]
    fn weighted_quorum_registry_state_ignores_untrusted_signers() {
        let key1 = TokenSigningKey::from_seed(&[93u8; 32]);
        let untrusted = TokenSigningKey::from_seed(&[94u8; 32]);

        let mut weights: std::collections::HashMap<[u8; 32], u32> =
            std::collections::HashMap::new();
        weights.insert(key1.verifying_key().to_bytes(), 5);

        let manifest = GuestImageManifestV1::sign(&key1, 123, vec![]).expect("manifest");
        let state = RegistryStateV1 {
            policy_epoch: 1,
            registry_root: dummy_hash(9),
            authorized_policies: vec![],
            guest_image_manifest: manifest,
        };

        // Required weight 5: only untrusted signs, should fail.
        let c = WeightedQuorumSignedRegistryStateV1::sign_contribution(&untrusted, &state, 456, 5)
            .expect("c");
        let signed =
            WeightedQuorumSignedRegistryStateV1::aggregate(state, 456, 5, vec![c]).expect("agg");

        assert!(signed.verify_with_trusted_signer_weights(&weights).is_err());
    }

    #[test]
    fn policy_authorization_provider_resolves_authorized_policy() {
        let key = TokenSigningKey::from_seed(&[101u8; 32]);
        let vk = key.verifying_key();

        let manifest = GuestImageManifestV1::sign(
            &key,
            123,
            vec![GuestImageEntryV1 {
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                image_id: [7u8; 32],
            }],
        )
        .expect("manifest");

        let policy_hash = dummy_hash(3);
        let state = RegistryStateV1 {
            policy_epoch: 1,
            registry_root: dummy_hash(9),
            authorized_policies: vec![AuthorizedPolicyV1 {
                policy_hash: policy_hash.clone(),
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: None,
                policy_source_hash: None,
            }],
            guest_image_manifest: manifest,
        };

        let provider = RegistryStatePolicyAuthorizationProvider::new(
            Arc::new(StaticRegistryStateProvider(state)),
            vk.clone(),
        );

        let resolved = provider
            .resolve(
                &policy_hash,
                &PolicyRef {
                    policy_epoch: 1,
                    registry_root: dummy_hash(9),
                },
            )
            .expect("resolve");
        assert_eq!(resolved.image_id, [7u8; 32]);
    }

    #[test]
    fn policy_authorization_provider_fails_closed_on_epoch_mismatch() {
        let key = TokenSigningKey::from_seed(&[102u8; 32]);
        let vk = key.verifying_key();

        let manifest = GuestImageManifestV1::sign(&key, 123, vec![]).expect("manifest");
        let state = RegistryStateV1 {
            policy_epoch: 1,
            registry_root: dummy_hash(9),
            authorized_policies: vec![],
            guest_image_manifest: manifest,
        };

        let provider = RegistryStatePolicyAuthorizationProvider::new(
            Arc::new(StaticRegistryStateProvider(state)),
            vk.clone(),
        );

        let err = provider
            .resolve(
                &dummy_hash(1),
                &PolicyRef {
                    policy_epoch: 2,
                    registry_root: dummy_hash(9),
                },
            )
            .unwrap_err();
        match err {
            mprd_core::MprdError::InvalidInput(msg) => {
                assert_eq!(msg, "policy_epoch mismatch vs registry_state");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // =========================================================================
    // Property-Based Tests
    // =========================================================================

    use proptest::prelude::*;

    proptest! {
        /// Property: quorum threshold is exact - k signatures pass, k-1 fail.
        #[test]
        fn quorum_threshold_is_exact(
            threshold in 1u8..=4,
            n_signers in 4usize..=6,
        ) {
            let threshold = threshold.min(n_signers as u8);
            let keys: Vec<TokenSigningKey> = (0..n_signers)
                .map(|i| TokenSigningKey::from_seed(&[(i + 100) as u8; 32]))
                .collect();
            let trusted_signers: Vec<[u8; 32]> = keys
                .iter()
                .map(|k| k.verifying_key().to_bytes())
                .collect();

            let manifest = GuestImageManifestV1::sign(&keys[0], 123, vec![]).expect("manifest");
            let state = RegistryStateV1 {
                policy_epoch: 1,
                registry_root: dummy_hash(9),
                authorized_policies: vec![],
                guest_image_manifest: manifest,
            };

            // Exactly k signatures should pass
            let contribs_k: Vec<QuorumSignerContribution> = keys[..threshold as usize]
                .iter()
                .map(|k| QuorumSignedRegistryStateV1::sign_contribution(k, &state, 456, threshold).expect("contrib"))
                .collect();
            let signed_k = QuorumSignedRegistryStateV1::aggregate(state.clone(), 456, threshold, contribs_k).expect("agg");
            prop_assert!(signed_k.verify_with_trusted_signers(&trusted_signers).is_ok(), "k sigs should pass");

            // k-1 signatures should fail (if threshold > 1)
            if threshold > 1 {
                let contribs_k_minus_1: Vec<QuorumSignerContribution> = keys[..(threshold - 1) as usize]
                    .iter()
                    .map(|k| QuorumSignedRegistryStateV1::sign_contribution(k, &state, 456, threshold).expect("contrib"))
                    .collect();
                let signed_k_minus_1 = QuorumSignedRegistryStateV1::aggregate(state.clone(), 456, threshold, contribs_k_minus_1).expect("agg");
                prop_assert!(signed_k_minus_1.verify_with_trusted_signers(&trusted_signers).is_err(), "k-1 sigs should fail");
            }
        }

        /// Property: sign-then-verify roundtrip always succeeds for valid keys.
        #[test]
        fn sign_then_verify_roundtrip(seed in any::<u8>()) {
            let key = TokenSigningKey::from_seed(&[seed; 32]);
            let vk = key.verifying_key();

            let manifest = GuestImageManifestV1::sign(&key, 123, vec![]).expect("manifest");
            let state = RegistryStateV1 {
                policy_epoch: seed as u64 + 1,
                registry_root: dummy_hash(seed),
                authorized_policies: vec![],
                guest_image_manifest: manifest,
            };

            let signed = SignedRegistryStateV1::sign(&key, 456, state).expect("sign");
            prop_assert!(signed.verify_with_key(&vk).is_ok(), "roundtrip should succeed");
        }
    }
}
