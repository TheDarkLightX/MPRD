//! Artifact Repo integration helpers (high ROI, pre-testnet).
//!
//! This wires the `mprd-core::artifact_repo` distribution layer to verifier-trusted
//! MPRD artifacts:
//! - `manifest/guest_image_manifest_v1` (signed guest image manifest)
//! - `registry/signed_registry_state_v2` (signed registry checkpoint, production anchor)
//!
//! The goal is fail-closed acceptance of a repo commit under the "production profile"
//! described in `internal/specs/mprd_artifact_repo_algorithms_v1.md`.

use mprd_core::artifact_repo::{
    verify_commit_header_and_signature, verify_commit_self_consistency, ArtifactRepoError,
    BlockStore, Commit, CommitConsistencyView, CommitId, Id32, RegistryCheckpointV2Fields,
    RepoArtifactVerifier, TrustAnchors, KEY_REGISTRY_SIGNED_REGISTRY_STATE_V2,
};
use mprd_core::{Hash32, MprdError, Result, TokenVerifyingKey};
use sha2::{Digest, Sha256};

use crate::manifest::GuestImageManifestV1;
use crate::registry_state::SignedRegistryStateV1;
use std::sync::RwLock;

#[derive(Debug, Clone)]
pub struct ZkRepoArtifactVerifier {
    pub trust_anchors: TrustAnchors,
}

impl ZkRepoArtifactVerifier {
    pub fn new(trust_anchors: TrustAnchors) -> Self {
        Self { trust_anchors }
    }
}

impl RepoArtifactVerifier for ZkRepoArtifactVerifier {
    fn verify_manifest_bytes(
        &self,
        manifest_bytes: &[u8],
    ) -> mprd_core::artifact_repo::Result<Id32> {
        let manifest: GuestImageManifestV1 =
            serde_json::from_slice(manifest_bytes).map_err(|e| {
                ArtifactRepoError::ManifestVerificationFailed(format!(
                    "manifest JSON decode failed: {e}"
                ))
            })?;

        if !self
            .trust_anchors
            .is_manifest_signer_trusted(&manifest.signer_pubkey)
        {
            return Err(ArtifactRepoError::ManifestVerificationFailed(
                "manifest signer not trusted".into(),
            ));
        }

        let vk = TokenVerifyingKey::from_bytes(&manifest.signer_pubkey).map_err(|e| {
            ArtifactRepoError::ManifestVerificationFailed(format!("invalid manifest pubkey: {e}"))
        })?;

        manifest.verify_with_key(&vk).map_err(|e| {
            ArtifactRepoError::ManifestVerificationFailed(format!(
                "manifest signature invalid: {e}"
            ))
        })?;

        let signing_bytes = manifest.signing_bytes_v1().map_err(|e| {
            ArtifactRepoError::ManifestVerificationFailed(format!(
                "manifest signing_bytes failed: {e}"
            ))
        })?;

        Ok(Id32(Sha256::digest(&signing_bytes).into()))
    }

    fn verify_registry_checkpoint_bytes(
        &self,
        checkpoint_bytes: &[u8],
    ) -> mprd_core::artifact_repo::Result<RegistryCheckpointV2Fields> {
        let signed: SignedRegistryStateV1 =
            serde_json::from_slice(checkpoint_bytes).map_err(|e| {
                ArtifactRepoError::RegistryCheckpointFailed(format!(
                    "registry checkpoint JSON decode failed: {e}"
                ))
            })?;

        if !self
            .trust_anchors
            .is_registry_checkpoint_signer_trusted(&signed.signer_pubkey)
        {
            return Err(ArtifactRepoError::RegistryCheckpointFailed(
                "registry checkpoint signer not trusted".into(),
            ));
        }

        let vk = TokenVerifyingKey::from_bytes(&signed.signer_pubkey).map_err(|e| {
            ArtifactRepoError::RegistryCheckpointFailed(format!(
                "invalid registry checkpoint pubkey: {e}"
            ))
        })?;

        signed.verify_with_key(&vk).map_err(|e| {
            ArtifactRepoError::RegistryCheckpointFailed(format!(
                "registry checkpoint signature invalid: {e}"
            ))
        })?;

        let manifest_signing = signed
            .state
            .guest_image_manifest
            .signing_bytes_v1()
            .map_err(|e| {
                ArtifactRepoError::RegistryCheckpointFailed(format!(
                    "registry checkpoint manifest signing_bytes failed: {e}"
                ))
            })?;
        let manifest_digest = Id32(Sha256::digest(&manifest_signing).into());

        Ok(RegistryCheckpointV2Fields {
            policy_epoch: signed.state.policy_epoch,
            registry_root: Id32(signed.state.registry_root.0),
            manifest_digest,
        })
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedRepoCommitV1 {
    pub commit_id: CommitId,
    pub commit: Commit,
    pub consistency: CommitConsistencyView,
    pub manifest: GuestImageManifestV1,
    pub signed_registry_state: Option<SignedRegistryStateV1>,
}

/// Bootstrap the latest acceptable repo commit under the production profile.
///
/// This is the end-to-end high-ROI integration:
/// - queries commit sources for their latest commit,
/// - verifies commit signature (Algorithm 2),
/// - fetches needed MST blocks from block sources,
/// - enforces commit self-consistency and signed registry checkpoint binding (Algorithm 3/3A),
/// - returns the decoded manifest + signed registry state (for verifier routing and authorization).
pub async fn bootstrap_verified_repo_commit_production_profile(
    store: &dyn mprd_core::artifact_repo::BlockStore,
    accepted_state: &RwLock<mprd_core::artifact_repo::AcceptedState>,
    trust_anchors: TrustAnchors,
    bounds: mprd_core::artifact_repo::RuntimeBounds,
    commit_sources: &[&dyn mprd_core::artifact_repo::CommitSource],
    block_sources: &[&dyn mprd_core::artifact_repo::BlockSource],
    client_instance_id: mprd_core::artifact_repo::ClientInstanceId,
) -> Result<VerifiedRepoCommitV1> {
    let verifier = ZkRepoArtifactVerifier::new(trust_anchors.clone());

    let best = mprd_core::artifact_repo::bootstrap_latest_acceptable_commit(
        mprd_core::artifact_repo::bootstrap::BootstrapLatestArgs {
            store,
            accepted_state,
            trust_anchors: &trust_anchors,
            bounds: &bounds,
            commit_sources,
            block_sources,
            client_instance_id: &client_instance_id,
            verifier: &verifier,
            require_signed_registry_checkpoint: true,
        },
    )
    .await
    .map_err(|e| MprdError::ZkError(format!("artifact repo bootstrap failed: {e}")))?;

    let commit_bytes = store.get(&best.commit_id).ok_or_else(|| {
        MprdError::ZkError("bootstrap succeeded but commit bytes missing from store".into())
    })?;

    verify_repo_commit_production_profile(
        store,
        best.commit_id,
        &commit_bytes,
        trust_anchors,
        bounds.max_block_fetch,
    )
}

/// Verify a repo commit under the "production profile" acceptance rules.
///
/// This enforces:
/// - Algorithm 2: commit content address + signature
/// - Algorithm 3: commit header fields match MST keys
/// - Algorithm 3A: presence + signature of `registry/signed_registry_state_v2` binding authority
pub fn verify_repo_commit_production_profile<S: BlockStore + ?Sized>(
    store: &S,
    commit_id: CommitId,
    commit_bytes: &[u8],
    trust_anchors: TrustAnchors,
    max_block_fetch_per_lookup: usize,
) -> Result<VerifiedRepoCommitV1> {
    let commit = verify_commit_header_and_signature(&commit_id, commit_bytes, &trust_anchors)
        .map_err(|e| MprdError::ZkError(format!("artifact repo commit verify failed: {e}")))?;

    let verifier = ZkRepoArtifactVerifier::new(trust_anchors.clone());
    let consistency =
        verify_commit_self_consistency(store, &commit, &verifier, max_block_fetch_per_lookup, true)
            .map_err(|e| MprdError::ZkError(format!("artifact repo consistency failed: {e}")))?;

    let manifest: GuestImageManifestV1 = serde_json::from_slice(&consistency.manifest_bytes)
        .map_err(|e| MprdError::ZkError(format!("manifest JSON decode failed: {e}")))?;

    let signed_registry_state = match &consistency.signed_registry_state_bytes {
        None => None,
        Some(bytes) => Some(
            serde_json::from_slice::<SignedRegistryStateV1>(bytes).map_err(|e| {
                MprdError::ZkError(format!(
                    "{} JSON decode failed: {e}",
                    KEY_REGISTRY_SIGNED_REGISTRY_STATE_V2
                ))
            })?,
        ),
    };

    Ok(VerifiedRepoCommitV1 {
        commit_id,
        commit,
        consistency,
        manifest,
        signed_registry_state,
    })
}

pub fn hash32_to_id32(h: &Hash32) -> Id32 {
    Id32(h.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{GuestImageEntryV1, MANIFEST_DOMAIN_V1};
    use crate::registry_state::{RegistryStateV1, SignedRegistryStateV1, REGISTRY_STATE_VERSION};
    use mprd_core::artifact_repo::commit::CommitFields;
    use mprd_core::artifact_repo::{
        create_signed_commit_with_token_key, encode_blob, mst_insert, Key, MemoryBlockStore,
        KEY_MANIFEST_GUEST_IMAGE_MANIFEST_V1, KEY_REGISTRY_POLICY_EPOCH,
        KEY_REGISTRY_REGISTRY_ROOT, KEY_REGISTRY_SIGNED_REGISTRY_STATE_V2,
    };
    use mprd_core::{TokenSigningKey, TokenVerifyingKey};
    use mprd_risc0_shared::{policy_exec_kind_mpb_id_v1, policy_exec_version_id_v1};

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    #[test]
    fn production_profile_commit_verifies() {
        let store = MemoryBlockStore::new();

        let commit_signer = TokenSigningKey::from_seed(&[21u8; 32]);
        let manifest_signer = TokenSigningKey::from_seed(&[22u8; 32]);
        let registry_signer = TokenSigningKey::from_seed(&[23u8; 32]);

        let commit_pub = commit_signer.verifying_key().to_bytes();
        let manifest_pub = manifest_signer.verifying_key().to_bytes();
        let registry_pub = registry_signer.verifying_key().to_bytes();

        let trust_anchors = TrustAnchors::new()
            .with_commit_signer(commit_pub)
            .with_manifest_signer(manifest_pub)
            .with_registry_checkpoint_signer(registry_pub);

        let policy_epoch = 7u64;
        let registry_root = Hash32([9u8; 32]);

        // Build and sign manifest.
        let entries = vec![GuestImageEntryV1 {
            policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            image_id: [3u8; 32],
        }];
        let manifest =
            GuestImageManifestV1::sign(&manifest_signer, 123, entries).expect("manifest sign");
        let manifest_json = serde_json::to_vec(&manifest).expect("manifest json");
        let manifest_signing = manifest.signing_bytes_v1().expect("manifest signing bytes");
        let manifest_digest = Id32(sha256(&manifest_signing));

        // Build and sign registry state (v2).
        let state = RegistryStateV1 {
            policy_epoch,
            registry_root: registry_root.clone(),
            authorized_policies: vec![],
            guest_image_manifest: manifest.clone(),
        };
        let signed_registry =
            SignedRegistryStateV1::sign(&registry_signer, 456, state).expect("registry sign");
        assert_eq!(
            signed_registry.registry_state_version,
            REGISTRY_STATE_VERSION
        );
        let signed_registry_json = serde_json::to_vec(&signed_registry).expect("registry json");

        // Put MST values.
        let epoch_blob = encode_blob(&policy_epoch.to_le_bytes()).unwrap();
        let epoch_id = mprd_core::artifact_repo::compute_block_id(&epoch_blob);
        store.put(epoch_id, epoch_blob).unwrap();

        let rr_blob = encode_blob(&registry_root.0).unwrap();
        let rr_id = mprd_core::artifact_repo::compute_block_id(&rr_blob);
        store.put(rr_id, rr_blob).unwrap();

        let manifest_blob = encode_blob(&manifest_json).unwrap();
        let manifest_id = mprd_core::artifact_repo::compute_block_id(&manifest_blob);
        store.put(manifest_id, manifest_blob).unwrap();

        let reg_blob = encode_blob(&signed_registry_json).unwrap();
        let reg_id = mprd_core::artifact_repo::compute_block_id(&reg_blob);
        store.put(reg_id, reg_blob).unwrap();

        let mut root = mst_insert(&store, None, &Key::new(KEY_REGISTRY_POLICY_EPOCH), epoch_id)
            .expect("insert epoch");
        root = mst_insert(
            &store,
            Some(root),
            &Key::new(KEY_REGISTRY_REGISTRY_ROOT),
            rr_id,
        )
        .expect("insert registry root");
        root = mst_insert(
            &store,
            Some(root),
            &Key::new(KEY_MANIFEST_GUEST_IMAGE_MANIFEST_V1),
            manifest_id,
        )
        .expect("insert manifest");
        root = mst_insert(
            &store,
            Some(root),
            &Key::new(KEY_REGISTRY_SIGNED_REGISTRY_STATE_V2),
            reg_id,
        )
        .expect("insert signed registry");

        // Create commit.
        let (commit_id, commit_bytes) = create_signed_commit_with_token_key(
            CommitFields {
                repo_version: 1,
                prev_commit: Id32::ZERO,
                commit_height: 1,
                repo_root: root,
                policy_epoch,
                registry_root: Id32(registry_root.0),
                manifest_digest,
                signed_at_ms: 999,
            },
            &commit_signer,
        );
        store.put(commit_id, commit_bytes.clone()).unwrap();

        let verified = verify_repo_commit_production_profile(
            &store,
            commit_id,
            &commit_bytes,
            trust_anchors,
            10_000,
        )
        .expect("verify");

        assert_eq!(verified.commit.policy_epoch, policy_epoch);
        assert_eq!(verified.commit.registry_root, Id32(registry_root.0));
        assert_eq!(verified.commit.manifest_digest, manifest_digest);

        // Manifest is decoded and can be used for image routing.
        let signing = verified.manifest.signing_bytes_v1().expect("signing bytes");
        assert_eq!(&signing[..MANIFEST_DOMAIN_V1.len()], MANIFEST_DOMAIN_V1);
        assert!(verified.signed_registry_state.is_some());

        // Sanity: registry state signature verifies under its key.
        let vk = TokenVerifyingKey::from_bytes(&registry_pub).unwrap();
        verified
            .signed_registry_state
            .as_ref()
            .unwrap()
            .verify_with_key(&vk)
            .expect("registry state verify");
    }

    #[test]
    fn production_profile_requires_signed_registry_checkpoint() {
        let store = MemoryBlockStore::new();

        let commit_signer = TokenSigningKey::from_seed(&[31u8; 32]);
        let manifest_signer = TokenSigningKey::from_seed(&[32u8; 32]);
        let registry_signer = TokenSigningKey::from_seed(&[33u8; 32]);

        let trust_anchors = TrustAnchors::new()
            .with_commit_signer(commit_signer.verifying_key().to_bytes())
            .with_manifest_signer(manifest_signer.verifying_key().to_bytes())
            .with_registry_checkpoint_signer(registry_signer.verifying_key().to_bytes());

        let policy_epoch = 7u64;
        let registry_root = Hash32([9u8; 32]);

        let manifest = GuestImageManifestV1::sign(&manifest_signer, 123, vec![]).unwrap();
        let manifest_json = serde_json::to_vec(&manifest).unwrap();
        let manifest_signing = manifest.signing_bytes_v1().unwrap();
        let manifest_digest = Id32(sha256(&manifest_signing));

        // Put MST values (but omit registry/signed_registry_state_v2).
        let epoch_blob = encode_blob(&policy_epoch.to_le_bytes()).unwrap();
        let epoch_id = mprd_core::artifact_repo::compute_block_id(&epoch_blob);
        store.put(epoch_id, epoch_blob).unwrap();

        let rr_blob = encode_blob(&registry_root.0).unwrap();
        let rr_id = mprd_core::artifact_repo::compute_block_id(&rr_blob);
        store.put(rr_id, rr_blob).unwrap();

        let manifest_blob = encode_blob(&manifest_json).unwrap();
        let manifest_id = mprd_core::artifact_repo::compute_block_id(&manifest_blob);
        store.put(manifest_id, manifest_blob).unwrap();

        let mut root = mst_insert(&store, None, &Key::new(KEY_REGISTRY_POLICY_EPOCH), epoch_id)
            .expect("insert epoch");
        root = mst_insert(
            &store,
            Some(root),
            &Key::new(KEY_REGISTRY_REGISTRY_ROOT),
            rr_id,
        )
        .expect("insert registry root");
        root = mst_insert(
            &store,
            Some(root),
            &Key::new(KEY_MANIFEST_GUEST_IMAGE_MANIFEST_V1),
            manifest_id,
        )
        .expect("insert manifest");

        let (commit_id, commit_bytes) = create_signed_commit_with_token_key(
            CommitFields {
                repo_version: 1,
                prev_commit: Id32::ZERO,
                commit_height: 1,
                repo_root: root,
                policy_epoch,
                registry_root: Id32(registry_root.0),
                manifest_digest,
                signed_at_ms: 999,
            },
            &commit_signer,
        );
        store.put(commit_id, commit_bytes.clone()).unwrap();

        let err = verify_repo_commit_production_profile(
            &store,
            commit_id,
            &commit_bytes,
            trust_anchors,
            10_000,
        )
        .unwrap_err();

        let msg = format!("{err}");
        assert!(
            msg.contains(KEY_REGISTRY_SIGNED_REGISTRY_STATE_V2) || msg.contains("signed_registry"),
            "unexpected error: {msg}"
        );
    }
}
