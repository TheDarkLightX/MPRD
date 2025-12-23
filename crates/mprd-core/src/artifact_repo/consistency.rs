//! Algorithm 3 (+3A): Commit self-consistency via minimal MST lookups.
//!
//! This module validates that a signature-verified commit header is consistent with the
//! authoritative values stored inside the repo's MST (policy_epoch, registry_root, manifest).
//!
//! For production acceptance, callers SHOULD also require a signed registry checkpoint
//! (Algorithm 3A) and verify it against verifier-trusted checkpoint signers.

use super::bounds::RuntimeBounds;
use super::error::{ArtifactRepoError, Result};
use super::fetch::ClientInstanceId;
use super::lookup::mst_lookup;
use super::lookup_fetch::mst_lookup_fetching;
use super::store::BlockSource;
use super::store::BlockStore;
use super::types::{Commit, Id32, Key, LookupResult};

pub const KEY_REGISTRY_POLICY_EPOCH: &str = "registry/policy_epoch";
pub const KEY_REGISTRY_REGISTRY_ROOT: &str = "registry/registry_root";
pub const KEY_MANIFEST_GUEST_IMAGE_MANIFEST_V1: &str = "manifest/guest_image_manifest_v1";
pub const KEY_REGISTRY_SIGNED_REGISTRY_STATE_V2: &str = "registry/signed_registry_state_v2";

/// Validation hook for artifact bytes stored in the repo.
///
/// This lives in `mprd-core` (no dependency on `mprd-zk`) and is intended to be implemented
/// by `mprd-zk` where the concrete signed artifact types live.
pub trait RepoArtifactVerifier: Send + Sync {
    /// Verify manifest bytes (signature, canonicality) and return the commit-pinned digest.
    fn verify_manifest_bytes(&self, manifest_bytes: &[u8]) -> Result<Id32>;

    /// Verify a signed registry checkpoint and return its bound values.
    fn verify_registry_checkpoint_bytes(
        &self,
        checkpoint_bytes: &[u8],
    ) -> Result<RegistryCheckpointV2Fields>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryCheckpointV2Fields {
    pub policy_epoch: u64,
    pub registry_root: Id32,
    pub manifest_digest: Id32,
}

#[derive(Debug, Clone)]
pub struct CommitConsistencyView {
    pub policy_epoch: u64,
    pub registry_root: Id32,
    pub manifest_bytes: Vec<u8>,
    pub manifest_digest: Id32,
    pub signed_registry_state_bytes: Option<Vec<u8>>,
}

/// Verify commit self-consistency against the MST (Algorithm 3) and optionally a signed registry
/// checkpoint binding (Algorithm 3A).
///
/// `commit` MUST already be verified by Algorithm 2 (content address + signature).
pub fn verify_commit_self_consistency<S: BlockStore + ?Sized, V: RepoArtifactVerifier>(
    store: &S,
    commit: &Commit,
    verifier: &V,
    max_block_fetch_per_lookup: usize,
    require_signed_registry_checkpoint: bool,
) -> Result<CommitConsistencyView> {
    let policy_epoch = read_required_u64_le(
        store,
        &commit.repo_root,
        Key::new(KEY_REGISTRY_POLICY_EPOCH),
        max_block_fetch_per_lookup,
    )?;
    if policy_epoch != commit.policy_epoch {
        return Err(ArtifactRepoError::SelfConsistencyFailed(
            "commit.policy_epoch does not match MST value".into(),
        ));
    }

    let registry_root = read_required_id32(
        store,
        &commit.repo_root,
        Key::new(KEY_REGISTRY_REGISTRY_ROOT),
        max_block_fetch_per_lookup,
    )?;
    if registry_root != commit.registry_root {
        return Err(ArtifactRepoError::SelfConsistencyFailed(
            "commit.registry_root does not match MST value".into(),
        ));
    }

    let manifest_bytes = read_required_bytes(
        store,
        &commit.repo_root,
        Key::new(KEY_MANIFEST_GUEST_IMAGE_MANIFEST_V1),
        max_block_fetch_per_lookup,
    )?;
    let manifest_digest = verifier.verify_manifest_bytes(&manifest_bytes)?;
    if manifest_digest != commit.manifest_digest {
        return Err(ArtifactRepoError::SelfConsistencyFailed(
            "commit.manifest_digest does not match manifest digest".into(),
        ));
    }

    let mut signed_registry_state_bytes = None;
    if require_signed_registry_checkpoint {
        let bytes = read_required_bytes(
            store,
            &commit.repo_root,
            Key::new(KEY_REGISTRY_SIGNED_REGISTRY_STATE_V2),
            max_block_fetch_per_lookup,
        )?;
        let fields = verifier.verify_registry_checkpoint_bytes(&bytes)?;

        if fields.policy_epoch != commit.policy_epoch {
            return Err(ArtifactRepoError::RegistryCheckpointFailed(
                "registry checkpoint policy_epoch does not match commit".into(),
            ));
        }
        if fields.registry_root != commit.registry_root {
            return Err(ArtifactRepoError::RegistryCheckpointFailed(
                "registry checkpoint registry_root does not match commit".into(),
            ));
        }
        if fields.manifest_digest != commit.manifest_digest {
            return Err(ArtifactRepoError::RegistryCheckpointFailed(
                "registry checkpoint manifest_digest does not match commit".into(),
            ));
        }

        signed_registry_state_bytes = Some(bytes);
    }

    Ok(CommitConsistencyView {
        policy_epoch,
        registry_root,
        manifest_bytes,
        manifest_digest,
        signed_registry_state_bytes,
    })
}

/// Async variant of `verify_commit_self_consistency` that fetches missing blocks from sources.
pub async fn verify_commit_self_consistency_fetching<V: RepoArtifactVerifier>(
    store: &dyn BlockStore,
    commit: &Commit,
    verifier: &V,
    block_sources: &[&dyn BlockSource],
    bounds: &RuntimeBounds,
    client_instance_id: &ClientInstanceId,
    require_signed_registry_checkpoint: bool,
) -> Result<CommitConsistencyView> {
    let policy_epoch = read_required_u64_le_fetching(
        store,
        &commit.repo_root,
        Key::new(KEY_REGISTRY_POLICY_EPOCH),
        block_sources,
        bounds,
        client_instance_id,
    )
    .await?;
    if policy_epoch != commit.policy_epoch {
        return Err(ArtifactRepoError::SelfConsistencyFailed(
            "commit.policy_epoch does not match MST value".into(),
        ));
    }

    let registry_root = read_required_id32_fetching(
        store,
        &commit.repo_root,
        Key::new(KEY_REGISTRY_REGISTRY_ROOT),
        block_sources,
        bounds,
        client_instance_id,
    )
    .await?;
    if registry_root != commit.registry_root {
        return Err(ArtifactRepoError::SelfConsistencyFailed(
            "commit.registry_root does not match MST value".into(),
        ));
    }

    let manifest_bytes = read_required_bytes_fetching(
        store,
        &commit.repo_root,
        Key::new(KEY_MANIFEST_GUEST_IMAGE_MANIFEST_V1),
        block_sources,
        bounds,
        client_instance_id,
    )
    .await?;
    let manifest_digest = verifier.verify_manifest_bytes(&manifest_bytes)?;
    if manifest_digest != commit.manifest_digest {
        return Err(ArtifactRepoError::SelfConsistencyFailed(
            "commit.manifest_digest does not match manifest digest".into(),
        ));
    }

    let mut signed_registry_state_bytes = None;
    if require_signed_registry_checkpoint {
        let bytes = read_required_bytes_fetching(
            store,
            &commit.repo_root,
            Key::new(KEY_REGISTRY_SIGNED_REGISTRY_STATE_V2),
            block_sources,
            bounds,
            client_instance_id,
        )
        .await?;
        let fields = verifier.verify_registry_checkpoint_bytes(&bytes)?;

        if fields.policy_epoch != commit.policy_epoch {
            return Err(ArtifactRepoError::RegistryCheckpointFailed(
                "registry checkpoint policy_epoch does not match commit".into(),
            ));
        }
        if fields.registry_root != commit.registry_root {
            return Err(ArtifactRepoError::RegistryCheckpointFailed(
                "registry checkpoint registry_root does not match commit".into(),
            ));
        }
        if fields.manifest_digest != commit.manifest_digest {
            return Err(ArtifactRepoError::RegistryCheckpointFailed(
                "registry checkpoint manifest_digest does not match commit".into(),
            ));
        }

        signed_registry_state_bytes = Some(bytes);
    }

    Ok(CommitConsistencyView {
        policy_epoch,
        registry_root,
        manifest_bytes,
        manifest_digest,
        signed_registry_state_bytes,
    })
}

fn read_required_bytes<S: BlockStore + ?Sized>(
    store: &S,
    root: &Id32,
    key: Key,
    max_block_fetch: usize,
) -> Result<Vec<u8>> {
    let result = mst_lookup(store, root, &key, max_block_fetch)?;
    match result {
        LookupResult::Found(p) => Ok(p.value_bytes),
        LookupResult::NotFound(_) => Err(ArtifactRepoError::KeyNotFound(key)),
    }
}

async fn read_required_bytes_fetching(
    store: &dyn BlockStore,
    root: &Id32,
    key: Key,
    block_sources: &[&dyn BlockSource],
    bounds: &RuntimeBounds,
    client_instance_id: &ClientInstanceId,
) -> Result<Vec<u8>> {
    let result =
        mst_lookup_fetching(store, root, &key, block_sources, bounds, client_instance_id).await?;
    match result {
        LookupResult::Found(p) => Ok(p.value_bytes),
        LookupResult::NotFound(_) => Err(ArtifactRepoError::KeyNotFound(key)),
    }
}

fn read_required_u64_le<S: BlockStore + ?Sized>(
    store: &S,
    root: &Id32,
    key: Key,
    max_block_fetch: usize,
) -> Result<u64> {
    let bytes = read_required_bytes(store, root, key, max_block_fetch)?;
    if bytes.len() != 8 {
        return Err(ArtifactRepoError::SelfConsistencyFailed(
            "expected u64 value to be exactly 8 bytes".into(),
        ));
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes);
    Ok(u64::from_le_bytes(arr))
}

async fn read_required_u64_le_fetching(
    store: &dyn BlockStore,
    root: &Id32,
    key: Key,
    block_sources: &[&dyn BlockSource],
    bounds: &RuntimeBounds,
    client_instance_id: &ClientInstanceId,
) -> Result<u64> {
    let bytes =
        read_required_bytes_fetching(store, root, key, block_sources, bounds, client_instance_id)
            .await?;
    if bytes.len() != 8 {
        return Err(ArtifactRepoError::SelfConsistencyFailed(
            "expected u64 value to be exactly 8 bytes".into(),
        ));
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes);
    Ok(u64::from_le_bytes(arr))
}

fn read_required_id32<S: BlockStore + ?Sized>(
    store: &S,
    root: &Id32,
    key: Key,
    max_block_fetch: usize,
) -> Result<Id32> {
    let bytes = read_required_bytes(store, root, key, max_block_fetch)?;
    if bytes.len() != 32 {
        return Err(ArtifactRepoError::SelfConsistencyFailed(
            "expected Id32 value to be exactly 32 bytes".into(),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Id32(arr))
}

async fn read_required_id32_fetching(
    store: &dyn BlockStore,
    root: &Id32,
    key: Key,
    block_sources: &[&dyn BlockSource],
    bounds: &RuntimeBounds,
    client_instance_id: &ClientInstanceId,
) -> Result<Id32> {
    let bytes =
        read_required_bytes_fetching(store, root, key, block_sources, bounds, client_instance_id)
            .await?;
    if bytes.len() != 32 {
        return Err(ArtifactRepoError::SelfConsistencyFailed(
            "expected Id32 value to be exactly 32 bytes".into(),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Id32(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_repo::codec::encode_blob;
    use crate::artifact_repo::mutation::mst_insert;
    use crate::artifact_repo::store::MemoryBlockStore;
    use crate::artifact_repo::types::{compute_block_id, Commit, CommitId, Id32};
    use proptest::prelude::*;

    #[derive(Clone)]
    struct DummyVerifier {
        manifest_digest: Id32,
        checkpoint_fields: RegistryCheckpointV2Fields,
    }

    impl RepoArtifactVerifier for DummyVerifier {
        fn verify_manifest_bytes(&self, _manifest_bytes: &[u8]) -> Result<Id32> {
            Ok(self.manifest_digest)
        }

        fn verify_registry_checkpoint_bytes(
            &self,
            _checkpoint_bytes: &[u8],
        ) -> Result<RegistryCheckpointV2Fields> {
            Ok(self.checkpoint_fields)
        }
    }

    fn put_blob(store: &MemoryBlockStore, payload: &[u8]) -> Id32 {
        let bytes = encode_blob(payload).expect("encode blob");
        let id = compute_block_id(&bytes);
        store.put(id, bytes).expect("put");
        id
    }

    fn build_repo_root(
        store: &MemoryBlockStore,
        policy_epoch: u64,
        registry_root: Id32,
        manifest_bytes: Vec<u8>,
        signed_registry_state_bytes: Option<Vec<u8>>,
    ) -> Id32 {
        let mut root: Option<Id32> = None;

        let policy_epoch_blob = put_blob(store, &policy_epoch.to_le_bytes());
        root = Some(
            mst_insert(
                store,
                root,
                &Key::new(KEY_REGISTRY_POLICY_EPOCH),
                policy_epoch_blob,
            )
            .expect("insert"),
        );

        let registry_root_blob = put_blob(store, &registry_root.0);
        root = Some(
            mst_insert(
                store,
                root,
                &Key::new(KEY_REGISTRY_REGISTRY_ROOT),
                registry_root_blob,
            )
            .expect("insert"),
        );

        let manifest_blob = put_blob(store, &manifest_bytes);
        root = Some(
            mst_insert(
                store,
                root,
                &Key::new(KEY_MANIFEST_GUEST_IMAGE_MANIFEST_V1),
                manifest_blob,
            )
            .expect("insert"),
        );

        if let Some(bytes) = signed_registry_state_bytes {
            let checkpoint_blob = put_blob(store, &bytes);
            root = Some(
                mst_insert(
                    store,
                    root,
                    &Key::new(KEY_REGISTRY_SIGNED_REGISTRY_STATE_V2),
                    checkpoint_blob,
                )
                .expect("insert"),
            );
        }

        root.expect("root")
    }

    #[test]
    fn self_consistency_fails_closed_when_registry_root_bytes_wrong_length() {
        let store = MemoryBlockStore::new();
        let policy_epoch = 7u64;
        let registry_root = Id32([9u8; 32]);
        let manifest_bytes = b"m".to_vec();

        // Build repo root with a bad registry_root value blob (wrong length).
        let mut root: Option<Id32> = None;
        let policy_epoch_blob = put_blob(&store, &policy_epoch.to_le_bytes());
        root = Some(
            mst_insert(
                &store,
                root,
                &Key::new(KEY_REGISTRY_POLICY_EPOCH),
                policy_epoch_blob,
            )
            .unwrap(),
        );
        let bad_registry_blob = put_blob(&store, b"short");
        root = Some(
            mst_insert(
                &store,
                root,
                &Key::new(KEY_REGISTRY_REGISTRY_ROOT),
                bad_registry_blob,
            )
            .unwrap(),
        );
        let manifest_blob = put_blob(&store, &manifest_bytes);
        root = Some(
            mst_insert(
                &store,
                root,
                &Key::new(KEY_MANIFEST_GUEST_IMAGE_MANIFEST_V1),
                manifest_blob,
            )
            .unwrap(),
        );
        let root = root.unwrap();

        let commit = Commit {
            repo_version: 1,
            prev_commit: CommitId::ZERO,
            commit_height: 1,
            repo_root: root,
            policy_epoch,
            registry_root,
            manifest_digest: Id32([1u8; 32]),
            signed_at_ms: 0,
            signer_pubkey: [0u8; 32],
            signature: [0u8; 64],
        };

        let verifier = DummyVerifier {
            manifest_digest: commit.manifest_digest,
            checkpoint_fields: RegistryCheckpointV2Fields {
                policy_epoch,
                registry_root,
                manifest_digest: commit.manifest_digest,
            },
        };

        assert!(verify_commit_self_consistency(&store, &commit, &verifier, 200, false).is_err());
    }

    proptest! {
        #[test]
        fn self_consistency_accepts_matching_repo_state(
            policy_epoch in any::<u64>(),
            registry_root in any::<[u8; 32]>(),
            manifest_bytes in proptest::collection::vec(any::<u8>(), 0..256),
            manifest_digest in any::<[u8; 32]>(),
        ) {
            let store = MemoryBlockStore::new();
            let registry_root = Id32(registry_root);
            let manifest_digest = Id32(manifest_digest);

            let root = build_repo_root(&store, policy_epoch, registry_root, manifest_bytes.clone(), None);

            let commit = Commit {
                repo_version: 1,
                prev_commit: CommitId::ZERO,
                commit_height: 1,
                repo_root: root,
                policy_epoch,
                registry_root,
                manifest_digest,
                signed_at_ms: 0,
                signer_pubkey: [0u8; 32],
                signature: [0u8; 64],
            };

            let verifier = DummyVerifier {
                manifest_digest,
                checkpoint_fields: RegistryCheckpointV2Fields {
                    policy_epoch,
                    registry_root,
                    manifest_digest,
                },
            };

            let view = verify_commit_self_consistency(&store, &commit, &verifier, 500, false).expect("ok");
            prop_assert_eq!(view.policy_epoch, policy_epoch);
            prop_assert_eq!(view.registry_root, registry_root);
            prop_assert_eq!(view.manifest_digest, manifest_digest);
            prop_assert!(view.signed_registry_state_bytes.is_none());
        }

        #[test]
        fn self_consistency_fails_closed_when_manifest_digest_mismatch(
            policy_epoch in any::<u64>(),
            registry_root in any::<[u8; 32]>(),
            manifest_bytes in proptest::collection::vec(any::<u8>(), 0..64),
            commit_digest in any::<[u8; 32]>(),
            verifier_digest in any::<[u8; 32]>(),
        ) {
            prop_assume!(commit_digest != verifier_digest);
            let store = MemoryBlockStore::new();
            let registry_root = Id32(registry_root);

            let root = build_repo_root(&store, policy_epoch, registry_root, manifest_bytes.clone(), None);

            let commit = Commit {
                repo_version: 1,
                prev_commit: CommitId::ZERO,
                commit_height: 1,
                repo_root: root,
                policy_epoch,
                registry_root,
                manifest_digest: Id32(commit_digest),
                signed_at_ms: 0,
                signer_pubkey: [0u8; 32],
                signature: [0u8; 64],
            };

            let verifier = DummyVerifier {
                manifest_digest: Id32(verifier_digest),
                checkpoint_fields: RegistryCheckpointV2Fields {
                    policy_epoch,
                    registry_root,
                    manifest_digest: Id32(verifier_digest),
                },
            };

            prop_assert!(verify_commit_self_consistency(&store, &commit, &verifier, 500, false).is_err());
        }

        #[test]
        fn self_consistency_requires_registry_checkpoint_when_enabled(
            policy_epoch in any::<u64>(),
            registry_root in any::<[u8; 32]>(),
            manifest_bytes in proptest::collection::vec(any::<u8>(), 0..64),
            manifest_digest in any::<[u8; 32]>(),
            checkpoint_bytes in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let store = MemoryBlockStore::new();
            let registry_root = Id32(registry_root);
            let manifest_digest = Id32(manifest_digest);

            let root = build_repo_root(&store, policy_epoch, registry_root, manifest_bytes.clone(), Some(checkpoint_bytes.clone()));

            let commit = Commit {
                repo_version: 1,
                prev_commit: CommitId::ZERO,
                commit_height: 1,
                repo_root: root,
                policy_epoch,
                registry_root,
                manifest_digest,
                signed_at_ms: 0,
                signer_pubkey: [0u8; 32],
                signature: [0u8; 64],
            };

            let verifier = DummyVerifier {
                manifest_digest,
                checkpoint_fields: RegistryCheckpointV2Fields {
                    policy_epoch,
                    registry_root,
                    manifest_digest,
                },
            };

            let view = verify_commit_self_consistency(&store, &commit, &verifier, 500, true).expect("ok");
            prop_assert_eq!(view.signed_registry_state_bytes, Some(checkpoint_bytes));
        }
    }
}
