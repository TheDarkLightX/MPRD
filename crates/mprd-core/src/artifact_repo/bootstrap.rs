//! Algorithm 1: Fast bootstrap ("Latest Acceptable Root").
//!
//! This selects the best acceptable repo commit from multiple untrusted sources:
//! - fetch candidate commit IDs,
//! - verify commits (Algorithm 2),
//! - verify commit self-consistency against the repo MST (Algorithm 3/3A),
//! - enforce anti-rollback (if a prior accepted commit exists),
//! - detect signer equivocation (same signer + same height, different commit id),
//! - choose the "best" commit deterministically.

use super::consistency::{verify_commit_self_consistency_fetching, RepoArtifactVerifier};
use super::error::{ArtifactRepoError, Result};
use super::fetch::ClientInstanceId;
use super::store::{AcceptedState, BlockSource, BlockStore, CommitSource, TrustAnchors};
use super::types::{Commit, CommitId};
use super::RuntimeBounds;
use crate::artifact_repo::commit::verify_commit_header_and_signature;
use std::sync::RwLock;

#[derive(Debug, Clone)]
pub struct AcceptableCommit {
    pub commit_id: CommitId,
    pub commit: Commit,
}

pub struct BootstrapLatestArgs<'a, V: RepoArtifactVerifier> {
    pub store: &'a dyn BlockStore,
    pub accepted_state: &'a RwLock<AcceptedState>,
    pub trust_anchors: &'a TrustAnchors,
    pub bounds: &'a RuntimeBounds,
    pub commit_sources: &'a [&'a dyn CommitSource],
    pub block_sources: &'a [&'a dyn BlockSource],
    pub client_instance_id: &'a ClientInstanceId,
    pub verifier: &'a V,
    pub require_signed_registry_checkpoint: bool,
}

/// Bootstrap the best acceptable commit under the v1.4 "production profile".
pub async fn bootstrap_latest_acceptable_commit<V: RepoArtifactVerifier>(
    args: BootstrapLatestArgs<'_, V>,
) -> Result<AcceptableCommit> {
    if args.commit_sources.is_empty() {
        return Err(ArtifactRepoError::AllSourcesFailed);
    }

    let mut candidates: Vec<AcceptableCommit> = Vec::new();
    let mut last_err: Option<ArtifactRepoError> = None;

    for src in args.commit_sources {
        let commit_id = match src.latest_commit().await {
            Ok(id) => id,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };

        let commit_bytes = match src.get_commit(&commit_id).await {
            Ok(b) => b,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };

        // Best-effort cache.
        if !args.store.contains(&commit_id) {
            let _ = args.store.put(commit_id, commit_bytes.clone());
        }

        let commit =
            match verify_commit_header_and_signature(&commit_id, &commit_bytes, args.trust_anchors)
            {
                Ok(c) => c,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };

        // Anti-rollback.
        {
            let g = args.accepted_state.read().unwrap();
            if g.would_rollback(
                commit.policy_epoch,
                commit.commit_height,
                &commit.signer_pubkey,
            ) {
                last_err = Some(ArtifactRepoError::RollbackAttempt {
                    new_epoch: commit.policy_epoch,
                    current_epoch: g.commit.as_ref().map(|c| c.policy_epoch).unwrap_or(0),
                });
                continue;
            }
        }

        // Self-consistency, fetching missing blocks as needed.
        if let Err(e) = verify_commit_self_consistency_fetching(
            args.store,
            &commit,
            args.verifier,
            args.block_sources,
            args.bounds,
            args.client_instance_id,
            args.require_signed_registry_checkpoint,
        )
        .await
        {
            last_err = Some(e);
            continue;
        }

        candidates.push(AcceptableCommit { commit_id, commit });
    }

    if candidates.is_empty() {
        return Err(last_err.unwrap_or(ArtifactRepoError::AllSourcesFailed));
    }

    detect_equivocation_in_candidates(&candidates)?;

    // Select best candidate deterministically.
    let mut best = candidates[0].clone();
    for c in candidates.iter().skip(1) {
        if is_better(c, &best) {
            best = c.clone();
        }
    }

    // Commit acceptance.
    {
        let mut g = args.accepted_state.write().unwrap();
        g.accept(best.commit_id, best.commit.clone());
    }

    Ok(best)
}

fn detect_equivocation_in_candidates(candidates: &[AcceptableCommit]) -> Result<()> {
    use std::collections::HashMap;
    let mut seen: HashMap<([u8; 32], u64), CommitId> = HashMap::new();
    for c in candidates {
        let k = (c.commit.signer_pubkey, c.commit.commit_height);
        if let Some(existing) = seen.get(&k) {
            if existing != &c.commit_id {
                return Err(ArtifactRepoError::EquivocationDetected(format!(
                    "signer equivocation at height {}",
                    c.commit.commit_height
                )));
            }
        } else {
            seen.insert(k, c.commit_id);
        }
    }
    Ok(())
}

fn is_better(a: &AcceptableCommit, b: &AcceptableCommit) -> bool {
    if a.commit.policy_epoch != b.commit.policy_epoch {
        return a.commit.policy_epoch > b.commit.policy_epoch;
    }
    if a.commit.signed_at_ms != b.commit.signed_at_ms {
        return a.commit.signed_at_ms > b.commit.signed_at_ms;
    }

    if a.commit.signer_pubkey == b.commit.signer_pubkey
        && a.commit.commit_height != b.commit.commit_height
    {
        return a.commit.commit_height > b.commit.commit_height;
    }

    // Lowest commit id wins final tie-break.
    a.commit_id.0 < b.commit_id.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_repo::codec::encode_blob;
    use crate::artifact_repo::commit::create_signed_commit_with_token_key;
    use crate::artifact_repo::mutation::mst_insert;
    use crate::artifact_repo::types::{compute_block_id, Id32, Key};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn block_on<F: Future>(mut fut: F) -> F::Output {
        fn raw_waker() -> RawWaker {
            fn clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            fn wake(_: *const ()) {}
            fn wake_by_ref(_: *const ()) {}
            fn drop(_: *const ()) {}
            static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
            RawWaker::new(std::ptr::null(), &VTABLE)
        }

        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        // Safety: we never move `fut` after pinning.
        let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    struct DummyVerifier {
        manifest_digest: Id32,
        checkpoint_fields: super::super::consistency::RegistryCheckpointV2Fields,
    }

    impl RepoArtifactVerifier for DummyVerifier {
        fn verify_manifest_bytes(&self, _manifest_bytes: &[u8]) -> Result<Id32> {
            Ok(self.manifest_digest)
        }

        fn verify_registry_checkpoint_bytes(
            &self,
            _checkpoint_bytes: &[u8],
        ) -> Result<super::super::consistency::RegistryCheckpointV2Fields> {
            Ok(self.checkpoint_fields)
        }
    }

    #[test]
    fn is_better_prefers_higher_height_for_same_signer_when_epoch_and_time_equal() {
        let signer = [7u8; 32];

        let lower = AcceptableCommit {
            commit_id: [0x00u8; 32].into(),
            commit: Commit {
                repo_version: 1,
                prev_commit: [0u8; 32].into(),
                commit_height: 10,
                repo_root: [0u8; 32].into(),
                policy_epoch: 5,
                registry_root: [0u8; 32].into(),
                manifest_digest: [0u8; 32].into(),
                signed_at_ms: 1234,
                signer_pubkey: signer,
                signature: [0u8; 64],
            },
        };

        // Higher height but "worse" commit_id to ensure height comparison is the deciding factor.
        let higher = AcceptableCommit {
            commit_id: [0xFFu8; 32].into(),
            commit: Commit {
                commit_height: 11,
                ..lower.commit.clone()
            },
        };

        assert!(is_better(&higher, &lower));
        assert!(!is_better(&lower, &higher));
    }

    struct StoreBackedBlockSource {
        id: super::super::types::SourceId,
        store: Arc<dyn BlockStore>,
    }

    #[async_trait::async_trait]
    impl BlockSource for StoreBackedBlockSource {
        fn source_id(&self) -> super::super::types::SourceId {
            self.id
        }

        async fn get_block(&self, block_id: &super::super::types::BlockId) -> Result<Vec<u8>> {
            self.store
                .get(block_id)
                .ok_or(ArtifactRepoError::BlockNotFound(*block_id))
        }
    }

    struct FixedCommitSource {
        id: super::super::types::SourceId,
        commit_id: CommitId,
        commit_bytes: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl CommitSource for FixedCommitSource {
        fn source_id(&self) -> super::super::types::SourceId {
            self.id
        }

        async fn latest_commit(&self) -> Result<CommitId> {
            Ok(self.commit_id)
        }

        async fn get_commit(&self, commit_id: &CommitId) -> Result<Vec<u8>> {
            if commit_id != &self.commit_id {
                return Err(ArtifactRepoError::CommitNotFound(*commit_id));
            }
            Ok(self.commit_bytes.clone())
        }
    }

    #[test]
    fn bootstrap_accepts_commit_with_fetching_consistency() {
        let local_store = super::super::store::MemoryBlockStore::new();
        let remote_store = super::super::store::MemoryBlockStore::new();

        // Prepare MST values in remote store.
        let policy_epoch = 7u64;
        let registry_root = Id32([9u8; 32]);
        let manifest_bytes = b"manifest-json-or-bytes";
        let checkpoint_bytes = b"checkpoint-json-or-bytes";

        let epoch_blob = encode_blob(&policy_epoch.to_le_bytes()).unwrap();
        let epoch_id = compute_block_id(&epoch_blob);
        remote_store.put(epoch_id, epoch_blob).unwrap();

        let rr_blob = encode_blob(&registry_root.0).unwrap();
        let rr_id = compute_block_id(&rr_blob);
        remote_store.put(rr_id, rr_blob).unwrap();

        let manifest_blob = encode_blob(manifest_bytes).unwrap();
        let manifest_id = compute_block_id(&manifest_blob);
        remote_store.put(manifest_id, manifest_blob).unwrap();

        let checkpoint_blob = encode_blob(checkpoint_bytes).unwrap();
        let checkpoint_id = compute_block_id(&checkpoint_blob);
        remote_store.put(checkpoint_id, checkpoint_blob).unwrap();

        let mut root = mst_insert(
            &remote_store,
            None,
            &Key::new(super::super::consistency::KEY_REGISTRY_POLICY_EPOCH),
            epoch_id,
        )
        .unwrap();
        root = mst_insert(
            &remote_store,
            Some(root),
            &Key::new(super::super::consistency::KEY_REGISTRY_REGISTRY_ROOT),
            rr_id,
        )
        .unwrap();
        root = mst_insert(
            &remote_store,
            Some(root),
            &Key::new(super::super::consistency::KEY_MANIFEST_GUEST_IMAGE_MANIFEST_V1),
            manifest_id,
        )
        .unwrap();
        root = mst_insert(
            &remote_store,
            Some(root),
            &Key::new(super::super::consistency::KEY_REGISTRY_SIGNED_REGISTRY_STATE_V2),
            checkpoint_id,
        )
        .unwrap();

        // Prepare commit bytes (also store it remotely, so a block source can serve it if needed).
        let commit_signer = crate::TokenSigningKey::from_seed(&[1u8; 32]);
        let manifest_digest = Id32([1u8; 32]);
        let (commit_id, commit_bytes) = create_signed_commit_with_token_key(
            crate::artifact_repo::commit::CommitFields {
                repo_version: 1,
                prev_commit: Id32::ZERO,
                commit_height: 1,
                repo_root: root,
                policy_epoch,
                registry_root,
                manifest_digest,
                signed_at_ms: 999,
            },
            &commit_signer,
        );
        remote_store.put(commit_id, commit_bytes.clone()).unwrap();

        // Trust anchors.
        let trust_anchors =
            TrustAnchors::new().with_commit_signer(commit_signer.verifying_key().to_bytes());
        // Dummy verifier matches the above.
        let verifier = DummyVerifier {
            manifest_digest,
            checkpoint_fields: super::super::consistency::RegistryCheckpointV2Fields {
                policy_epoch,
                registry_root,
                manifest_digest,
            },
        };

        let block_source = StoreBackedBlockSource {
            id: super::super::types::compute_source_id(b"remote"),
            store: Arc::new(remote_store),
        };
        let commit_source = FixedCommitSource {
            id: super::super::types::compute_source_id(b"commit"),
            commit_id,
            commit_bytes,
        };

        let accepted_state = RwLock::new(AcceptedState::new());
        let bounds = RuntimeBounds::default();
        let client_instance_id = Id32([7u8; 32]);

        let best = block_on(bootstrap_latest_acceptable_commit(BootstrapLatestArgs {
            store: &local_store,
            accepted_state: &accepted_state,
            trust_anchors: &trust_anchors,
            bounds: &bounds,
            commit_sources: &[&commit_source],
            block_sources: &[&block_source],
            client_instance_id: &client_instance_id,
            verifier: &verifier,
            require_signed_registry_checkpoint: true,
        }))
        .unwrap();

        assert_eq!(best.commit_id, commit_id);

        // Local store should now have at least the commit and some MST blocks.
        assert!(local_store.contains(&commit_id));
    }
}
