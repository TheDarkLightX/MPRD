//! Block storage and source traits for MPRD Artifact Repository.
//!
//! All sources are untrusted. Only signatures + hashes make them valid.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::bounds::RuntimeBounds;
use super::error::{ArtifactRepoError, Result};
use super::types::{compute_block_id, BlockId, Commit, CommitId, SourceId};

/// Local block storage (cache + persistent).
pub trait BlockStore: Send + Sync {
    /// Get block bytes by ID. Returns None if not found.
    fn get(&self, block_id: &BlockId) -> Option<Vec<u8>>;

    /// Store block bytes. Implementation should verify content addressing.
    fn put(&self, block_id: BlockId, bytes: Vec<u8>) -> Result<()>;

    /// Check if block exists without fetching.
    fn contains(&self, block_id: &BlockId) -> bool {
        self.get(block_id).is_some()
    }
}

/// Remote block source (untrusted network endpoint).
#[async_trait::async_trait]
pub trait BlockSource: Send + Sync {
    /// Unique identifier for this source.
    fn source_id(&self) -> SourceId;

    /// Fetch block bytes by ID. Returns error if not found or network failure.
    async fn get_block(&self, block_id: &BlockId) -> Result<Vec<u8>>;
}

/// Remote commit source (untrusted network endpoint).
#[async_trait::async_trait]
pub trait CommitSource: Send + Sync {
    /// Unique identifier for this source.
    fn source_id(&self) -> SourceId;

    /// Get the latest commit ID from this source.
    async fn latest_commit(&self) -> Result<CommitId>;

    /// Fetch commit bytes by ID.
    async fn get_commit(&self, commit_id: &CommitId) -> Result<Vec<u8>>;
}

/// In-memory block store for testing.
#[derive(Debug, Default)]
pub struct MemoryBlockStore {
    blocks: RwLock<HashMap<BlockId, Vec<u8>>>,
}

impl MemoryBlockStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.blocks.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl BlockStore for MemoryBlockStore {
    fn get(&self, block_id: &BlockId) -> Option<Vec<u8>> {
        self.blocks.read().unwrap().get(block_id).cloned()
    }

    fn put(&self, block_id: BlockId, bytes: Vec<u8>) -> Result<()> {
        // Verify content addressing
        let computed_id = compute_block_id(&bytes);
        if computed_id != block_id {
            return Err(ArtifactRepoError::ContentAddressMismatch {
                expected: block_id,
                actual: computed_id,
            });
        }
        self.blocks.write().unwrap().insert(block_id, bytes);
        Ok(())
    }

    fn contains(&self, block_id: &BlockId) -> bool {
        self.blocks.read().unwrap().contains_key(block_id)
    }
}

/// Writable block store that tracks new blocks for commits.
pub struct WritableBlockStore<S: BlockStore> {
    inner: S,
    new_blocks: RwLock<Vec<BlockId>>,
}

impl<S: BlockStore> WritableBlockStore<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            new_blocks: RwLock::new(Vec::new()),
        }
    }

    /// Get list of new blocks written since creation.
    pub fn new_blocks(&self) -> Vec<BlockId> {
        self.new_blocks.read().unwrap().clone()
    }

    /// Clear the new blocks list.
    pub fn clear_new_blocks(&self) {
        self.new_blocks.write().unwrap().clear();
    }
}

impl<S: BlockStore> BlockStore for WritableBlockStore<S> {
    fn get(&self, block_id: &BlockId) -> Option<Vec<u8>> {
        self.inner.get(block_id)
    }

    fn put(&self, block_id: BlockId, bytes: Vec<u8>) -> Result<()> {
        self.inner.put(block_id, bytes)?;
        self.new_blocks.write().unwrap().push(block_id);
        Ok(())
    }

    fn contains(&self, block_id: &BlockId) -> bool {
        self.inner.contains(block_id)
    }
}

/// Trust anchors for verification.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    /// Trusted commit signers (distribution layer).
    pub commit_signers: Vec<[u8; 32]>,
    /// Trusted registry checkpoint signers (authority).
    pub registry_checkpoint_signers: Vec<[u8; 32]>,
    /// Trusted manifest signers.
    pub manifest_signers: Vec<[u8; 32]>,
}

impl TrustAnchors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_commit_signer(mut self, pubkey: [u8; 32]) -> Self {
        self.commit_signers.push(pubkey);
        self
    }

    pub fn with_registry_checkpoint_signer(mut self, pubkey: [u8; 32]) -> Self {
        self.registry_checkpoint_signers.push(pubkey);
        self
    }

    pub fn with_manifest_signer(mut self, pubkey: [u8; 32]) -> Self {
        self.manifest_signers.push(pubkey);
        self
    }

    pub fn is_commit_signer_trusted(&self, pubkey: &[u8; 32]) -> bool {
        self.commit_signers.contains(pubkey)
    }

    pub fn is_registry_checkpoint_signer_trusted(&self, pubkey: &[u8; 32]) -> bool {
        self.registry_checkpoint_signers.contains(pubkey)
    }

    pub fn is_manifest_signer_trusted(&self, pubkey: &[u8; 32]) -> bool {
        self.manifest_signers.contains(pubkey)
    }
}

/// Accepted commit state for anti-rollback protection.
#[derive(Debug, Clone, Default)]
pub struct AcceptedState {
    /// Last accepted commit (if any).
    pub commit: Option<Commit>,
    /// Last accepted commit ID.
    pub commit_id: Option<CommitId>,
}

impl AcceptedState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update accepted state after successful verification.
    pub fn accept(&mut self, commit_id: CommitId, commit: Commit) {
        self.commit_id = Some(commit_id);
        self.commit = Some(commit);
    }

    /// Check if a new commit would be a rollback.
    pub fn would_rollback(
        &self,
        new_policy_epoch: u64,
        new_commit_height: u64,
        new_signer: &[u8; 32],
    ) -> bool {
        if let Some(ref prev) = self.commit {
            // Rollback if policy epoch decreases
            if new_policy_epoch < prev.policy_epoch {
                return true;
            }
            // Rollback if same epoch, same signer, and height decreases
            if new_policy_epoch == prev.policy_epoch
                && new_signer == &prev.signer_pubkey
                && new_commit_height < prev.commit_height
            {
                return true;
            }
        }
        false
    }
}

/// Repository context combining store, sources, and trust anchors.
pub struct RepoContext<S: BlockStore> {
    pub store: Arc<S>,
    pub trust_anchors: TrustAnchors,
    pub bounds: RuntimeBounds,
    pub accepted_state: RwLock<AcceptedState>,
}

impl<S: BlockStore> RepoContext<S> {
    pub fn new(store: S, trust_anchors: TrustAnchors) -> Self {
        Self {
            store: Arc::new(store),
            trust_anchors,
            bounds: RuntimeBounds::default(),
            accepted_state: RwLock::new(AcceptedState::new()),
        }
    }

    pub fn with_bounds(mut self, bounds: RuntimeBounds) -> Self {
        self.bounds = bounds;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_roundtrip() {
        let store = MemoryBlockStore::new();
        let data = b"test block data";
        let block_id = compute_block_id(data);

        assert!(!store.contains(&block_id));
        store.put(block_id, data.to_vec()).unwrap();
        assert!(store.contains(&block_id));

        let retrieved = store.get(&block_id).unwrap();
        assert_eq!(retrieved, data);
    }

    #[test]
    fn memory_store_rejects_wrong_hash() {
        let store = MemoryBlockStore::new();
        let data = b"test block data";
        let wrong_id = crate::artifact_repo::types::Id32([0xaa; 32]);

        let result = store.put(wrong_id, data.to_vec());
        assert!(matches!(
            result,
            Err(ArtifactRepoError::ContentAddressMismatch { .. })
        ));
    }

    #[test]
    fn trust_anchors() {
        let pubkey = [0x42; 32];
        let anchors = TrustAnchors::new().with_commit_signer(pubkey);

        assert!(anchors.is_commit_signer_trusted(&pubkey));
        assert!(!anchors.is_commit_signer_trusted(&[0x00; 32]));
    }

    #[test]
    fn anti_rollback() {
        let mut state = AcceptedState::new();
        let signer = [0x42; 32];

        // Initially no rollback possible
        assert!(!state.would_rollback(100, 50, &signer));

        // Accept a commit
        let commit = Commit {
            repo_version: 1,
            prev_commit: CommitId::ZERO,
            commit_height: 50,
            repo_root: BlockId::ZERO,
            policy_epoch: 100,
            registry_root: super::super::types::Id32::ZERO,
            manifest_digest: super::super::types::Id32::ZERO,
            signed_at_ms: 0,
            signer_pubkey: signer,
            signature: [0; 64],
        };
        state.accept(CommitId::ZERO, commit);

        // Same epoch, higher height: OK
        assert!(!state.would_rollback(100, 51, &signer));

        // Higher epoch: OK
        assert!(!state.would_rollback(101, 1, &signer));

        // Lower epoch: ROLLBACK
        assert!(state.would_rollback(99, 100, &signer));

        // Same signer, lower height: ROLLBACK
        assert!(state.would_rollback(100, 49, &signer));

        // Different signer, lower height: OK (different chain)
        assert!(!state.would_rollback(100, 49, &[0x00; 32]));
    }
}
