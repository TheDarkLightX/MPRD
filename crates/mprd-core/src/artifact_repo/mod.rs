//! MPRD Artifact Repository — Algorithms v1.4 Implementation.
//!
//! This module implements the algorithms specified in:
//! `internal/specs/mprd_artifact_repo_algorithms_v1.md`
//!
//! # Algorithm Summary
//!
//! | Algorithm | Module | Description |
//! |-----------|--------|-------------|
//! | 1 | `bootstrap` | Fast Bootstrap ("Latest Acceptable Root") |
//! | 2 | `commit` | Verify Commit Header + Signature |
//! | 3 | `consistency` | Commit Self-Consistency via Minimal MST Lookups |
//! | 4 | `lookup` | MST Key Lookup + Proofs |
//! | 4B | `lookup_fetch` | MST Lookup with Block Fetch |
//! | 5 | `fetch` | Bounded Multi-source Block Fetch Scheduler |
//! | 7 | `diff` | Hash-Guided Diff (Incremental Sync) |
//! | 8 | `mutation` | MST Insert/Delete (COW Mutation) |
//! | 9 | `apply` | Incremental Apply (Companion to Diff) |
//! | 10 | `chain` | Commit Chain Fetch (Backward Walk) |
//! | 11 | `chain` | Commit Chain Verification (Auditor Use) |
//!
//! # Design Principles
//!
//! All algorithms are:
//! - **Deterministic** given their inputs
//! - **Bounded** by explicit parameters (MAX_BLOCK_FETCH, etc.)
//! - **Fail-closed** (any error returns failure; no partial trust)
//!
//! # Example Usage
//!
//! ```ignore
//! use mprd_core::artifact_repo::{
//!     store::{MemoryBlockStore, TrustAnchors},
//!     commit::verify_commit_header_and_signature,
//!     lookup::mst_lookup,
//!     mutation::mst_insert,
//!     diff::mst_diff,
//!     apply::apply_diff,
//! };
//!
//! // Create store and trust anchors
//! let store = MemoryBlockStore::new();
//! let trust_anchors = TrustAnchors::new()
//!     .with_commit_signer(signer_pubkey);
//!
//! // Verify a commit
//! let commit = verify_commit_header_and_signature(
//!     &commit_id,
//!     &commit_bytes,
//!     &trust_anchors,
//! )?;
//!
//! // Lookup a key
//! let result = mst_lookup(&store, &root, &key, MAX_BLOCK_FETCH)?;
//!
//! // Insert a key
//! let new_root = mst_insert(&store, Some(root), &key, value_id)?;
//!
//! // Compute diff between two states
//! let diff = mst_diff(&store, Some(old_root), Some(new_root))?;
//!
//! // Apply diff to reach new state
//! let result_root = apply_diff(&store, Some(old_root), &diff, Some(new_root))?;
//! ```

pub mod apply;
pub mod bootstrap;
pub mod bounds;
pub mod chain;
pub mod codec;
pub mod commit;
pub mod consistency;
pub mod diff;
pub mod error;
pub mod fetch;
pub mod lookup;
pub mod lookup_fetch;
pub mod mutation;
pub mod store;
pub mod types;

// Re-export commonly used items
pub use apply::{apply_diff, apply_diff_batched};
pub use bootstrap::{bootstrap_latest_acceptable_commit, AcceptableCommit, BootstrapLatestArgs};
pub use bounds::{RuntimeBounds, MAX_BLOCK_FETCH, MAX_COMMIT_CHAIN};
pub use chain::{detect_equivocation, fetch_commit_chain, verify_commit_chain, ChainVerified};
pub use codec::{
    decode_blob, decode_commit, decode_mst_node, encode_blob, encode_commit, encode_mst_node,
};
pub use commit::{
    create_signed_commit, create_signed_commit_with_token_key, verify_commit_header_and_signature,
    CommitFields,
};
pub use consistency::verify_commit_self_consistency_fetching;
pub use consistency::{
    verify_commit_self_consistency, CommitConsistencyView, RegistryCheckpointV2Fields,
    RepoArtifactVerifier, KEY_MANIFEST_GUEST_IMAGE_MANIFEST_V1, KEY_REGISTRY_POLICY_EPOCH,
    KEY_REGISTRY_REGISTRY_ROOT, KEY_REGISTRY_SIGNED_REGISTRY_STATE_V2,
};
pub use diff::mst_diff;
pub use error::{ArtifactRepoError, Result};
pub use fetch::{fetch_block_multi_source, schedule_sources_for_block, ClientInstanceId};
pub use lookup::{mst_batch_lookup, mst_lookup, verify_proof};
pub use lookup_fetch::mst_lookup_fetching;
pub use mutation::{mst_delete, mst_insert};
pub use store::{
    AcceptedState, BlockSource, BlockStore, CommitSource, MemoryBlockStore, RepoContext,
    TrustAnchors, WritableBlockStore,
};
pub use types::{
    compute_block_id, compute_source_id, BlockId, BlockTag, ChainVerified as ChainVerifiedType,
    Commit, CommitId, DiffEntry, Id32, InclusionProof, Key, KeyHash, LookupResult, MstEntry,
    MstNode, NonInclusionProof, NonInclusionReason, SourceId,
};
