//! Error types for MPRD Artifact Repository.
//!
//! All errors are fail-closed: any error terminates the operation.

use thiserror::Error;

use super::types::{BlockId, CommitId, Key};

/// Artifact repository error.
#[derive(Debug, Error)]
pub enum ArtifactRepoError {
    #[error("block not found: {0}")]
    BlockNotFound(BlockId),

    #[error("commit not found: {0}")]
    CommitNotFound(CommitId),

    #[error("content address mismatch: expected {expected}, got {actual}")]
    ContentAddressMismatch { expected: BlockId, actual: BlockId },

    #[error("block too large: {size} bytes > {max} max")]
    BlockTooLarge { size: usize, max: usize },

    #[error("key too large: {size} bytes > {max} max")]
    KeyTooLarge { size: usize, max: usize },

    #[error("value too large: {size} bytes > {max} max")]
    ValueTooLarge { size: usize, max: usize },

    #[error("bounds exceeded: {0}")]
    BoundsExceeded(&'static str),

    #[error("invalid block tag: {0}")]
    InvalidBlockTag(u8),

    #[error("invalid codec version: {0}")]
    InvalidCodecVersion(u8),

    #[error("malformed block: {0}")]
    MalformedBlock(String),

    #[error("malformed commit: {0}")]
    MalformedCommit(String),

    #[error("malformed MST node: {0}")]
    MalformedMstNode(String),

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("signer not trusted: {}", hex::encode(.0))]
    SignerNotTrusted([u8; 32]),

    #[error("commit chain broken at height {height}: {reason}")]
    ChainBroken { height: u64, reason: String },

    #[error("equivocation detected: {0}")]
    EquivocationDetected(String),

    #[error("rollback attempt: new epoch {new_epoch} < current {current_epoch}")]
    RollbackAttempt { new_epoch: u64, current_epoch: u64 },

    #[error("self-consistency check failed: {0}")]
    SelfConsistencyFailed(String),

    #[error("registry checkpoint verification failed: {0}")]
    RegistryCheckpointFailed(String),

    #[error("manifest verification failed: {0}")]
    ManifestVerificationFailed(String),

    #[error("diff bounds exceeded: {count} entries > {max} max")]
    DiffBoundsExceeded { count: usize, max: usize },

    #[error("MST depth exceeded: {depth} > 64")]
    MstDepthExceeded { depth: usize },

    #[error("key hash collision at depth {depth}")]
    KeyHashCollision { depth: usize },

    #[error("key not found: {0:?}")]
    KeyNotFound(Key),

    #[error("all sources failed")]
    AllSourcesFailed,

    #[error("timeout")]
    Timeout,

    #[error("network error: {0}")]
    NetworkError(String),

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("decode error: {0}")]
    DecodeError(String),

    #[error("expected root mismatch after apply: expected {expected}, got {actual}")]
    ApplyRootMismatch { expected: BlockId, actual: BlockId },
}

/// Result type for artifact repository operations.
pub type Result<T> = std::result::Result<T, ArtifactRepoError>;
