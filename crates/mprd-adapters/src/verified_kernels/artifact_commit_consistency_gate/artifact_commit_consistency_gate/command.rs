//! Commands for artifact_commit_consistency_gate.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Accept,
    CheckpointFails,
    MstFails,
    Reject,
    RequireCheckpoint,
    SigFails,
}
