//! State struct for artifact_commit_consistency_gate.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub checkpoint_ok: bool,
    pub checkpoint_required: bool,
    pub commit_sig_ok: bool,
    pub mst_consistency_ok: bool,
    pub result: ResultPhase,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            commit_sig_ok: true,
            mst_consistency_ok: true,
            checkpoint_required: false,
            checkpoint_ok: true,
            result: ResultPhase::Pending,
        }
    }
}
