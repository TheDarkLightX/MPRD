//! State struct for opi_oracle_round.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub commit_count: u64,
    pub has_aggregate: bool,
    pub phase: Phase,
    pub reveal_count: u64,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            commit_count: 0,
            has_aggregate: false,
            phase: Phase::Commit,
            reveal_count: 0,
        }
    }
}
