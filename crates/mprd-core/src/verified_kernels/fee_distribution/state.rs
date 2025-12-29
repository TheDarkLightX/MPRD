//! State struct for fee_distribution.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub burned: u64,
    pub collected: u64,
    pub distributed: u64,
    pub phase: Phase,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            phase: Phase::Collecting,
            collected: 0,
            distributed: 0,
            burned: 0,
        }
    }
}
