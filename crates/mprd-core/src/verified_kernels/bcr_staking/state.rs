//! State struct for bcr_staking.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub bonded_amount: u64,
    pub pending_slash: bool,
    pub phase: Phase,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            phase: Phase::Idle,
            bonded_amount: 0,
            pending_slash: false,
        }
    }
}
