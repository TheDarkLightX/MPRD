//! State struct for policy_registry_gate.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub current_epoch: u64,
    pub frozen: bool,
    pub last_update_height: u64,
    pub policy_count: u64,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            current_epoch: 0,
            policy_count: 0,
            last_update_height: 0,
            frozen: false,
        }
    }
}
