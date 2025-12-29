//! State struct for tau_attestation_replay_guard.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub epoch_newer: bool,
    pub hash_chain_valid: bool,
    pub result: ResultPhase,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            epoch_newer: true,
            hash_chain_valid: true,
            result: ResultPhase::Pending,
        }
    }
}
