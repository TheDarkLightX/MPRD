//! State struct for decision_token_anti_replay_race.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub phase_a: PhaseA,
    pub phase_b: PhaseB,
    pub successes: u64,
    pub token_claimed: bool,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            phase_a: PhaseA::Idlea,
            phase_b: PhaseB::Idleb,
            token_claimed: false,
            successes: 0,
        }
    }
}
