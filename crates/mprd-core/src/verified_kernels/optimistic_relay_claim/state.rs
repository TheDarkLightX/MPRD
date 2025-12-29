//! State struct for optimistic_relay_claim.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub has_verdict: bool,
    pub phase: Phase,
    pub round_count: u64,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            has_verdict: false,
            phase: Phase::Pending,
            round_count: 0,
        }
    }
}
