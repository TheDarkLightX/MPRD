//! State struct for slashing_escrow.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub bond_amount: u64,
    pub challenge_deadline: u64,
    pub evidence_submitted: bool,
    pub phase: Phase,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            phase: Phase::Released,
            bond_amount: 100,
            challenge_deadline: 0,
            evidence_submitted: false,
        }
    }
}
