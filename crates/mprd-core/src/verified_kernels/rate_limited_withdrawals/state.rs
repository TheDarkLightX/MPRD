//! State struct for rate_limited_withdrawals.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub available_balance: u64,
    pub epoch_limit: u64,
    pub epoch_withdrawn: u64,
    pub hours_since_halt: u64,
    pub phase: Phase,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            phase: Phase::Active,
            available_balance: 500,
            epoch_withdrawn: 0,
            epoch_limit: 50,
            hours_since_halt: 0,
        }
    }
}
