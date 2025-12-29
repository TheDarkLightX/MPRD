//! State struct for drip_payroll.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub epoch: u64,
    pub epoch_budget: u64,
    pub phase: Phase,
    pub recipients_paid: u64,
    pub total_payout: u64,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            phase: Phase::Pending,
            epoch: 0,
            epoch_budget: 1000,
            total_payout: 0,
            recipients_paid: 0,
        }
    }
}
