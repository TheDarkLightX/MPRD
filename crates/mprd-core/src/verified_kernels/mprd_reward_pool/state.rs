//! State struct for mprd_reward_pool.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub distributed_total: u64,
    pub phase: Phase,
    pub pool_balance: u64,
    pub pool_balance_at_distribution_start: u64,
    pub recipients_count: u64,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            phase: Phase::Empty,
            pool_balance: 0,
            recipients_count: 0,
            distributed_total: 0,
            pool_balance_at_distribution_start: 0,
        }
    }
}
