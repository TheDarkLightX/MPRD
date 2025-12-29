//! State struct for reserve_management.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub coverage_ratio_bps: u64,
    pub emergency_mode: bool,
    pub reserve_balance: u64,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            reserve_balance: 0,
            coverage_ratio_bps: 0,
            emergency_mode: false,
        }
    }
}
