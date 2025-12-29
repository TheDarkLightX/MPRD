//! State struct for policy_algebra_operators.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub eval_depth: u64,
    pub evaluations_count: u64,
    pub last_result: bool,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            eval_depth: 0,
            last_result: false,
            evaluations_count: 0,
        }
    }
}
