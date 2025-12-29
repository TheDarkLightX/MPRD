//! State struct for executor_circuit_breaker.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub state: StatePhase,
    pub consecutive_failures: u8,
    pub consecutive_successes: u8,
    pub cooldown_remaining: u8,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            state: StatePhase::Closed,
            consecutive_failures: 0,
            consecutive_successes: 0,
            cooldown_remaining: 0,
        }
    }
}
