//! State struct for executor_circuit_breaker.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub consecutive_failures: u64,
    pub consecutive_successes: u64,
    pub cooldown_remaining: u64,
    pub state: ExecutorCircuitBreakerState,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            state: ExecutorCircuitBreakerState::Closed,
            consecutive_failures: 0,
            consecutive_successes: 0,
            cooldown_remaining: 0,
        }
    }
}
