//! State struct for nonce_manager_lifecycle.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub consumed_count: u64,
    pub current_time: u64,
    pub window_size: u64,
    pub window_start: u64,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            consumed_count: 0,
            window_start: 0,
            current_time: 0,
            window_size: 60,
        }
    }
}
