//! State struct for selector_fail_closed_required_limits.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub any_allowed: bool,
    pub chosen_allowed: bool,
    pub limits_present: bool,
    pub limits_valid: bool,
    pub result: ModelResult,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            any_allowed: false,
            limits_present: true,
            limits_valid: true,
            result: ModelResult::Pending,
            chosen_allowed: false,
        }
    }
}
