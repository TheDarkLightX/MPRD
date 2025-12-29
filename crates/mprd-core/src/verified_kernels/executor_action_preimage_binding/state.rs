//! State struct for executor_action_preimage_binding.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub action_hash_matches: bool,
    pub limits_binding_ok: bool,
    pub preimage_present: bool,
    pub result: ModelResult,
    pub schema_valid: bool,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            limits_binding_ok: true,
            preimage_present: true,
            action_hash_matches: true,
            schema_valid: true,
            result: ModelResult::Pending,
        }
    }
}
