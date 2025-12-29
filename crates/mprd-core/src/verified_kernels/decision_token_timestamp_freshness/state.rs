//! State struct for decision_token_timestamp_freshness.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub age_class: AgeClass,
    pub validation_ok: bool,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            age_class: AgeClass::Ok,
            validation_ok: false,
        }
    }
}
