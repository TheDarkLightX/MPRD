//! State struct for ui_trust_anchor_fingerprints_only.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub display_state: DisplayState,
    pub key_loaded: bool,
    pub leaks_raw: bool,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            key_loaded: false,
            display_state: DisplayState::Hidden,
            leaks_raw: false,
        }
    }
}
