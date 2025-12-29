//! State struct for ui_mode_adaptive_gates.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub anchors_configured: bool,
    pub mode: Mode,
    pub run_pipeline_disabled: bool,
    pub trust_anchor_warning: bool,
    pub zk_actions_disabled: bool,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            mode: Mode::Local,
            anchors_configured: false,
            run_pipeline_disabled: false,
            zk_actions_disabled: true,
            trust_anchor_warning: false,
        }
    }
}
