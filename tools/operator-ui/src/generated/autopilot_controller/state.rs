//! State struct for autopilot_controller.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub anchors_configured: bool,
    pub attention_budget: u8,
    pub critical_incidents: u8,
    pub failure_rate_pct: u8,
    pub hours_since_ack: u8,
    pub mode: ModePhase,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            mode: ModePhase::Off,
            anchors_configured: false,
            hours_since_ack: 0,
            failure_rate_pct: 0,
            critical_incidents: 0,
            attention_budget: 5,
        }
    }
}
