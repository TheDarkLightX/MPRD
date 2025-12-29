//! Commands for autopilot_controller.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    AddCritical,
    AutoDegrade,
    ConfigureAnchors,
    GoAssisted,
    GoAutopilot,
    GoOff,
    HumanAck,
    ResolveCritical,
    TickHour,
    UpdateFailureRate { new_rate: u64 },
}
