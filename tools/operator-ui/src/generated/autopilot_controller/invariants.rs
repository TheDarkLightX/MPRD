//! Invariant checker for autopilot_controller.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    // I10_FailRateDegrades
    if !(((!(state.failure_rate_pct > 20)) || (ModePhase::Autopilot != state.mode))) {
        return Err(Error::InvariantViolation("I10_FailRateDegrades"));
    }

    // I11_AckTimeout
    if !(((!(state.hours_since_ack >= 8)) || (ModePhase::Autopilot != state.mode))) {
        return Err(Error::InvariantViolation("I11_AckTimeout"));
    }

    // I12_AttentionBudget
    if !(((!(state.critical_incidents > state.attention_budget)) || (ModePhase::Autopilot != state.mode))) {
        return Err(Error::InvariantViolation("I12_AttentionBudget"));
    }

    // I9_AnchorRequired
    if !(((!(ModePhase::Autopilot == state.mode)) || state.anchors_configured)) {
        return Err(Error::InvariantViolation("I9_AnchorRequired"));
    }

    Ok(())
}
