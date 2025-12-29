//! Invariant checker for autopilot_controller.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.attention_budget < 0u64 || state.attention_budget > 10u64 {
        return Err(Error::DomainViolation("attention_budget"));
    }
    if state.critical_incidents < 0u64 || state.critical_incidents > 20u64 {
        return Err(Error::DomainViolation("critical_incidents"));
    }
    if state.failure_rate_pct < 0u64 || state.failure_rate_pct > 100u64 {
        return Err(Error::DomainViolation("failure_rate_pct"));
    }
    if state.hours_since_ack < 0u64 || state.hours_since_ack > 48u64 {
        return Err(Error::DomainViolation("hours_since_ack"));
    }

    // I10_FailRateDegrades
    if !(((!(state.failure_rate_pct > 20)) || (Mode::Autopilot != state.mode))) {
        return Err(Error::InvariantViolation("I10_FailRateDegrades"));
    }

    // I11_AckTimeout
    if !(((!(state.hours_since_ack >= 8)) || (Mode::Autopilot != state.mode))) {
        return Err(Error::InvariantViolation("I11_AckTimeout"));
    }

    // I12_AttentionBudget
    if !(((!(state.critical_incidents > state.attention_budget)) || (Mode::Autopilot != state.mode))) {
        return Err(Error::InvariantViolation("I12_AttentionBudget"));
    }

    // I9_AnchorRequired
    if !(((!(Mode::Autopilot == state.mode)) || state.anchors_configured)) {
        return Err(Error::InvariantViolation("I9_AnchorRequired"));
    }

    Ok(())
}
