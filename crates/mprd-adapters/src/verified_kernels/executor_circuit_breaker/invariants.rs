//! Invariant checker for executor_circuit_breaker.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    // FailureThresholdOpens
    if !(((!(state.consecutive_failures >= 5)) || (state.state != StatePhase::Closed))) {
        return Err(Error::InvariantViolation("FailureThresholdOpens"));
    }

    // HalfOpenRequiresCooldown
    if !(((!(state.state == StatePhase::Halfopen)) || (state.cooldown_remaining == 0))) {
        return Err(Error::InvariantViolation("HalfOpenRequiresCooldown"));
    }

    // ClosedMeansRecovered
    if !(((!(state.state == StatePhase::Closed)) || (state.consecutive_failures < 5))) {
        return Err(Error::InvariantViolation("ClosedMeansRecovered"));
    }

    Ok(())
}
