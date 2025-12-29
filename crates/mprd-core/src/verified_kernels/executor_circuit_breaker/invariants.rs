//! Invariant checker for executor_circuit_breaker.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.consecutive_failures < 0u64 || state.consecutive_failures > 10u64 {
        return Err(Error::DomainViolation("consecutive_failures"));
    }
    if state.consecutive_successes < 0u64 || state.consecutive_successes > 5u64 {
        return Err(Error::DomainViolation("consecutive_successes"));
    }
    if state.cooldown_remaining < 0u64 || state.cooldown_remaining > 60u64 {
        return Err(Error::DomainViolation("cooldown_remaining"));
    }

    // ClosedMeansRecovered
    if !((!(ExecutorCircuitBreakerState::Closed == state.state))
        || (state.consecutive_failures < 5))
    {
        return Err(Error::InvariantViolation("ClosedMeansRecovered"));
    }

    // FailureThresholdOpens
    if !((!(state.consecutive_failures >= 5))
        || (ExecutorCircuitBreakerState::Closed != state.state))
    {
        return Err(Error::InvariantViolation("FailureThresholdOpens"));
    }

    // HalfOpenRequiresCooldown
    if !((!(ExecutorCircuitBreakerState::Halfopen == state.state))
        || (0 == state.cooldown_remaining))
    {
        return Err(Error::InvariantViolation("HalfOpenRequiresCooldown"));
    }

    Ok(())
}
