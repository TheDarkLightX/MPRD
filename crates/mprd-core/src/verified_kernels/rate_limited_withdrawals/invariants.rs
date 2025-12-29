//! Invariant checker for rate_limited_withdrawals.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.available_balance < 0u64 || state.available_balance > 1000u64 {
        return Err(Error::DomainViolation("available_balance"));
    }
    if state.epoch_limit < 10u64 || state.epoch_limit > 100u64 {
        return Err(Error::DomainViolation("epoch_limit"));
    }
    if state.epoch_withdrawn < 0u64 || state.epoch_withdrawn > 100u64 {
        return Err(Error::DomainViolation("epoch_withdrawn"));
    }
    if state.hours_since_halt < 0u64 || state.hours_since_halt > 48u64 {
        return Err(Error::DomainViolation("hours_since_halt"));
    }

    // EmergencyHaltCooldown
    if !(((!(Phase::Active == state.phase)) || (state.hours_since_halt < 24))) {
        return Err(Error::InvariantViolation("EmergencyHaltCooldown"));
    }

    // EpochWithdrawalCap
    if !((state.epoch_withdrawn <= state.epoch_limit)) {
        return Err(Error::InvariantViolation("EpochWithdrawalCap"));
    }

    // SolvencyInvariant
    if !((state.available_balance >= 0)) {
        return Err(Error::InvariantViolation("SolvencyInvariant"));
    }

    Ok(())
}
