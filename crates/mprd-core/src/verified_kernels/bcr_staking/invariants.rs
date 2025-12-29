//! Invariant checker for bcr_staking.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.bonded_amount < 0u64 || state.bonded_amount > 1000u64 {
        return Err(Error::DomainViolation("bonded_amount"));
    }

    // BondedAmountNonNegative
    if !(state.bonded_amount >= 0) {
        return Err(Error::InvariantViolation("BondedAmountNonNegative"));
    }

    // BondedImpliesPositive
    if !((!(Phase::Bonded == state.phase)) || (state.bonded_amount > 0)) {
        return Err(Error::InvariantViolation("BondedImpliesPositive"));
    }

    // IdleImpliesZero
    if !((!(Phase::Idle == state.phase)) || (0 == state.bonded_amount)) {
        return Err(Error::InvariantViolation("IdleImpliesZero"));
    }

    // IdleNoPendingSlash
    if !((!(Phase::Idle == state.phase)) || (false == state.pending_slash)) {
        return Err(Error::InvariantViolation("IdleNoPendingSlash"));
    }

    // PendingSlashImpliesPositive
    if !((!state.pending_slash) || (state.bonded_amount > 0)) {
        return Err(Error::InvariantViolation("PendingSlashImpliesPositive"));
    }

    // PendingSlashImpliesStakedPhase
    if !((!state.pending_slash)
        || ((Phase::Bonded == state.phase) || (Phase::Unbonding == state.phase)))
    {
        return Err(Error::InvariantViolation("PendingSlashImpliesStakedPhase"));
    }

    // SlashedImpliesZero
    if !((!(Phase::Slashed == state.phase)) || (0 == state.bonded_amount)) {
        return Err(Error::InvariantViolation("SlashedImpliesZero"));
    }

    // SlashedNoPendingSlash
    if !((!(Phase::Slashed == state.phase)) || (false == state.pending_slash)) {
        return Err(Error::InvariantViolation("SlashedNoPendingSlash"));
    }

    // UnbondingImpliesPositive
    if !((!(Phase::Unbonding == state.phase)) || (state.bonded_amount > 0)) {
        return Err(Error::InvariantViolation("UnbondingImpliesPositive"));
    }

    Ok(())
}
