//! Invariant checker for fee_distribution.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.burned < 0u64 || state.burned > 500u64 {
        return Err(Error::DomainViolation("burned"));
    }
    if state.collected < 0u64 || state.collected > 1000u64 {
        return Err(Error::DomainViolation("collected"));
    }
    if state.distributed < 0u64 || state.distributed > 1000u64 {
        return Err(Error::DomainViolation("distributed"));
    }

    // CollectingNoSpend
    if !((!(Phase::Collecting == state.phase)) || ((0 == state.burned) && (0 == state.distributed)))
    {
        return Err(Error::InvariantViolation("CollectingNoSpend"));
    }

    // CompleteExact
    if !((!(Phase::Complete == state.phase))
        || ((state
            .burned
            .checked_add(state.distributed)
            .ok_or(Error::Overflow)?)
            == state.collected))
    {
        return Err(Error::InvariantViolation("CompleteExact"));
    }

    // Conservation
    if !((state
        .burned
        .checked_add(state.distributed)
        .ok_or(Error::Overflow)?)
        <= state.collected)
    {
        return Err(Error::InvariantViolation("Conservation"));
    }

    Ok(())
}
