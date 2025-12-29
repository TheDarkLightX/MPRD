//! Invariant checker for tokenomics_ceo_menu.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.auction_units < 5u64 || state.auction_units > 50u64 {
        return Err(Error::DomainViolation("auction_units"));
    }
    if state.burn_units < 0u64 || state.burn_units > 45u64 {
        return Err(Error::DomainViolation("burn_units"));
    }
    if state.drip_units < 1u64 || state.drip_units > 20u64 {
        return Err(Error::DomainViolation("drip_units"));
    }

    // SplitCap
    if !((state
        .auction_units
        .checked_add(state.burn_units)
        .ok_or(Error::Overflow)?)
        <= 50)
    {
        return Err(Error::InvariantViolation("SplitCap"));
    }

    Ok(())
}
