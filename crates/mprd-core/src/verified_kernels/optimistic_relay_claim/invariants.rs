//! Invariant checker for optimistic_relay_claim.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.round_count < 0u64 || state.round_count > 4u64 {
        return Err(Error::DomainViolation("round_count"));
    }

    // RoundBound
    if !(state.round_count <= 3) {
        return Err(Error::InvariantViolation("RoundBound"));
    }

    // Soundness
    if !(((!(Phase::Challenged == state.phase)) || (false == state.has_verdict))
        && ((!(Phase::Pending == state.phase)) || (false == state.has_verdict))
        && ((!(Phase::Resolved == state.phase)) || (true == state.has_verdict))
        && ((!(Phase::Slashed == state.phase)) || (true == state.has_verdict)))
    {
        return Err(Error::InvariantViolation("Soundness"));
    }

    Ok(())
}
