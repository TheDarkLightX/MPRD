//! Invariant checker for opi_oracle_round.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.commit_count < 0u64 || state.commit_count > 4u64 {
        return Err(Error::DomainViolation("commit_count"));
    }
    if state.reveal_count < 0u64 || state.reveal_count > 4u64 {
        return Err(Error::DomainViolation("reveal_count"));
    }

    // CommitBeforeReveal
    if !(state.reveal_count <= state.commit_count) {
        return Err(Error::InvariantViolation("CommitBeforeReveal"));
    }

    // FinalizedFrozen
    if !((!(Phase::Finalized == state.phase)) || (true == state.has_aggregate)) {
        return Err(Error::InvariantViolation("FinalizedFrozen"));
    }

    Ok(())
}
