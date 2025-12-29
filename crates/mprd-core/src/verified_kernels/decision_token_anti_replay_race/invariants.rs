//! Invariant checker for decision_token_anti_replay_race.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.successes < 0u64 || state.successes > 2u64 {
        return Err(Error::DomainViolation("successes"));
    }

    // AExecutedImpliesSuccess
    if !(((!(PhaseA::Executeda == state.phase_a)) || (1 == state.successes))) {
        return Err(Error::InvariantViolation("AExecutedImpliesSuccess"));
    }

    // BExecutedImpliesSuccess
    if !(((!(PhaseB::Executedb == state.phase_b)) || (1 == state.successes))) {
        return Err(Error::InvariantViolation("BExecutedImpliesSuccess"));
    }

    // MutualExclusionOnExecuted
    if !((!((PhaseA::Executeda == state.phase_a) && (PhaseB::Executedb == state.phase_b)))) {
        return Err(Error::InvariantViolation("MutualExclusionOnExecuted"));
    }

    // S4_AtMostOneSuccess
    if !((state.successes <= 1)) {
        return Err(Error::InvariantViolation("S4_AtMostOneSuccess"));
    }

    Ok(())
}
