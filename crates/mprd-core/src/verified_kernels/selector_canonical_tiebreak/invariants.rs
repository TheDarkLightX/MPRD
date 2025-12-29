//! Invariant checker for selector_canonical_tiebreak.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {

    // ChosenRequiresAllowed
    if !(((!(Chosen::None != state.chosen)) || state.both_allowed)) {
        return Err(Error::InvariantViolation("ChosenRequiresAllowed"));
    }

    // TieCanonicalA
    if !(((!((Chosen::None != state.chosen) && state.both_allowed && state.canonical_a_lt_b && state.score_tie)) || (Chosen::A == state.chosen))) {
        return Err(Error::InvariantViolation("TieCanonicalA"));
    }

    // TieCanonicalB
    if !(((!((Chosen::None != state.chosen) && (!state.canonical_a_lt_b) && state.both_allowed && state.score_tie)) || (Chosen::B == state.chosen))) {
        return Err(Error::InvariantViolation("TieCanonicalB"));
    }

    Ok(())
}
