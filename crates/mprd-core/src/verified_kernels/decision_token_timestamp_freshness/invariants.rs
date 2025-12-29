//! Invariant checker for decision_token_timestamp_freshness.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {

    // InvalidAgeRejects
    if !(((!(AgeClass::Ok != state.age_class)) || (!state.validation_ok))) {
        return Err(Error::InvariantViolation("InvalidAgeRejects"));
    }

    // ValidationRequiresOkAge
    if !(((!state.validation_ok) || (AgeClass::Ok == state.age_class))) {
        return Err(Error::InvariantViolation("ValidationRequiresOkAge"));
    }

    Ok(())
}
