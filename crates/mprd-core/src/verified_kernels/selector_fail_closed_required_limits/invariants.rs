//! Invariant checker for selector_fail_closed_required_limits.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {

    // DecisionRequiresAllowed
    if !(((!(ModelResult::Decision == state.result)) || state.chosen_allowed)) {
        return Err(Error::InvariantViolation("DecisionRequiresAllowed"));
    }

    // DecisionRequiresValidLimits
    if !(((!(ModelResult::Decision == state.result)) || (state.limits_present && state.limits_valid))) {
        return Err(Error::InvariantViolation("DecisionRequiresValidLimits"));
    }

    // ErrorImpliesNotChosen
    if !(((!(ModelResult::Error == state.result)) || (!state.chosen_allowed))) {
        return Err(Error::InvariantViolation("ErrorImpliesNotChosen"));
    }

    Ok(())
}
