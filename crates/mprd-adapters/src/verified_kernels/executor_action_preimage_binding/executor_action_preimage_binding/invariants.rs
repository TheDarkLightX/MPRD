//! Invariant checker for executor_action_preimage_binding.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    // ExecuteRequiresAllBindings
    if !(((!(ResultPhase::Executed == state.result)) || (state.action_hash_matches && state.limits_binding_ok && state.preimage_present && state.schema_valid))) {
        return Err(Error::InvariantViolation("ExecuteRequiresAllBindings"));
    }

    // RejectedImpliesBindingFailed
    if !(((!(ResultPhase::Rejected == state.result)) || (!(state.action_hash_matches && state.limits_binding_ok && state.preimage_present && state.schema_valid)))) {
        return Err(Error::InvariantViolation("RejectedImpliesBindingFailed"));
    }

    Ok(())
}
