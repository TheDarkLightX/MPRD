//! Invariant checker for policy_algebra_operators.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.eval_depth < 0u64 || state.eval_depth > 5u64 {
        return Err(Error::DomainViolation("eval_depth"));
    }
    if state.evaluations_count < 0u64 || state.evaluations_count > 100u64 {
        return Err(Error::DomainViolation("evaluations_count"));
    }

    // DepthBounded
    if !(state.eval_depth <= 5) {
        return Err(Error::InvariantViolation("DepthBounded"));
    }

    // EvaluationsBounded
    if !(state.evaluations_count <= 100) {
        return Err(Error::InvariantViolation("EvaluationsBounded"));
    }

    Ok(())
}
