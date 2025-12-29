//! Invariant checker for policy_registry_gate.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.current_epoch < 0u64 || state.current_epoch > 1000u64 {
        return Err(Error::DomainViolation("current_epoch"));
    }
    if state.last_update_height < 0u64 || state.last_update_height > 10000u64 {
        return Err(Error::DomainViolation("last_update_height"));
    }
    if state.policy_count < 0u64 || state.policy_count > 100u64 {
        return Err(Error::DomainViolation("policy_count"));
    }

    // EpochNonNegative
    if !(state.current_epoch >= 0) {
        return Err(Error::InvariantViolation("EpochNonNegative"));
    }

    // PolicyCountBounded
    if !(state.policy_count <= 100) {
        return Err(Error::InvariantViolation("PolicyCountBounded"));
    }

    Ok(())
}
