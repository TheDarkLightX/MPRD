//! Invariant checker for nonce_manager_lifecycle.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.consumed_count < 0u64 || state.consumed_count > 1000u64 {
        return Err(Error::DomainViolation("consumed_count"));
    }
    if state.current_time < 0u64 || state.current_time > 10000u64 {
        return Err(Error::DomainViolation("current_time"));
    }
    if state.window_size < 1u64 || state.window_size > 100u64 {
        return Err(Error::DomainViolation("window_size"));
    }
    if state.window_start < 0u64 || state.window_start > 10000u64 {
        return Err(Error::DomainViolation("window_start"));
    }

    // ConsumedBounded
    if !((state.consumed_count <= 1000)) {
        return Err(Error::InvariantViolation("ConsumedBounded"));
    }

    // TimeNotBeforeWindow
    if !((state.current_time >= state.window_start)) {
        return Err(Error::InvariantViolation("TimeNotBeforeWindow"));
    }

    // WindowPositive
    if !((state.window_size >= 1)) {
        return Err(Error::InvariantViolation("WindowPositive"));
    }

    Ok(())
}
