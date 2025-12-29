//! Invariant checker for reserve_management.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.coverage_ratio_bps < 0u64 || state.coverage_ratio_bps > 10000u64 {
        return Err(Error::DomainViolation("coverage_ratio_bps"));
    }
    if state.reserve_balance < 0u64 || state.reserve_balance > 10000u64 {
        return Err(Error::DomainViolation("reserve_balance"));
    }

    // EmergencyImpliesLowCoverage
    if !((!(true == state.emergency_mode)) || (state.coverage_ratio_bps < 5000)) {
        return Err(Error::InvariantViolation("EmergencyImpliesLowCoverage"));
    }

    // ReserveNonNegative
    if !(state.reserve_balance >= 0) {
        return Err(Error::InvariantViolation("ReserveNonNegative"));
    }

    Ok(())
}
