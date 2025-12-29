//! Invariant checker for mprd_emission_schedule.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.emission_rate < 100u64 || state.emission_rate > 1000u64 {
        return Err(Error::DomainViolation("emission_rate"));
    }
    if state.epoch < 0u64 || state.epoch > 100u64 {
        return Err(Error::DomainViolation("epoch"));
    }
    if state.epoch_budget < 0u64 || state.epoch_budget > 1000u64 {
        return Err(Error::DomainViolation("epoch_budget"));
    }
    if state.halving_period < 10u64 || state.halving_period > 10u64 {
        return Err(Error::DomainViolation("halving_period"));
    }
    if state.total_emitted < 0u64 || state.total_emitted > 10000u64 {
        return Err(Error::DomainViolation("total_emitted"));
    }

    // HalvingSchedule
    if !(if state.epoch < state.halving_period {
        1000
    } else {
        if state.epoch < (state.halving_period.checked_mul(2).ok_or(Error::Overflow)?) {
            500
        } else {
            if state.epoch < (state.halving_period.checked_mul(3).ok_or(Error::Overflow)?) {
                250
            } else {
                if state.epoch < (state.halving_period.checked_mul(4).ok_or(Error::Overflow)?) {
                    125
                } else {
                    100
                }
            }
        }
    } == state.emission_rate)
    {
        return Err(Error::InvariantViolation("HalvingSchedule"));
    }

    // MaxSupplyCap
    if !(state.total_emitted <= 10000) {
        return Err(Error::InvariantViolation("MaxSupplyCap"));
    }

    // PerEpochCap
    if !(state.epoch_budget <= state.emission_rate) {
        return Err(Error::InvariantViolation("PerEpochCap"));
    }

    Ok(())
}
