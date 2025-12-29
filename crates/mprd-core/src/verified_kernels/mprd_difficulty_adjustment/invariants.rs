//! Invariant checker for mprd_difficulty_adjustment.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.adjustment_factor < 0u64 || state.adjustment_factor > 200u64 {
        return Err(Error::DomainViolation("adjustment_factor"));
    }
    if state.blocks_in_window < 0u64 || state.blocks_in_window > 100u64 {
        return Err(Error::DomainViolation("blocks_in_window"));
    }
    if state.difficulty_level < 1u64 || state.difficulty_level > 100u64 {
        return Err(Error::DomainViolation("difficulty_level"));
    }
    if state.target_rate < 10u64 || state.target_rate > 10u64 {
        return Err(Error::DomainViolation("target_rate"));
    }

    // AdjustmentFactorCap
    if !((state.adjustment_factor <= 200)) {
        return Err(Error::InvariantViolation("AdjustmentFactorCap"));
    }

    // MinDifficulty
    if !((state.difficulty_level >= 1)) {
        return Err(Error::InvariantViolation("MinDifficulty"));
    }

    Ok(())
}
