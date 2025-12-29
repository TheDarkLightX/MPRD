//! Invariant checker for ui_mode_adaptive_gates.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {

    // I1_TrustlessRequiresAnchors
    if !(((!((Mode::Local != state.mode) && (!state.anchors_configured))) || (state.run_pipeline_disabled && state.trust_anchor_warning))) {
        return Err(Error::InvariantViolation("I1_TrustlessRequiresAnchors"));
    }

    // I2_LocalDisablesZK
    if !(((!(Mode::Local == state.mode)) || state.zk_actions_disabled)) {
        return Err(Error::InvariantViolation("I2_LocalDisablesZK"));
    }

    Ok(())
}
