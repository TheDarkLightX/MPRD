//! Invariant checker for ui_trust_anchor_fingerprints_only.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    // BlockedLeakDoesNotLeak
    if !((!(DisplayState::Attemptedrawleak == state.display_state)) || (!state.leaks_raw)) {
        return Err(Error::InvariantViolation("BlockedLeakDoesNotLeak"));
    }

    // FingerprintRequiresKey
    if !((!(DisplayState::Showingfingerprint == state.display_state)) || state.key_loaded) {
        return Err(Error::InvariantViolation("FingerprintRequiresKey"));
    }

    // I1_NeverLeakRaw
    if !(!state.leaks_raw) {
        return Err(Error::InvariantViolation("I1_NeverLeakRaw"));
    }

    Ok(())
}
