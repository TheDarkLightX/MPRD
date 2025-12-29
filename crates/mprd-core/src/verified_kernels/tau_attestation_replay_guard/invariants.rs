//! Invariant checker for tau_attestation_replay_guard.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    // AcceptRequiresNewerEpoch
    if !((!(ModelResult::Accepted == state.result)) || state.epoch_newer) {
        return Err(Error::InvariantViolation("AcceptRequiresNewerEpoch"));
    }

    // AcceptRequiresValidChain
    if !((!(ModelResult::Accepted == state.result)) || state.hash_chain_valid) {
        return Err(Error::InvariantViolation("AcceptRequiresValidChain"));
    }

    // RejectedImpliesInvalid
    if !((!(ModelResult::Rejected == state.result))
        || (!(state.epoch_newer && state.hash_chain_valid)))
    {
        return Err(Error::InvariantViolation("RejectedImpliesInvalid"));
    }

    Ok(())
}
