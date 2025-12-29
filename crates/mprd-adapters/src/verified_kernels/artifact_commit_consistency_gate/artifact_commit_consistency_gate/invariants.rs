//! Invariant checker for artifact_commit_consistency_gate.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    // AcceptRequiresCheckpoint
    if !(((!((ResultPhase::Accepted == state.result) && state.checkpoint_required)) || state.checkpoint_ok)) {
        return Err(Error::InvariantViolation("AcceptRequiresCheckpoint"));
    }

    // AcceptRequiresMST
    if !(((!(ResultPhase::Accepted == state.result)) || state.mst_consistency_ok)) {
        return Err(Error::InvariantViolation("AcceptRequiresMST"));
    }

    // AcceptRequiresSig
    if !(((!(ResultPhase::Accepted == state.result)) || state.commit_sig_ok)) {
        return Err(Error::InvariantViolation("AcceptRequiresSig"));
    }

    Ok(())
}
