//! Invariant checker for mprd_work_submission.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.dispute_filed < 0u64 || state.dispute_filed > 1u64 {
        return Err(Error::DomainViolation("dispute_filed"));
    }
    if state.proof_valid < 0u64 || state.proof_valid > 1u64 {
        return Err(Error::DomainViolation("proof_valid"));
    }
    if state.spec_satisfied < 0u64 || state.spec_satisfied > 1u64 {
        return Err(Error::DomainViolation("spec_satisfied"));
    }
    if state.work_hash < 0u64 || state.work_hash > 1000u64 {
        return Err(Error::DomainViolation("work_hash"));
    }

    // DisputedOnlyWhenInconclusive
    if !(((!(Phase::Disputed == state.phase)) || (VerifierResult::Inconclusive == state.verifier_result))) {
        return Err(Error::InvariantViolation("DisputedOnlyWhenInconclusive"));
    }

    // InvalidImpliesObjectiveFailure
    if !(((!(Phase::Invalid == state.phase)) || ((0 == state.proof_valid) || (0 == state.spec_satisfied)))) {
        return Err(Error::InvariantViolation("InvalidImpliesObjectiveFailure"));
    }

    // RewardedRequiresProofAndSpec
    if !(((!(Phase::Rewarded == state.phase)) || ((1 == state.proof_valid) && (1 == state.spec_satisfied)))) {
        return Err(Error::InvariantViolation("RewardedRequiresProofAndSpec"));
    }

    Ok(())
}
