//! Invariant checker for mprd_operator_mining_round.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.dispute_filed < 0u64 || state.dispute_filed > 1u64 {
        return Err(Error::DomainViolation("dispute_filed"));
    }
    if state.proof_valid < 0u64 || state.proof_valid > 1u64 {
        return Err(Error::DomainViolation("proof_valid"));
    }
    if state.rewards_paid < 0u64 || state.rewards_paid > 50u64 {
        return Err(Error::DomainViolation("rewards_paid"));
    }
    if state.round_reward < 0u64 || state.round_reward > 1000u64 {
        return Err(Error::DomainViolation("round_reward"));
    }
    if state.spec_satisfied < 0u64 || state.spec_satisfied > 1u64 {
        return Err(Error::DomainViolation("spec_satisfied"));
    }
    if state.submissions_count < 0u64 || state.submissions_count > 50u64 {
        return Err(Error::DomainViolation("submissions_count"));
    }
    if state.valid_count < 0u64 || state.valid_count > 50u64 {
        return Err(Error::DomainViolation("valid_count"));
    }
    if state.work_hash < 0u64 || state.work_hash > 1000u64 {
        return Err(Error::DomainViolation("work_hash"));
    }

    // Budget
    if !((state.rewards_paid.checked_mul(10).ok_or(Error::Overflow)?) <= state.round_reward) {
        return Err(Error::InvariantViolation("Budget"));
    }

    // DisputedOnlyWhenInconclusive
    if !((!(Phase::Disputed == state.phase))
        || (VerifierResult::Inconclusive == state.verifier_result))
    {
        return Err(Error::InvariantViolation("DisputedOnlyWhenInconclusive"));
    }

    // PaidImpliesAllPaid
    if !((!(Phase::Paid == state.phase)) || (state.rewards_paid == state.valid_count)) {
        return Err(Error::InvariantViolation("PaidImpliesAllPaid"));
    }

    // PaidLeqValid
    if !(state.rewards_paid <= state.valid_count) {
        return Err(Error::InvariantViolation("PaidLeqValid"));
    }

    // ValidLeqSubmissions
    if !(state.valid_count <= state.submissions_count) {
        return Err(Error::InvariantViolation("ValidLeqSubmissions"));
    }

    Ok(())
}
