//! Invariant checker for mprd_proof_market_slot.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.deadline < 0u64 || state.deadline > 10u64 {
        return Err(Error::DomainViolation("deadline"));
    }
    if state.deadline0 < 0u64 || state.deadline0 > 10u64 {
        return Err(Error::DomainViolation("deadline0"));
    }
    if state.deposit < 0u64 || state.deposit > 5u64 {
        return Err(Error::DomainViolation("deposit"));
    }
    if state.now < 0u64 || state.now > 10u64 {
        return Err(Error::DomainViolation("now"));
    }
    if state.payout < 0u64 || state.payout > 5u64 {
        return Err(Error::DomainViolation("payout"));
    }
    if state.protocol_subsidy < 0u64 || state.protocol_subsidy > 5u64 {
        return Err(Error::DomainViolation("protocol_subsidy"));
    }
    if state.total_deposits < 0u64 || state.total_deposits > 10u64 {
        return Err(Error::DomainViolation("total_deposits"));
    }
    if state.total_payouts < 0u64 || state.total_payouts > 10u64 {
        return Err(Error::DomainViolation("total_payouts"));
    }

    // I1_NoDoubleClaim
    if !(state.claimer == state.claimer0) {
        return Err(Error::InvariantViolation("I1_NoDoubleClaim"));
    }

    // I2_BudgetConservation
    if !(state.total_payouts
        <= (state
            .protocol_subsidy
            .checked_add(state.total_deposits)
            .ok_or(Error::Overflow)?))
    {
        return Err(Error::InvariantViolation("I2_BudgetConservation"));
    }

    // I3_DeadlineMonotonicity
    if !(state.deadline0 <= state.deadline) {
        return Err(Error::InvariantViolation("I3_DeadlineMonotonicity"));
    }

    // I4_ObjectiveSlashing
    if !((!(Phase::Slashed == state.phase))
        || ((state.deadline < state.now) && (false == state.proof_verified)))
    {
        return Err(Error::InvariantViolation("I4_ObjectiveSlashing"));
    }

    // I5_NoOverpayout
    if !((!(Phase::Settled == state.phase)) || (state.payout <= state.deposit)) {
        return Err(Error::InvariantViolation("I5_NoOverpayout"));
    }

    // I6_PayToClaimer
    if !((!(Phase::Settled == state.phase))
        || ((0 == state.payout) || (state.claimer0 == state.payee)))
    {
        return Err(Error::InvariantViolation("I6_PayToClaimer"));
    }

    // I7_SoundnessBinding
    if !((!(Phase::Settled == state.phase))
        || (state.job_hash_present && state.proof_binds_job && state.proof_verified))
    {
        return Err(Error::InvariantViolation("I7_SoundnessBinding"));
    }

    Ok(())
}
