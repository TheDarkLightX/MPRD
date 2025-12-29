//! Invariant checker for mprd_reward_pool.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.distributed_total < 0u64 || state.distributed_total > 1000u64 {
        return Err(Error::DomainViolation("distributed_total"));
    }
    if state.pool_balance < 0u64 || state.pool_balance > 1000u64 {
        return Err(Error::DomainViolation("pool_balance"));
    }
    if state.pool_balance_at_distribution_start < 0u64 || state.pool_balance_at_distribution_start > 1000u64 {
        return Err(Error::DomainViolation("pool_balance_at_distribution_start"));
    }
    if state.recipients_count < 0u64 || state.recipients_count > 20u64 {
        return Err(Error::DomainViolation("recipients_count"));
    }

    // ConservationBound
    if !((state.distributed_total <= state.pool_balance_at_distribution_start)) {
        return Err(Error::InvariantViolation("ConservationBound"));
    }

    // DistributingConservation
    if !(((!(Phase::Distributing == state.phase)) || ((state.distributed_total.checked_add(state.pool_balance).ok_or(Error::Overflow)?) == state.pool_balance_at_distribution_start))) {
        return Err(Error::InvariantViolation("DistributingConservation"));
    }

    // DistributingHasRecipients
    if !(((!(Phase::Distributing == state.phase)) || (state.recipients_count > 0))) {
        return Err(Error::InvariantViolation("DistributingHasRecipients"));
    }

    // EmptyImpliesZeroBalance
    if !(((!(Phase::Empty == state.phase)) || (0 == state.pool_balance))) {
        return Err(Error::InvariantViolation("EmptyImpliesZeroBalance"));
    }

    // NotDistributingResets
    if !(((!(Phase::Distributing != state.phase)) || ((0 == state.distributed_total) && (0 == state.pool_balance_at_distribution_start)))) {
        return Err(Error::InvariantViolation("NotDistributingResets"));
    }

    Ok(())
}
