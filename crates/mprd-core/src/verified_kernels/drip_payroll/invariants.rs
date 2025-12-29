//! Invariant checker for drip_payroll.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.epoch < 0u64 || state.epoch > 100u64 {
        return Err(Error::DomainViolation("epoch"));
    }
    if state.epoch_budget < 0u64 || state.epoch_budget > 1000u64 {
        return Err(Error::DomainViolation("epoch_budget"));
    }
    if state.recipients_paid < 0u64 || state.recipients_paid > 10u64 {
        return Err(Error::DomainViolation("recipients_paid"));
    }
    if state.total_payout < 0u64 || state.total_payout > 1000u64 {
        return Err(Error::DomainViolation("total_payout"));
    }

    // BudgetCap
    if !(state.total_payout <= state.epoch_budget) {
        return Err(Error::InvariantViolation("BudgetCap"));
    }

    // PaidImpliesRecipientsPaid
    if !((!(Phase::Paid == state.phase)) || (state.recipients_paid > 0)) {
        return Err(Error::InvariantViolation("PaidImpliesRecipientsPaid"));
    }

    // PendingImpliesZeroPayout
    if !((!(Phase::Pending == state.phase)) || (0 == state.total_payout)) {
        return Err(Error::InvariantViolation("PendingImpliesZeroPayout"));
    }

    // PendingImpliesZeroRecipients
    if !((!(Phase::Pending == state.phase)) || (0 == state.recipients_paid)) {
        return Err(Error::InvariantViolation("PendingImpliesZeroRecipients"));
    }

    // ZeroRecipientsImpliesZeroPayout
    if !((!(0 == state.recipients_paid)) || (0 == state.total_payout)) {
        return Err(Error::InvariantViolation("ZeroRecipientsImpliesZeroPayout"));
    }

    Ok(())
}
