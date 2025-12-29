//! Invariant checker for mprd_v6_auction_escrow_carry.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.auction_carry < 0u64 || state.auction_carry > 3u64 {
        return Err(Error::DomainViolation("auction_carry"));
    }
    if state.bcr_balance < 0u64 || state.bcr_balance > 8u64 {
        return Err(Error::DomainViolation("bcr_balance"));
    }
    if state.bcr_escrow < 0u64 || state.bcr_escrow > 8u64 {
        return Err(Error::DomainViolation("bcr_escrow"));
    }
    if state.bid1_qty < 0u64 || state.bid1_qty > 4u64 {
        return Err(Error::DomainViolation("bid1_qty"));
    }
    if state.bid2_qty < 0u64 || state.bid2_qty > 4u64 {
        return Err(Error::DomainViolation("bid2_qty"));
    }
    if state.burned_total < 0u64 || state.burned_total > 12u64 {
        return Err(Error::DomainViolation("burned_total"));
    }
    if state.last_bcr_burned < 0u64 || state.last_bcr_burned > 8u64 {
        return Err(Error::DomainViolation("last_bcr_burned"));
    }
    if state.last_payout_total < 0u64 || state.last_payout_total > 12u64 {
        return Err(Error::DomainViolation("last_payout_total"));
    }
    if state.locked_total < 0u64 || state.locked_total > 12u64 {
        return Err(Error::DomainViolation("locked_total"));
    }

    // CarryCapped
    if !((state.auction_carry <= 3)) {
        return Err(Error::InvariantViolation("CarryCapped"));
    }

    // EscrowMatchesBids
    if !(((state.bid1_qty.checked_add(state.bid2_qty).ok_or(Error::Overflow)?) == state.bcr_escrow)) {
        return Err(Error::InvariantViolation("EscrowMatchesBids"));
    }

    Ok(())
}
