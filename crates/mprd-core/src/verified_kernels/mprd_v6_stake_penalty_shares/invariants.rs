//! Invariant checker for mprd_v6_stake_penalty_shares.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.agrs_balance < 0u64 || state.agrs_balance > 12u64 {
        return Err(Error::DomainViolation("agrs_balance"));
    }
    if state.auction_carry < 0u64 || state.auction_carry > 5u64 {
        return Err(Error::DomainViolation("auction_carry"));
    }
    if state.burned_total < 0u64 || state.burned_total > 20u64 {
        return Err(Error::DomainViolation("burned_total"));
    }
    if state.shares_active < 0u64 || state.shares_active > 12u64 {
        return Err(Error::DomainViolation("shares_active"));
    }
    if state.stake_amount < 0u64 || state.stake_amount > 6u64 {
        return Err(Error::DomainViolation("stake_amount"));
    }
    if state.stake_shares < 0u64 || state.stake_shares > 6u64 {
        return Err(Error::DomainViolation("stake_shares"));
    }
    if state.total_shares_issued < 0u64 || state.total_shares_issued > 20u64 {
        return Err(Error::DomainViolation("total_shares_issued"));
    }

    // CarryCapped
    if !(state.auction_carry <= 5) {
        return Err(Error::InvariantViolation("CarryCapped"));
    }

    // SharesActiveLeIssuedTotal
    if !(state.shares_active <= state.total_shares_issued) {
        return Err(Error::InvariantViolation("SharesActiveLeIssuedTotal"));
    }

    // SharesActiveMatchesStake
    if !(if state.stake_active {
        (state.shares_active == state.stake_shares)
            && (state.stake_amount > 0)
            && (state.stake_shares > 0)
    } else {
        (0 == state.shares_active) && (0 == state.stake_amount) && (0 == state.stake_shares)
    }) {
        return Err(Error::InvariantViolation("SharesActiveMatchesStake"));
    }

    Ok(())
}
