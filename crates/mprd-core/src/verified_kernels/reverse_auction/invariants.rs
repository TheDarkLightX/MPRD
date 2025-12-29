//! Invariant checker for reverse_auction.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.best_bid < 0u64 || state.best_bid > 1000u64 {
        return Err(Error::DomainViolation("best_bid"));
    }
    if state.bid_count < 0u64 || state.bid_count > 10u64 {
        return Err(Error::DomainViolation("bid_count"));
    }

    // BidCountCap
    if !((state.bid_count <= 10)) {
        return Err(Error::InvariantViolation("BidCountCap"));
    }

    // NoBidsSentinelBestBid
    if !(((!(0 == state.bid_count)) || (1000 == state.best_bid))) {
        return Err(Error::InvariantViolation("NoBidsSentinelBestBid"));
    }

    // OpenImpliesNoWinner
    if !(((!(Phase::Open == state.phase)) || (false == state.winner_set))) {
        return Err(Error::InvariantViolation("OpenImpliesNoWinner"));
    }

    // SealedImpliesNoWinner
    if !(((!(Phase::Sealed == state.phase)) || (false == state.winner_set))) {
        return Err(Error::InvariantViolation("SealedImpliesNoWinner"));
    }

    // SettledImpliesWinnerSet
    if !(((!(Phase::Settled == state.phase)) || (true == state.winner_set))) {
        return Err(Error::InvariantViolation("SettledImpliesWinnerSet"));
    }

    // SettledRequiresBid
    if !(((!(Phase::Settled == state.phase)) || (state.bid_count > 0))) {
        return Err(Error::InvariantViolation("SettledRequiresBid"));
    }

    // WinnerSetImpliesSettled
    if !(((!state.winner_set) || (Phase::Settled == state.phase))) {
        return Err(Error::InvariantViolation("WinnerSetImpliesSettled"));
    }

    Ok(())
}
