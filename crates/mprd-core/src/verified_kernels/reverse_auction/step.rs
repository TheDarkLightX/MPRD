//! Step function for reverse_auction.
//! This is the CBC kernel chokepoint.

use super::{command::Command, invariants::check_invariants, state::State, types::*};

/// Effects produced by a transition (data, not side effects).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Effects {
    // (no observable effects)
}

/// Execute a transition: (state, command) -> Result<(new_state, effects), Error>
///
/// This is the single chokepoint for all state transitions.
/// Invariants are checked pre and post; preconditions in guards.
pub fn step(state: &State, cmd: Command) -> Result<(State, Effects), Error> {
    // Pre-check invariants (includes domain checks).
    check_invariants(state)?;

    // Dispatch to transition handler.
    let (post, effects) = match cmd {
        Command::PlaceBid { amt } => {
            if amt < 0u64 || amt > 1000u64 {
                return Err(Error::ParamDomainViolation("amt"));
            }
            if !((state.bid_count < 10) && (Phase::Open == state.phase)) {
                return Err(Error::PreconditionFailed("place_bid guard"));
            }

            let next = State {
                best_bid: std::cmp::min(amt, state.best_bid),
                bid_count: (state.bid_count.checked_add(1).ok_or(Error::Overflow)?),
                phase: state.phase.clone(),
                winner_set: state.winner_set.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Seal => {
            if !((Phase::Open == state.phase) && (state.bid_count > 0)) {
                return Err(Error::PreconditionFailed("seal guard"));
            }

            let next = State {
                best_bid: state.best_bid.clone(),
                bid_count: state.bid_count.clone(),
                phase: Phase::Sealed,
                winner_set: state.winner_set.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Settle => {
            if !((Phase::Sealed == state.phase) && (state.bid_count > 0)) {
                return Err(Error::PreconditionFailed("settle guard"));
            }

            let next = State {
                best_bid: state.best_bid.clone(),
                bid_count: state.bid_count.clone(),
                phase: Phase::Settled,
                winner_set: true,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
