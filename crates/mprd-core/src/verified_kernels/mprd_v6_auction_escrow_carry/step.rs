//! Step function for mprd_v6_auction_escrow_carry.
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
        Command::RevealBid1 { qty } => {
            if qty < 1u64 || qty > 4u64 {
                return Err(Error::ParamDomainViolation("qty"));
            }
            let post_bcr_escrow = qty.checked_add(state.bcr_escrow).ok_or(Error::Overflow)?;

            let guard_ok =
                (post_bcr_escrow <= 8) && (0 == state.bid1_qty) && (state.bcr_balance >= qty);
            if !guard_ok {
                return Err(Error::PreconditionFailed("reveal_bid1 guard"));
            }

            let next = State {
                auction_carry: state.auction_carry.clone(),
                bcr_balance: (state.bcr_balance.checked_sub(qty).ok_or(Error::Underflow)?),
                bcr_escrow: (qty.checked_add(state.bcr_escrow).ok_or(Error::Overflow)?),
                bid1_qty: qty,
                bid2_qty: state.bid2_qty.clone(),
                burned_total: state.burned_total.clone(),
                last_bcr_burned: state.last_bcr_burned.clone(),
                last_payout_total: state.last_payout_total.clone(),
                locked_total: state.locked_total.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::RevealBid2 { qty } => {
            if qty < 1u64 || qty > 4u64 {
                return Err(Error::ParamDomainViolation("qty"));
            }
            let post_bcr_escrow = qty.checked_add(state.bcr_escrow).ok_or(Error::Overflow)?;

            let guard_ok =
                (post_bcr_escrow <= 8) && (0 == state.bid2_qty) && (state.bcr_balance >= qty);
            if !guard_ok {
                return Err(Error::PreconditionFailed("reveal_bid2 guard"));
            }

            let next = State {
                auction_carry: state.auction_carry.clone(),
                bcr_balance: (state.bcr_balance.checked_sub(qty).ok_or(Error::Underflow)?),
                bcr_escrow: (qty.checked_add(state.bcr_escrow).ok_or(Error::Overflow)?),
                bid1_qty: state.bid1_qty.clone(),
                bid2_qty: qty,
                burned_total: state.burned_total.clone(),
                last_bcr_burned: state.last_bcr_burned.clone(),
                last_payout_total: state.last_payout_total.clone(),
                locked_total: state.locked_total.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Settle {
            auction_new,
            bcr_burned,
            payout_total,
        } => {
            if auction_new < 0u64 || auction_new > 6u64 {
                return Err(Error::ParamDomainViolation("auction_new"));
            }
            if bcr_burned < 0u64 || bcr_burned > 8u64 {
                return Err(Error::ParamDomainViolation("bcr_burned"));
            }
            if payout_total < 0u64 || payout_total > 12u64 {
                return Err(Error::ParamDomainViolation("payout_total"));
            }
            let tmp_1 = ((state
                .bid1_qty
                .checked_add(state.bid2_qty)
                .ok_or(Error::Overflow)?)
            .checked_sub(bcr_burned)
            .ok_or(Error::Underflow)?)
            .checked_add(state.bcr_balance)
            .ok_or(Error::Overflow)?;
            let tmp_2 = (((auction_new
                .checked_add(state.auction_carry)
                .ok_or(Error::Overflow)?)
            .checked_sub(payout_total)
            .ok_or(Error::Underflow)?)
            .checked_sub(std::cmp::min(
                3,
                (auction_new
                    .checked_add(state.auction_carry)
                    .ok_or(Error::Overflow)?)
                .checked_sub(payout_total)
                .ok_or(Error::Underflow)?,
            ))
            .ok_or(Error::Underflow)?)
            .checked_add(state.burned_total)
            .ok_or(Error::Overflow)?;
            let post_locked_total = payout_total
                .checked_add(state.locked_total)
                .ok_or(Error::Overflow)?;
            let tmp_3 = state
                .bid1_qty
                .checked_add(state.bid2_qty)
                .ok_or(Error::Overflow)?;
            let post_auction_carry = auction_new
                .checked_add(state.auction_carry)
                .ok_or(Error::Overflow)?;

            let guard_ok = (tmp_1 <= 8)
                && (tmp_2 <= 12)
                && (post_locked_total <= 12)
                && (bcr_burned <= tmp_3)
                && (payout_total <= post_auction_carry);
            if !guard_ok {
                return Err(Error::PreconditionFailed("settle guard"));
            }

            let next = State {
                auction_carry: std::cmp::min(
                    3,
                    (auction_new
                        .checked_add(state.auction_carry)
                        .ok_or(Error::Overflow)?)
                    .checked_sub(payout_total)
                    .ok_or(Error::Underflow)?,
                ),
                bcr_balance: (((state
                    .bid1_qty
                    .checked_add(state.bid2_qty)
                    .ok_or(Error::Overflow)?)
                .checked_sub(bcr_burned)
                .ok_or(Error::Underflow)?)
                .checked_add(state.bcr_balance)
                .ok_or(Error::Overflow)?),
                bcr_escrow: 0,
                bid1_qty: 0,
                bid2_qty: 0,
                burned_total: ((((auction_new
                    .checked_add(state.auction_carry)
                    .ok_or(Error::Overflow)?)
                .checked_sub(payout_total)
                .ok_or(Error::Underflow)?)
                .checked_sub(std::cmp::min(
                    3,
                    (auction_new
                        .checked_add(state.auction_carry)
                        .ok_or(Error::Overflow)?)
                    .checked_sub(payout_total)
                    .ok_or(Error::Underflow)?,
                ))
                .ok_or(Error::Underflow)?)
                .checked_add(state.burned_total)
                .ok_or(Error::Overflow)?),
                last_bcr_burned: bcr_burned,
                last_payout_total: payout_total,
                locked_total: (payout_total
                    .checked_add(state.locked_total)
                    .ok_or(Error::Overflow)?),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
