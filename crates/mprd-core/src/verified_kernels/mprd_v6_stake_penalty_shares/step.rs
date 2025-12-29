//! Step function for mprd_v6_stake_penalty_shares.
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
        Command::StakeEnd { penalty } => {
            if penalty < 0u64 || penalty > 6u64 {
                return Err(Error::ParamDomainViolation("penalty"));
            }
            let tmp_1 = ((penalty
                .checked_add(state.auction_carry)
                .ok_or(Error::Overflow)?)
            .checked_sub(std::cmp::min(
                5,
                penalty
                    .checked_add(state.auction_carry)
                    .ok_or(Error::Overflow)?,
            ))
            .ok_or(Error::Underflow)?)
            .checked_add(state.burned_total)
            .ok_or(Error::Overflow)?;
            let tmp_2 = (state
                .stake_amount
                .checked_sub(penalty)
                .ok_or(Error::Underflow)?)
            .checked_add(state.agrs_balance)
            .ok_or(Error::Overflow)?;

            let guard_ok = (tmp_1 <= 20)
                && (tmp_2 <= 12)
                && (penalty <= state.stake_amount)
                && state.stake_active;
            if !guard_ok {
                return Err(Error::PreconditionFailed("stake_end guard"));
            }

            let next = State {
                agrs_balance: ((state
                    .stake_amount
                    .checked_sub(penalty)
                    .ok_or(Error::Underflow)?)
                .checked_add(state.agrs_balance)
                .ok_or(Error::Overflow)?),
                auction_carry: std::cmp::min(
                    5,
                    penalty
                        .checked_add(state.auction_carry)
                        .ok_or(Error::Overflow)?,
                ),
                burned_total: (((penalty
                    .checked_add(state.auction_carry)
                    .ok_or(Error::Overflow)?)
                .checked_sub(std::cmp::min(
                    5,
                    penalty
                        .checked_add(state.auction_carry)
                        .ok_or(Error::Overflow)?,
                ))
                .ok_or(Error::Underflow)?)
                .checked_add(state.burned_total)
                .ok_or(Error::Overflow)?),
                shares_active: 0,
                stake_active: false,
                stake_amount: 0,
                stake_shares: 0,
                total_shares_issued: state.total_shares_issued.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::StakeStart { amount, shares } => {
            if amount < 1u64 || amount > 6u64 {
                return Err(Error::ParamDomainViolation("amount"));
            }
            if shares < 1u64 || shares > 6u64 {
                return Err(Error::ParamDomainViolation("shares"));
            }
            let post_total_shares_issued = shares
                .checked_add(state.total_shares_issued)
                .ok_or(Error::Overflow)?;

            let guard_ok = (post_total_shares_issued <= 20)
                && (false == state.stake_active)
                && (state.agrs_balance >= amount);
            if !guard_ok {
                return Err(Error::PreconditionFailed("stake_start guard"));
            }

            let next = State {
                agrs_balance: (state
                    .agrs_balance
                    .checked_sub(amount)
                    .ok_or(Error::Underflow)?),
                auction_carry: state.auction_carry.clone(),
                burned_total: state.burned_total.clone(),
                shares_active: shares,
                stake_active: true,
                stake_amount: amount,
                stake_shares: shares,
                total_shares_issued: (shares
                    .checked_add(state.total_shares_issued)
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
