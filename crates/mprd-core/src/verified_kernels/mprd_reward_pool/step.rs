//! Step function for mprd_reward_pool.
//! This is the CBC kernel chokepoint.

use super::{{types::*, state::State, command::Command, invariants::check_invariants}};

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
        Command::AddToPool { amt } => {
            if amt < 1u64 || amt > 1000u64 {
                return Err(Error::ParamDomainViolation("amt"));
            }
            let post_pool_balance = amt.checked_add(state.pool_balance).ok_or(Error::Overflow)?;

            let guard_ok = (Phase::Distributing != state.phase) && (post_pool_balance <= 1000);
            if !guard_ok {
                return Err(Error::PreconditionFailed("add_to_pool guard"));
            }
            
            let next = State {
                distributed_total: 0,
                phase: if Phase::Empty == state.phase { Phase::Accumulating } else { state.phase },
                pool_balance: (amt.checked_add(state.pool_balance).ok_or(Error::Overflow)?),
                pool_balance_at_distribution_start: 0,
                recipients_count: std::cmp::min(20, state.recipients_count.checked_add(1).ok_or(Error::Overflow)?),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Finalize => {
            if !(((0 == state.pool_balance) && (Phase::Distributing == state.phase))) {
                return Err(Error::PreconditionFailed("finalize guard"));
            }
            
            let next = State {
                distributed_total: 0,
                phase: Phase::Empty,
                pool_balance: 0,
                pool_balance_at_distribution_start: 0,
                recipients_count: 0,
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::PayRecipient { amt } => {
            if amt < 1u64 || amt > 1000u64 {
                return Err(Error::ParamDomainViolation("amt"));
            }
            let post_distributed_total = amt.checked_add(state.distributed_total).ok_or(Error::Overflow)?;

            let guard_ok = (post_distributed_total <= state.pool_balance_at_distribution_start) && (amt <= state.pool_balance) && (Phase::Distributing == state.phase) && (state.recipients_count > 0) && ((state.recipients_count > 1) || ((1 == state.recipients_count) && (amt == state.pool_balance)));
            if !guard_ok {
                return Err(Error::PreconditionFailed("pay_recipient guard"));
            }
            
            let next = State {
                distributed_total: if 1 == state.recipients_count { 0 } else { amt.checked_add(state.distributed_total).ok_or(Error::Overflow)? },
                phase: if 1 == state.recipients_count { Phase::Empty } else { Phase::Distributing },
                pool_balance: if 1 == state.recipients_count { 0 } else { state.pool_balance.checked_sub(amt).ok_or(Error::Underflow)? },
                pool_balance_at_distribution_start: if 1 == state.recipients_count { 0 } else { state.pool_balance_at_distribution_start },
                recipients_count: if 1 == state.recipients_count { 0 } else { state.recipients_count.checked_sub(1).ok_or(Error::Underflow)? },
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::StartDistribution => {
            let guard_ok = (Phase::Accumulating == state.phase) && (state.pool_balance > 0) && (state.recipients_count > 0);
            if !guard_ok {
                return Err(Error::PreconditionFailed("start_distribution guard"));
            }
            
            let next = State {
                distributed_total: 0,
                phase: Phase::Distributing,
                pool_balance: state.pool_balance.clone(),
                pool_balance_at_distribution_start: state.pool_balance,
                recipients_count: state.recipients_count.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
