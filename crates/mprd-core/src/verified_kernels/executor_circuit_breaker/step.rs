//! Step function for executor_circuit_breaker.
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
        Command::ManualReset => {
            if !(true) {
                return Err(Error::PreconditionFailed("manual_reset guard"));
            }

            let next = State {
                consecutive_failures: 0,
                consecutive_successes: 0,
                cooldown_remaining: 0,
                state: ExecutorCircuitBreakerState::Closed,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::RecordFailure => {
            if !(ExecutorCircuitBreakerState::Open != state.state) {
                return Err(Error::PreconditionFailed("record_failure guard"));
            }

            let next = State {
                consecutive_failures: std::cmp::min(
                    10,
                    (state
                        .consecutive_failures
                        .checked_add(1)
                        .ok_or(Error::Overflow)?),
                ),
                consecutive_successes: 0,
                cooldown_remaining: if ((state
                    .consecutive_failures
                    .checked_add(1)
                    .ok_or(Error::Overflow)?)
                    >= 5)
                {
                    30
                } else {
                    state.cooldown_remaining
                },
                state: if ((state
                    .consecutive_failures
                    .checked_add(1)
                    .ok_or(Error::Overflow)?)
                    >= 5)
                {
                    ExecutorCircuitBreakerState::Open
                } else {
                    state.state
                },
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::RecordSuccess => {
            if !(ExecutorCircuitBreakerState::Open != state.state) {
                return Err(Error::PreconditionFailed("record_success guard"));
            }

            let next = State {
                consecutive_failures: 0,
                consecutive_successes: std::cmp::min(
                    5,
                    (state
                        .consecutive_successes
                        .checked_add(1)
                        .ok_or(Error::Overflow)?),
                ),
                cooldown_remaining: state.cooldown_remaining.clone(),
                state: if ((ExecutorCircuitBreakerState::Halfopen == state.state)
                    && ((state
                        .consecutive_successes
                        .checked_add(1)
                        .ok_or(Error::Overflow)?)
                        >= 3))
                {
                    ExecutorCircuitBreakerState::Closed
                } else {
                    state.state
                },
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Tick => {
            if !(state.cooldown_remaining > 0) {
                return Err(Error::PreconditionFailed("tick guard"));
            }

            let next = State {
                consecutive_failures: state.consecutive_failures.clone(),
                consecutive_successes: state.consecutive_successes.clone(),
                cooldown_remaining: (state
                    .cooldown_remaining
                    .checked_sub(1)
                    .ok_or(Error::Underflow)?),
                state: state.state.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::TryHalfOpen => {
            if !((0 == state.cooldown_remaining)
                && (ExecutorCircuitBreakerState::Open == state.state))
            {
                return Err(Error::PreconditionFailed("try_half_open guard"));
            }

            let next = State {
                consecutive_failures: state.consecutive_failures.clone(),
                consecutive_successes: 0,
                cooldown_remaining: state.cooldown_remaining.clone(),
                state: ExecutorCircuitBreakerState::Halfopen,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
