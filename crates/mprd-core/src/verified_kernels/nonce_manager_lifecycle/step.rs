//! Step function for nonce_manager_lifecycle.
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
        Command::AdvanceWindow => {
            if !((state
                .current_time
                .checked_sub(state.window_start)
                .ok_or(Error::Underflow)?)
                >= state.window_size)
            {
                return Err(Error::PreconditionFailed("advance_window guard"));
            }

            let next = State {
                consumed_count: 0,
                current_time: state.current_time.clone(),
                window_size: state.window_size.clone(),
                window_start: (state
                    .window_size
                    .checked_add(state.window_start)
                    .ok_or(Error::Overflow)?),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::ConsumeNonce { nonce_time } => {
            if nonce_time < 0u64 || nonce_time > 10000u64 {
                return Err(Error::ParamDomainViolation("nonce_time"));
            }
            let guard_ok = ((state.consumed_count < 1000)
                && (nonce_time <= state.current_time)
                && (nonce_time >= state.window_start));
            if !guard_ok {
                return Err(Error::PreconditionFailed("consume_nonce guard"));
            }

            let next = State {
                consumed_count: (state.consumed_count.checked_add(1).ok_or(Error::Overflow)?),
                current_time: state.current_time.clone(),
                window_size: state.window_size.clone(),
                window_start: state.window_start.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::SetWindowSize { new_size } => {
            if new_size < 1u64 || new_size > 100u64 {
                return Err(Error::ParamDomainViolation("new_size"));
            }
            if !(new_size >= 1) {
                return Err(Error::PreconditionFailed("set_window_size guard"));
            }

            let next = State {
                consumed_count: state.consumed_count.clone(),
                current_time: state.current_time.clone(),
                window_size: new_size,
                window_start: state.window_start.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::TickTime { new_time } => {
            if new_time < 0u64 || new_time > 10000u64 {
                return Err(Error::ParamDomainViolation("new_time"));
            }
            if !(new_time > state.current_time) {
                return Err(Error::PreconditionFailed("tick_time guard"));
            }

            let next = State {
                consumed_count: state.consumed_count.clone(),
                current_time: new_time,
                window_size: state.window_size.clone(),
                window_start: state.window_start.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
