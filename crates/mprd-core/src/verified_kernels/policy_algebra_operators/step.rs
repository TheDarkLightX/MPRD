//! Step function for policy_algebra_operators.
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
        Command::EvalAnd {
            left_result,
            right_result,
        } => {
            if !(state.evaluations_count < 100) {
                return Err(Error::PreconditionFailed("eval_and guard"));
            }

            let next = State {
                eval_depth: state.eval_depth.clone(),
                evaluations_count: (state
                    .evaluations_count
                    .checked_add(1)
                    .ok_or(Error::Overflow)?),
                last_result: (left_result && right_result),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::EvalNot { sub_result } => {
            if !(state.evaluations_count < 100) {
                return Err(Error::PreconditionFailed("eval_not guard"));
            }

            let next = State {
                eval_depth: state.eval_depth.clone(),
                evaluations_count: (state
                    .evaluations_count
                    .checked_add(1)
                    .ok_or(Error::Overflow)?),
                last_result: (!sub_result),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::EvalOr {
            left_result,
            right_result,
        } => {
            if !(state.evaluations_count < 100) {
                return Err(Error::PreconditionFailed("eval_or guard"));
            }

            let next = State {
                eval_depth: state.eval_depth.clone(),
                evaluations_count: (state
                    .evaluations_count
                    .checked_add(1)
                    .ok_or(Error::Overflow)?),
                last_result: (left_result || right_result),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::PopComposite => {
            if !(state.eval_depth > 0) {
                return Err(Error::PreconditionFailed("pop_composite guard"));
            }

            let next = State {
                eval_depth: (state.eval_depth.checked_sub(1).ok_or(Error::Underflow)?),
                evaluations_count: state.evaluations_count.clone(),
                last_result: state.last_result.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::PushComposite => {
            if !(state.eval_depth < 5) {
                return Err(Error::PreconditionFailed("push_composite guard"));
            }

            let next = State {
                eval_depth: (state.eval_depth.checked_add(1).ok_or(Error::Overflow)?),
                evaluations_count: state.evaluations_count.clone(),
                last_result: state.last_result.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::ResetSession => {
            if !(true) {
                return Err(Error::PreconditionFailed("reset_session guard"));
            }

            let next = State {
                eval_depth: 0,
                evaluations_count: 0,
                last_result: false,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
