//! Step function for selector_fail_closed_required_limits.
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
        Command::LimitsInvalid => {
            if !((ModelResult::Pending == state.result) && state.limits_present) {
                return Err(Error::PreconditionFailed("limits_invalid guard"));
            }

            let next = State {
                any_allowed: state.any_allowed.clone(),
                chosen_allowed: state.chosen_allowed.clone(),
                limits_present: state.limits_present.clone(),
                limits_valid: false,
                result: state.result.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::LimitsMissing => {
            if !(ModelResult::Pending == state.result) {
                return Err(Error::PreconditionFailed("limits_missing guard"));
            }

            let next = State {
                any_allowed: state.any_allowed.clone(),
                chosen_allowed: state.chosen_allowed.clone(),
                limits_present: false,
                limits_valid: state.limits_valid.clone(),
                result: state.result.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::NoneAllowed => {
            if !((ModelResult::Pending == state.result) && (!state.any_allowed)) {
                return Err(Error::PreconditionFailed("none_allowed guard"));
            }

            let next = State {
                any_allowed: state.any_allowed.clone(),
                chosen_allowed: false,
                limits_present: state.limits_present.clone(),
                limits_valid: state.limits_valid.clone(),
                result: ModelResult::Error,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::ReceiveAllowed => {
            if !(ModelResult::Pending == state.result) {
                return Err(Error::PreconditionFailed("receive_allowed guard"));
            }

            let next = State {
                any_allowed: true,
                chosen_allowed: state.chosen_allowed.clone(),
                limits_present: state.limits_present.clone(),
                limits_valid: state.limits_valid.clone(),
                result: state.result.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Select => {
            if !((ModelResult::Pending == state.result) && state.any_allowed) {
                return Err(Error::PreconditionFailed("select guard"));
            }

            let next = State {
                any_allowed: state.any_allowed.clone(),
                chosen_allowed: if (state.limits_present && state.limits_valid) {
                    true
                } else {
                    false
                },
                limits_present: state.limits_present.clone(),
                limits_valid: state.limits_valid.clone(),
                result: if (state.limits_present && state.limits_valid) {
                    ModelResult::Decision
                } else {
                    ModelResult::Error
                },
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
