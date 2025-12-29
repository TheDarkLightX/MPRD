//! Step function for selector_fail_closed_required_limits.
//! This is the CBC kernel chokepoint.

use super::{{types::*, state::State, command::Command, invariants::check_invariants}};

/// Effects produced by a transition (data, not side effects).
#[derive(Debug, Clone, Default)]
pub struct Effects {
    // TODO: Add effect fields as needed
}

/// Execute a transition: (state, command) -> Result<(new_state, effects), Error>
/// 
/// This is the single chokepoint for all state transitions.
/// Invariants are checked pre and post; preconditions in guards.
pub fn step(state: &State, cmd: Command) -> Result<(State, Effects), Error> {
    // Pre-check invariants
    check_invariants(state)?;
    
    // Dispatch to transition handler
    let (next, effects) = match cmd {
        Command::LimitsInvalid => {
            if !(((ResultPhase::Pending == state.result) && state.limits_present)) {
                return Err(Error::PreconditionFailed("limits_invalid guard"));
            }
            
            let next = State {
                any_allowed: state.any_allowed.clone(),
                chosen_allowed: state.chosen_allowed.clone(),
                limits_present: state.limits_present.clone(),
                limits_valid: false,
                result: state.result.clone(),
            };
            (next, Effects::default())
        }
        Command::LimitsMissing => {
            if !((ResultPhase::Pending == state.result)) {
                return Err(Error::PreconditionFailed("limits_missing guard"));
            }
            
            let next = State {
                any_allowed: state.any_allowed.clone(),
                chosen_allowed: state.chosen_allowed.clone(),
                limits_present: false,
                limits_valid: state.limits_valid.clone(),
                result: state.result.clone(),
            };
            (next, Effects::default())
        }
        Command::NoneAllowed => {
            if !(((ResultPhase::Pending == state.result) && (!state.any_allowed))) {
                return Err(Error::PreconditionFailed("none_allowed guard"));
            }
            
            let next = State {
                any_allowed: state.any_allowed.clone(),
                chosen_allowed: false,
                limits_present: state.limits_present.clone(),
                limits_valid: state.limits_valid.clone(),
                result: ResultPhase::Error,
            };
            (next, Effects::default())
        }
        Command::ReceiveAllowed => {
            if !((ResultPhase::Pending == state.result)) {
                return Err(Error::PreconditionFailed("receive_allowed guard"));
            }
            
            let next = State {
                any_allowed: true,
                chosen_allowed: state.chosen_allowed.clone(),
                limits_present: state.limits_present.clone(),
                limits_valid: state.limits_valid.clone(),
                result: state.result.clone(),
            };
            (next, Effects::default())
        }
        Command::Select => {
            if !(((ResultPhase::Pending == state.result) && state.any_allowed)) {
                return Err(Error::PreconditionFailed("select guard"));
            }
            
            let next = State {
                any_allowed: state.any_allowed.clone(),
                chosen_allowed: if (state.limits_present && state.limits_valid) { true } else { false },
                limits_present: state.limits_present.clone(),
                limits_valid: state.limits_valid.clone(),
                result: if (state.limits_present && state.limits_valid) { ResultPhase::Decision } else { ResultPhase::Error },
            };
            (next, Effects::default())
        }
    };
    
    // Post-check invariants
    check_invariants(&next)?;
    
    Ok((next, effects))
}
