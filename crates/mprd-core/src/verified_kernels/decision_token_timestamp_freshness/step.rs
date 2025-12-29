//! Step function for decision_token_timestamp_freshness.
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
        Command::Reject => {
            if !((AgeClass::Ok != state.age_class)) {
                return Err(Error::PreconditionFailed("reject guard"));
            }
            
            let next = State {
                age_class: state.age_class.clone(),
                validation_ok: false,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::TokenExpires => {
            if !((AgeClass::Ok == state.age_class)) {
                return Err(Error::PreconditionFailed("token_expires guard"));
            }
            
            let next = State {
                age_class: AgeClass::Expired,
                validation_ok: false,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::TokenFuture => {
            if !((AgeClass::Ok == state.age_class)) {
                return Err(Error::PreconditionFailed("token_future guard"));
            }
            
            let next = State {
                age_class: AgeClass::Future,
                validation_ok: false,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::ValidateFresh => {
            if !(((AgeClass::Ok == state.age_class) && (!state.validation_ok))) {
                return Err(Error::PreconditionFailed("validate_fresh guard"));
            }
            
            let next = State {
                age_class: state.age_class.clone(),
                validation_ok: true,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
