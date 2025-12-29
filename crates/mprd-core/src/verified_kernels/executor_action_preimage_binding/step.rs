//! Step function for executor_action_preimage_binding.
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
        Command::Execute => {
            let guard_ok = ((ModelResult::Pending == state.result)
                && state.action_hash_matches
                && state.limits_binding_ok
                && state.preimage_present
                && state.schema_valid);
            if !guard_ok {
                return Err(Error::PreconditionFailed("execute guard"));
            }

            let next = State {
                action_hash_matches: state.action_hash_matches.clone(),
                limits_binding_ok: state.limits_binding_ok.clone(),
                preimage_present: state.preimage_present.clone(),
                result: ModelResult::Executed,
                schema_valid: state.schema_valid.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::HashMismatch => {
            if !(ModelResult::Pending == state.result) {
                return Err(Error::PreconditionFailed("hash_mismatch guard"));
            }

            let next = State {
                action_hash_matches: false,
                limits_binding_ok: state.limits_binding_ok.clone(),
                preimage_present: state.preimage_present.clone(),
                result: state.result.clone(),
                schema_valid: state.schema_valid.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::LimitsBindingFail => {
            if !(ModelResult::Pending == state.result) {
                return Err(Error::PreconditionFailed("limits_binding_fail guard"));
            }

            let next = State {
                action_hash_matches: state.action_hash_matches.clone(),
                limits_binding_ok: false,
                preimage_present: state.preimage_present.clone(),
                result: state.result.clone(),
                schema_valid: state.schema_valid.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::PreimageMissing => {
            if !(ModelResult::Pending == state.result) {
                return Err(Error::PreconditionFailed("preimage_missing guard"));
            }

            let next = State {
                action_hash_matches: state.action_hash_matches.clone(),
                limits_binding_ok: state.limits_binding_ok.clone(),
                preimage_present: false,
                result: state.result.clone(),
                schema_valid: state.schema_valid.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Reject => {
            let guard_ok = ((ModelResult::Pending == state.result)
                && (!(state.action_hash_matches
                    && state.limits_binding_ok
                    && state.preimage_present
                    && state.schema_valid)));
            if !guard_ok {
                return Err(Error::PreconditionFailed("reject guard"));
            }

            let next = State {
                action_hash_matches: state.action_hash_matches.clone(),
                limits_binding_ok: state.limits_binding_ok.clone(),
                preimage_present: state.preimage_present.clone(),
                result: ModelResult::Rejected,
                schema_valid: state.schema_valid.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::SchemaInvalid => {
            if !(ModelResult::Pending == state.result) {
                return Err(Error::PreconditionFailed("schema_invalid guard"));
            }

            let next = State {
                action_hash_matches: state.action_hash_matches.clone(),
                limits_binding_ok: state.limits_binding_ok.clone(),
                preimage_present: state.preimage_present.clone(),
                result: state.result.clone(),
                schema_valid: false,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
