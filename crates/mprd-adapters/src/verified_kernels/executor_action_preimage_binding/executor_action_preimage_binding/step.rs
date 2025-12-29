//! Step function for executor_action_preimage_binding.
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
        Command::Execute => {
            if !(((ResultPhase::Pending == state.result) && state.action_hash_matches && state.limits_binding_ok && state.preimage_present && state.schema_valid)) {
                return Err(Error::PreconditionFailed("execute guard"));
            }
            
            let next = State {
                action_hash_matches: state.action_hash_matches.clone(),
                limits_binding_ok: state.limits_binding_ok.clone(),
                preimage_present: state.preimage_present.clone(),
                result: ResultPhase::Executed,
                schema_valid: state.schema_valid.clone(),
            };
            (next, Effects::default())
        }
        Command::HashMismatch => {
            if !((ResultPhase::Pending == state.result)) {
                return Err(Error::PreconditionFailed("hash_mismatch guard"));
            }
            
            let next = State {
                action_hash_matches: false,
                limits_binding_ok: state.limits_binding_ok.clone(),
                preimage_present: state.preimage_present.clone(),
                result: state.result.clone(),
                schema_valid: state.schema_valid.clone(),
            };
            (next, Effects::default())
        }
        Command::LimitsBindingFail => {
            if !((ResultPhase::Pending == state.result)) {
                return Err(Error::PreconditionFailed("limits_binding_fail guard"));
            }
            
            let next = State {
                action_hash_matches: state.action_hash_matches.clone(),
                limits_binding_ok: false,
                preimage_present: state.preimage_present.clone(),
                result: state.result.clone(),
                schema_valid: state.schema_valid.clone(),
            };
            (next, Effects::default())
        }
        Command::PreimageMissing => {
            if !((ResultPhase::Pending == state.result)) {
                return Err(Error::PreconditionFailed("preimage_missing guard"));
            }
            
            let next = State {
                action_hash_matches: state.action_hash_matches.clone(),
                limits_binding_ok: state.limits_binding_ok.clone(),
                preimage_present: false,
                result: state.result.clone(),
                schema_valid: state.schema_valid.clone(),
            };
            (next, Effects::default())
        }
        Command::Reject => {
            if !(((ResultPhase::Pending == state.result) && (!(state.action_hash_matches && state.limits_binding_ok && state.preimage_present && state.schema_valid)))) {
                return Err(Error::PreconditionFailed("reject guard"));
            }
            
            let next = State {
                action_hash_matches: state.action_hash_matches.clone(),
                limits_binding_ok: state.limits_binding_ok.clone(),
                preimage_present: state.preimage_present.clone(),
                result: ResultPhase::Rejected,
                schema_valid: state.schema_valid.clone(),
            };
            (next, Effects::default())
        }
        Command::SchemaInvalid => {
            if !((ResultPhase::Pending == state.result)) {
                return Err(Error::PreconditionFailed("schema_invalid guard"));
            }
            
            let next = State {
                action_hash_matches: state.action_hash_matches.clone(),
                limits_binding_ok: state.limits_binding_ok.clone(),
                preimage_present: state.preimage_present.clone(),
                result: state.result.clone(),
                schema_valid: false,
            };
            (next, Effects::default())
        }
    };
    
    // Post-check invariants
    check_invariants(&next)?;
    
    Ok((next, effects))
}
