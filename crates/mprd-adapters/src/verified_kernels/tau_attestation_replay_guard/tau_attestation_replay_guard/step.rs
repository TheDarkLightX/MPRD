//! Step function for tau_attestation_replay_guard.
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
        Command::Accept => {
            if !(((ResultPhase::Pending == state.result) && state.epoch_newer && state.hash_chain_valid)) {
                return Err(Error::PreconditionFailed("accept guard"));
            }
            
            let next = State {
                epoch_newer: state.epoch_newer.clone(),
                hash_chain_valid: state.hash_chain_valid.clone(),
                result: ResultPhase::Accepted,
            };
            (next, Effects::default())
        }
        Command::ChainBreaks => {
            if !((ResultPhase::Pending == state.result)) {
                return Err(Error::PreconditionFailed("chain_breaks guard"));
            }
            
            let next = State {
                epoch_newer: state.epoch_newer.clone(),
                hash_chain_valid: false,
                result: state.result.clone(),
            };
            (next, Effects::default())
        }
        Command::ReceiveStale => {
            if !((ResultPhase::Pending == state.result)) {
                return Err(Error::PreconditionFailed("receive_stale guard"));
            }
            
            let next = State {
                epoch_newer: false,
                hash_chain_valid: state.hash_chain_valid.clone(),
                result: state.result.clone(),
            };
            (next, Effects::default())
        }
        Command::Reject => {
            if !(((ResultPhase::Pending == state.result) && (!(state.epoch_newer && state.hash_chain_valid)))) {
                return Err(Error::PreconditionFailed("reject guard"));
            }
            
            let next = State {
                epoch_newer: state.epoch_newer.clone(),
                hash_chain_valid: state.hash_chain_valid.clone(),
                result: ResultPhase::Rejected,
            };
            (next, Effects::default())
        }
    };
    
    // Post-check invariants
    check_invariants(&next)?;
    
    Ok((next, effects))
}
