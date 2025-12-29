//! Step function for artifact_commit_consistency_gate.
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
            if !(((ResultPhase::Pending == state.result) && ((!state.checkpoint_required) || state.checkpoint_ok) && state.commit_sig_ok && state.mst_consistency_ok)) {
                return Err(Error::PreconditionFailed("accept guard"));
            }
            
            let next = State {
                checkpoint_ok: state.checkpoint_ok.clone(),
                checkpoint_required: state.checkpoint_required.clone(),
                commit_sig_ok: state.commit_sig_ok.clone(),
                mst_consistency_ok: state.mst_consistency_ok.clone(),
                result: ResultPhase::Accepted,
            };
            (next, Effects::default())
        }
        Command::CheckpointFails => {
            if !(((ResultPhase::Pending == state.result) && state.checkpoint_required)) {
                return Err(Error::PreconditionFailed("checkpoint_fails guard"));
            }
            
            let next = State {
                checkpoint_ok: false,
                checkpoint_required: state.checkpoint_required.clone(),
                commit_sig_ok: state.commit_sig_ok.clone(),
                mst_consistency_ok: state.mst_consistency_ok.clone(),
                result: state.result.clone(),
            };
            (next, Effects::default())
        }
        Command::MstFails => {
            if !((ResultPhase::Pending == state.result)) {
                return Err(Error::PreconditionFailed("mst_fails guard"));
            }
            
            let next = State {
                checkpoint_ok: state.checkpoint_ok.clone(),
                checkpoint_required: state.checkpoint_required.clone(),
                commit_sig_ok: state.commit_sig_ok.clone(),
                mst_consistency_ok: false,
                result: state.result.clone(),
            };
            (next, Effects::default())
        }
        Command::Reject => {
            if !(((ResultPhase::Pending == state.result) && (!(((!state.checkpoint_required) || state.checkpoint_ok) && state.commit_sig_ok && state.mst_consistency_ok)))) {
                return Err(Error::PreconditionFailed("reject guard"));
            }
            
            let next = State {
                checkpoint_ok: state.checkpoint_ok.clone(),
                checkpoint_required: state.checkpoint_required.clone(),
                commit_sig_ok: state.commit_sig_ok.clone(),
                mst_consistency_ok: state.mst_consistency_ok.clone(),
                result: ResultPhase::Rejected,
            };
            (next, Effects::default())
        }
        Command::RequireCheckpoint => {
            if !((ResultPhase::Pending == state.result)) {
                return Err(Error::PreconditionFailed("require_checkpoint guard"));
            }
            
            let next = State {
                checkpoint_ok: state.checkpoint_ok.clone(),
                checkpoint_required: true,
                commit_sig_ok: state.commit_sig_ok.clone(),
                mst_consistency_ok: state.mst_consistency_ok.clone(),
                result: state.result.clone(),
            };
            (next, Effects::default())
        }
        Command::SigFails => {
            if !((ResultPhase::Pending == state.result)) {
                return Err(Error::PreconditionFailed("sig_fails guard"));
            }
            
            let next = State {
                checkpoint_ok: state.checkpoint_ok.clone(),
                checkpoint_required: state.checkpoint_required.clone(),
                commit_sig_ok: false,
                mst_consistency_ok: state.mst_consistency_ok.clone(),
                result: state.result.clone(),
            };
            (next, Effects::default())
        }
    };
    
    // Post-check invariants
    check_invariants(&next)?;
    
    Ok((next, effects))
}
