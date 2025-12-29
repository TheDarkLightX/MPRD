//! Step function for tau_attestation_replay_guard.
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
        Command::Accept => {
            if !((ModelResult::Pending == state.result)
                && state.epoch_newer
                && state.hash_chain_valid)
            {
                return Err(Error::PreconditionFailed("accept guard"));
            }

            let next = State {
                epoch_newer: state.epoch_newer.clone(),
                hash_chain_valid: state.hash_chain_valid.clone(),
                result: ModelResult::Accepted,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::ChainBreaks => {
            if !(ModelResult::Pending == state.result) {
                return Err(Error::PreconditionFailed("chain_breaks guard"));
            }

            let next = State {
                epoch_newer: state.epoch_newer.clone(),
                hash_chain_valid: false,
                result: state.result.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::ReceiveStale => {
            if !(ModelResult::Pending == state.result) {
                return Err(Error::PreconditionFailed("receive_stale guard"));
            }

            let next = State {
                epoch_newer: false,
                hash_chain_valid: state.hash_chain_valid.clone(),
                result: state.result.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Reject => {
            let guard_ok = ((ModelResult::Pending == state.result)
                && (!(state.epoch_newer && state.hash_chain_valid)));
            if !guard_ok {
                return Err(Error::PreconditionFailed("reject guard"));
            }

            let next = State {
                epoch_newer: state.epoch_newer.clone(),
                hash_chain_valid: state.hash_chain_valid.clone(),
                result: ModelResult::Rejected,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
