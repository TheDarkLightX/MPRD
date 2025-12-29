//! Step function for policy_registry_gate.
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
        Command::AdvanceEpoch { new_epoch } => {
            if new_epoch < 0u64 || new_epoch > 1000u64 {
                return Err(Error::ParamDomainViolation("new_epoch"));
            }
            if !((new_epoch > state.current_epoch) && (!state.frozen)) {
                return Err(Error::PreconditionFailed("advance_epoch guard"));
            }

            let next = State {
                current_epoch: new_epoch,
                frozen: state.frozen.clone(),
                last_update_height: state.last_update_height.clone(),
                policy_count: state.policy_count.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Freeze => {
            if !(!state.frozen) {
                return Err(Error::PreconditionFailed("freeze guard"));
            }

            let next = State {
                current_epoch: state.current_epoch.clone(),
                frozen: true,
                last_update_height: state.last_update_height.clone(),
                policy_count: state.policy_count.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::RegisterPolicy { block_height } => {
            if block_height < 0u64 || block_height > 10000u64 {
                return Err(Error::ParamDomainViolation("block_height"));
            }
            let guard_ok = ((state.policy_count < 100)
                && (block_height >= state.last_update_height)
                && (!state.frozen));
            if !guard_ok {
                return Err(Error::PreconditionFailed("register_policy guard"));
            }

            let next = State {
                current_epoch: state.current_epoch.clone(),
                frozen: state.frozen.clone(),
                last_update_height: block_height,
                policy_count: (state.policy_count.checked_add(1).ok_or(Error::Overflow)?),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
