//! Step function for optimistic_relay_claim.
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
        Command::Challenge => {
            let guard_ok = ((Phase::Pending == state.phase)
                || ((state.round_count < 3) && (Phase::Challenged == state.phase)));
            if !guard_ok {
                return Err(Error::PreconditionFailed("challenge guard"));
            }

            let next = State {
                has_verdict: false,
                phase: Phase::Challenged,
                round_count: if (Phase::Pending == state.phase) {
                    0
                } else {
                    (state.round_count.checked_add(1).ok_or(Error::Overflow)?)
                },
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Commit => {
            if !(Phase::Pending == state.phase) {
                return Err(Error::PreconditionFailed("commit guard"));
            }

            let next = State {
                has_verdict: false,
                phase: state.phase.clone(),
                round_count: 0,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Finalize => {
            if !((Phase::Pending == state.phase) || (Phase::Resolved == state.phase)) {
                return Err(Error::PreconditionFailed("finalize guard"));
            }

            let next = State {
                has_verdict: if (Phase::Resolved == state.phase) {
                    true
                } else {
                    false
                },
                phase: Phase::Finalized,
                round_count: state.round_count.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Resolve => {
            if !((3 == state.round_count) && (Phase::Challenged == state.phase)) {
                return Err(Error::PreconditionFailed("resolve guard"));
            }

            let next = State {
                has_verdict: true,
                phase: Phase::Resolved,
                round_count: state.round_count.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Slash => {
            if !(Phase::Resolved == state.phase) {
                return Err(Error::PreconditionFailed("slash guard"));
            }

            let next = State {
                has_verdict: state.has_verdict.clone(),
                phase: Phase::Slashed,
                round_count: state.round_count.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
