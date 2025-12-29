//! Step function for opi_oracle_round.
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
        Command::Aggregate => {
            if !((Phase::Reveal == state.phase) && (state.commit_count == state.reveal_count)) {
                return Err(Error::PreconditionFailed("aggregate guard"));
            }

            let next = State {
                commit_count: state.commit_count.clone(),
                has_aggregate: if (state.commit_count >= 2) {
                    true
                } else {
                    false
                },
                phase: Phase::Aggregate,
                reveal_count: state.reveal_count.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Commit => {
            if !((state.commit_count < 4) && (Phase::Commit == state.phase)) {
                return Err(Error::PreconditionFailed("commit guard"));
            }

            let next = State {
                commit_count: (state.commit_count.checked_add(1).ok_or(Error::Overflow)?),
                has_aggregate: state.has_aggregate.clone(),
                phase: if (4 == (state.commit_count.checked_add(1).ok_or(Error::Overflow)?)) {
                    Phase::Reveal
                } else {
                    Phase::Commit
                },
                reveal_count: state.reveal_count.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Finalize => {
            if !((true == state.has_aggregate) && (Phase::Aggregate == state.phase)) {
                return Err(Error::PreconditionFailed("finalize guard"));
            }

            let next = State {
                commit_count: state.commit_count.clone(),
                has_aggregate: state.has_aggregate.clone(),
                phase: Phase::Finalized,
                reveal_count: state.reveal_count.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Reveal => {
            if !((state.reveal_count < state.commit_count) && (Phase::Reveal == state.phase)) {
                return Err(Error::PreconditionFailed("reveal guard"));
            }

            let next = State {
                commit_count: state.commit_count.clone(),
                has_aggregate: state.has_aggregate.clone(),
                phase: state.phase.clone(),
                reveal_count: (state.reveal_count.checked_add(1).ok_or(Error::Overflow)?),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
