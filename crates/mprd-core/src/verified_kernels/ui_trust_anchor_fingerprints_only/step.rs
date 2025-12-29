//! Step function for ui_trust_anchor_fingerprints_only.
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
        Command::AttemptRawDisplay => {
            if !((DisplayState::Attemptedrawleak != state.display_state) && state.key_loaded) {
                return Err(Error::PreconditionFailed("attempt_raw_display guard"));
            }

            let next = State {
                display_state: DisplayState::Attemptedrawleak,
                key_loaded: state.key_loaded.clone(),
                leaks_raw: false,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::ClearKey => {
            if !(state.key_loaded) {
                return Err(Error::PreconditionFailed("clear_key guard"));
            }

            let next = State {
                display_state: DisplayState::Hidden,
                key_loaded: false,
                leaks_raw: state.leaks_raw.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::DisplayFingerprint => {
            if !((DisplayState::Showingfingerprint != state.display_state) && state.key_loaded) {
                return Err(Error::PreconditionFailed("display_fingerprint guard"));
            }

            let next = State {
                display_state: DisplayState::Showingfingerprint,
                key_loaded: state.key_loaded.clone(),
                leaks_raw: false,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::HideDisplay => {
            if !(DisplayState::Hidden != state.display_state) {
                return Err(Error::PreconditionFailed("hide_display guard"));
            }

            let next = State {
                display_state: DisplayState::Hidden,
                key_loaded: state.key_loaded.clone(),
                leaks_raw: state.leaks_raw.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::LoadKey => {
            if !(!state.key_loaded) {
                return Err(Error::PreconditionFailed("load_key guard"));
            }

            let next = State {
                display_state: state.display_state.clone(),
                key_loaded: true,
                leaks_raw: state.leaks_raw.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
