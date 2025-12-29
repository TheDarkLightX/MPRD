//! Step function for ui_mode_adaptive_gates.
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
        Command::ConfigureAnchors => {
            if !(true) {
                return Err(Error::PreconditionFailed("configure_anchors guard"));
            }

            let next = State {
                anchors_configured: true,
                mode: state.mode.clone(),
                run_pipeline_disabled: false,
                trust_anchor_warning: false,
                zk_actions_disabled: state.zk_actions_disabled.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::GoLocal => {
            if !(Mode::Local != state.mode) {
                return Err(Error::PreconditionFailed("go_local guard"));
            }

            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                mode: Mode::Local,
                run_pipeline_disabled: false,
                trust_anchor_warning: false,
                zk_actions_disabled: true,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::GoPrivate => {
            if !(Mode::Private != state.mode) {
                return Err(Error::PreconditionFailed("go_private guard"));
            }

            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                mode: Mode::Private,
                run_pipeline_disabled: if state.anchors_configured {
                    false
                } else {
                    true
                },
                trust_anchor_warning: if state.anchors_configured {
                    false
                } else {
                    true
                },
                zk_actions_disabled: false,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::GoTrustless => {
            if !(Mode::Trustless != state.mode) {
                return Err(Error::PreconditionFailed("go_trustless guard"));
            }

            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                mode: Mode::Trustless,
                run_pipeline_disabled: if state.anchors_configured {
                    false
                } else {
                    true
                },
                trust_anchor_warning: if state.anchors_configured {
                    false
                } else {
                    true
                },
                zk_actions_disabled: false,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
