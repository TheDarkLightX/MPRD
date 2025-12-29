//! Step function for autopilot_controller.
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
        Command::AddCritical => {
            if !(state.critical_incidents < 20) {
                return Err(Error::PreconditionFailed("add_critical guard"));
            }

            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                attention_budget: state.attention_budget.clone(),
                critical_incidents: (state
                    .critical_incidents
                    .checked_add(1)
                    .ok_or(Error::Overflow)?),
                failure_rate_pct: state.failure_rate_pct.clone(),
                hours_since_ack: state.hours_since_ack.clone(),
                mode: if ((Mode::Autopilot == state.mode)
                    && ((state
                        .critical_incidents
                        .checked_add(1)
                        .ok_or(Error::Overflow)?)
                        > state.attention_budget))
                {
                    Mode::Assisted
                } else {
                    state.mode
                },
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::AutoDegrade => {
            let guard_ok = ((Mode::Autopilot == state.mode)
                && ((state.critical_incidents > state.attention_budget)
                    || (state.failure_rate_pct > 20)
                    || (state.hours_since_ack >= 8)));
            if !guard_ok {
                return Err(Error::PreconditionFailed("auto_degrade guard"));
            }

            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                attention_budget: state.attention_budget.clone(),
                critical_incidents: state.critical_incidents.clone(),
                failure_rate_pct: state.failure_rate_pct.clone(),
                hours_since_ack: state.hours_since_ack.clone(),
                mode: Mode::Assisted,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::ConfigureAnchors => {
            if !(true) {
                return Err(Error::PreconditionFailed("configure_anchors guard"));
            }

            let next = State {
                anchors_configured: true,
                attention_budget: state.attention_budget.clone(),
                critical_incidents: state.critical_incidents.clone(),
                failure_rate_pct: state.failure_rate_pct.clone(),
                hours_since_ack: state.hours_since_ack.clone(),
                mode: state.mode.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::GoAssisted => {
            if !((Mode::Autopilot == state.mode) || (Mode::Off == state.mode)) {
                return Err(Error::PreconditionFailed("go_assisted guard"));
            }

            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                attention_budget: state.attention_budget.clone(),
                critical_incidents: state.critical_incidents.clone(),
                failure_rate_pct: state.failure_rate_pct.clone(),
                hours_since_ack: state.hours_since_ack.clone(),
                mode: Mode::Assisted,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::GoAutopilot => {
            let guard_ok = ((state.hours_since_ack < 8)
                && (state.critical_incidents <= state.attention_budget)
                && (state.failure_rate_pct <= 20)
                && (Mode::Assisted == state.mode)
                && state.anchors_configured);
            if !guard_ok {
                return Err(Error::PreconditionFailed("go_autopilot guard"));
            }

            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                attention_budget: state.attention_budget.clone(),
                critical_incidents: state.critical_incidents.clone(),
                failure_rate_pct: state.failure_rate_pct.clone(),
                hours_since_ack: state.hours_since_ack.clone(),
                mode: Mode::Autopilot,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::GoOff => {
            if !(true) {
                return Err(Error::PreconditionFailed("go_off guard"));
            }

            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                attention_budget: state.attention_budget.clone(),
                critical_incidents: state.critical_incidents.clone(),
                failure_rate_pct: state.failure_rate_pct.clone(),
                hours_since_ack: state.hours_since_ack.clone(),
                mode: Mode::Off,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::HumanAck => {
            if !(true) {
                return Err(Error::PreconditionFailed("human_ack guard"));
            }

            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                attention_budget: state.attention_budget.clone(),
                critical_incidents: state.critical_incidents.clone(),
                failure_rate_pct: state.failure_rate_pct.clone(),
                hours_since_ack: 0,
                mode: state.mode.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::ResolveCritical => {
            if !(state.critical_incidents > 0) {
                return Err(Error::PreconditionFailed("resolve_critical guard"));
            }

            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                attention_budget: state.attention_budget.clone(),
                critical_incidents: (state
                    .critical_incidents
                    .checked_sub(1)
                    .ok_or(Error::Underflow)?),
                failure_rate_pct: state.failure_rate_pct.clone(),
                hours_since_ack: state.hours_since_ack.clone(),
                mode: state.mode.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::TickHour => {
            if !(state.hours_since_ack < 48) {
                return Err(Error::PreconditionFailed("tick_hour guard"));
            }

            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                attention_budget: state.attention_budget.clone(),
                critical_incidents: state.critical_incidents.clone(),
                failure_rate_pct: state.failure_rate_pct.clone(),
                hours_since_ack: (state
                    .hours_since_ack
                    .checked_add(1)
                    .ok_or(Error::Overflow)?),
                mode: if ((Mode::Autopilot == state.mode)
                    && ((state
                        .hours_since_ack
                        .checked_add(1)
                        .ok_or(Error::Overflow)?)
                        >= 8))
                {
                    Mode::Assisted
                } else {
                    state.mode
                },
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::UpdateFailureRate { new_rate } => {
            if new_rate < 0u64 || new_rate > 100u64 {
                return Err(Error::ParamDomainViolation("new_rate"));
            }
            if !(true) {
                return Err(Error::PreconditionFailed("update_failure_rate guard"));
            }

            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                attention_budget: state.attention_budget.clone(),
                critical_incidents: state.critical_incidents.clone(),
                failure_rate_pct: new_rate,
                hours_since_ack: state.hours_since_ack.clone(),
                mode: if ((Mode::Autopilot == state.mode) && (new_rate > 20)) {
                    Mode::Assisted
                } else {
                    state.mode
                },
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
