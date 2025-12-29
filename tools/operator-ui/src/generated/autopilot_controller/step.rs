//! Step function for autopilot_controller.
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
        Command::AddCritical => {
            if !((state.critical_incidents < 20)) {
                return Err(Error::PreconditionFailed("add_critical guard"));
            }
            
            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                attention_budget: state.attention_budget.clone(),
                critical_incidents: (1.checked_add(state.critical_incidents).ok_or(Error::Overflow)?),
                failure_rate_pct: state.failure_rate_pct.clone(),
                hours_since_ack: state.hours_since_ack.clone(),
                mode: if ((ModePhase::Autopilot == state.mode) && ((1.checked_add(state.critical_incidents).ok_or(Error::Overflow)?) > state.attention_budget)) { ModePhase::Assisted } else { state.mode },
            };
            (next, Effects::default())
        }
        Command::AutoDegrade => {
            if !(((ModePhase::Autopilot == state.mode) && ((state.critical_incidents > state.attention_budget) || (state.failure_rate_pct > 20) || (state.hours_since_ack >= 8)))) {
                return Err(Error::PreconditionFailed("auto_degrade guard"));
            }
            
            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                attention_budget: state.attention_budget.clone(),
                critical_incidents: state.critical_incidents.clone(),
                failure_rate_pct: state.failure_rate_pct.clone(),
                hours_since_ack: state.hours_since_ack.clone(),
                mode: ModePhase::Assisted,
            };
            (next, Effects::default())
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
            (next, Effects::default())
        }
        Command::GoAssisted => {
            if !(((ModePhase::Autopilot == state.mode) || (ModePhase::Off == state.mode))) {
                return Err(Error::PreconditionFailed("go_assisted guard"));
            }
            
            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                attention_budget: state.attention_budget.clone(),
                critical_incidents: state.critical_incidents.clone(),
                failure_rate_pct: state.failure_rate_pct.clone(),
                hours_since_ack: state.hours_since_ack.clone(),
                mode: ModePhase::Assisted,
            };
            (next, Effects::default())
        }
        Command::GoAutopilot => {
            if !(((state.hours_since_ack < 8) && (state.critical_incidents <= state.attention_budget) && (state.failure_rate_pct <= 20) && (ModePhase::Assisted == state.mode) && state.anchors_configured)) {
                return Err(Error::PreconditionFailed("go_autopilot guard"));
            }
            
            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                attention_budget: state.attention_budget.clone(),
                critical_incidents: state.critical_incidents.clone(),
                failure_rate_pct: state.failure_rate_pct.clone(),
                hours_since_ack: state.hours_since_ack.clone(),
                mode: ModePhase::Autopilot,
            };
            (next, Effects::default())
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
                mode: ModePhase::Off,
            };
            (next, Effects::default())
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
            (next, Effects::default())
        }
        Command::ResolveCritical => {
            if !((state.critical_incidents > 0)) {
                return Err(Error::PreconditionFailed("resolve_critical guard"));
            }
            
            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                attention_budget: state.attention_budget.clone(),
                critical_incidents: (state.critical_incidents.checked_sub(1).ok_or(Error::Underflow)?),
                failure_rate_pct: state.failure_rate_pct.clone(),
                hours_since_ack: state.hours_since_ack.clone(),
                mode: state.mode.clone(),
            };
            (next, Effects::default())
        }
        Command::TickHour => {
            if !((state.hours_since_ack < 48)) {
                return Err(Error::PreconditionFailed("tick_hour guard"));
            }
            
            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                attention_budget: state.attention_budget.clone(),
                critical_incidents: state.critical_incidents.clone(),
                failure_rate_pct: state.failure_rate_pct.clone(),
                hours_since_ack: (1.checked_add(state.hours_since_ack).ok_or(Error::Overflow)?),
                mode: if ((ModePhase::Autopilot == state.mode) && ((1.checked_add(state.hours_since_ack).ok_or(Error::Overflow)?) >= 8)) { ModePhase::Assisted } else { state.mode },
            };
            (next, Effects::default())
        }
        Command::UpdateFailureRate { new_rate } => {
            if !(true) {
                return Err(Error::PreconditionFailed("update_failure_rate guard"));
            }
            
            let next = State {
                anchors_configured: state.anchors_configured.clone(),
                attention_budget: state.attention_budget.clone(),
                critical_incidents: state.critical_incidents.clone(),
                failure_rate_pct: new_rate,
                hours_since_ack: state.hours_since_ack.clone(),
                mode: if ((ModePhase::Autopilot == state.mode) && (new_rate > 20)) { ModePhase::Assisted } else { state.mode },
            };
            (next, Effects::default())
        }
    };
    
    // Post-check invariants
    check_invariants(&next)?;
    
    Ok((next, effects))
}
