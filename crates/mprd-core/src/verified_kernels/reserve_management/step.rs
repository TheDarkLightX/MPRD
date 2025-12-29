//! Step function for reserve_management.
//! This is the CBC kernel chokepoint.

use super::{{types::*, state::State, command::Command, invariants::check_invariants}};

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
        Command::Deposit { amt } => {
            if amt < 1u64 || amt > 10000u64 {
                return Err(Error::ParamDomainViolation("amt"));
            }
            if !(((amt.checked_add(state.reserve_balance).ok_or(Error::Overflow)?) <= 10000)) {
                return Err(Error::PreconditionFailed("deposit guard"));
            }
            
            let next = State {
                coverage_ratio_bps: state.coverage_ratio_bps.clone(),
                emergency_mode: state.emergency_mode.clone(),
                reserve_balance: (amt.checked_add(state.reserve_balance).ok_or(Error::Overflow)?),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::EnterEmergency => {
            if !(((state.coverage_ratio_bps < 5000) && (false == state.emergency_mode))) {
                return Err(Error::PreconditionFailed("enter_emergency guard"));
            }
            
            let next = State {
                coverage_ratio_bps: state.coverage_ratio_bps.clone(),
                emergency_mode: true,
                reserve_balance: state.reserve_balance.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::ExitEmergency => {
            if !(((true == state.emergency_mode) && (state.reserve_balance >= 5000))) {
                return Err(Error::PreconditionFailed("exit_emergency guard"));
            }
            
            let next = State {
                coverage_ratio_bps: state.reserve_balance,
                emergency_mode: false,
                reserve_balance: state.reserve_balance.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::UpdateCoverage => {
            if !(true) {
                return Err(Error::PreconditionFailed("update_coverage guard"));
            }
            
            let next = State {
                coverage_ratio_bps: if state.emergency_mode { std::cmp::min(4999, state.reserve_balance) } else { state.reserve_balance },
                emergency_mode: state.emergency_mode.clone(),
                reserve_balance: state.reserve_balance.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Withdraw { amt } => {
            if amt < 1u64 || amt > 10000u64 {
                return Err(Error::ParamDomainViolation("amt"));
            }
            if !(((amt <= state.reserve_balance) && (false == state.emergency_mode))) {
                return Err(Error::PreconditionFailed("withdraw guard"));
            }
            
            let next = State {
                coverage_ratio_bps: state.coverage_ratio_bps.clone(),
                emergency_mode: state.emergency_mode.clone(),
                reserve_balance: (state.reserve_balance.checked_sub(amt).ok_or(Error::Underflow)?),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
