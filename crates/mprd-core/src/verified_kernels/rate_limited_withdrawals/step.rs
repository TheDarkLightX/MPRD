//! Step function for rate_limited_withdrawals.
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
        Command::Deposit { amount } => {
            if amount < 1u64 || amount > 100u64 {
                return Err(Error::ParamDomainViolation("amount"));
            }
            if !(((amount.checked_add(state.available_balance).ok_or(Error::Overflow)?) <= 1000)) {
                return Err(Error::PreconditionFailed("deposit guard"));
            }
            
            let next = State {
                available_balance: (amount.checked_add(state.available_balance).ok_or(Error::Overflow)?),
                epoch_limit: state.epoch_limit.clone(),
                epoch_withdrawn: state.epoch_withdrawn.clone(),
                hours_since_halt: state.hours_since_halt.clone(),
                phase: state.phase.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::EmergencyHalt => {
            if !((Phase::Emergencyhalt != state.phase)) {
                return Err(Error::PreconditionFailed("emergency_halt guard"));
            }
            
            let next = State {
                available_balance: state.available_balance.clone(),
                epoch_limit: state.epoch_limit.clone(),
                epoch_withdrawn: state.epoch_withdrawn.clone(),
                hours_since_halt: 0,
                phase: Phase::Emergencyhalt,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::LiftHalt => {
            if !(((Phase::Emergencyhalt == state.phase) && (state.hours_since_halt >= 24))) {
                return Err(Error::PreconditionFailed("lift_halt guard"));
            }
            
            let next = State {
                available_balance: state.available_balance.clone(),
                epoch_limit: state.epoch_limit.clone(),
                epoch_withdrawn: state.epoch_withdrawn.clone(),
                hours_since_halt: 0,
                phase: Phase::Active,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::NewEpoch => {
            if !((Phase::Emergencyhalt != state.phase)) {
                return Err(Error::PreconditionFailed("new_epoch guard"));
            }
            
            let next = State {
                available_balance: state.available_balance.clone(),
                epoch_limit: state.epoch_limit.clone(),
                epoch_withdrawn: 0,
                hours_since_halt: state.hours_since_halt.clone(),
                phase: state.phase.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Pause => {
            if !((Phase::Active == state.phase)) {
                return Err(Error::PreconditionFailed("pause guard"));
            }
            
            let next = State {
                available_balance: state.available_balance.clone(),
                epoch_limit: state.epoch_limit.clone(),
                epoch_withdrawn: state.epoch_withdrawn.clone(),
                hours_since_halt: state.hours_since_halt.clone(),
                phase: Phase::Paused,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Resume => {
            if !((Phase::Paused == state.phase)) {
                return Err(Error::PreconditionFailed("resume guard"));
            }
            
            let next = State {
                available_balance: state.available_balance.clone(),
                epoch_limit: state.epoch_limit.clone(),
                epoch_withdrawn: state.epoch_withdrawn.clone(),
                hours_since_halt: 0,
                phase: Phase::Active,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::TickHour => {
            if !(((state.hours_since_halt < 48) && (Phase::Emergencyhalt == state.phase))) {
                return Err(Error::PreconditionFailed("tick_hour guard"));
            }
            
            let next = State {
                available_balance: state.available_balance.clone(),
                epoch_limit: state.epoch_limit.clone(),
                epoch_withdrawn: state.epoch_withdrawn.clone(),
                hours_since_halt: (state.hours_since_halt.checked_add(1).ok_or(Error::Overflow)?),
                phase: state.phase.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Withdraw { amount } => {
            if amount < 1u64 || amount > 50u64 {
                return Err(Error::ParamDomainViolation("amount"));
            }
            let post_epoch_withdrawn = (amount.checked_add(state.epoch_withdrawn).ok_or(Error::Overflow)?);

            let guard_ok = ((post_epoch_withdrawn <= state.epoch_limit) && (amount <= state.available_balance) && (Phase::Active == state.phase));
            if !guard_ok {
                return Err(Error::PreconditionFailed("withdraw guard"));
            }
            
            let next = State {
                available_balance: (state.available_balance.checked_sub(amount).ok_or(Error::Underflow)?),
                epoch_limit: state.epoch_limit.clone(),
                epoch_withdrawn: (amount.checked_add(state.epoch_withdrawn).ok_or(Error::Overflow)?),
                hours_since_halt: state.hours_since_halt.clone(),
                phase: state.phase.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
