//! Step function for bcr_staking.
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
        Command::Bond { amt } => {
            if amt < 1u64 || amt > 1000u64 {
                return Err(Error::ParamDomainViolation("amt"));
            }
            let guard_ok = ((false == state.pending_slash) && (0 == state.bonded_amount) && (Phase::Idle == state.phase));
            if !guard_ok {
                return Err(Error::PreconditionFailed("bond guard"));
            }
            
            let next = State {
                bonded_amount: amt,
                pending_slash: false,
                phase: Phase::Bonded,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::FinalizeUnbond => {
            if !(((false == state.pending_slash) && (Phase::Unbonding == state.phase))) {
                return Err(Error::PreconditionFailed("finalize_unbond guard"));
            }
            
            let next = State {
                bonded_amount: 0,
                pending_slash: false,
                phase: Phase::Idle,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Slash => {
            let guard_ok = ((Phase::Idle != state.phase) && (Phase::Slashed != state.phase) && (state.bonded_amount > 0));
            if !guard_ok {
                return Err(Error::PreconditionFailed("slash guard"));
            }
            
            let next = State {
                bonded_amount: if state.pending_slash { 0 } else { state.bonded_amount },
                pending_slash: if state.pending_slash { false } else { true },
                phase: if state.pending_slash { Phase::Slashed } else { state.phase },
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Unbond => {
            if !((Phase::Bonded == state.phase)) {
                return Err(Error::PreconditionFailed("unbond guard"));
            }
            
            let next = State {
                bonded_amount: state.bonded_amount.clone(),
                pending_slash: state.pending_slash.clone(),
                phase: Phase::Unbonding,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
