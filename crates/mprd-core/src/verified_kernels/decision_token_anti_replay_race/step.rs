//! Step function for decision_token_anti_replay_race.
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
        Command::AClaim => {
            if !(((PhaseA::Validatinga == state.phase_a) && (!state.token_claimed))) {
                return Err(Error::PreconditionFailed("a_claim guard"));
            }
            
            let next = State {
                phase_a: PhaseA::Claimeda,
                phase_b: state.phase_b.clone(),
                successes: state.successes.clone(),
                token_claimed: true,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::AExecute => {
            if !(((state.successes < 1) && (PhaseA::Claimeda == state.phase_a))) {
                return Err(Error::PreconditionFailed("a_execute guard"));
            }
            
            let next = State {
                phase_a: PhaseA::Executeda,
                phase_b: state.phase_b.clone(),
                successes: (state.successes.checked_add(1).ok_or(Error::Overflow)?),
                token_claimed: state.token_claimed.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::AReject => {
            if !(((PhaseA::Validatinga == state.phase_a) && state.token_claimed)) {
                return Err(Error::PreconditionFailed("a_reject guard"));
            }
            
            let next = State {
                phase_a: PhaseA::Rejecteda,
                phase_b: state.phase_b.clone(),
                successes: state.successes.clone(),
                token_claimed: state.token_claimed.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::AStartValidate => {
            if !((PhaseA::Idlea == state.phase_a)) {
                return Err(Error::PreconditionFailed("a_start_validate guard"));
            }
            
            let next = State {
                phase_a: PhaseA::Validatinga,
                phase_b: state.phase_b.clone(),
                successes: state.successes.clone(),
                token_claimed: state.token_claimed.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::BClaim => {
            if !(((PhaseB::Validatingb == state.phase_b) && (!state.token_claimed))) {
                return Err(Error::PreconditionFailed("b_claim guard"));
            }
            
            let next = State {
                phase_a: state.phase_a.clone(),
                phase_b: PhaseB::Claimedb,
                successes: state.successes.clone(),
                token_claimed: true,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::BExecute => {
            if !(((state.successes < 1) && (PhaseB::Claimedb == state.phase_b))) {
                return Err(Error::PreconditionFailed("b_execute guard"));
            }
            
            let next = State {
                phase_a: state.phase_a.clone(),
                phase_b: PhaseB::Executedb,
                successes: (state.successes.checked_add(1).ok_or(Error::Overflow)?),
                token_claimed: state.token_claimed.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::BReject => {
            if !(((PhaseB::Validatingb == state.phase_b) && state.token_claimed)) {
                return Err(Error::PreconditionFailed("b_reject guard"));
            }
            
            let next = State {
                phase_a: state.phase_a.clone(),
                phase_b: PhaseB::Rejectedb,
                successes: state.successes.clone(),
                token_claimed: state.token_claimed.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::BStartValidate => {
            if !((PhaseB::Idleb == state.phase_b)) {
                return Err(Error::PreconditionFailed("b_start_validate guard"));
            }
            
            let next = State {
                phase_a: state.phase_a.clone(),
                phase_b: PhaseB::Validatingb,
                successes: state.successes.clone(),
                token_claimed: state.token_claimed.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
