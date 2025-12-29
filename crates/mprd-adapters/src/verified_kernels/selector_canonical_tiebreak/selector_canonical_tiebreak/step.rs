//! Step function for selector_canonical_tiebreak.
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
        Command::SelectByScore => {
            if !(((ChosenPhase::None == state.chosen) && (!state.score_tie) && state.both_allowed)) {
                return Err(Error::PreconditionFailed("select_by_score guard"));
            }
            
            let next = State {
                a_score_higher: state.a_score_higher.clone(),
                both_allowed: state.both_allowed.clone(),
                canonical_a_lt_b: state.canonical_a_lt_b.clone(),
                chosen: if state.a_score_higher { ChosenPhase::A } else { ChosenPhase::B },
                score_tie: state.score_tie.clone(),
            };
            (next, Effects::default())
        }
        Command::SelectCanonical => {
            if !(((ChosenPhase::None == state.chosen) && state.both_allowed && state.score_tie)) {
                return Err(Error::PreconditionFailed("select_canonical guard"));
            }
            
            let next = State {
                a_score_higher: state.a_score_higher.clone(),
                both_allowed: state.both_allowed.clone(),
                canonical_a_lt_b: state.canonical_a_lt_b.clone(),
                chosen: if state.canonical_a_lt_b { ChosenPhase::A } else { ChosenPhase::B },
                score_tie: state.score_tie.clone(),
            };
            (next, Effects::default())
        }
        Command::SetupAWinsScore => {
            if !((ChosenPhase::None == state.chosen)) {
                return Err(Error::PreconditionFailed("setup_a_wins_score guard"));
            }
            
            let next = State {
                a_score_higher: true,
                both_allowed: true,
                canonical_a_lt_b: state.canonical_a_lt_b.clone(),
                chosen: state.chosen.clone(),
                score_tie: false,
            };
            (next, Effects::default())
        }
        Command::SetupBWinsScore => {
            if !((ChosenPhase::None == state.chosen)) {
                return Err(Error::PreconditionFailed("setup_b_wins_score guard"));
            }
            
            let next = State {
                a_score_higher: false,
                both_allowed: true,
                canonical_a_lt_b: state.canonical_a_lt_b.clone(),
                chosen: state.chosen.clone(),
                score_tie: false,
            };
            (next, Effects::default())
        }
        Command::SetupTieACanonical => {
            if !((ChosenPhase::None == state.chosen)) {
                return Err(Error::PreconditionFailed("setup_tie_a_canonical guard"));
            }
            
            let next = State {
                a_score_higher: state.a_score_higher.clone(),
                both_allowed: true,
                canonical_a_lt_b: true,
                chosen: state.chosen.clone(),
                score_tie: true,
            };
            (next, Effects::default())
        }
        Command::SetupTieBCanonical => {
            if !((ChosenPhase::None == state.chosen)) {
                return Err(Error::PreconditionFailed("setup_tie_b_canonical guard"));
            }
            
            let next = State {
                a_score_higher: state.a_score_higher.clone(),
                both_allowed: true,
                canonical_a_lt_b: false,
                chosen: state.chosen.clone(),
                score_tie: true,
            };
            (next, Effects::default())
        }
    };
    
    // Post-check invariants
    check_invariants(&next)?;
    
    Ok((next, effects))
}
