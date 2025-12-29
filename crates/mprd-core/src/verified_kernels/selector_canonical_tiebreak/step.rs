//! Step function for selector_canonical_tiebreak.
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
        Command::SelectByScore => {
            if !(((Chosen::None == state.chosen) && (!state.score_tie) && state.both_allowed)) {
                return Err(Error::PreconditionFailed("select_by_score guard"));
            }
            
            let next = State {
                a_score_higher: state.a_score_higher.clone(),
                both_allowed: state.both_allowed.clone(),
                canonical_a_lt_b: state.canonical_a_lt_b.clone(),
                chosen: if state.a_score_higher { Chosen::A } else { Chosen::B },
                score_tie: state.score_tie.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::SelectCanonical => {
            if !(((Chosen::None == state.chosen) && state.both_allowed && state.score_tie)) {
                return Err(Error::PreconditionFailed("select_canonical guard"));
            }
            
            let next = State {
                a_score_higher: state.a_score_higher.clone(),
                both_allowed: state.both_allowed.clone(),
                canonical_a_lt_b: state.canonical_a_lt_b.clone(),
                chosen: if state.canonical_a_lt_b { Chosen::A } else { Chosen::B },
                score_tie: state.score_tie.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::SetupAWinsScore => {
            if !((Chosen::None == state.chosen)) {
                return Err(Error::PreconditionFailed("setup_a_wins_score guard"));
            }
            
            let next = State {
                a_score_higher: true,
                both_allowed: true,
                canonical_a_lt_b: state.canonical_a_lt_b.clone(),
                chosen: state.chosen.clone(),
                score_tie: false,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::SetupBWinsScore => {
            if !((Chosen::None == state.chosen)) {
                return Err(Error::PreconditionFailed("setup_b_wins_score guard"));
            }
            
            let next = State {
                a_score_higher: false,
                both_allowed: true,
                canonical_a_lt_b: state.canonical_a_lt_b.clone(),
                chosen: state.chosen.clone(),
                score_tie: false,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::SetupTieACanonical => {
            if !((Chosen::None == state.chosen)) {
                return Err(Error::PreconditionFailed("setup_tie_a_canonical guard"));
            }
            
            let next = State {
                a_score_higher: state.a_score_higher.clone(),
                both_allowed: true,
                canonical_a_lt_b: true,
                chosen: state.chosen.clone(),
                score_tie: true,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::SetupTieBCanonical => {
            if !((Chosen::None == state.chosen)) {
                return Err(Error::PreconditionFailed("setup_tie_b_canonical guard"));
            }
            
            let next = State {
                a_score_higher: state.a_score_higher.clone(),
                both_allowed: true,
                canonical_a_lt_b: false,
                chosen: state.chosen.clone(),
                score_tie: true,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
