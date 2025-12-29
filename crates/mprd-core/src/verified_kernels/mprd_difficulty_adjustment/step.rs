//! Step function for mprd_difficulty_adjustment.
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
        Command::AdjustDown => {
            if !(((state.adjustment_factor < 100) && (state.difficulty_level > 1))) {
                return Err(Error::PreconditionFailed("adjust_down guard"));
            }
            
            let next = State {
                adjustment_factor: 100,
                blocks_in_window: state.blocks_in_window.clone(),
                difficulty_level: std::cmp::max(1, std::cmp::min(100, { let n = state.adjustment_factor.checked_mul(state.difficulty_level).ok_or(Error::Overflow)?; let d = 100; if d == 0 { 0 } else { n.div_euclid(d) } })),
                target_rate: state.target_rate.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::AdjustUp => {
            if !(((state.difficulty_level < 100) && (state.adjustment_factor > 100))) {
                return Err(Error::PreconditionFailed("adjust_up guard"));
            }
            
            let next = State {
                adjustment_factor: 100,
                blocks_in_window: state.blocks_in_window.clone(),
                difficulty_level: std::cmp::max(1, std::cmp::min(100, { let n = state.adjustment_factor.checked_mul(state.difficulty_level).ok_or(Error::Overflow)?; let d = 100; if d == 0 { 0 } else { n.div_euclid(d) } })),
                target_rate: state.target_rate.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::EndWindow => {
            if !(true) {
                return Err(Error::PreconditionFailed("end_window guard"));
            }
            
            let next = State {
                adjustment_factor: if state.blocks_in_window > state.target_rate { std::cmp::min(200, ((state.blocks_in_window.checked_sub(state.target_rate).ok_or(Error::Underflow)?).checked_mul(10).ok_or(Error::Overflow)?).checked_add(100).ok_or(Error::Overflow)?) } else { if state.blocks_in_window < state.target_rate { std::cmp::max(0, 100u64.checked_sub((state.target_rate.checked_sub(state.blocks_in_window).ok_or(Error::Underflow)?).checked_mul(10).ok_or(Error::Overflow)?).ok_or(Error::Underflow)?) } else { 100 } },
                blocks_in_window: 0,
                difficulty_level: state.difficulty_level.clone(),
                target_rate: state.target_rate.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::SubmitBlock => {
            if !((state.blocks_in_window < 100)) {
                return Err(Error::PreconditionFailed("submit_block guard"));
            }
            
            let next = State {
                adjustment_factor: state.adjustment_factor.clone(),
                blocks_in_window: (state.blocks_in_window.checked_add(1).ok_or(Error::Overflow)?),
                difficulty_level: state.difficulty_level.clone(),
                target_rate: state.target_rate.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
