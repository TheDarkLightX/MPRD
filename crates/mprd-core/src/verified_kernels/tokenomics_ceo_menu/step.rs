//! Step function for tokenomics_ceo_menu.
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
        Command::StepAuctionDown => {
            if !((state.auction_units > 5)) {
                return Err(Error::PreconditionFailed("step_auction_down guard"));
            }
            
            let next = State {
                auction_units: ((state.auction_units.checked_sub(5).ok_or(Error::Underflow)?).checked_add(4).ok_or(Error::Overflow)?),
                burn_units: state.burn_units.clone(),
                drip_units: state.drip_units.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::StepAuctionUp => {
            let tmp_1 = (state.auction_units.checked_add(state.burn_units).ok_or(Error::Overflow)?);

            let guard_ok = ((tmp_1 < 50) && (state.auction_units < 50));
            if !guard_ok {
                return Err(Error::PreconditionFailed("step_auction_up guard"));
            }
            
            let next = State {
                auction_units: ((state.auction_units.checked_sub(5).ok_or(Error::Underflow)?).checked_add(6).ok_or(Error::Overflow)?),
                burn_units: state.burn_units.clone(),
                drip_units: state.drip_units.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::StepBurnDown => {
            if !((state.burn_units > 0)) {
                return Err(Error::PreconditionFailed("step_burn_down guard"));
            }
            
            let next = State {
                auction_units: state.auction_units.clone(),
                burn_units: (state.burn_units.checked_sub(1).ok_or(Error::Underflow)?),
                drip_units: state.drip_units.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::StepBurnUp => {
            let tmp_1 = (state.auction_units.checked_add(state.burn_units).ok_or(Error::Overflow)?);

            let guard_ok = ((tmp_1 < 50) && (state.burn_units < 45));
            if !guard_ok {
                return Err(Error::PreconditionFailed("step_burn_up guard"));
            }
            
            let next = State {
                auction_units: state.auction_units.clone(),
                burn_units: (state.burn_units.checked_add(1).ok_or(Error::Overflow)?),
                drip_units: state.drip_units.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::StepDripDown => {
            if !((state.drip_units > 1)) {
                return Err(Error::PreconditionFailed("step_drip_down guard"));
            }
            
            let next = State {
                auction_units: state.auction_units.clone(),
                burn_units: state.burn_units.clone(),
                drip_units: (state.drip_units.checked_sub(1).ok_or(Error::Underflow)?),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::StepDripUp => {
            if !((state.drip_units < 20)) {
                return Err(Error::PreconditionFailed("step_drip_up guard"));
            }
            
            let next = State {
                auction_units: state.auction_units.clone(),
                burn_units: state.burn_units.clone(),
                drip_units: (state.drip_units.checked_add(1).ok_or(Error::Overflow)?),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
