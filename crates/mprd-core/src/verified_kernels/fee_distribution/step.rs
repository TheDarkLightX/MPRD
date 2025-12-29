//! Step function for fee_distribution.
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
        Command::Burn { amt } => {
            if amt < 1u64 || amt > 500u64 {
                return Err(Error::ParamDomainViolation("amt"));
            }
            let tmp_1 = ((state.burned.checked_add(state.distributed).ok_or(Error::Overflow)?).checked_add(amt).ok_or(Error::Overflow)?);
            let post_burned = (amt.checked_add(state.burned).ok_or(Error::Overflow)?);

            let guard_ok = ((tmp_1 <= state.collected) && (post_burned <= 500) && (Phase::Distributing == state.phase));
            if !guard_ok {
                return Err(Error::PreconditionFailed("burn guard"));
            }
            
            let next = State {
                burned: (amt.checked_add(state.burned).ok_or(Error::Overflow)?),
                collected: state.collected.clone(),
                distributed: state.distributed.clone(),
                phase: state.phase.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Collect { amt } => {
            if amt < 1u64 || amt > 1000u64 {
                return Err(Error::ParamDomainViolation("amt"));
            }
            let post_collected = (amt.checked_add(state.collected).ok_or(Error::Overflow)?);

            let guard_ok = ((post_collected <= 1000) && (Phase::Collecting == state.phase));
            if !guard_ok {
                return Err(Error::PreconditionFailed("collect guard"));
            }
            
            let next = State {
                burned: state.burned.clone(),
                collected: (amt.checked_add(state.collected).ok_or(Error::Overflow)?),
                distributed: state.distributed.clone(),
                phase: state.phase.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Distribute { amt } => {
            if amt < 1u64 || amt > 1000u64 {
                return Err(Error::ParamDomainViolation("amt"));
            }
            let tmp_1 = ((state.burned.checked_add(state.distributed).ok_or(Error::Overflow)?).checked_add(amt).ok_or(Error::Overflow)?);
            let post_distributed = (amt.checked_add(state.distributed).ok_or(Error::Overflow)?);

            let guard_ok = ((tmp_1 <= state.collected) && (post_distributed <= 1000) && (Phase::Distributing == state.phase));
            if !guard_ok {
                return Err(Error::PreconditionFailed("distribute guard"));
            }
            
            let next = State {
                burned: state.burned.clone(),
                collected: state.collected.clone(),
                distributed: (amt.checked_add(state.distributed).ok_or(Error::Overflow)?),
                phase: state.phase.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Finalize => {
            let guard_ok = ((Phase::Collecting == state.phase) || ((Phase::Distributing == state.phase) && ((state.burned.checked_add(state.distributed).ok_or(Error::Overflow)?) == state.collected)));
            if !guard_ok {
                return Err(Error::PreconditionFailed("finalize guard"));
            }
            
            let next = State {
                burned: state.burned.clone(),
                collected: state.collected.clone(),
                distributed: state.distributed.clone(),
                phase: if (Phase::Collecting == state.phase) { Phase::Distributing } else { Phase::Complete },
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
