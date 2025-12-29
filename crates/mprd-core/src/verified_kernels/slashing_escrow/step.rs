//! Step function for slashing_escrow.
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
        Command::Challenge => {
            if !((Phase::Locked == state.phase)) {
                return Err(Error::PreconditionFailed("challenge guard"));
            }
            
            let next = State {
                bond_amount: state.bond_amount.clone(),
                challenge_deadline: state.challenge_deadline.clone(),
                evidence_submitted: state.evidence_submitted.clone(),
                phase: Phase::Challenged,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Lock { amt } => {
            if amt < 100u64 || amt > 10000u64 {
                return Err(Error::ParamDomainViolation("amt"));
            }
            if !(((Phase::Released == state.phase) || (Phase::Slashed == state.phase))) {
                return Err(Error::PreconditionFailed("lock guard"));
            }
            
            let next = State {
                bond_amount: amt,
                challenge_deadline: 100,
                evidence_submitted: false,
                phase: Phase::Locked,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Release => {
            let guard_ok = ((false == state.evidence_submitted) && ((Phase::Challenged == state.phase) || (Phase::Locked == state.phase)));
            if !guard_ok {
                return Err(Error::PreconditionFailed("release guard"));
            }
            
            let next = State {
                bond_amount: state.bond_amount.clone(),
                challenge_deadline: 0,
                evidence_submitted: false,
                phase: Phase::Released,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Slash => {
            if !(((true == state.evidence_submitted) && (Phase::Challenged == state.phase))) {
                return Err(Error::PreconditionFailed("slash guard"));
            }
            
            let next = State {
                bond_amount: state.bond_amount.clone(),
                challenge_deadline: 0,
                evidence_submitted: true,
                phase: Phase::Slashed,
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::SubmitEvidence => {
            if !(((false == state.evidence_submitted) && (Phase::Challenged == state.phase))) {
                return Err(Error::PreconditionFailed("submit_evidence guard"));
            }
            
            let next = State {
                bond_amount: state.bond_amount.clone(),
                challenge_deadline: state.challenge_deadline.clone(),
                evidence_submitted: true,
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
