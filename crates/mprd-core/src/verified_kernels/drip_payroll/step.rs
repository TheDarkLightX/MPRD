//! Step function for drip_payroll.
//! This is the CBC kernel chokepoint.

use super::{command::Command, invariants::check_invariants, state::State, types::*};

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
        Command::Approve => {
            if !(Phase::Pending == state.phase) {
                return Err(Error::PreconditionFailed("approve guard"));
            }

            let next = State {
                epoch: state.epoch.clone(),
                epoch_budget: state.epoch_budget.clone(),
                phase: Phase::Approved,
                recipients_paid: state.recipients_paid.clone(),
                total_payout: state.total_payout.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::FinalizeEpoch => {
            if !((Phase::Approved == state.phase) && (state.recipients_paid > 0)) {
                return Err(Error::PreconditionFailed("finalize_epoch guard"));
            }

            let next = State {
                epoch: if (state.epoch < 100) {
                    (state.epoch.checked_add(1).ok_or(Error::Overflow)?)
                } else {
                    state.epoch
                },
                epoch_budget: state.epoch_budget.clone(),
                phase: Phase::Paid,
                recipients_paid: state.recipients_paid.clone(),
                total_payout: state.total_payout.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::PayRecipient { amt } => {
            if amt < 1u64 || amt > 1000u64 {
                return Err(Error::ParamDomainViolation("amt"));
            }
            let post_total_payout = (amt.checked_add(state.total_payout).ok_or(Error::Overflow)?);

            let guard_ok = ((state.recipients_paid < 10)
                && (post_total_payout <= 1000)
                && (post_total_payout <= state.epoch_budget)
                && (Phase::Approved == state.phase));
            if !guard_ok {
                return Err(Error::PreconditionFailed("pay_recipient guard"));
            }

            let next = State {
                epoch: state.epoch.clone(),
                epoch_budget: state.epoch_budget.clone(),
                phase: state.phase.clone(),
                recipients_paid: (state
                    .recipients_paid
                    .checked_add(1)
                    .ok_or(Error::Overflow)?),
                total_payout: (amt.checked_add(state.total_payout).ok_or(Error::Overflow)?),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
