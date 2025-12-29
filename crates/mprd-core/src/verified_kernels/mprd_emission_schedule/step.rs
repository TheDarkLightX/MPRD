//! Step function for mprd_emission_schedule.
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
        Command::AdvanceEpoch => {
            if !(state.epoch < 100) {
                return Err(Error::PreconditionFailed("advance_epoch guard"));
            }

            let next = State {
                emission_rate: if (state.epoch.checked_add(1).ok_or(Error::Overflow)?)
                    < state.halving_period
                {
                    1000
                } else {
                    if (state.epoch.checked_add(1).ok_or(Error::Overflow)?)
                        < (state.halving_period.checked_mul(2).ok_or(Error::Overflow)?)
                    {
                        500
                    } else {
                        if (state.epoch.checked_add(1).ok_or(Error::Overflow)?)
                            < (state.halving_period.checked_mul(3).ok_or(Error::Overflow)?)
                        {
                            250
                        } else {
                            if (state.epoch.checked_add(1).ok_or(Error::Overflow)?)
                                < (state.halving_period.checked_mul(4).ok_or(Error::Overflow)?)
                            {
                                125
                            } else {
                                100
                            }
                        }
                    }
                },
                epoch: (state.epoch.checked_add(1).ok_or(Error::Overflow)?),
                epoch_budget: 0,
                halving_period: state.halving_period.clone(),
                total_emitted: state.total_emitted.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::EmitTokens { amt } => {
            if amt < 1u64 || amt > 1000u64 {
                return Err(Error::ParamDomainViolation("amt"));
            }
            let post_epoch_budget = amt.checked_add(state.epoch_budget).ok_or(Error::Overflow)?;
            let post_total_emitted = amt
                .checked_add(state.total_emitted)
                .ok_or(Error::Overflow)?;

            let guard_ok =
                (post_epoch_budget <= state.emission_rate) && (post_total_emitted <= 10000);
            if !guard_ok {
                return Err(Error::PreconditionFailed("emit_tokens guard"));
            }

            let next = State {
                emission_rate: state.emission_rate.clone(),
                epoch: state.epoch.clone(),
                epoch_budget: (amt.checked_add(state.epoch_budget).ok_or(Error::Overflow)?),
                halving_period: state.halving_period.clone(),
                total_emitted: (amt
                    .checked_add(state.total_emitted)
                    .ok_or(Error::Overflow)?),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::HalveRate => {
            let mul_result_1 = ({
                let n = state.epoch;
                let d = state.halving_period;
                if d == 0 {
                    0
                } else {
                    n.div_euclid(d)
                }
            })
            .checked_mul(state.halving_period)
            .ok_or(Error::Overflow)?;

            let guard_ok = (mul_result_1 == state.epoch) && (state.epoch > 0);
            if !guard_ok {
                return Err(Error::PreconditionFailed("halve_rate guard"));
            }

            let next = State {
                emission_rate: if state.epoch < state.halving_period {
                    1000
                } else {
                    if state.epoch < (state.halving_period.checked_mul(2).ok_or(Error::Overflow)?) {
                        500
                    } else {
                        if state.epoch
                            < (state.halving_period.checked_mul(3).ok_or(Error::Overflow)?)
                        {
                            250
                        } else {
                            if state.epoch
                                < (state.halving_period.checked_mul(4).ok_or(Error::Overflow)?)
                            {
                                125
                            } else {
                                100
                            }
                        }
                    }
                },
                epoch: state.epoch.clone(),
                epoch_budget: state.epoch_budget.clone(),
                halving_period: state.halving_period.clone(),
                total_emitted: state.total_emitted.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
