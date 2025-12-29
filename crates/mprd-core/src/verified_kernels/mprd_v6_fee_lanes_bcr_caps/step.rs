//! Step function for mprd_v6_fee_lanes_bcr_caps.
//! This is the CBC kernel chokepoint.

use super::{command::Command, invariants::check_invariants, state::State, types::*};

/// Effects produced by a transition (data, not side effects).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Effects {
    pub offset_applied: i128,
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
        Command::ApplyTx {
            base_fee,
            tip,
            offset_req,
        } => {
            if base_fee < 0u64 || base_fee > 6u64 {
                return Err(Error::ParamDomainViolation("base_fee"));
            }
            if tip < 0u64 || tip > 6u64 {
                return Err(Error::ParamDomainViolation("tip"));
            }
            if offset_req < 0u64 || offset_req > 6u64 {
                return Err(Error::ParamDomainViolation("offset_req"));
            }
            let post_base_fee_gross = base_fee
                .checked_add(state.base_fee_gross)
                .ok_or(Error::Overflow)?;
            let post_offset_total = offset_req
                .checked_add(state.offset_total)
                .ok_or(Error::Overflow)?;
            let div_result_1 = {
                let n = (base_fee
                    .checked_add(state.base_fee_gross)
                    .ok_or(Error::Overflow)?)
                .checked_mul(50)
                .ok_or(Error::Overflow)?;
                let d = 100;
                if d == 0 {
                    0
                } else {
                    n.div_euclid(d)
                }
            };
            let post_servicer_tip_total = tip
                .checked_add(state.servicer_tip_total)
                .ok_or(Error::Overflow)?;
            let div_result_2 = {
                let n = base_fee.checked_mul(50).ok_or(Error::Overflow)?;
                let d = 100;
                if d == 0 {
                    0
                } else {
                    n.div_euclid(d)
                }
            };

            let guard_ok = (post_base_fee_gross <= 12)
                && (post_offset_total <= 12)
                && (post_offset_total <= div_result_1)
                && (post_servicer_tip_total <= 12)
                && (offset_req <= div_result_2)
                && (state.payer_bcr >= offset_req);
            if !guard_ok {
                return Err(Error::PreconditionFailed("apply_tx guard"));
            }

            let next = State {
                base_fee_gross: (base_fee
                    .checked_add(state.base_fee_gross)
                    .ok_or(Error::Overflow)?),
                offset_total: (offset_req
                    .checked_add(state.offset_total)
                    .ok_or(Error::Overflow)?),
                payer_bcr: (state
                    .payer_bcr
                    .checked_sub(offset_req)
                    .ok_or(Error::Underflow)?),
                servicer_tip_total: (tip
                    .checked_add(state.servicer_tip_total)
                    .ok_or(Error::Overflow)?),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects {
                offset_applied: (offset_req as i128),
            };
            (post, effects)
        }
    };

    Ok((post, effects))
}
