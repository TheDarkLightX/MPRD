//! Step function for mprd_proof_market_slot.
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
        Command::Commit {
            deadline,
            deposit,
            prover,
        } => {
            if deadline < 0u64 || deadline > 10u64 {
                return Err(Error::ParamDomainViolation("deadline"));
            }
            if deposit < 0u64 || deposit > 5u64 {
                return Err(Error::ParamDomainViolation("deposit"));
            }
            let post_total_deposits = (deposit
                .checked_add(state.total_deposits)
                .ok_or(Error::Overflow)?);

            let guard_ok = ((state.now < deadline)
                && (post_total_deposits <= 10)
                && (Phase::Idle == state.phase));
            if !guard_ok {
                return Err(Error::PreconditionFailed("commit guard"));
            }

            let next = State {
                claimer: prover,
                claimer0: prover,
                deadline: deadline,
                deadline0: deadline,
                deposit: deposit,
                job_hash_present: true,
                now: state.now.clone(),
                payee: prover,
                payout: 0,
                phase: Phase::Committed,
                proof_binds_job: false,
                proof_verified: false,
                protocol_subsidy: state.protocol_subsidy.clone(),
                total_deposits: (deposit
                    .checked_add(state.total_deposits)
                    .ok_or(Error::Overflow)?),
                total_payouts: state.total_payouts.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Expire => {
            let guard_ok = ((state.deadline < state.now)
                && (false == state.proof_verified)
                && (Phase::Proving == state.phase));
            if !guard_ok {
                return Err(Error::PreconditionFailed("expire guard"));
            }

            let next = State {
                claimer: state.claimer.clone(),
                claimer0: state.claimer0.clone(),
                deadline: state.deadline.clone(),
                deadline0: state.deadline0.clone(),
                deposit: state.deposit.clone(),
                job_hash_present: state.job_hash_present.clone(),
                now: state.now.clone(),
                payee: state.payee.clone(),
                payout: state.payout.clone(),
                phase: Phase::Expired,
                proof_binds_job: state.proof_binds_job.clone(),
                proof_verified: state.proof_verified.clone(),
                protocol_subsidy: state.protocol_subsidy.clone(),
                total_deposits: state.total_deposits.clone(),
                total_payouts: state.total_payouts.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Settle { payout } => {
            if payout < 0u64 || payout > 5u64 {
                return Err(Error::ParamDomainViolation("payout"));
            }
            let post_total_payouts = (payout
                .checked_add(state.total_payouts)
                .ok_or(Error::Overflow)?);
            let tmp_1 = (state
                .protocol_subsidy
                .checked_add(state.total_deposits)
                .ok_or(Error::Overflow)?);

            let guard_ok = ((post_total_payouts <= 10)
                && (post_total_payouts <= tmp_1)
                && (payout <= state.deposit)
                && (state.now <= state.deadline)
                && (Phase::Proving == state.phase)
                && state.job_hash_present);
            if !guard_ok {
                return Err(Error::PreconditionFailed("settle guard"));
            }

            let next = State {
                claimer: state.claimer.clone(),
                claimer0: state.claimer0.clone(),
                deadline: state.deadline.clone(),
                deadline0: state.deadline0.clone(),
                deposit: state.deposit.clone(),
                job_hash_present: state.job_hash_present.clone(),
                now: state.now.clone(),
                payee: state.claimer0,
                payout: payout,
                phase: Phase::Settled,
                proof_binds_job: true,
                proof_verified: true,
                protocol_subsidy: state.protocol_subsidy.clone(),
                total_deposits: state.total_deposits.clone(),
                total_payouts: (payout
                    .checked_add(state.total_payouts)
                    .ok_or(Error::Overflow)?),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Slash => {
            let guard_ok = ((state.deadline < state.now)
                && (false == state.proof_verified)
                && (Phase::Expired == state.phase));
            if !guard_ok {
                return Err(Error::PreconditionFailed("slash guard"));
            }

            let next = State {
                claimer: state.claimer.clone(),
                claimer0: state.claimer0.clone(),
                deadline: state.deadline.clone(),
                deadline0: state.deadline0.clone(),
                deposit: state.deposit.clone(),
                job_hash_present: state.job_hash_present.clone(),
                now: state.now.clone(),
                payee: state.payee.clone(),
                payout: state.payout.clone(),
                phase: Phase::Slashed,
                proof_binds_job: state.proof_binds_job.clone(),
                proof_verified: state.proof_verified.clone(),
                protocol_subsidy: state.protocol_subsidy.clone(),
                total_deposits: state.total_deposits.clone(),
                total_payouts: state.total_payouts.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::StartProving => {
            if !(Phase::Committed == state.phase) {
                return Err(Error::PreconditionFailed("start_proving guard"));
            }

            let next = State {
                claimer: state.claimer.clone(),
                claimer0: state.claimer0.clone(),
                deadline: state.deadline.clone(),
                deadline0: state.deadline0.clone(),
                deposit: state.deposit.clone(),
                job_hash_present: state.job_hash_present.clone(),
                now: state.now.clone(),
                payee: state.payee.clone(),
                payout: state.payout.clone(),
                phase: Phase::Proving,
                proof_binds_job: state.proof_binds_job.clone(),
                proof_verified: state.proof_verified.clone(),
                protocol_subsidy: state.protocol_subsidy.clone(),
                total_deposits: state.total_deposits.clone(),
                total_payouts: state.total_payouts.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Tick { dt } => {
            if dt < 0u64 || dt > 3u64 {
                return Err(Error::ParamDomainViolation("dt"));
            }
            if !((dt.checked_add(state.now).ok_or(Error::Overflow)?) <= 10) {
                return Err(Error::PreconditionFailed("tick guard"));
            }

            let next = State {
                claimer: state.claimer.clone(),
                claimer0: state.claimer0.clone(),
                deadline: state.deadline.clone(),
                deadline0: state.deadline0.clone(),
                deposit: state.deposit.clone(),
                job_hash_present: state.job_hash_present.clone(),
                now: (dt.checked_add(state.now).ok_or(Error::Overflow)?),
                payee: state.payee.clone(),
                payout: state.payout.clone(),
                phase: state.phase.clone(),
                proof_binds_job: state.proof_binds_job.clone(),
                proof_verified: state.proof_verified.clone(),
                protocol_subsidy: state.protocol_subsidy.clone(),
                total_deposits: state.total_deposits.clone(),
                total_payouts: state.total_payouts.clone(),
            };
            let mut post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
