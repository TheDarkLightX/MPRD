//! Step function for mprd_operator_mining_round.
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
        Command::CloseRound { hash } => {
            if hash < 0u64 || hash > 1000u64 {
                return Err(Error::ParamDomainViolation("hash"));
            }
            if !(Phase::Open == state.phase) {
                return Err(Error::PreconditionFailed("close_round guard"));
            }

            let next = State {
                dispute_filed: 0,
                phase: Phase::Closed,
                proof_valid: 0,
                rewards_paid: 0,
                round_reward: state.round_reward.clone(),
                spec_satisfied: 0,
                submissions_count: state.submissions_count.clone(),
                valid_count: 0,
                verifier_result: VerifierResult::Inconclusive,
                work_hash: hash,
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::CompletePayments => {
            if !((Phase::Evaluated == state.phase) && (state.rewards_paid == state.valid_count)) {
                return Err(Error::PreconditionFailed("complete_payments guard"));
            }

            let next = State {
                dispute_filed: state.dispute_filed.clone(),
                phase: Phase::Paid,
                proof_valid: state.proof_valid.clone(),
                rewards_paid: state.rewards_paid.clone(),
                round_reward: state.round_reward.clone(),
                spec_satisfied: state.spec_satisfied.clone(),
                submissions_count: state.submissions_count.clone(),
                valid_count: state.valid_count.clone(),
                verifier_result: state.verifier_result.clone(),
                work_hash: state.work_hash.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::FileDispute => {
            let guard_ok = (0 == state.dispute_filed)
                && (VerifierResult::Inconclusive == state.verifier_result)
                && (Phase::Proofchecking == state.phase)
                && (state.work_hash > 990);
            if !guard_ok {
                return Err(Error::PreconditionFailed("file_dispute guard"));
            }

            let next = State {
                dispute_filed: 1,
                phase: Phase::Disputed,
                proof_valid: state.proof_valid.clone(),
                rewards_paid: state.rewards_paid.clone(),
                round_reward: state.round_reward.clone(),
                spec_satisfied: state.spec_satisfied.clone(),
                submissions_count: state.submissions_count.clone(),
                valid_count: state.valid_count.clone(),
                verifier_result: VerifierResult::Inconclusive,
                work_hash: state.work_hash.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Finalize => {
            if !(Phase::Paid == state.phase) {
                return Err(Error::PreconditionFailed("finalize guard"));
            }

            let next = State {
                dispute_filed: 0,
                phase: Phase::Open,
                proof_valid: 0,
                rewards_paid: 0,
                round_reward: state.round_reward.clone(),
                spec_satisfied: 0,
                submissions_count: 0,
                valid_count: 0,
                verifier_result: VerifierResult::Inconclusive,
                work_hash: 0,
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::PayMiner => {
            let mul_result_1 = (state.rewards_paid.checked_add(1).ok_or(Error::Overflow)?)
                .checked_mul(10)
                .ok_or(Error::Overflow)?;

            let guard_ok = (state.rewards_paid < state.valid_count)
                && (mul_result_1 <= state.round_reward)
                && (Phase::Evaluated == state.phase);
            if !guard_ok {
                return Err(Error::PreconditionFailed("pay_miner guard"));
            }

            let next = State {
                dispute_filed: state.dispute_filed.clone(),
                phase: if (state.rewards_paid.checked_add(1).ok_or(Error::Overflow)?)
                    == state.valid_count
                {
                    Phase::Paid
                } else {
                    Phase::Evaluated
                },
                proof_valid: state.proof_valid.clone(),
                rewards_paid: (state.rewards_paid.checked_add(1).ok_or(Error::Overflow)?),
                round_reward: state.round_reward.clone(),
                spec_satisfied: state.spec_satisfied.clone(),
                submissions_count: state.submissions_count.clone(),
                valid_count: state.valid_count.clone(),
                verifier_result: state.verifier_result.clone(),
                work_hash: state.work_hash.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::RunProofCheck => {
            if !(Phase::Closed == state.phase) {
                return Err(Error::PreconditionFailed("run_proof_check guard"));
            }

            let next = State {
                dispute_filed: state.dispute_filed.clone(),
                phase: Phase::Proofchecking,
                proof_valid: if state.work_hash > 990 {
                    0
                } else {
                    if (state.work_hash <= 800) && (state.work_hash > 0) {
                        1
                    } else {
                        0
                    }
                },
                rewards_paid: state.rewards_paid.clone(),
                round_reward: state.round_reward.clone(),
                spec_satisfied: state.spec_satisfied.clone(),
                submissions_count: state.submissions_count.clone(),
                valid_count: state.valid_count.clone(),
                verifier_result: if state.work_hash > 990 {
                    VerifierResult::Inconclusive
                } else {
                    if (state.work_hash <= 800) && (state.work_hash > 0) {
                        VerifierResult::Inconclusive
                    } else {
                        VerifierResult::Invalid
                    }
                },
                work_hash: state.work_hash.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::RunSpecCheck => {
            if !(Phase::Proofchecking == state.phase) {
                return Err(Error::PreconditionFailed("run_spec_check guard"));
            }

            let next = State {
                dispute_filed: state.dispute_filed.clone(),
                phase: if state.work_hash > 990 {
                    Phase::Proofchecking
                } else {
                    Phase::Evaluated
                },
                proof_valid: state.proof_valid.clone(),
                rewards_paid: 0,
                round_reward: state.round_reward.clone(),
                spec_satisfied: if state.work_hash > 990 {
                    0
                } else {
                    if (state.work_hash <= 900) && (state.work_hash > 0) {
                        1
                    } else {
                        0
                    }
                },
                submissions_count: state.submissions_count.clone(),
                valid_count: if (1 == state.proof_valid)
                    && ((state.work_hash <= 900) && (state.work_hash > 0))
                {
                    state.submissions_count
                } else {
                    0
                },
                verifier_result: if state.work_hash > 990 {
                    VerifierResult::Inconclusive
                } else {
                    if (1 == state.proof_valid)
                        && ((state.work_hash <= 900) && (state.work_hash > 0))
                    {
                        VerifierResult::Valid
                    } else {
                        VerifierResult::Invalid
                    }
                },
                work_hash: state.work_hash.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Submit => {
            if !((state.submissions_count < 50) && (Phase::Open == state.phase)) {
                return Err(Error::PreconditionFailed("submit guard"));
            }

            let next = State {
                dispute_filed: state.dispute_filed.clone(),
                phase: state.phase.clone(),
                proof_valid: state.proof_valid.clone(),
                rewards_paid: state.rewards_paid.clone(),
                round_reward: state.round_reward.clone(),
                spec_satisfied: state.spec_satisfied.clone(),
                submissions_count: (state
                    .submissions_count
                    .checked_add(1)
                    .ok_or(Error::Overflow)?),
                valid_count: state.valid_count.clone(),
                verifier_result: state.verifier_result.clone(),
                work_hash: state.work_hash.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
