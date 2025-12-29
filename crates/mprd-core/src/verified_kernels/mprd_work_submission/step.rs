//! Step function for mprd_work_submission.
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
        Command::FileDispute => {
            let guard_ok = (0 == state.dispute_filed) && (VerifierResult::Inconclusive == state.verifier_result) && (Phase::Proofchecking == state.phase) && (state.work_hash > 990);
            if !guard_ok {
                return Err(Error::PreconditionFailed("file_dispute guard"));
            }
            
            let next = State {
                dispute_filed: 1,
                phase: Phase::Disputed,
                proof_valid: state.proof_valid.clone(),
                spec_satisfied: state.spec_satisfied.clone(),
                verifier_result: VerifierResult::Inconclusive,
                work_hash: state.work_hash.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Reject => {
            let guard_ok = (Phase::Proofchecking == state.phase) && (VerifierResult::Verifierinvalid == state.verifier_result) && ((0 == state.proof_valid) || (0 == state.spec_satisfied));
            if !guard_ok {
                return Err(Error::PreconditionFailed("reject guard"));
            }
            
            let next = State {
                dispute_filed: state.dispute_filed.clone(),
                phase: Phase::Invalid,
                proof_valid: state.proof_valid.clone(),
                spec_satisfied: state.spec_satisfied.clone(),
                verifier_result: state.verifier_result.clone(),
                work_hash: state.work_hash.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::Reward => {
            let guard_ok = (1 == state.proof_valid) && (1 == state.spec_satisfied) && (Phase::Valid == state.phase);
            if !guard_ok {
                return Err(Error::PreconditionFailed("reward guard"));
            }
            
            let next = State {
                dispute_filed: state.dispute_filed.clone(),
                phase: Phase::Rewarded,
                proof_valid: state.proof_valid.clone(),
                spec_satisfied: state.spec_satisfied.clone(),
                verifier_result: state.verifier_result.clone(),
                work_hash: state.work_hash.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::RunProofCheck => {
            if !((Phase::Submitted == state.phase)) {
                return Err(Error::PreconditionFailed("run_proof_check guard"));
            }
            
            let next = State {
                dispute_filed: state.dispute_filed.clone(),
                phase: Phase::Proofchecking,
                proof_valid: if state.work_hash > 990 { 0 } else { if (state.work_hash <= 800) && (state.work_hash > 0) { 1 } else { 0 } },
                spec_satisfied: state.spec_satisfied.clone(),
                verifier_result: if state.work_hash > 990 { VerifierResult::Inconclusive } else { if (state.work_hash <= 800) && (state.work_hash > 0) { VerifierResult::Inconclusive } else { VerifierResult::Verifierinvalid } },
                work_hash: state.work_hash.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::RunSpecCheck => {
            if !((Phase::Proofchecking == state.phase)) {
                return Err(Error::PreconditionFailed("run_spec_check guard"));
            }
            
            let next = State {
                dispute_filed: state.dispute_filed.clone(),
                phase: if state.work_hash > 990 { Phase::Proofchecking } else { if (1 == state.proof_valid) && ((state.work_hash <= 900) && (state.work_hash > 0)) { Phase::Valid } else { Phase::Proofchecking } },
                proof_valid: state.proof_valid.clone(),
                spec_satisfied: if state.work_hash > 990 { 0 } else { if (state.work_hash <= 900) && (state.work_hash > 0) { 1 } else { 0 } },
                verifier_result: if state.work_hash > 990 { VerifierResult::Inconclusive } else { if (1 == state.proof_valid) && ((state.work_hash <= 900) && (state.work_hash > 0)) { VerifierResult::Verifiervalid } else { VerifierResult::Verifierinvalid } },
                work_hash: state.work_hash.clone(),
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
        Command::SubmitWork { hash } => {
            if hash < 0u64 || hash > 1000u64 {
                return Err(Error::ParamDomainViolation("hash"));
            }
            if !(true) {
                return Err(Error::PreconditionFailed("submit_work guard"));
            }
            
            let next = State {
                dispute_filed: 0,
                phase: Phase::Submitted,
                proof_valid: 0,
                spec_satisfied: 0,
                verifier_result: VerifierResult::Inconclusive,
                work_hash: hash,
            };
            let post = next;
            check_invariants(&post)?;
            let effects = Effects::default();
            (post, effects)
        }
    };

    Ok((post, effects))
}
