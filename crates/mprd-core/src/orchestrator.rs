use crate::{
    CandidateAction, Decision, DecisionToken, ExecutionResult, MprdError, ProofBundle, Result,
    StateProvider, StateSnapshot, PolicyEngine, PolicyHash, Proposer, Selector, VerificationStatus,
    ZkAttestor, ZkLocalVerifier, ExecutorAdapter,
};

/// Factory responsible for constructing signed decision tokens from
/// decisions and state snapshots.
pub trait DecisionTokenFactory {
    /// Preconditions:
    /// - `decision` was produced by a compliant `Selector`.
    /// - `state` is the same snapshot used during selection.
    /// Postconditions:
    /// - Returned token binds `policy_hash`, `state_hash` and
    ///   `chosen_action_hash` consistently.
    fn create(&self, decision: &Decision, state: &StateSnapshot) -> Result<DecisionToken>;
}

/// Execute a single MPRD decision cycle:
///
/// 1. Observe state.
/// 2. Propose candidates.
/// 3. Evaluate with policy engine.
/// 4. Select deterministically.
/// 5. Create decision token.
/// 6. Attest with ZK.
/// 7. Verify locally.
/// 8. Execute via adapter.
pub fn run_once<P, Pr, PE, S, TF, ZA, ZV, E>(
    state_provider: &P,
    proposer: &Pr,
    policy_engine: &PE,
    selector: &S,
    token_factory: &TF,
    attestor: &ZA,
    verifier: &ZV,
    executor: &E,
    policy_hash: &PolicyHash,
) -> Result<ExecutionResult>
where
    P: StateProvider,
    Pr: Proposer,
    PE: PolicyEngine,
    S: Selector,
    TF: DecisionTokenFactory,
    ZA: ZkAttestor,
    ZV: ZkLocalVerifier,
    E: ExecutorAdapter,
{
    let state = state_provider.snapshot()?;
    let candidates: Vec<CandidateAction> = proposer.propose(&state)?;
    let verdicts = policy_engine.evaluate(policy_hash, &state, &candidates)?;
    let decision = selector.select(policy_hash, &state, &candidates, &verdicts)?;
    let token = token_factory.create(&decision, &state)?;
    let proof: ProofBundle = attestor.attest(&decision, &state, &candidates)?;

    match verifier.verify(&token, &proof) {
        VerificationStatus::Success => executor.execute(&token, &proof),
        VerificationStatus::Failure(msg) => Err(MprdError::ZkError(msg)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CandidateHash, Hash32, RuleVerdict, Score, StateHash, Value,
    };
    use std::collections::HashMap;

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    struct DummyStateProvider;

    impl StateProvider for DummyStateProvider {
        fn snapshot(&self) -> Result<StateSnapshot> {
            Ok(StateSnapshot {
                fields: HashMap::new(),
                policy_inputs: HashMap::new(),
                state_hash: dummy_hash(1),
            })
        }
    }

    struct DummyProposer;

    impl Proposer for DummyProposer {
        fn propose(&self, _state: &StateSnapshot) -> Result<Vec<CandidateAction>> {
            Ok(vec![CandidateAction {
                action_type: "A".into(),
                params: HashMap::from([("x".into(), Value::Int(1))]),
                score: Score(10),
                candidate_hash: dummy_hash(2),
            }])
        }
    }

    struct AllowAllPolicyEngine;

    impl PolicyEngine for AllowAllPolicyEngine {
        fn evaluate(
            &self,
            _policy_hash: &PolicyHash,
            _state: &StateSnapshot,
            candidates: &[CandidateAction],
        ) -> Result<Vec<RuleVerdict>> {
            Ok(candidates
                .iter()
                .map(|_| RuleVerdict {
                    allowed: true,
                    reasons: vec![],
                    limits: HashMap::new(),
                })
                .collect())
        }
    }

    struct DummyTokenFactory;

    impl DecisionTokenFactory for DummyTokenFactory {
        fn create(&self, decision: &Decision, state: &StateSnapshot) -> Result<DecisionToken> {
            Ok(DecisionToken {
                policy_hash: decision.policy_hash.clone(),
                state_hash: state.state_hash.clone(),
                chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
                nonce_or_tx_hash: dummy_hash(3),
                timestamp_ms: 0,
                signature: vec![],
            })
        }
    }

    struct DummyAttestor;

    impl ZkAttestor for DummyAttestor {
        fn attest(
            &self,
            decision: &Decision,
            state: &StateSnapshot,
            _candidates: &[CandidateAction],
        ) -> Result<ProofBundle> {
            Ok(ProofBundle {
                policy_hash: decision.policy_hash.clone(),
                state_hash: state.state_hash.clone(),
                candidate_set_hash: dummy_hash(4),
                chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
                risc0_receipt: vec![],
                attestation_metadata: HashMap::new(),
            })
        }
    }

    struct DummyVerifier;

    impl ZkLocalVerifier for DummyVerifier {
        fn verify(&self, _token: &DecisionToken, _proof: &ProofBundle) -> VerificationStatus {
            VerificationStatus::Success
        }
    }

    struct DummyExecutor;

    impl ExecutorAdapter for DummyExecutor {
        fn execute(&self, _token: &DecisionToken, _proof: &ProofBundle) -> Result<ExecutionResult> {
            Ok(ExecutionResult {
                success: true,
                message: Some("ok".into()),
            })
        }
    }

    struct DummySelector;

    impl Selector for DummySelector {
        fn select(
            &self,
            policy_hash: &PolicyHash,
            _state: &StateSnapshot,
            candidates: &[CandidateAction],
            _verdicts: &[RuleVerdict],
        ) -> Result<Decision> {
            let chosen_action = candidates[0].clone();
            Ok(Decision {
                chosen_index: 0,
                chosen_action,
                policy_hash: policy_hash.clone(),
                decision_commitment: dummy_hash(5),
            })
        }
    }

    #[test]
    fn run_once_happy_path_with_dummy_components() {
        let state_provider = DummyStateProvider;
        let proposer = DummyProposer;
        let policy_engine = AllowAllPolicyEngine;
        let selector = DummySelector;
        let token_factory = DummyTokenFactory;
        let attestor = DummyAttestor;
        let verifier = DummyVerifier;
        let executor = DummyExecutor;
        let policy_hash = Hash32([9u8; 32]);

        let result = run_once(
            &state_provider,
            &proposer,
            &policy_engine,
            &selector,
            &token_factory,
            &attestor,
            &verifier,
            &executor,
            &policy_hash,
        )
        .expect("run_once should succeed in dummy pipeline");

        assert!(result.success);
        assert_eq!(result.message.as_deref(), Some("ok"));
    }
}

