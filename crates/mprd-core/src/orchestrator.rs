use crate::{
    CandidateAction, Decision, DecisionToken, ExecutionResult, MprdError, ProofBundle, Result,
    StateProvider, StateSnapshot, PolicyEngine, PolicyHash, Proposer, Selector, VerificationStatus,
    ZkAttestor, ZkLocalVerifier, ExecutorAdapter,
};
use tracing::{debug, error, info, instrument, warn, Span};

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

/// Optional hook for recording verified decisions (e.g., on-chain/Tau anchoring).
pub trait DecisionRecorder {
    /// Called after ZK verification succeeds but before execution.
    fn record(&self, token: &DecisionToken, proof: &ProofBundle) -> Result<()>;
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
///
/// # Tracing
///
/// This function is instrumented with tracing spans and events:
/// - `run_once` span with policy_hash field
/// - Events for each stage (state, propose, evaluate, select, etc.)
#[instrument(
    name = "mprd_run_once",
    skip(state_provider, proposer, policy_engine, selector, token_factory, attestor, verifier, executor, recorder),
    fields(
        policy_hash = %hex::encode(&policy_hash.0[..8]),
        candidates = tracing::field::Empty,
        allowed = tracing::field::Empty,
        chosen_index = tracing::field::Empty,
    )
)]
fn run_once_internal<P, Pr, PE, S, TF, ZA, ZV, E>(
    state_provider: &P,
    proposer: &Pr,
    policy_engine: &PE,
    selector: &S,
    token_factory: &TF,
    attestor: &ZA,
    verifier: &ZV,
    executor: &E,
    recorder: Option<&dyn DecisionRecorder>,
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
    // 1. Observe state
    debug!("Capturing state snapshot");
    let state = state_provider.snapshot()?;
    debug!(state_hash = %hex::encode(&state.state_hash.0[..8]), "State captured");

    // 2. Propose candidates
    debug!("Proposing candidates");
    let candidates: Vec<CandidateAction> = proposer.propose(&state)?;
    Span::current().record("candidates", candidates.len());
    debug!(num_candidates = candidates.len(), "Candidates proposed");

    // 3. Evaluate with policy engine
    debug!("Evaluating policy");
    let verdicts = policy_engine.evaluate(policy_hash, &state, &candidates)?;
    let allowed_count = verdicts.iter().filter(|v| v.allowed).count();
    Span::current().record("allowed", allowed_count);
    debug!(allowed = allowed_count, denied = candidates.len() - allowed_count, "Policy evaluated");

    // 4. Select deterministically
    debug!("Selecting action");
    let decision = selector.select(policy_hash, &state, &candidates, &verdicts)?;
    Span::current().record("chosen_index", decision.chosen_index);
    info!(
        chosen_index = decision.chosen_index,
        action_type = %decision.chosen_action.action_type,
        "Action selected"
    );

    // 5. Create decision token
    debug!("Creating decision token");
    let token = token_factory.create(&decision, &state)?;
    debug!(nonce = %hex::encode(&token.nonce_or_tx_hash.0[..8]), "Token created");

    // 6. Attest with ZK
    debug!("Generating attestation");
    let proof: ProofBundle = attestor.attest(&decision, &state, &candidates)?;
    debug!("Attestation complete");

    // 7. Verify locally
    debug!("Verifying proof");
    match verifier.verify(&token, &proof) {
        VerificationStatus::Success => {
            debug!("Verification passed");

            if let Some(r) = recorder {
                debug!("Recording verified decision");
                r.record(&token, &proof)?;
            }

            // 8. Execute via adapter
            debug!("Executing action");
            let result = executor.execute(&token, &proof)?;
            
            if result.success {
                info!(message = ?result.message, "Execution successful");
            } else {
                warn!(message = ?result.message, "Execution completed with failure status");
            }
            
            Ok(result)
        }
        VerificationStatus::Failure(msg) => {
            error!(reason = %msg, "Verification failed");
            Err(MprdError::ZkError(msg))
        }
    }
}

/// Execute a single MPRD decision cycle without recording.
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
    run_once_internal(
        state_provider,
        proposer,
        policy_engine,
        selector,
        token_factory,
        attestor,
        verifier,
        executor,
        None,
        policy_hash,
    )
}

/// Execute a single MPRD decision cycle and record verified decisions.
pub fn run_once_with_recorder<P, Pr, PE, S, TF, ZA, ZV, E>(
    state_provider: &P,
    proposer: &Pr,
    policy_engine: &PE,
    selector: &S,
    token_factory: &TF,
    attestor: &ZA,
    verifier: &ZV,
    executor: &E,
    recorder: &dyn DecisionRecorder,
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
    run_once_internal(
        state_provider,
        proposer,
        policy_engine,
        selector,
        token_factory,
        attestor,
        verifier,
        executor,
        Some(recorder),
        policy_hash,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash32, RuleVerdict, Score, Value};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

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

    struct RecordingRecorder {
        called: Arc<AtomicBool>,
    }

    impl DecisionRecorder for RecordingRecorder {
        fn record(&self, _token: &DecisionToken, _proof: &ProofBundle) -> Result<()> {
            self.called.store(true, Ordering::SeqCst);
            Ok(())
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

    #[test]
    fn run_once_with_recorder_invokes_recorder() {
        let state_provider = DummyStateProvider;
        let proposer = DummyProposer;
        let policy_engine = AllowAllPolicyEngine;
        let selector = DummySelector;
        let token_factory = DummyTokenFactory;
        let attestor = DummyAttestor;
        let verifier = DummyVerifier;
        let executor = DummyExecutor;
        let policy_hash = Hash32([9u8; 32]);

        let called = Arc::new(AtomicBool::new(false));
        let recorder = RecordingRecorder { called: called.clone() };

        let result = run_once_with_recorder(
            &state_provider,
            &proposer,
            &policy_engine,
            &selector,
            &token_factory,
            &attestor,
            &verifier,
            &executor,
            &recorder,
            &policy_hash,
        )
        .expect("run_once_with_recorder should succeed in dummy pipeline");

        assert!(result.success);
        assert_eq!(result.message.as_deref(), Some("ok"));
        assert!(called.load(Ordering::SeqCst));
    }
}

