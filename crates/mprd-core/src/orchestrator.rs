use crate::metrics::{self, MprdMetrics, StageTimer};
use crate::validation::{canonicalize_candidates_v1, canonicalize_state_snapshot_v1};
use crate::{
    CandidateAction, Decision, DecisionToken, ExecutionResult, ExecutorAdapter, MprdError,
    PolicyEngine, PolicyHash, PolicyRef, ProofBundle, Proposer, Result, Selector, StateProvider,
    StateSnapshot, VerificationStatus, VerifiedBundle, ZkAttestor, ZkLocalVerifier,
};
use tracing::{debug, error, info, instrument, warn, Span};

/// Factory responsible for constructing signed decision tokens from
/// decisions and state snapshots.
pub trait DecisionTokenFactory {
    /// Preconditions:
    /// - `decision` was produced by a compliant `Selector`.
    /// - `state` is the same snapshot used during selection.
    ///
    /// Postconditions:
    /// - Returned token binds `policy_hash`, `state_hash` and
    ///   `chosen_action_hash` consistently.
    fn create(
        &self,
        decision: &Decision,
        state: &StateSnapshot,
        nonce_or_tx_hash: Option<crate::NonceHash>,
        policy_ref: &PolicyRef,
    ) -> Result<DecisionToken>;
}

/// Optional hook for recording verified decisions (e.g., on-chain/Tau anchoring).
pub trait DecisionRecorder {
    /// Called after ZK verification succeeds but before execution.
    fn record(&self, token: &DecisionToken, proof: &ProofBundle) -> Result<()>;
}

/// Optional hook for recording operator-facing decision detail.
///
/// This is intended for local observability and UX (operator console), not as a trust anchor.
///
/// Semantics:
/// - Called only after local verification succeeds.
/// - Implementations MUST be bounded and MUST NOT introduce unbounded work on the hot path.
/// - Errors are treated as best-effort (they are logged, but do not fail the pipeline).
pub trait DecisionAuditRecorder {
    /// Called after ZK verification succeeds but before execution.
    fn record_verified_decision(
        &self,
        token: &DecisionToken,
        proof: &ProofBundle,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
        verdicts: &[crate::RuleVerdict],
        decision: &Decision,
    ) -> Result<()>;
}

pub struct RunOnceInputs<'a, P, Pr, PE, S, TF, ZA, ZV, E> {
    pub state_provider: &'a P,
    pub proposer: &'a Pr,
    pub policy_engine: &'a PE,
    pub selector: &'a S,
    pub token_factory: &'a TF,
    pub attestor: &'a ZA,
    pub verifier: &'a ZV,
    pub executor: &'a E,
    pub policy_hash: &'a PolicyHash,
    /// Verifier-trusted policy authorization context (epoch/root).
    pub policy_ref: PolicyRef,
    /// Optional caller-provided nonce (recommended for production).
    pub nonce_or_tx_hash: Option<crate::NonceHash>,
    /// Optional metrics sink for latency/counters (no effect when `None`).
    pub metrics: Option<&'a MprdMetrics>,
    /// Optional audit recorder for operator UX (best-effort).
    pub audit_recorder: Option<&'a dyn DecisionAuditRecorder>,
}

pub struct RunOnceInputsWithRecorder<'a, P, Pr, PE, S, TF, ZA, ZV, E> {
    pub inputs: RunOnceInputs<'a, P, Pr, PE, S, TF, ZA, ZV, E>,
    pub recorder: &'a dyn DecisionRecorder,
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
    skip(inputs, recorder),
    fields(
        policy_hash = %hex::encode(&inputs.policy_hash.0[..8]),
        candidates = tracing::field::Empty,
        allowed = tracing::field::Empty,
        chosen_index = tracing::field::Empty,
    )
)]
fn run_once_internal<P, Pr, PE, S, TF, ZA, ZV, E>(
    inputs: RunOnceInputs<'_, P, Pr, PE, S, TF, ZA, ZV, E>,
    recorder: Option<&dyn DecisionRecorder>,
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
    // SECURITY BOUNDARY (pipeline): this function is the single place where an action becomes a
    // side effect. The pipeline is designed to be fail-closed:
    // - Any error from state/propose/evaluate/select/token/attest/verify/record/execute aborts.
    // - Execution is only attempted after local verification returns Success.
    //
    // Ordering invariant:
    // - Create token -> attest -> verify -> (optional) record -> execute.
    // This ensures any recorder observes only verified proofs, and the executor only runs on
    // verified inputs.

    let _total_timer = inputs
        .metrics
        .map(|m| StageTimer::start(&m.total_pipeline_latency));

    fn error_code(e: &MprdError) -> &'static str {
        match e {
            MprdError::InvalidInput(_) => "invalid_input",
            MprdError::BoundedValueExceeded(_) => "bounded_value_exceeded",
            MprdError::PolicyEvaluationFailed(_) => "policy_evaluation_failed",
            MprdError::SelectionFailed(_) => "selection_failed",
            MprdError::ZkError(_) => "zk_error",
            MprdError::ExecutionError(_) => "execution_error",
            MprdError::PolicyHashCollision { .. } => "policy_hash_collision",
            MprdError::PolicyNotFound { .. } => "policy_not_found",
            MprdError::TokenExpired { .. } => "token_expired",
            MprdError::TokenFromFuture { .. } => "token_from_future",
            MprdError::NonceReplay { .. } => "nonce_replay",
            MprdError::CryptoError(_) => "crypto_error",
            MprdError::SignatureInvalid(_) => "signature_invalid",
            MprdError::ConfigError(_) => "config_error",
        }
    }

    fn record_stage_failure(metrics: Option<&MprdMetrics>, stage: &'static str, err: &MprdError) {
        if let Some(m) = metrics {
            m.inc_failure_reason(&format!("stage.{stage}.{}", error_code(err)));
            match stage {
                "select" => m.selection_failures.inc(),
                "execute" => m.execution_failures.inc(),
                _ => {}
            }
        }
        error!(
            stage = stage,
            code = error_code(err),
            error = %err,
            "Pipeline stage failed (fail-closed)"
        );
    }

    fn classify_verification_failure(msg: &str) -> &'static str {
        // Keep this mapping stable. It's intentionally conservative and only covers
        // verifier-returned failures that are security-relevant and common.
        if msg.starts_with("registry_state unavailable") {
            "registry_state_unavailable"
        } else if msg.starts_with("invalid guest image manifest") {
            "invalid_guest_image_manifest"
        } else if msg.contains("policy_hash not authorized") {
            "policy_not_authorized"
        } else if msg.contains("policy_epoch mismatch") {
            "policy_epoch_mismatch"
        } else if msg.contains("registry_root mismatch") {
            "registry_root_mismatch"
        } else if msg.contains("image_id") && msg.contains("mismatch") {
            "image_id_mismatch"
        } else if msg.contains("journal_version") {
            "journal_version"
        } else if msg.contains("encoding") && msg.contains("id") {
            "encoding_id"
        } else if msg.contains("nonce_or_tx_hash") {
            "nonce_or_tx_hash"
        } else if msg.contains("limits_hash") {
            "limits_hash"
        } else if msg.contains("decision_commitment") {
            "decision_commitment"
        } else {
            "unknown"
        }
    }

    // 1. Observe state
    debug!("Capturing state snapshot");
    let state = if let Some(m) = inputs.metrics {
        metrics::timed_state(m, || inputs.state_provider.snapshot())
    } else {
        inputs.state_provider.snapshot()
    }
    .inspect_err(|e| record_stage_failure(inputs.metrics, "state", e))?;
    let state = canonicalize_state_snapshot_v1(state)
        .inspect_err(|e| record_stage_failure(inputs.metrics, "state", e))?;
    debug!(
        state_hash = %hex::encode(&state.state_hash.0[..8]),
        "State captured"
    );

    // 2. Propose candidates
    debug!("Proposing candidates");
    let candidates: Vec<CandidateAction> = if let Some(m) = inputs.metrics {
        metrics::timed_propose(m, || inputs.proposer.propose(&state))
    } else {
        inputs.proposer.propose(&state)
    }
    .inspect_err(|e| record_stage_failure(inputs.metrics, "propose", e))?;
    let candidates = canonicalize_candidates_v1(candidates)
        .inspect_err(|e| record_stage_failure(inputs.metrics, "propose", e))?;
    Span::current().record("candidates", candidates.len());
    debug!(num_candidates = candidates.len(), "Candidates proposed");

    // 3. Evaluate with policy engine
    debug!("Evaluating policy");
    let verdicts = if let Some(m) = inputs.metrics {
        metrics::timed_evaluate(m, || {
            inputs
                .policy_engine
                .evaluate(inputs.policy_hash, &state, &candidates)
        })
    } else {
        inputs
            .policy_engine
            .evaluate(inputs.policy_hash, &state, &candidates)
    }
    .inspect_err(|e| record_stage_failure(inputs.metrics, "evaluate", e))?;
    let allowed_count = verdicts.iter().filter(|v| v.allowed).count();
    Span::current().record("allowed", allowed_count);
    if let Some(m) = inputs.metrics {
        m.actions_allowed.inc_by(allowed_count as u64);
        m.actions_denied
            .inc_by((candidates.len() - allowed_count) as u64);
    }
    debug!(
        allowed = allowed_count,
        denied = candidates.len() - allowed_count,
        "Policy evaluated"
    );

    // 4. Select deterministically
    debug!("Selecting action");
    let decision = if let Some(m) = inputs.metrics {
        metrics::timed_select(m, || {
            inputs
                .selector
                .select(inputs.policy_hash, &state, &candidates, &verdicts)
        })
    } else {
        inputs
            .selector
            .select(inputs.policy_hash, &state, &candidates, &verdicts)
    }
    .inspect_err(|e| record_stage_failure(inputs.metrics, "select", e))?;
    Span::current().record("chosen_index", decision.chosen_index);
    info!(
        chosen_index = decision.chosen_index,
        action_type = %decision.chosen_action.action_type,
        "Action selected"
    );

    enforce_selector_contract(&decision, &candidates, &verdicts)
        .inspect_err(|e| record_stage_failure(inputs.metrics, "select_contract", e))?;

    // 5. Create decision token
    debug!("Creating decision token");
    let token = inputs
        .token_factory
        .create(
            &decision,
            &state,
            inputs.nonce_or_tx_hash,
            &inputs.policy_ref,
        )
        .inspect_err(|e| record_stage_failure(inputs.metrics, "token", e))?;
    debug!(nonce = %hex::encode(&token.nonce_or_tx_hash.0[..8]), "Token created");

    // 6. Attest with ZK
    debug!("Generating attestation");
    let proof: ProofBundle = if let Some(m) = inputs.metrics {
        metrics::timed_attest(m, || {
            inputs
                .attestor
                .attest(&token, &decision, &state, &candidates)
        })
    } else {
        inputs
            .attestor
            .attest(&token, &decision, &state, &candidates)
    }
    .inspect_err(|e| record_stage_failure(inputs.metrics, "attest", e))?;
    debug!("Attestation complete");

    // 7. Verify locally
    debug!("Verifying proof");
    let status = if let Some(m) = inputs.metrics {
        metrics::timed_verify(m, || inputs.verifier.verify(&token, &proof))
    } else {
        inputs.verifier.verify(&token, &proof)
    };

    match status {
        VerificationStatus::Success => {
            debug!("Verification passed");

            if let Some(a) = inputs.audit_recorder {
                // Best-effort: operator UX should not block execution.
                if let Err(e) = a.record_verified_decision(
                    &token,
                    &proof,
                    &state,
                    &candidates,
                    &verdicts,
                    &decision,
                ) {
                    warn!(error = %e, "Audit recorder failed (continuing)");
                    if let Some(m) = inputs.metrics {
                        m.inc_failure_reason("audit_recorder.failed");
                    }
                }
            }

            if let Some(r) = recorder {
                // SECURITY: record only after verification succeeds and before execution.
                debug!("Recording verified decision");
                r.record(&token, &proof)
                    .inspect_err(|e| record_stage_failure(inputs.metrics, "record", e))?;
            }

            // 8. Execute via adapter
            debug!("Executing action");
            let verified = VerifiedBundle::new(&token, &proof);
            let result = if let Some(m) = inputs.metrics {
                metrics::timed_execute(m, || inputs.executor.execute(&verified))
            } else {
                inputs.executor.execute(&verified)
            }
            .inspect_err(|e| record_stage_failure(inputs.metrics, "execute", e))?;

            if result.success {
                info!(message = ?result.message, "Execution successful");
            } else {
                warn!(message = ?result.message, "Execution completed with failure status");
                if let Some(m) = inputs.metrics {
                    m.execution_failures.inc();
                    m.inc_failure_reason("execution.result_failure");
                }
            }

            Ok(result)
        }
        VerificationStatus::Failure(msg) => {
            let reason_code = classify_verification_failure(&msg);
            error!(reason_code = reason_code, reason = %msg, "Verification failed");
            if let Some(m) = inputs.metrics {
                m.verification_failures.inc();
                m.inc_failure_reason(&format!("verify.{reason_code}"));
            }
            Err(MprdError::ZkError(msg))
        }
    }
}

/// Execute a single MPRD decision cycle without recording.
pub fn run_once<P, Pr, PE, S, TF, ZA, ZV, E>(
    inputs: RunOnceInputs<'_, P, Pr, PE, S, TF, ZA, ZV, E>,
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
    run_once_internal(inputs, None)
}

/// Execute a single MPRD decision cycle and record verified decisions.
pub fn run_once_with_recorder<P, Pr, PE, S, TF, ZA, ZV, E>(
    inputs: RunOnceInputsWithRecorder<'_, P, Pr, PE, S, TF, ZA, ZV, E>,
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
    run_once_internal(inputs.inputs, Some(inputs.recorder))
}

fn enforce_selector_contract(
    decision: &Decision,
    candidates: &[CandidateAction],
    verdicts: &[crate::RuleVerdict],
) -> Result<()> {
    if candidates.len() != verdicts.len() {
        return Err(MprdError::InvalidInput(
            "selector contract violated: candidates/verdicts length mismatch".into(),
        ));
    }
    let idx = decision.chosen_index;
    if idx >= candidates.len() {
        return Err(MprdError::InvalidInput(
            "selector contract violated: chosen_index out of bounds".into(),
        ));
    }
    let chosen = &candidates[idx];
    if chosen.candidate_hash != decision.chosen_action.candidate_hash {
        return Err(MprdError::InvalidInput(
            "selector contract violated: chosen_action does not match candidates[chosen_index]"
                .into(),
        ));
    }
    if !verdicts[idx].allowed {
        return Err(MprdError::InvalidInput(
            "selector contract violated: chosen action is not allowed".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ltlf;
    use crate::{Hash32, RuleVerdict, Score, Value};
    use proptest::prelude::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    type CallLog = Arc<Mutex<Vec<&'static str>>>;

    fn new_call_log() -> CallLog {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn push_call(log: &CallLog, call: &'static str) {
        log.lock().expect("call log").push(call);
    }

    fn call_log_snapshot(log: &CallLog) -> Vec<&'static str> {
        log.lock().expect("call log").clone()
    }

    fn calls_to_trace(calls: &[&'static str]) -> Vec<ltlf::Valuation> {
        calls
            .iter()
            .map(|c| {
                let mut v = ltlf::Valuation::new();
                v.insert((*c).to_string());
                v
            })
            .collect()
    }

    /// Security-oriented temporal spec for the orchestrator pipeline ordering.
    ///
    /// This checks the *gap* that is usually only described in comments:
    /// multi-step ordering invariants like "verify before execute" and "record (if present) before execute".
    fn assert_pipeline_temporal_spec(calls: &[&'static str]) {
        let spec = ltlf::Formula::and(vec![
            // Core CBC pipeline boundary:
            ltlf::Formula::precedence("token", "attest"),
            ltlf::Formula::precedence("attest", "verify"),
            ltlf::Formula::precedence("verify_ok", "execute"),
            // Record is optional; if it happens, it must happen before execute.
            ltlf::Formula::optional_precedence("record", "execute"),
            // Audit is optional; if it happens, it must be after verify and before record/execute.
            ltlf::Formula::precedence("verify_ok", "audit"),
            ltlf::Formula::optional_precedence("audit", "record"),
            ltlf::Formula::optional_precedence("audit", "execute"),
            // Record (if present) is never allowed before verify.
            ltlf::Formula::precedence("verify_ok", "record"),
            // Safety: if verification fails, execute/record must never happen.
            // G(verify_fail -> G(!execute))
            ltlf::Formula::always(ltlf::Formula::or(vec![
                ltlf::Formula::not_atom("verify_fail"),
                ltlf::Formula::always(ltlf::Formula::not_atom("execute")),
            ])),
            // G(verify_fail -> G(!record))
            ltlf::Formula::always(ltlf::Formula::or(vec![
                ltlf::Formula::not_atom("verify_fail"),
                ltlf::Formula::always(ltlf::Formula::not_atom("record")),
            ])),
        ]);
        let trace = calls_to_trace(calls);
        assert!(
            ltlf::eval_trace(spec, &trace),
            "temporal spec violated by call trace: {calls:?}"
        );
    }

    fn failure_reason_count(metrics: &MprdMetrics, reason: &str) -> u64 {
        let json = metrics.to_json();
        let reasons = match json.get("failure_reasons").and_then(|v| v.as_array()) {
            Some(v) => v,
            None => return 0,
        };

        for entry in reasons {
            let items = match entry.as_array() {
                Some(v) => v,
                None => continue,
            };
            if items.len() != 2 {
                continue;
            }
            let key = match items[0].as_str() {
                Some(v) => v,
                None => continue,
            };
            if key != reason {
                continue;
            }
            return items[1].as_u64().unwrap_or(0);
        }

        0
    }

    struct LoggedStateProvider {
        log: CallLog,
        state: StateSnapshot,
    }

    impl StateProvider for LoggedStateProvider {
        fn snapshot(&self) -> Result<StateSnapshot> {
            push_call(&self.log, "state");
            Ok(self.state.clone())
        }
    }

    struct LoggedProposer {
        log: CallLog,
        candidates: Vec<CandidateAction>,
    }

    impl Proposer for LoggedProposer {
        fn propose(&self, _state: &StateSnapshot) -> Result<Vec<CandidateAction>> {
            push_call(&self.log, "propose");
            Ok(self.candidates.clone())
        }
    }

    struct LoggedPolicyEngine {
        log: CallLog,
    }

    impl PolicyEngine for LoggedPolicyEngine {
        fn evaluate(
            &self,
            _policy_hash: &PolicyHash,
            _state: &StateSnapshot,
            candidates: &[CandidateAction],
        ) -> Result<Vec<RuleVerdict>> {
            push_call(&self.log, "evaluate");
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

    struct LoggedSelector {
        log: CallLog,
    }

    impl Selector for LoggedSelector {
        fn select(
            &self,
            policy_hash: &PolicyHash,
            _state: &StateSnapshot,
            candidates: &[CandidateAction],
            _verdicts: &[RuleVerdict],
        ) -> Result<Decision> {
            push_call(&self.log, "select");
            Ok(Decision {
                chosen_index: 0,
                chosen_action: candidates[0].clone(),
                policy_hash: policy_hash.clone(),
                decision_commitment: dummy_hash(5),
            })
        }
    }

    struct LoggedTokenFactory {
        log: CallLog,
    }

    impl DecisionTokenFactory for LoggedTokenFactory {
        fn create(
            &self,
            decision: &Decision,
            state: &StateSnapshot,
            nonce_or_tx_hash: Option<crate::NonceHash>,
            policy_ref: &PolicyRef,
        ) -> Result<DecisionToken> {
            push_call(&self.log, "token");
            Ok(DecisionToken {
                policy_hash: decision.policy_hash.clone(),
                policy_ref: policy_ref.clone(),
                state_hash: state.state_hash.clone(),
                state_ref: state.state_ref.clone(),
                chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
                nonce_or_tx_hash: nonce_or_tx_hash.unwrap_or_else(|| dummy_hash(3)),
                timestamp_ms: 0,
                signature: vec![],
            })
        }
    }

    struct LoggedAttestor {
        log: CallLog,
    }

    impl ZkAttestor for LoggedAttestor {
        fn attest(
            &self,
            token: &DecisionToken,
            decision: &Decision,
            state: &StateSnapshot,
            _candidates: &[CandidateAction],
        ) -> Result<ProofBundle> {
            push_call(&self.log, "attest");
            let mut metadata = HashMap::new();
            metadata.insert(
                "nonce_or_tx_hash".into(),
                hex::encode(token.nonce_or_tx_hash.0),
            );
            Ok(ProofBundle {
                policy_hash: decision.policy_hash.clone(),
                state_hash: state.state_hash.clone(),
                candidate_set_hash: dummy_hash(4),
                chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
                limits_hash: crate::limits::limits_hash_v1(&[]),
                limits_bytes: vec![],
                chosen_action_preimage: crate::hash::candidate_hash_preimage(
                    &decision.chosen_action,
                ),
                risc0_receipt: vec![],
                attestation_metadata: metadata,
            })
        }
    }

    struct LoggedVerifier {
        log: CallLog,
        status: VerificationStatus,
    }

    impl ZkLocalVerifier for LoggedVerifier {
        fn verify(&self, _token: &DecisionToken, _proof: &ProofBundle) -> VerificationStatus {
            push_call(&self.log, "verify");
            match &self.status {
                VerificationStatus::Success => push_call(&self.log, "verify_ok"),
                VerificationStatus::Failure(_) => push_call(&self.log, "verify_fail"),
            }
            self.status.clone()
        }
    }

    struct LoggedAuditRecorder {
        log: CallLog,
        fail: bool,
    }

    impl DecisionAuditRecorder for LoggedAuditRecorder {
        fn record_verified_decision(
            &self,
            _token: &DecisionToken,
            _proof: &ProofBundle,
            _state: &StateSnapshot,
            _candidates: &[CandidateAction],
            _verdicts: &[crate::RuleVerdict],
            _decision: &Decision,
        ) -> Result<()> {
            push_call(&self.log, "audit");
            if self.fail {
                return Err(MprdError::ExecutionError("audit recorder failed".into()));
            }
            Ok(())
        }
    }

    struct LoggedRecorder {
        log: CallLog,
    }

    impl DecisionRecorder for LoggedRecorder {
        fn record(&self, _token: &DecisionToken, _proof: &ProofBundle) -> Result<()> {
            push_call(&self.log, "record");
            Ok(())
        }
    }

    struct LoggedExecutor {
        log: CallLog,
    }

    impl ExecutorAdapter for LoggedExecutor {
        fn execute(&self, _verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
            push_call(&self.log, "execute");
            Ok(ExecutionResult {
                success: true,
                message: Some("ok".into()),
            })
        }
    }

    struct DummyStateProvider;

    impl StateProvider for DummyStateProvider {
        fn snapshot(&self) -> Result<StateSnapshot> {
            Ok(StateSnapshot {
                fields: HashMap::new(),
                policy_inputs: HashMap::new(),
                state_hash: dummy_hash(1),
                state_ref: crate::StateRef::unknown(),
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
        fn create(
            &self,
            decision: &Decision,
            state: &StateSnapshot,
            nonce_or_tx_hash: Option<crate::NonceHash>,
            policy_ref: &PolicyRef,
        ) -> Result<DecisionToken> {
            Ok(DecisionToken {
                policy_hash: decision.policy_hash.clone(),
                policy_ref: policy_ref.clone(),
                state_hash: state.state_hash.clone(),
                state_ref: state.state_ref.clone(),
                chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
                nonce_or_tx_hash: nonce_or_tx_hash.unwrap_or_else(|| dummy_hash(3)),
                timestamp_ms: 0,
                signature: vec![],
            })
        }
    }

    struct DummyAttestor;

    impl ZkAttestor for DummyAttestor {
        fn attest(
            &self,
            token: &DecisionToken,
            decision: &Decision,
            state: &StateSnapshot,
            _candidates: &[CandidateAction],
        ) -> Result<ProofBundle> {
            let mut metadata = HashMap::new();
            metadata.insert(
                "nonce_or_tx_hash".into(),
                hex::encode(token.nonce_or_tx_hash.0),
            );
            Ok(ProofBundle {
                policy_hash: decision.policy_hash.clone(),
                state_hash: state.state_hash.clone(),
                candidate_set_hash: dummy_hash(4),
                chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
                limits_hash: crate::limits::limits_hash_v1(&[]),
                limits_bytes: vec![],
                chosen_action_preimage: crate::hash::candidate_hash_preimage(
                    &decision.chosen_action,
                ),
                risc0_receipt: vec![],
                attestation_metadata: metadata,
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
        fn execute(&self, _verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
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
        let policy_ref = PolicyRef {
            policy_epoch: 1,
            registry_root: Hash32([8u8; 32]),
        };

        let result = run_once(RunOnceInputs {
            state_provider: &state_provider,
            proposer: &proposer,
            policy_engine: &policy_engine,
            selector: &selector,
            token_factory: &token_factory,
            attestor: &attestor,
            verifier: &verifier,
            executor: &executor,
            policy_hash: &policy_hash,
            policy_ref: policy_ref.clone(),
            nonce_or_tx_hash: None,
            metrics: None,
            audit_recorder: None,
        })
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
        let policy_ref = PolicyRef {
            policy_epoch: 1,
            registry_root: Hash32([8u8; 32]),
        };

        let called = Arc::new(AtomicBool::new(false));
        let recorder = RecordingRecorder {
            called: called.clone(),
        };

        let result = run_once_with_recorder(RunOnceInputsWithRecorder {
            inputs: RunOnceInputs {
                state_provider: &state_provider,
                proposer: &proposer,
                policy_engine: &policy_engine,
                selector: &selector,
                token_factory: &token_factory,
                attestor: &attestor,
                verifier: &verifier,
                executor: &executor,
                policy_hash: &policy_hash,
                policy_ref,
                nonce_or_tx_hash: None,
                metrics: None,
                audit_recorder: None,
            },
            recorder: &recorder,
        })
        .expect("run_once_with_recorder should succeed in dummy pipeline");

        assert!(result.success);
        assert_eq!(result.message.as_deref(), Some("ok"));
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn run_once_records_actions_allowed_and_denied_counts() {
        struct TwoCandidateProposer;

        impl Proposer for TwoCandidateProposer {
            fn propose(&self, _state: &StateSnapshot) -> Result<Vec<CandidateAction>> {
                Ok(vec![
                    CandidateAction {
                        action_type: "A".into(),
                        params: HashMap::new(),
                        score: Score(1),
                        candidate_hash: dummy_hash(2),
                    },
                    CandidateAction {
                        action_type: "B".into(),
                        params: HashMap::new(),
                        score: Score(1),
                        candidate_hash: dummy_hash(3),
                    },
                ])
            }
        }

        struct MixedPolicyEngine;

        impl PolicyEngine for MixedPolicyEngine {
            fn evaluate(
                &self,
                _policy_hash: &PolicyHash,
                _state: &StateSnapshot,
                candidates: &[CandidateAction],
            ) -> Result<Vec<RuleVerdict>> {
                assert_eq!(candidates.len(), 2);
                Ok(vec![
                    RuleVerdict {
                        allowed: true,
                        reasons: vec![],
                        limits: HashMap::new(),
                    },
                    RuleVerdict {
                        allowed: false,
                        reasons: vec!["deny".into()],
                        limits: HashMap::new(),
                    },
                ])
            }
        }

        let metrics = MprdMetrics::new();
        let state_provider = DummyStateProvider;
        let proposer = TwoCandidateProposer;
        let policy_engine = MixedPolicyEngine;
        let selector = DummySelector;
        let token_factory = DummyTokenFactory;
        let attestor = DummyAttestor;
        let verifier = DummyVerifier;
        let executor = DummyExecutor;
        let policy_hash = dummy_hash(9);
        let policy_ref = PolicyRef {
            policy_epoch: 1,
            registry_root: dummy_hash(8),
        };

        let result = run_once(RunOnceInputs {
            state_provider: &state_provider,
            proposer: &proposer,
            policy_engine: &policy_engine,
            selector: &selector,
            token_factory: &token_factory,
            attestor: &attestor,
            verifier: &verifier,
            executor: &executor,
            policy_hash: &policy_hash,
            policy_ref,
            nonce_or_tx_hash: None,
            metrics: Some(&metrics),
            audit_recorder: None,
        })
        .expect("success");

        assert!(result.success);
        assert_eq!(metrics.actions_allowed.get(), 1);
        assert_eq!(metrics.actions_denied.get(), 1);
    }

    #[test]
    fn run_once_records_selection_failure_reason_and_counter() {
        struct FailingSelector;

        impl Selector for FailingSelector {
            fn select(
                &self,
                _policy_hash: &PolicyHash,
                _state: &StateSnapshot,
                _candidates: &[CandidateAction],
                _verdicts: &[RuleVerdict],
            ) -> Result<Decision> {
                Err(MprdError::SelectionFailed("boom".into()))
            }
        }

        let metrics = MprdMetrics::new();
        let state_provider = DummyStateProvider;
        let proposer = DummyProposer;
        let policy_engine = AllowAllPolicyEngine;
        let selector = FailingSelector;
        let token_factory = DummyTokenFactory;
        let attestor = DummyAttestor;
        let verifier = DummyVerifier;
        let executor = DummyExecutor;
        let policy_hash = dummy_hash(9);
        let policy_ref = PolicyRef {
            policy_epoch: 1,
            registry_root: dummy_hash(8),
        };

        let err = run_once(RunOnceInputs {
            state_provider: &state_provider,
            proposer: &proposer,
            policy_engine: &policy_engine,
            selector: &selector,
            token_factory: &token_factory,
            attestor: &attestor,
            verifier: &verifier,
            executor: &executor,
            policy_hash: &policy_hash,
            policy_ref,
            nonce_or_tx_hash: None,
            metrics: Some(&metrics),
            audit_recorder: None,
        })
        .expect_err("should fail");

        assert!(matches!(err, MprdError::SelectionFailed(_)));
        assert_eq!(metrics.selection_failures.get(), 1);
        assert_eq!(
            failure_reason_count(&metrics, "stage.select.selection_failed"),
            1
        );
    }

    #[test]
    fn run_once_records_execution_failure_reason_and_counter() {
        struct FailingExecutor;

        impl ExecutorAdapter for FailingExecutor {
            fn execute(&self, _verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
                Err(MprdError::ExecutionError("boom".into()))
            }
        }

        let metrics = MprdMetrics::new();
        let state_provider = DummyStateProvider;
        let proposer = DummyProposer;
        let policy_engine = AllowAllPolicyEngine;
        let selector = DummySelector;
        let token_factory = DummyTokenFactory;
        let attestor = DummyAttestor;
        let verifier = DummyVerifier;
        let executor = FailingExecutor;
        let policy_hash = dummy_hash(9);
        let policy_ref = PolicyRef {
            policy_epoch: 1,
            registry_root: dummy_hash(8),
        };

        let err = run_once(RunOnceInputs {
            state_provider: &state_provider,
            proposer: &proposer,
            policy_engine: &policy_engine,
            selector: &selector,
            token_factory: &token_factory,
            attestor: &attestor,
            verifier: &verifier,
            executor: &executor,
            policy_hash: &policy_hash,
            policy_ref,
            nonce_or_tx_hash: None,
            metrics: Some(&metrics),
            audit_recorder: None,
        })
        .expect_err("should fail");

        assert!(matches!(err, MprdError::ExecutionError(_)));
        assert_eq!(metrics.execution_failures.get(), 1);
        assert_eq!(
            failure_reason_count(&metrics, "stage.execute.execution_error"),
            1
        );
    }

    #[test]
    fn run_once_records_verification_failure_reason_image_id_mismatch() {
        struct FailingVerifier {
            msg: &'static str,
        }

        impl ZkLocalVerifier for FailingVerifier {
            fn verify(&self, _token: &DecisionToken, _proof: &ProofBundle) -> VerificationStatus {
                VerificationStatus::Failure(self.msg.to_string())
            }
        }

        let metrics = MprdMetrics::new();
        let state_provider = DummyStateProvider;
        let proposer = DummyProposer;
        let policy_engine = AllowAllPolicyEngine;
        let selector = DummySelector;
        let token_factory = DummyTokenFactory;
        let attestor = DummyAttestor;
        let verifier = FailingVerifier {
            msg: "image_id mismatch",
        };
        let executor = DummyExecutor;
        let policy_hash = dummy_hash(9);
        let policy_ref = PolicyRef {
            policy_epoch: 1,
            registry_root: dummy_hash(8),
        };

        let err = run_once(RunOnceInputs {
            state_provider: &state_provider,
            proposer: &proposer,
            policy_engine: &policy_engine,
            selector: &selector,
            token_factory: &token_factory,
            attestor: &attestor,
            verifier: &verifier,
            executor: &executor,
            policy_hash: &policy_hash,
            policy_ref,
            nonce_or_tx_hash: None,
            metrics: Some(&metrics),
            audit_recorder: None,
        })
        .expect_err("should fail");

        assert!(matches!(err, MprdError::ZkError(_)));
        assert_eq!(metrics.verification_failures.get(), 1);
        assert_eq!(
            failure_reason_count(&metrics, "verify.image_id_mismatch"),
            1
        );
    }

    #[test]
    fn run_once_records_verification_failure_reason_unknown_when_partial_image_id_match() {
        struct FailingVerifier {
            msg: &'static str,
        }

        impl ZkLocalVerifier for FailingVerifier {
            fn verify(&self, _token: &DecisionToken, _proof: &ProofBundle) -> VerificationStatus {
                VerificationStatus::Failure(self.msg.to_string())
            }
        }

        let metrics = MprdMetrics::new();
        let state_provider = DummyStateProvider;
        let proposer = DummyProposer;
        let policy_engine = AllowAllPolicyEngine;
        let selector = DummySelector;
        let token_factory = DummyTokenFactory;
        let attestor = DummyAttestor;
        let verifier = FailingVerifier {
            msg: "image_id present",
        };
        let executor = DummyExecutor;
        let policy_hash = dummy_hash(9);
        let policy_ref = PolicyRef {
            policy_epoch: 1,
            registry_root: dummy_hash(8),
        };

        let err = run_once(RunOnceInputs {
            state_provider: &state_provider,
            proposer: &proposer,
            policy_engine: &policy_engine,
            selector: &selector,
            token_factory: &token_factory,
            attestor: &attestor,
            verifier: &verifier,
            executor: &executor,
            policy_hash: &policy_hash,
            policy_ref,
            nonce_or_tx_hash: None,
            metrics: Some(&metrics),
            audit_recorder: None,
        })
        .expect_err("should fail");

        assert!(matches!(err, MprdError::ZkError(_)));
        assert_eq!(metrics.verification_failures.get(), 1);
        assert_eq!(failure_reason_count(&metrics, "verify.unknown"), 1);
    }

    #[test]
    fn run_once_records_verification_failure_reason_unknown_when_partial_encoding_match() {
        struct FailingVerifier {
            msg: &'static str,
        }

        impl ZkLocalVerifier for FailingVerifier {
            fn verify(&self, _token: &DecisionToken, _proof: &ProofBundle) -> VerificationStatus {
                VerificationStatus::Failure(self.msg.to_string())
            }
        }

        let metrics = MprdMetrics::new();
        let state_provider = DummyStateProvider;
        let proposer = DummyProposer;
        let policy_engine = AllowAllPolicyEngine;
        let selector = DummySelector;
        let token_factory = DummyTokenFactory;
        let attestor = DummyAttestor;
        let verifier = FailingVerifier {
            msg: "encoding mismatch",
        };
        let executor = DummyExecutor;
        let policy_hash = dummy_hash(9);
        let policy_ref = PolicyRef {
            policy_epoch: 1,
            registry_root: dummy_hash(8),
        };

        let err = run_once(RunOnceInputs {
            state_provider: &state_provider,
            proposer: &proposer,
            policy_engine: &policy_engine,
            selector: &selector,
            token_factory: &token_factory,
            attestor: &attestor,
            verifier: &verifier,
            executor: &executor,
            policy_hash: &policy_hash,
            policy_ref,
            nonce_or_tx_hash: None,
            metrics: Some(&metrics),
            audit_recorder: None,
        })
        .expect_err("should fail");

        assert!(matches!(err, MprdError::ZkError(_)));
        assert_eq!(metrics.verification_failures.get(), 1);
        assert_eq!(failure_reason_count(&metrics, "verify.unknown"), 1);
    }

    #[test]
    fn run_once_fails_closed_when_state_canonicalization_fails() {
        let log = new_call_log();
        let mut fields = HashMap::new();
        for i in 0..=crate::validation::MAX_STATE_FIELDS_V1 {
            fields.insert(format!("k{i}"), Value::UInt(1));
        }
        let state_provider = LoggedStateProvider {
            log: log.clone(),
            state: StateSnapshot {
                fields,
                policy_inputs: HashMap::new(),
                state_hash: dummy_hash(1),
                state_ref: crate::StateRef::unknown(),
            },
        };
        let proposer = LoggedProposer {
            log: log.clone(),
            candidates: vec![CandidateAction {
                action_type: "A".into(),
                params: HashMap::new(),
                score: Score(1),
                candidate_hash: dummy_hash(2),
            }],
        };
        let policy_engine = LoggedPolicyEngine { log: log.clone() };
        let selector = LoggedSelector { log: log.clone() };
        let token_factory = LoggedTokenFactory { log: log.clone() };
        let attestor = LoggedAttestor { log: log.clone() };
        let verifier = LoggedVerifier {
            log: log.clone(),
            status: VerificationStatus::Success,
        };
        let executor = LoggedExecutor { log: log.clone() };
        let policy_hash = dummy_hash(9);
        let policy_ref = PolicyRef {
            policy_epoch: 1,
            registry_root: dummy_hash(8),
        };

        let result = run_once(RunOnceInputs {
            state_provider: &state_provider,
            proposer: &proposer,
            policy_engine: &policy_engine,
            selector: &selector,
            token_factory: &token_factory,
            attestor: &attestor,
            verifier: &verifier,
            executor: &executor,
            policy_hash: &policy_hash,
            policy_ref,
            nonce_or_tx_hash: None,
            metrics: None,
            audit_recorder: None,
        });

        assert!(matches!(result, Err(MprdError::BoundedValueExceeded(_))));
        let calls = call_log_snapshot(&log);
        assert_eq!(calls, vec!["state"]);
        assert_pipeline_temporal_spec(&calls);
    }

    #[test]
    fn run_once_fails_closed_when_candidates_canonicalization_fails() {
        let log = new_call_log();
        let state_provider = LoggedStateProvider {
            log: log.clone(),
            state: StateSnapshot {
                fields: HashMap::new(),
                policy_inputs: HashMap::new(),
                state_hash: dummy_hash(1),
                state_ref: crate::StateRef::unknown(),
            },
        };
        let proposer = LoggedProposer {
            log: log.clone(),
            candidates: vec![CandidateAction {
                action_type: "".into(),
                params: HashMap::new(),
                score: Score(1),
                candidate_hash: dummy_hash(2),
            }],
        };
        let policy_engine = LoggedPolicyEngine { log: log.clone() };
        let selector = LoggedSelector { log: log.clone() };
        let token_factory = LoggedTokenFactory { log: log.clone() };
        let attestor = LoggedAttestor { log: log.clone() };
        let verifier = LoggedVerifier {
            log: log.clone(),
            status: VerificationStatus::Success,
        };
        let executor = LoggedExecutor { log: log.clone() };
        let policy_hash = dummy_hash(9);
        let policy_ref = PolicyRef {
            policy_epoch: 1,
            registry_root: dummy_hash(8),
        };

        let result = run_once(RunOnceInputs {
            state_provider: &state_provider,
            proposer: &proposer,
            policy_engine: &policy_engine,
            selector: &selector,
            token_factory: &token_factory,
            attestor: &attestor,
            verifier: &verifier,
            executor: &executor,
            policy_hash: &policy_hash,
            policy_ref,
            nonce_or_tx_hash: None,
            metrics: None,
            audit_recorder: None,
        });

        assert!(matches!(result, Err(MprdError::InvalidInput(_))));
        let calls = call_log_snapshot(&log);
        assert_eq!(calls, vec!["state", "propose"]);
        assert_pipeline_temporal_spec(&calls);
    }

    #[test]
    fn run_once_fails_closed_when_verification_fails_and_does_not_record_or_execute() {
        let log = new_call_log();
        let state_provider = LoggedStateProvider {
            log: log.clone(),
            state: StateSnapshot {
                fields: HashMap::new(),
                policy_inputs: HashMap::new(),
                state_hash: dummy_hash(1),
                state_ref: crate::StateRef::unknown(),
            },
        };
        let proposer = LoggedProposer {
            log: log.clone(),
            candidates: vec![CandidateAction {
                action_type: "A".into(),
                params: HashMap::new(),
                score: Score(1),
                candidate_hash: dummy_hash(2),
            }],
        };
        let policy_engine = LoggedPolicyEngine { log: log.clone() };
        let selector = LoggedSelector { log: log.clone() };
        let token_factory = LoggedTokenFactory { log: log.clone() };
        let attestor = LoggedAttestor { log: log.clone() };
        let verifier = LoggedVerifier {
            log: log.clone(),
            status: VerificationStatus::Failure("verify failed".into()),
        };
        let executor = LoggedExecutor { log: log.clone() };
        let recorder = LoggedRecorder { log: log.clone() };
        let audit = LoggedAuditRecorder {
            log: log.clone(),
            fail: false,
        };
        let policy_hash = dummy_hash(9);
        let policy_ref = PolicyRef {
            policy_epoch: 1,
            registry_root: dummy_hash(8),
        };

        let result = run_once_with_recorder(RunOnceInputsWithRecorder {
            inputs: RunOnceInputs {
                state_provider: &state_provider,
                proposer: &proposer,
                policy_engine: &policy_engine,
                selector: &selector,
                token_factory: &token_factory,
                attestor: &attestor,
                verifier: &verifier,
                executor: &executor,
                policy_hash: &policy_hash,
                policy_ref,
                nonce_or_tx_hash: None,
                metrics: None,
                audit_recorder: Some(&audit),
            },
            recorder: &recorder,
        });

        assert!(matches!(result, Err(MprdError::ZkError(_))));
        let calls = call_log_snapshot(&log);
        assert_eq!(
            calls,
            vec![
                "state",
                "propose",
                "evaluate",
                "select",
                "token",
                "attest",
                "verify",
                "verify_fail"
            ]
        );
        assert_pipeline_temporal_spec(&calls);
    }

    #[test]
    fn run_once_orders_verify_then_audit_then_record_then_execute() {
        let log = new_call_log();
        let state_provider = LoggedStateProvider {
            log: log.clone(),
            state: StateSnapshot {
                fields: HashMap::new(),
                policy_inputs: HashMap::new(),
                state_hash: dummy_hash(1),
                state_ref: crate::StateRef::unknown(),
            },
        };
        let proposer = LoggedProposer {
            log: log.clone(),
            candidates: vec![CandidateAction {
                action_type: "A".into(),
                params: HashMap::new(),
                score: Score(1),
                candidate_hash: dummy_hash(2),
            }],
        };
        let policy_engine = LoggedPolicyEngine { log: log.clone() };
        let selector = LoggedSelector { log: log.clone() };
        let token_factory = LoggedTokenFactory { log: log.clone() };
        let attestor = LoggedAttestor { log: log.clone() };
        let verifier = LoggedVerifier {
            log: log.clone(),
            status: VerificationStatus::Success,
        };
        let executor = LoggedExecutor { log: log.clone() };
        let recorder = LoggedRecorder { log: log.clone() };
        let audit = LoggedAuditRecorder {
            log: log.clone(),
            fail: false,
        };
        let policy_hash = dummy_hash(9);
        let policy_ref = PolicyRef {
            policy_epoch: 1,
            registry_root: dummy_hash(8),
        };

        let result = run_once_with_recorder(RunOnceInputsWithRecorder {
            inputs: RunOnceInputs {
                state_provider: &state_provider,
                proposer: &proposer,
                policy_engine: &policy_engine,
                selector: &selector,
                token_factory: &token_factory,
                attestor: &attestor,
                verifier: &verifier,
                executor: &executor,
                policy_hash: &policy_hash,
                policy_ref,
                nonce_or_tx_hash: None,
                metrics: None,
                audit_recorder: Some(&audit),
            },
            recorder: &recorder,
        })
        .expect("success");

        assert!(result.success);
        let calls = call_log_snapshot(&log);
        assert_eq!(
            calls,
            vec![
                "state",
                "propose",
                "evaluate",
                "select",
                "token",
                "attest",
                "verify",
                "verify_ok",
                "audit",
                "record",
                "execute"
            ]
        );
        assert_pipeline_temporal_spec(&calls);
    }

    #[test]
    fn ltlf_orchestrator_temporal_spec_holds_under_adversarial_outcomes() {
        // This test approximates the "environment vs controller" view from LTLf synthesis:
        // external calls can fail (environment), but the pipeline must preserve ordering and fail-closed.

        #[derive(Clone)]
        struct ScenarioRecorder {
            log: CallLog,
            fail: bool,
        }

        impl DecisionRecorder for ScenarioRecorder {
            fn record(&self, _token: &DecisionToken, _proof: &ProofBundle) -> Result<()> {
                push_call(&self.log, "record");
                if self.fail {
                    return Err(MprdError::ExecutionError("recorder failed".into()));
                }
                Ok(())
            }
        }

        #[derive(Clone)]
        struct ScenarioExecutor {
            log: CallLog,
            fail: bool,
        }

        impl ExecutorAdapter for ScenarioExecutor {
            fn execute(&self, _verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
                push_call(&self.log, "execute");
                if self.fail {
                    return Err(MprdError::ExecutionError("executor failed".into()));
                }
                Ok(ExecutionResult {
                    success: true,
                    message: Some("ok".into()),
                })
            }
        }

        #[derive(Clone, Copy, Debug)]
        struct Scenario {
            name: &'static str,
            verify_ok: bool,
            with_audit: bool,
            audit_fail: bool,
            with_recorder: bool,
            recorder_fail: bool,
            executor_fail: bool,
        }

        let scenarios = [
            Scenario {
                name: "verify_fails_no_record_no_execute",
                verify_ok: false,
                with_audit: true,
                audit_fail: false,
                with_recorder: true,
                recorder_fail: false,
                executor_fail: false,
            },
            Scenario {
                name: "verify_ok_no_audit_no_recorder_executes",
                verify_ok: true,
                with_audit: false,
                audit_fail: false,
                with_recorder: false,
                recorder_fail: false,
                executor_fail: false,
            },
            Scenario {
                name: "verify_ok_audit_ok_recorder_ok_executes",
                verify_ok: true,
                with_audit: true,
                audit_fail: false,
                with_recorder: true,
                recorder_fail: false,
                executor_fail: false,
            },
            Scenario {
                name: "verify_ok_audit_fails_best_effort_still_executes",
                verify_ok: true,
                with_audit: true,
                audit_fail: true,
                with_recorder: true,
                recorder_fail: false,
                executor_fail: false,
            },
            Scenario {
                name: "verify_ok_recorder_fails_abort_before_execute",
                verify_ok: true,
                with_audit: true,
                audit_fail: false,
                with_recorder: true,
                recorder_fail: true,
                executor_fail: false,
            },
            Scenario {
                name: "verify_ok_executor_fails_but_ordering_holds",
                verify_ok: true,
                with_audit: true,
                audit_fail: false,
                with_recorder: true,
                recorder_fail: false,
                executor_fail: true,
            },
        ];

        for sc in scenarios {
            let log = new_call_log();
            let state_provider = LoggedStateProvider {
                log: log.clone(),
                state: StateSnapshot {
                    fields: HashMap::new(),
                    policy_inputs: HashMap::new(),
                    state_hash: dummy_hash(1),
                    state_ref: crate::StateRef::unknown(),
                },
            };
            let proposer = LoggedProposer {
                log: log.clone(),
                candidates: vec![CandidateAction {
                    action_type: "A".into(),
                    params: HashMap::new(),
                    score: Score(1),
                    candidate_hash: dummy_hash(2),
                }],
            };
            let policy_engine = LoggedPolicyEngine { log: log.clone() };
            let selector = LoggedSelector { log: log.clone() };
            let token_factory = LoggedTokenFactory { log: log.clone() };
            let attestor = LoggedAttestor { log: log.clone() };
            let verifier = LoggedVerifier {
                log: log.clone(),
                status: if sc.verify_ok {
                    VerificationStatus::Success
                } else {
                    VerificationStatus::Failure("verify failed".into())
                },
            };
            let executor = ScenarioExecutor {
                log: log.clone(),
                fail: sc.executor_fail,
            };
            let policy_hash = dummy_hash(9);
            let policy_ref = PolicyRef {
                policy_epoch: 1,
                registry_root: dummy_hash(8),
            };

            let audit = LoggedAuditRecorder {
                log: log.clone(),
                fail: sc.audit_fail,
            };
            let audit_opt: Option<&dyn DecisionAuditRecorder> =
                if sc.with_audit { Some(&audit) } else { None };

            let inputs = RunOnceInputs {
                state_provider: &state_provider,
                proposer: &proposer,
                policy_engine: &policy_engine,
                selector: &selector,
                token_factory: &token_factory,
                attestor: &attestor,
                verifier: &verifier,
                executor: &executor,
                policy_hash: &policy_hash,
                policy_ref: policy_ref.clone(),
                nonce_or_tx_hash: None,
                metrics: None,
                audit_recorder: audit_opt,
            };

            let outcome = if sc.with_recorder {
                let recorder = ScenarioRecorder {
                    log: log.clone(),
                    fail: sc.recorder_fail,
                };
                run_once_with_recorder(RunOnceInputsWithRecorder {
                    inputs,
                    recorder: &recorder,
                })
            } else {
                run_once(inputs)
            };
            // We don't care whether the scenario succeeds; we care that any executed trace respects the ordering spec.
            let _ = outcome;

            let calls = call_log_snapshot(&log);
            assert_pipeline_temporal_spec(&calls);
        }
    }

    #[test]
    fn ltlf_orchestrator_bmc_no_violation_under_all_failure_branches() {
        // Paper-aligned improvement: instead of hand-picking scenarios, explicitly explore the
        // nondeterministic (environment) failure branches of the pipeline model and search for a
        // counterexample trace that violates the temporal ordering spec.

        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        enum Stage {
            State,
            Propose,
            Evaluate,
            Select,
            Token,
            Attest,
            Verify,
            Audit,
            Record,
            Execute,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        struct Model {
            stage: Stage,
            with_audit: bool,
            with_recorder: bool,
        }

        fn v(name: &'static str) -> ltlf::Valuation {
            let mut out = ltlf::Valuation::new();
            out.insert(name.to_string());
            out
        }

        fn pipeline_spec() -> ltlf::Formula {
            ltlf::Formula::and(vec![
                ltlf::Formula::precedence("token", "attest"),
                ltlf::Formula::precedence("attest", "verify"),
                ltlf::Formula::precedence("verify_ok", "execute"),
                ltlf::Formula::optional_precedence("record", "execute"),
                ltlf::Formula::precedence("verify_ok", "audit"),
                ltlf::Formula::optional_precedence("audit", "record"),
                ltlf::Formula::optional_precedence("audit", "execute"),
                ltlf::Formula::precedence("verify_ok", "record"),
                // If verification fails, no execute/record may occur.
                ltlf::Formula::always(ltlf::Formula::or(vec![
                    ltlf::Formula::not_atom("verify_fail"),
                    ltlf::Formula::always(ltlf::Formula::not_atom("execute")),
                ])),
                ltlf::Formula::always(ltlf::Formula::or(vec![
                    ltlf::Formula::not_atom("verify_fail"),
                    ltlf::Formula::always(ltlf::Formula::not_atom("record")),
                ])),
            ])
        }

        fn step(m: &Model) -> Vec<(ltlf::Valuation, Model, bool)> {
            match m.stage {
                Stage::State => vec![
                    (
                        v("state"),
                        Model {
                            stage: Stage::Propose,
                            ..*m
                        },
                        false,
                    ),
                    (v("state"), *m, true),
                ],
                Stage::Propose => vec![
                    (
                        v("propose"),
                        Model {
                            stage: Stage::Evaluate,
                            ..*m
                        },
                        false,
                    ),
                    (v("propose"), *m, true),
                ],
                Stage::Evaluate => vec![
                    (
                        v("evaluate"),
                        Model {
                            stage: Stage::Select,
                            ..*m
                        },
                        false,
                    ),
                    (v("evaluate"), *m, true),
                ],
                Stage::Select => vec![
                    (
                        v("select"),
                        Model {
                            stage: Stage::Token,
                            ..*m
                        },
                        false,
                    ),
                    (v("select"), *m, true),
                ],
                Stage::Token => vec![
                    (
                        v("token"),
                        Model {
                            stage: Stage::Attest,
                            ..*m
                        },
                        false,
                    ),
                    (v("token"), *m, true),
                ],
                Stage::Attest => vec![
                    (
                        v("attest"),
                        Model {
                            stage: Stage::Verify,
                            ..*m
                        },
                        false,
                    ),
                    (v("attest"), *m, true),
                ],
                Stage::Verify => {
                    let next = if m.with_audit {
                        Stage::Audit
                    } else if m.with_recorder {
                        Stage::Record
                    } else {
                        Stage::Execute
                    };
                    // Environment nondeterminism: verify can succeed or fail.
                    vec![
                        (v("verify_ok"), Model { stage: next, ..*m }, false),
                        (v("verify_fail"), *m, true),
                    ]
                }
                Stage::Audit => {
                    let next = if m.with_recorder {
                        Stage::Record
                    } else {
                        Stage::Execute
                    };
                    // Audit failures are best-effort; for ordering specs we don't distinguish ok/err.
                    vec![(v("audit"), Model { stage: next, ..*m }, false)]
                }
                Stage::Record => {
                    // Recorder failures abort before execute.
                    vec![
                        (
                            v("record"),
                            Model {
                                stage: Stage::Execute,
                                ..*m
                            },
                            false,
                        ),
                        (v("record"), *m, true),
                    ]
                }
                Stage::Execute => {
                    // Execution is always the last step in the trace (success or error).
                    vec![(v("execute"), *m, true)]
                }
            }
        }

        for with_audit in [false, true] {
            for with_recorder in [false, true] {
                let init = Model {
                    stage: Stage::State,
                    with_audit,
                    with_recorder,
                };
                let spec = pipeline_spec();
                let ce = ltlf::bmc_find_violation(spec, init, 16, step);
                assert!(
                    ce.is_none(),
                    "found temporal counterexample (with_audit={with_audit}, with_recorder={with_recorder}): {:?}",
                    ce.map(|x| x.trace)
                );
            }
        }
    }

    struct DenyAllPolicyEngine;

    impl PolicyEngine for DenyAllPolicyEngine {
        fn evaluate(
            &self,
            _policy_hash: &PolicyHash,
            _state: &StateSnapshot,
            candidates: &[CandidateAction],
        ) -> Result<Vec<RuleVerdict>> {
            Ok(candidates
                .iter()
                .map(|_| RuleVerdict {
                    allowed: false,
                    reasons: vec!["deny".into()],
                    limits: HashMap::new(),
                })
                .collect())
        }
    }

    struct ChoosingDisallowedSelector;

    impl Selector for ChoosingDisallowedSelector {
        fn select(
            &self,
            policy_hash: &PolicyHash,
            _state: &StateSnapshot,
            candidates: &[CandidateAction],
            _verdicts: &[RuleVerdict],
        ) -> Result<Decision> {
            Ok(Decision {
                chosen_index: 0,
                chosen_action: candidates[0].clone(),
                policy_hash: policy_hash.clone(),
                decision_commitment: dummy_hash(5),
            })
        }
    }

    struct OutOfBoundsSelector;

    impl Selector for OutOfBoundsSelector {
        fn select(
            &self,
            policy_hash: &PolicyHash,
            _state: &StateSnapshot,
            candidates: &[CandidateAction],
            _verdicts: &[RuleVerdict],
        ) -> Result<Decision> {
            Ok(Decision {
                chosen_index: candidates.len() + 1,
                chosen_action: candidates[0].clone(),
                policy_hash: policy_hash.clone(),
                decision_commitment: dummy_hash(5),
            })
        }
    }

    struct RecordingExecutor {
        called: Arc<AtomicBool>,
    }

    impl ExecutorAdapter for RecordingExecutor {
        fn execute(&self, _verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
            self.called.store(true, Ordering::SeqCst);
            Ok(ExecutionResult {
                success: true,
                message: None,
            })
        }
    }

    #[test]
    fn run_once_fails_closed_when_selector_picks_disallowed_action() {
        let state_provider = DummyStateProvider;
        let proposer = DummyProposer;
        let policy_engine = DenyAllPolicyEngine;
        let selector = ChoosingDisallowedSelector;
        let token_factory = DummyTokenFactory;
        let attestor = DummyAttestor;
        let verifier = DummyVerifier;
        let called = Arc::new(AtomicBool::new(false));
        let executor = RecordingExecutor {
            called: called.clone(),
        };
        let policy_hash = Hash32([9u8; 32]);
        let policy_ref = PolicyRef {
            policy_epoch: 1,
            registry_root: Hash32([8u8; 32]),
        };

        let result = run_once(RunOnceInputs {
            state_provider: &state_provider,
            proposer: &proposer,
            policy_engine: &policy_engine,
            selector: &selector,
            token_factory: &token_factory,
            attestor: &attestor,
            verifier: &verifier,
            executor: &executor,
            policy_hash: &policy_hash,
            policy_ref,
            nonce_or_tx_hash: None,
            metrics: None,
            audit_recorder: None,
        });

        assert!(result.is_err());
        assert!(!called.load(Ordering::SeqCst));
    }

    #[test]
    fn run_once_fails_closed_when_selector_returns_out_of_bounds_index() {
        let state_provider = DummyStateProvider;
        let proposer = DummyProposer;
        let policy_engine = AllowAllPolicyEngine;
        let selector = OutOfBoundsSelector;
        let token_factory = DummyTokenFactory;
        let attestor = DummyAttestor;
        let verifier = DummyVerifier;
        let called = Arc::new(AtomicBool::new(false));
        let executor = RecordingExecutor {
            called: called.clone(),
        };
        let policy_hash = Hash32([9u8; 32]);
        let policy_ref = PolicyRef {
            policy_epoch: 1,
            registry_root: Hash32([8u8; 32]),
        };

        let result = run_once(RunOnceInputs {
            state_provider: &state_provider,
            proposer: &proposer,
            policy_engine: &policy_engine,
            selector: &selector,
            token_factory: &token_factory,
            attestor: &attestor,
            verifier: &verifier,
            executor: &executor,
            policy_hash: &policy_hash,
            policy_ref,
            nonce_or_tx_hash: None,
            metrics: None,
            audit_recorder: None,
        });

        assert!(result.is_err());
        assert!(!called.load(Ordering::SeqCst));
    }

    proptest! {
        #[test]
        fn enforce_selector_contract_accepts_only_allowed_choice(allowed in any::<bool>()) {
            let candidates = vec![CandidateAction {
                action_type: "A".into(),
                params: HashMap::new(),
                score: Score(1),
                candidate_hash: dummy_hash(1),
            }];
            let verdicts = vec![RuleVerdict {
                allowed,
                reasons: vec![],
                limits: HashMap::new(),
            }];
            let decision = Decision {
                chosen_index: 0,
                chosen_action: candidates[0].clone(),
                policy_hash: dummy_hash(2),
                decision_commitment: dummy_hash(3),
            };
            let r = enforce_selector_contract(&decision, &candidates, &verdicts);
            prop_assert_eq!(r.is_ok(), allowed);
        }
    }
}
