use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

pub mod anti_replay;
pub mod artifact_repo;
pub mod cegis;
pub mod components;
pub mod config;
pub mod crypto;
pub mod decision_log;
pub mod egress;
pub mod fee_router;
pub mod hash;
pub mod limits;
pub mod ltlf;
pub mod metrics;
pub mod mpb;
pub mod nonce;
pub mod observability;
pub mod orchestrator;
pub mod policy_algebra;
pub mod registry;
pub mod selectors;
pub mod state_provenance;
pub mod tau;
pub mod tau_testnet;
pub mod tau_net_output_attestation;
pub mod tokenomics_v6;
pub mod validation;
pub mod verified_kernels;
pub mod wire;

pub use config::MprdConfig;

pub use crypto::{TokenSigningKey, TokenVerifyingKey};

/// 32-byte hash newtype used for commitments (policy, state, actions, etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct Hash32(pub [u8; 32]);

pub type PolicyHash = Hash32;
pub type StateHash = Hash32;
pub type CandidateHash = Hash32;
pub type NonceHash = Hash32;

/// Internal-only semantic hash for policy equivalence/dedup.
///
/// Security contract:
/// - Do NOT use this as a protocol commitment or authorization handle.
/// - Only use as a cache key for “policy meaning” under the current compiler restrictions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct PolicySemanticHash(pub Hash32);

/// Reference to the policy authorization context.
///
/// A verifier MUST be able to check that `policy_hash` was authorized at exactly this
/// `(policy_epoch, registry_root)` (fail-closed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRef {
    /// Monotonic policy registry epoch (authorization context).
    pub policy_epoch: u64,
    /// Commitment to the registry root at `policy_epoch`.
    pub registry_root: Hash32,
}

/// Reference to the state provenance context.
///
/// ZK receipts prove correctness *conditional on inputs*; production deployments must define how
/// `state_hash` relates to reality. This struct binds a verifier-checkable provenance identity into
/// the signed token and (for ZK modes) into the public journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRef {
    /// Domain-separated ID describing the state source/provenance scheme (e.g. "signed_snapshot_v1").
    pub state_source_id: Hash32,
    /// Monotonic state epoch (e.g. block height / snapshot sequence).
    pub state_epoch: u64,
    /// Commitment to the provenance attestation material (e.g. signature bytes / merkle proof hash).
    pub state_attestation_hash: Hash32,
}

impl StateRef {
    /// Placeholder provenance used for local testing or transitional deployments.
    ///
    /// Production configurations should reject this value (fail-closed).
    pub fn unknown() -> Self {
        Self {
            state_source_id: Hash32([0u8; 32]),
            state_epoch: 0,
            state_attestation_hash: Hash32([0u8; 32]),
        }
    }
}

impl Default for StateRef {
    fn default() -> Self {
        Self::unknown()
    }
}

/// Generic bounded value used in state fields and action parameters.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Bool(bool),
    Int(i64),
    UInt(u64),
    String(String),
    Bytes(Vec<u8>),
}

/// Snapshot of the environment as seen by the rules engine.
///
/// Preconditions (DbC):
/// - All keys are non-empty and normalized (e.g., lower_snake_case).
/// - All values are within configured bounds (sizes, ranges).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub fields: HashMap<String, Value>,
    pub policy_inputs: HashMap<String, Vec<u8>>, // Canonical encoding for Tau.
    pub state_hash: StateHash,
    /// Provenance context for `state_hash` (source/epoch/attestation commitment).
    pub state_ref: StateRef,
}

/// Score used by proposers to rank candidates.
/// Deterministic fixed-point representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Score(pub i64);

/// Single candidate action proposed by a model or heuristic.
///
/// Preconditions (DbC):
/// - `action_type` is non-empty and from a configured vocabulary.
/// - `params` are bounded and schema-valid for `action_type`.
/// - `candidate_hash` commits to `(action_type, params, score)`.
#[derive(Clone, Debug, PartialEq)]
pub struct CandidateAction {
    pub action_type: String,
    pub params: HashMap<String, Value>,
    pub score: Score,
    pub candidate_hash: CandidateHash,
}

/// Verdict returned by the policy engine for a single candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleVerdict {
    pub allowed: bool,
    pub reasons: Vec<String>,
    pub limits: HashMap<String, Value>,
}

/// Deterministic decision over a candidate set under a specific policy.
///
/// Postconditions (DbC):
/// - `chosen_index` is within bounds of the original candidate list.
/// - `chosen_action_hash` equals the hash of the chosen candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    pub chosen_index: usize,
    pub chosen_action: CandidateAction,
    pub policy_hash: PolicyHash,
    pub decision_commitment: Hash32,
}

/// Minimal token that executors consume, binding policy, state and action.
#[derive(Clone, Debug, PartialEq)]
pub struct DecisionToken {
    pub policy_hash: PolicyHash,
    /// Authorization context for `policy_hash` (S6 / downgrade resistance).
    pub policy_ref: PolicyRef,
    pub state_hash: StateHash,
    /// Provenance context for `state_hash` (ZK inputs are only as good as their source).
    pub state_ref: StateRef,
    pub chosen_action_hash: Hash32,
    pub nonce_or_tx_hash: NonceHash,
    pub timestamp_ms: i64,
    pub signature: Vec<u8>,
}

/// Proof bundle produced by the ZK attestor (Risc0 host).
#[derive(Clone, Debug, PartialEq)]
pub struct ProofBundle {
    pub policy_hash: PolicyHash,
    pub state_hash: StateHash,
    pub candidate_set_hash: Hash32,
    pub chosen_action_hash: Hash32,
    /// Hash of canonical execution-affecting limits bytes committed by the guest.
    pub limits_hash: Hash32,
    /// Canonical execution-affecting limits bytes whose hash must equal `limits_hash`.
    pub limits_bytes: Vec<u8>,
    /// Canonical v1 action preimage bytes whose hash must equal `chosen_action_hash`.
    ///
    /// This enables executors to derive and execute *exactly* the committed action.
    pub chosen_action_preimage: Vec<u8>,
    pub risc0_receipt: Vec<u8>,
    pub attestation_metadata: HashMap<String, String>,
}

/// A proof bundle that has been locally verified against its token.
///
/// This is a **type-level gate**: executors can only be called with a `VerifiedBundle`,
/// making the "verify before side effects" rule correct-by-conposition.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedBundle<'a> {
    token: &'a DecisionToken,
    proof: &'a ProofBundle,
}

impl<'a> VerifiedBundle<'a> {
    pub fn token(&self) -> &'a DecisionToken {
        self.token
    }

    pub fn proof(&self) -> &'a ProofBundle {
        self.proof
    }

    pub(crate) fn new(token: &'a DecisionToken, proof: &'a ProofBundle) -> Self {
        Self { token, proof }
    }
}

/// Concrete execution-boundary witness carried after the final fail-closed binding checks pass.
///
/// This is the first runtime step toward replacing free execution booleans with witness-carrying
/// types on the RC1 path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionBoundaryWitnessV1 {
    chosen_action_preimage: Vec<u8>,
}

impl ExecutionBoundaryWitnessV1 {
    pub fn chosen_action_preimage(&self) -> &[u8] {
        &self.chosen_action_preimage
    }
}

/// A locally verified bundle that is also admitted through the concrete execution boundary.
#[derive(Clone, Debug)]
pub struct ExecutionReadyBundle<'a> {
    verified: VerifiedBundle<'a>,
    boundary: ExecutionBoundaryWitnessV1,
}

impl<'a> ExecutionReadyBundle<'a> {
    pub fn verified(&self) -> &VerifiedBundle<'a> {
        &self.verified
    }

    pub fn boundary(&self) -> &ExecutionBoundaryWitnessV1 {
        &self.boundary
    }

    pub fn token(&self) -> &'a DecisionToken {
        self.verified.token()
    }

    pub fn proof(&self) -> &'a ProofBundle {
        self.verified.proof()
    }
}

/// Concrete policy authority witness carried on the RC1 path.
///
/// This binds the exact `(policy_hash, policy_ref)` pair the orchestrator was authorized to use
/// and lets downstream stages fail closed on any selector/token drift.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyAuthorityWitnessV1 {
    policy_hash: PolicyHash,
    policy_ref: PolicyRef,
}

impl PolicyAuthorityWitnessV1 {
    pub fn policy_hash(&self) -> &PolicyHash {
        &self.policy_hash
    }

    pub fn policy_ref(&self) -> &PolicyRef {
        &self.policy_ref
    }
}

/// Construct the concrete policy authority witness for a run.
pub fn policy_authority_witness_v1(
    policy_hash: &PolicyHash,
    policy_ref: &PolicyRef,
) -> Result<PolicyAuthorityWitnessV1> {
    Ok(PolicyAuthorityWitnessV1 {
        policy_hash: *policy_hash,
        policy_ref: policy_ref.clone(),
    })
}

/// Verify that the selector preserved the orchestrator-authorized policy identity.
pub fn verify_decision_policy_authority_v1(
    authority: &PolicyAuthorityWitnessV1,
    decision: &Decision,
) -> Result<()> {
    if decision.policy_hash != authority.policy_hash {
        return Err(MprdError::InvalidInput(
            "decision policy_hash drifted from authorized policy context".into(),
        ));
    }
    Ok(())
}

/// Verify that the decision token preserved the orchestrator-authorized policy identity.
pub fn verify_token_policy_authority_v1(
    authority: &PolicyAuthorityWitnessV1,
    token: &DecisionToken,
) -> Result<()> {
    if token.policy_hash != authority.policy_hash {
        return Err(MprdError::InvalidInput(
            "token policy_hash drifted from authorized policy context".into(),
        ));
    }
    if token.policy_ref != authority.policy_ref {
        return Err(MprdError::InvalidInput(
            "token policy_ref drifted from authorized policy context".into(),
        ));
    }
    Ok(())
}

/// Verify `proof` against `token` and, on success, produce a `VerifiedBundle` for execution.
pub fn verify_for_execution<'a>(
    verifier: &dyn ZkLocalVerifier,
    token: &'a DecisionToken,
    proof: &'a ProofBundle,
) -> Result<VerifiedBundle<'a>> {
    match verifier.verify(token, proof) {
        VerificationStatus::Success => Ok(VerifiedBundle::new(token, proof)),
        VerificationStatus::Failure(reason) => Err(MprdError::ZkError(reason)),
    }
}

/// Verify that the locally-verified bundle also satisfies the concrete execution boundary.
pub fn execution_boundary_witness_v1(
    verified: &VerifiedBundle<'_>,
) -> Result<ExecutionBoundaryWitnessV1> {
    let token = verified.token();
    let proof = verified.proof();

    limits::verify_limits_binding_v1(&proof.limits_hash, &proof.limits_bytes)?;
    let _ = limits::parse_limits_v1(&proof.limits_bytes)?;

    if proof.chosen_action_preimage.is_empty() {
        return Err(MprdError::ExecutionError(
            "missing chosen_action_preimage (execution boundary requires committed action bytes)"
                .into(),
        ));
    }

    let h = hash::hash_candidate_preimage_v1(&proof.chosen_action_preimage);
    if h != token.chosen_action_hash || h != proof.chosen_action_hash {
        return Err(MprdError::ExecutionError(
            "chosen_action_preimage hash mismatch".into(),
        ));
    }

    let (action_type, params, _score) =
        validation::decode_candidate_preimage_v1(&proof.chosen_action_preimage)?;
    validation::validate_action_schema_v1(&action_type, &params)?;

    Ok(ExecutionBoundaryWitnessV1 {
        chosen_action_preimage: proof.chosen_action_preimage.clone(),
    })
}

/// Upgrade a verified bundle into an execution-ready bundle carrying the concrete boundary witness.
pub fn prepare_execution_ready<'a>(verified: VerifiedBundle<'a>) -> Result<ExecutionReadyBundle<'a>> {
    let boundary = execution_boundary_witness_v1(&verified)?;
    Ok(ExecutionReadyBundle { verified, boundary })
}

/// Unified error type for MPRD core operations.
#[derive(Debug, Error)]
pub enum MprdError {
    // Input validation errors
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Bounded value exceeded: {0}")]
    BoundedValueExceeded(String),

    // Policy errors
    #[error("Policy evaluation failed: {0}")]
    PolicyEvaluationFailed(String),

    #[error("Selection failed: {0}")]
    SelectionFailed(String),

    // ZK errors
    #[error("ZK error: {0}")]
    ZkError(String),

    // Execution errors
    #[error("Execution error: {0}")]
    ExecutionError(String),

    // Policy registry errors (S6)
    #[error("Policy hash collision for hash {hash:?}")]
    PolicyHashCollision { hash: PolicyHash },

    #[error("Policy not found for hash {hash:?}")]
    PolicyNotFound { hash: PolicyHash },

    // Anti-replay errors (S4)
    #[error("Token expired: age {age_ms}ms exceeds max {max_age_ms}ms")]
    TokenExpired { age_ms: i64, max_age_ms: i64 },

    #[error("Token from future: skew {skew_ms}ms")]
    TokenFromFuture { skew_ms: i64 },

    #[error("Nonce replay detected")]
    NonceReplay { nonce: NonceHash },

    // Cryptographic errors
    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Signature invalid: {0}")]
    SignatureInvalid(String),

    // Configuration errors
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, MprdError>;

/// Upper bound on candidate set size accepted by the core.
pub const MAX_CANDIDATES: usize = 64;

/// Provides a normalized `StateSnapshot` from the environment.
pub trait StateProvider {
    /// Preconditions:
    /// - Underlying data sources are reachable or provide explicit errors.
    ///
    /// Postconditions:
    /// - Returned state satisfies all `StateSnapshot` invariants.
    fn snapshot(&self) -> Result<StateSnapshot>;
}

/// Generates a finite set of candidate actions from a state.
pub trait Proposer {
    /// Preconditions:
    /// - `state` satisfies `StateSnapshot` invariants.
    ///
    /// Postconditions:
    /// - Returned slice length is `<= MAX_CANDIDATES`.
    /// - Each candidate is schema-valid for its `action_type`.
    fn propose(&self, state: &StateSnapshot) -> Result<Vec<CandidateAction>>;
}

/// Evaluates candidates under a Tau-backed policy.
pub trait PolicyEngine {
    /// Preconditions:
    /// - `policy_hash` refers to an immutable, known Tau spec.
    /// - `candidates.len() <= MAX_CANDIDATES`.
    ///
    /// Postconditions:
    /// - `verdicts.len() == candidates.len()`.
    fn evaluate(
        &self,
        policy_hash: &PolicyHash,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<Vec<RuleVerdict>>;
}

/// Deterministically selects one action from the allowed set.
pub trait Selector {
    /// Preconditions:
    /// - `candidates.len() == verdicts.len()`.
    ///
    /// Postconditions:
    /// - For fixed inputs, returns the same `Decision` on every call.
    fn select(
        &self,
        policy_hash: &PolicyHash,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
        verdicts: &[RuleVerdict],
    ) -> Result<Decision>;
}

/// Produces a ZK proof bundle (Risc0) for a given decision.
pub trait ZkAttestor {
    /// Preconditions:
    /// - `token` was produced by the configured `DecisionTokenFactory` for `decision` and `state`.
    /// - `decision` was produced by a compliant `Selector`.
    /// - `candidates.len() <= MAX_CANDIDATES`.
    ///
    /// Postconditions:
    /// - Returned bundle commitments are consistent with inputs.
    fn attest(
        &self,
        token: &DecisionToken,
        decision: &Decision,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<ProofBundle>;
}

/// Verification outcome for ZK proofs.
#[derive(Clone, Debug, PartialEq)]
pub enum VerificationStatus {
    Success,
    Failure(String),
}

/// Locally verifies a ZK proof bundle against a decision token.
pub trait ZkLocalVerifier {
    /// Preconditions:
    /// - `token` and `bundle` are well-formed and not null.
    ///
    /// Postconditions:
    /// - Returns `Success` iff the proof and commitments are valid.
    fn verify(&self, token: &DecisionToken, proof: &ProofBundle) -> VerificationStatus;
}

/// Result of executing an approved action.
#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionResult {
    pub success: bool,
    pub message: Option<String>,
}

/// Single choke point for all side effects under MPRD control.
pub trait ExecutorAdapter {
    /// Postconditions:
    /// - Either performs the side effect exactly once, or performs none.
    fn execute(&self, verified: &VerifiedBundle<'_>) -> Result<ExecutionResult>;

    /// Preferred RC1 path: only execute bundles that also carry a concrete execution witness.
    ///
    /// RC1 note: this default preserves compatibility for adapters that have not yet been migrated
    /// to consume `ExecutionReadyBundle` directly. The orchestrator already requires the witness
    /// before any executor call; future tightening should move adapters onto the witness-native path.
    fn execute_ready(&self, ready: &ExecutionReadyBundle<'_>) -> Result<ExecutionResult> {
        self.execute(ready.verified())
    }
}

pub struct DefaultSelector;

impl Selector for DefaultSelector {
    fn select(
        &self,
        policy_hash: &PolicyHash,
        _state: &StateSnapshot,
        candidates: &[CandidateAction],
        verdicts: &[RuleVerdict],
    ) -> Result<Decision> {
        if candidates.len() != verdicts.len() {
            return Err(MprdError::InvalidInput(
                "candidates and verdicts length mismatch".into(),
            ));
        }
        if candidates.is_empty() {
            return Err(MprdError::SelectionFailed("no candidates provided".into()));
        }
        if candidates.len() > MAX_CANDIDATES {
            return Err(MprdError::BoundedValueExceeded(
                "too many candidates".into(),
            ));
        }

        let mut best_index: Option<usize> = None;
        for (idx, (candidate, verdict)) in candidates.iter().zip(verdicts.iter()).enumerate() {
            if !verdict.allowed {
                continue;
            }
            match best_index {
                None => best_index = Some(idx),
                Some(current) => {
                    if candidate.score > candidates[current].score {
                        best_index = Some(idx);
                    }
                }
            }
        }

        let chosen_index =
            best_index.ok_or_else(|| MprdError::SelectionFailed("no allowed candidates".into()))?;

        let chosen_action = candidates[chosen_index].clone();
        let decision_commitment = Hash32([0u8; 32]);

        Ok(Decision {
            chosen_index,
            chosen_action,
            policy_hash: policy_hash.clone(),
            decision_commitment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    #[test]
    fn selects_highest_score_allowed() {
        let policy_hash = dummy_hash(1);
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(2),
            state_ref: StateRef::unknown(),
        };
        let candidates = vec![
            CandidateAction {
                action_type: "A".into(),
                params: HashMap::new(),
                score: Score(10),
                candidate_hash: dummy_hash(3),
            },
            CandidateAction {
                action_type: "B".into(),
                params: HashMap::new(),
                score: Score(20),
                candidate_hash: dummy_hash(4),
            },
        ];
        let verdicts = vec![
            RuleVerdict {
                allowed: true,
                reasons: vec![],
                limits: HashMap::new(),
            },
            RuleVerdict {
                allowed: true,
                reasons: vec![],
                limits: HashMap::new(),
            },
        ];

        let selector = DefaultSelector;
        let decision = selector
            .select(&policy_hash, &state, &candidates, &verdicts)
            .expect("selection should succeed");

        assert_eq!(decision.chosen_index, 1);
        assert_eq!(decision.chosen_action.action_type, "B");
    }

    #[test]
    fn fails_when_no_allowed_candidates() {
        let policy_hash = dummy_hash(5);
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(6),
            state_ref: StateRef::unknown(),
        };
        let candidates = vec![CandidateAction {
            action_type: "A".into(),
            params: HashMap::new(),
            score: Score(10),
            candidate_hash: dummy_hash(7),
        }];
        let verdicts = vec![RuleVerdict {
            allowed: false,
            reasons: vec!["denied".into()],
            limits: HashMap::new(),
        }];

        let selector = DefaultSelector;
        let result = selector.select(&policy_hash, &state, &candidates, &verdicts);
        assert!(matches!(result, Err(MprdError::SelectionFailed(_))));
    }

    #[test]
    fn fails_when_too_many_candidates() {
        let policy_hash = dummy_hash(8);
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(9),
            state_ref: StateRef::unknown(),
        };

        let mut candidates = Vec::new();
        let mut verdicts = Vec::new();
        for i in 0..=MAX_CANDIDATES {
            candidates.push(CandidateAction {
                action_type: "A".into(),
                params: HashMap::new(),
                score: Score(i as i64),
                candidate_hash: dummy_hash(10),
            });
            verdicts.push(RuleVerdict {
                allowed: true,
                reasons: vec![],
                limits: HashMap::new(),
            });
        }

        let selector = DefaultSelector;
        let result = selector.select(&policy_hash, &state, &candidates, &verdicts);
        assert!(matches!(result, Err(MprdError::BoundedValueExceeded(_))));
    }

    fn valid_http_call_candidate() -> CandidateAction {
        let params = HashMap::from([
            ("http_method".into(), Value::String("GET".into())),
            (
                "http_url".into(),
                Value::String("https://example.com/health".into()),
            ),
        ]);
        let mut candidate = CandidateAction {
            action_type: validation::ACTION_TYPE_HTTP_CALL_V1.into(),
            params,
            score: Score(7),
            candidate_hash: dummy_hash(0),
        };
        candidate.candidate_hash = hash::hash_candidate_preimage_v1(&hash::candidate_hash_preimage(
            &candidate,
        ));
        candidate
    }

    #[test]
    fn prepare_execution_ready_accepts_well_bound_transcript() {
        let candidate = valid_http_call_candidate();
        let token = DecisionToken {
            policy_hash: dummy_hash(1),
            policy_ref: PolicyRef {
                policy_epoch: 1,
                registry_root: dummy_hash(2),
            },
            state_hash: dummy_hash(3),
            state_ref: StateRef::unknown(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(4),
            timestamp_ms: 0,
            signature: vec![],
        };
        let proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(5),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };

        let ready = prepare_execution_ready(VerifiedBundle::new(&token, &proof)).expect("ready");
        assert_eq!(
            ready.boundary().chosen_action_preimage(),
            proof.chosen_action_preimage.as_slice()
        );
    }

    #[test]
    fn prepare_execution_ready_rejects_missing_chosen_action_preimage() {
        let candidate = valid_http_call_candidate();
        let token = DecisionToken {
            policy_hash: dummy_hash(11),
            policy_ref: PolicyRef {
                policy_epoch: 1,
                registry_root: dummy_hash(12),
            },
            state_hash: dummy_hash(13),
            state_ref: StateRef::unknown(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(14),
            timestamp_ms: 0,
            signature: vec![],
        };
        let proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(15),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };

        let err = prepare_execution_ready(VerifiedBundle::new(&token, &proof)).unwrap_err();
        assert!(matches!(err, MprdError::ExecutionError(_)));
    }

    #[test]
    fn policy_authority_witness_accepts_aligned_decision_and_token() {
        let policy_hash = dummy_hash(21);
        let policy_ref = PolicyRef {
            policy_epoch: 7,
            registry_root: dummy_hash(22),
        };
        let authority =
            policy_authority_witness_v1(&policy_hash, &policy_ref).expect("authority witness");
        let candidate = valid_http_call_candidate();
        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate.clone(),
            policy_hash,
            decision_commitment: dummy_hash(23),
        };
        let token = DecisionToken {
            policy_hash,
            policy_ref: policy_ref.clone(),
            state_hash: dummy_hash(24),
            state_ref: StateRef::unknown(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(25),
            timestamp_ms: 0,
            signature: vec![],
        };

        verify_decision_policy_authority_v1(&authority, &decision)
            .expect("aligned decision should pass");
        verify_token_policy_authority_v1(&authority, &token)
            .expect("aligned token should pass");
    }

    #[test]
    fn policy_authority_witness_rejects_token_policy_ref_drift() {
        let policy_hash = dummy_hash(31);
        let policy_ref = PolicyRef {
            policy_epoch: 7,
            registry_root: dummy_hash(32),
        };
        let authority =
            policy_authority_witness_v1(&policy_hash, &policy_ref).expect("authority witness");
        let token = DecisionToken {
            policy_hash,
            policy_ref: PolicyRef {
                policy_epoch: 8,
                registry_root: dummy_hash(33),
            },
            state_hash: dummy_hash(34),
            state_ref: StateRef::unknown(),
            chosen_action_hash: dummy_hash(35),
            nonce_or_tx_hash: dummy_hash(36),
            timestamp_ms: 0,
            signature: vec![],
        };

        let err = verify_token_policy_authority_v1(&authority, &token)
            .expect_err("policy_ref drift must fail closed");
        assert!(matches!(err, MprdError::InvalidInput(message) if message == "token policy_ref drifted from authorized policy context"));
    }
}
