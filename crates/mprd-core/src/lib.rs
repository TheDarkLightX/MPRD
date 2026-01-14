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
}
