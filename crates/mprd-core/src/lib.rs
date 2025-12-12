use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod anti_replay;
pub mod components;
pub mod config;
pub mod crypto;
pub mod hash;
pub mod metrics;
pub mod mpb;
pub mod orchestrator;
pub mod registry;
pub mod tau;

pub use config::MprdConfig;
pub use crypto::{TokenSigningKey, TokenVerifyingKey};

/// 32-byte hash newtype used for commitments (policy, state, actions, etc.).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash32(pub [u8; 32]);

pub type PolicyHash = Hash32;
pub type StateHash = Hash32;
pub type CandidateHash = Hash32;
pub type NonceHash = Hash32;

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
    pub state_hash: StateHash,
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
    pub risc0_receipt: Vec<u8>,
    pub attestation_metadata: HashMap<String, String>,
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
    /// Postconditions:
    /// - Returned state satisfies all `StateSnapshot` invariants.
    fn snapshot(&self) -> Result<StateSnapshot>;
}

/// Generates a finite set of candidate actions from a state.
pub trait Proposer {
    /// Preconditions:
    /// - `state` satisfies `StateSnapshot` invariants.
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
    /// - `decision` was produced by a compliant `Selector`.
    /// - `candidates.len() <= MAX_CANDIDATES`.
    /// Postconditions:
    /// - Returned bundle commitments are consistent with inputs.
    fn attest(
        &self,
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
    /// Preconditions:
    /// - `ZkLocalVerifier::verify(token, proof)` has returned `Success`.
    /// - Token freshness and anti-replay checks have passed.
    /// Postconditions:
    /// - Either performs the side effect exactly once, or performs none.
    fn execute(&self, token: &DecisionToken, proof: &ProofBundle) -> Result<ExecutionResult>;
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
            return Err(MprdError::SelectionFailed(
                "no candidates provided".into(),
            ));
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

        let chosen_index = best_index.ok_or_else(|| {
            MprdError::SelectionFailed("no allowed candidates".into())
        })?;

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

pub fn init() {}
