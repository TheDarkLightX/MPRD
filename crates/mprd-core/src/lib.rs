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
pub mod tau_net_output_attestation;
pub mod tau_testnet;
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
    limits_binding: limits::LimitsBindingWitnessV1,
}

impl ExecutionBoundaryWitnessV1 {
    pub fn chosen_action_preimage(&self) -> &[u8] {
        &self.chosen_action_preimage
    }

    pub fn limits_binding(&self) -> &limits::LimitsBindingWitnessV1 {
        &self.limits_binding
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

/// A token/decision/state packet admitted for attestation after fail-closed identity checks.
#[derive(Clone, Copy, Debug)]
pub struct AttestationReadyBundle<'a> {
    token: &'a DecisionToken,
    decision: &'a Decision,
    state: &'a StateSnapshot,
    governance: Option<GovernanceAdmissionWitnessV1>,
}

impl<'a> AttestationReadyBundle<'a> {
    pub fn token(&self) -> &'a DecisionToken {
        self.token
    }

    pub fn decision(&self) -> &'a Decision {
        self.decision
    }

    pub fn state(&self) -> &'a StateSnapshot {
        self.state
    }

    pub fn governance(&self) -> Option<&GovernanceAdmissionWitnessV1> {
        self.governance.as_ref()
    }
}

pub const GOVERNANCE_INPUT_IS_POLICY_TWEAK_V1: &str = "is_policy_tweak";
pub const GOVERNANCE_INPUT_IS_SAFETY_CHANGE_V1: &str = "is_safety_change";
pub const GOVERNANCE_INPUT_IS_CAP_EXPAND_V1: &str = "is_cap_expand";
pub const GOVERNANCE_INPUT_PROFILE_APP_OK_V1: &str = "profile_app_ok";
pub const GOVERNANCE_INPUT_PROFILE_SAFETY_OK_V1: &str = "profile_safety_ok";
pub const GOVERNANCE_INPUT_LINK_OK_V1: &str = "link_ok";

const GOVERNANCE_PREPARED_INPUT_KEYS_V1: [&str; 6] = [
    GOVERNANCE_INPUT_IS_POLICY_TWEAK_V1,
    GOVERNANCE_INPUT_IS_SAFETY_CHANGE_V1,
    GOVERNANCE_INPUT_IS_CAP_EXPAND_V1,
    GOVERNANCE_INPUT_PROFILE_APP_OK_V1,
    GOVERNANCE_INPUT_PROFILE_SAFETY_OK_V1,
    GOVERNANCE_INPUT_LINK_OK_V1,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernanceUpdateKindV1 {
    PolicyTweak,
    SafetyRuleChange,
    AgentCapabilityExpand,
}

impl GovernanceUpdateKindV1 {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PolicyTweak => "policy_tweak",
            Self::SafetyRuleChange => "safety_rule_change",
            Self::AgentCapabilityExpand => "agent_capability_expand",
        }
    }
}

/// Concrete governance-admission witness derived from the prepared Tau governance lane surface.
///
/// This keeps governance admission off the RC1 path as a free boolean when the canonical
/// governance input rails are present in `state.policy_inputs`.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GovernanceAdmissionWitnessV1 {
    update_kind: GovernanceUpdateKindV1,
    profile_app_ok: bool,
    profile_safety_ok: bool,
    // Retained for audit/export surfaces even though the current constructor only produces `true`.
    link_ok: bool,
}

impl GovernanceAdmissionWitnessV1 {
    pub fn update_kind(&self) -> GovernanceUpdateKindV1 {
        self.update_kind
    }

    pub fn profile_app_ok(&self) -> bool {
        self.profile_app_ok
    }

    pub fn profile_safety_ok(&self) -> bool {
        self.profile_safety_ok
    }

    pub fn link_ok(&self) -> bool {
        self.link_ok
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

/// Concrete token-binding witness carried before token materialization on the RC1 path.
///
/// This narrows the token-factory role: factories receive one immutable binding packet for the
/// critical identity fields instead of reconstructing those fields from loose orchestrator inputs.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionTokenBindingWitnessV1 {
    policy_hash: PolicyHash,
    policy_ref: PolicyRef,
    state_hash: StateHash,
    state_ref: StateRef,
    chosen_action_hash: Hash32,
}

impl DecisionTokenBindingWitnessV1 {
    pub fn policy_hash(&self) -> &PolicyHash {
        &self.policy_hash
    }

    pub fn policy_ref(&self) -> &PolicyRef {
        &self.policy_ref
    }

    pub fn state_hash(&self) -> &StateHash {
        &self.state_hash
    }

    pub fn state_ref(&self) -> &StateRef {
        &self.state_ref
    }

    pub fn chosen_action_hash(&self) -> &Hash32 {
        &self.chosen_action_hash
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

fn decode_policy_input_bool_v1(raw: &[u8]) -> Result<bool> {
    if raw == [0u8] {
        return Ok(false);
    }
    if raw == [1u8] {
        return Ok(true);
    }

    let s = std::str::from_utf8(raw).map_err(|_| {
        MprdError::InvalidInput("governance policy input must be valid utf-8".into())
    })?;
    match s {
        "0" | "false" | "False" | "FALSE" | "F" => Ok(false),
        "1" | "true" | "True" | "TRUE" | "T" => Ok(true),
        _ => Err(MprdError::InvalidInput(format!(
            "unsupported governance policy input bool encoding: {s}"
        ))),
    }
}

/// Construct a concrete governance-admission witness when the prepared Tau governance rails are
/// present in the observed state.
///
/// Semantics:
/// - if none of the canonical governance prepared-input keys are present, governance admission is
///   not modeled on this runtime packet and `Ok(None)` is returned.
/// - if any of the keys are present, all required keys must be present and must satisfy the
///   canonical prepared-lane admission rule fail-closed.
pub fn governance_admission_witness_v1(
    state: &StateSnapshot,
) -> Result<Option<GovernanceAdmissionWitnessV1>> {
    let has_any = GOVERNANCE_PREPARED_INPUT_KEYS_V1
        .iter()
        .any(|k| state.policy_inputs.contains_key(*k));
    if !has_any {
        return Ok(None);
    }

    let read = |key: &str| -> Result<bool> {
        let raw = state.policy_inputs.get(key).ok_or_else(|| {
            MprdError::InvalidInput(format!("missing governance prepared input: {key}"))
        })?;
        decode_policy_input_bool_v1(raw)
    };

    let is_policy_tweak = read(GOVERNANCE_INPUT_IS_POLICY_TWEAK_V1)?;
    let is_safety_change = read(GOVERNANCE_INPUT_IS_SAFETY_CHANGE_V1)?;
    let is_cap_expand = read(GOVERNANCE_INPUT_IS_CAP_EXPAND_V1)?;
    let profile_app_ok = read(GOVERNANCE_INPUT_PROFILE_APP_OK_V1)?;
    let profile_safety_ok = read(GOVERNANCE_INPUT_PROFILE_SAFETY_OK_V1)?;
    let link_ok = read(GOVERNANCE_INPUT_LINK_OK_V1)?;

    let one_hot_count =
        usize::from(is_policy_tweak) + usize::from(is_safety_change) + usize::from(is_cap_expand);
    if one_hot_count != 1 {
        return Err(MprdError::InvalidInput(
            "governance prepared lane is not one-hot".into(),
        ));
    }
    if !link_ok {
        return Err(MprdError::InvalidInput(
            "governance admission requires link_ok".into(),
        ));
    }

    let update_kind = if is_policy_tweak {
        if !profile_app_ok {
            return Err(MprdError::InvalidInput(
                "governance policy_tweak admission requires profile_app_ok".into(),
            ));
        }
        GovernanceUpdateKindV1::PolicyTweak
    } else if is_safety_change {
        if !profile_safety_ok {
            return Err(MprdError::InvalidInput(
                "governance safety_rule_change admission requires profile_safety_ok".into(),
            ));
        }
        GovernanceUpdateKindV1::SafetyRuleChange
    } else {
        if !(profile_app_ok && profile_safety_ok) {
            return Err(MprdError::InvalidInput(
                "governance agent_capability_expand admission requires both profile thresholds"
                    .into(),
            ));
        }
        GovernanceUpdateKindV1::AgentCapabilityExpand
    };

    Ok(Some(GovernanceAdmissionWitnessV1 {
        update_kind,
        profile_app_ok,
        profile_safety_ok,
        link_ok,
    }))
}

/// Construct the concrete token-binding witness from the orchestrator's authority, state, and
/// selected action.
#[must_use]
pub fn decision_token_binding_witness_v1(
    authority: &PolicyAuthorityWitnessV1,
    state_binding: &crate::state_provenance::StateBindingWitnessV1,
    decision: &Decision,
) -> DecisionTokenBindingWitnessV1 {
    DecisionTokenBindingWitnessV1 {
        policy_hash: *authority.policy_hash(),
        policy_ref: authority.policy_ref().clone(),
        state_hash: *state_binding.state_hash(),
        state_ref: state_binding.state_ref().clone(),
        chosen_action_hash: crate::hash::hash_candidate(&decision.chosen_action),
    }
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

    let limits_binding =
        limits::limits_binding_witness_v1(&proof.limits_hash, &proof.limits_bytes)?;

    if proof.chosen_action_preimage.is_empty() {
        return Err(MprdError::InvalidInput(
            "missing chosen_action_preimage (execution boundary requires committed action bytes)"
                .into(),
        ));
    }

    let h = hash::hash_candidate_preimage_v1(&proof.chosen_action_preimage);
    if h != token.chosen_action_hash || h != proof.chosen_action_hash {
        return Err(MprdError::InvalidInput(
            "chosen_action_preimage hash mismatch".into(),
        ));
    }

    let (action_type, params, _score) =
        validation::decode_candidate_preimage_v1(&proof.chosen_action_preimage)?;
    validation::validate_action_schema_v1(&action_type, &params)?;

    Ok(ExecutionBoundaryWitnessV1 {
        chosen_action_preimage: proof.chosen_action_preimage.clone(),
        limits_binding,
    })
}

/// Upgrade a verified bundle into an execution-ready bundle carrying the concrete boundary witness.
pub fn prepare_execution_ready<'a>(
    verified: VerifiedBundle<'a>,
) -> Result<ExecutionReadyBundle<'a>> {
    let boundary = execution_boundary_witness_v1(&verified)?;
    Ok(ExecutionReadyBundle { verified, boundary })
}

/// Upgrade token, decision, and state inputs into an attestation-ready bundle after checking that
/// they still agree on the selected action and observed state identity.
pub fn prepare_attestation_ready<'a>(
    token: &'a DecisionToken,
    decision: &'a Decision,
    state: &'a StateSnapshot,
) -> Result<AttestationReadyBundle<'a>> {
    if token.policy_hash != decision.policy_hash {
        return Err(MprdError::InvalidInput(
            "token policy_hash drifted from selected decision before attestation".into(),
        ));
    }
    if token.state_hash != state.state_hash {
        return Err(MprdError::InvalidInput(
            "token state_hash drifted from observed snapshot before attestation".into(),
        ));
    }
    if token.state_ref != state.state_ref {
        return Err(MprdError::InvalidInput(
            "token state_ref drifted from observed snapshot before attestation".into(),
        ));
    }
    if token.chosen_action_hash != hash::hash_candidate(&decision.chosen_action) {
        return Err(MprdError::InvalidInput(
            "token chosen_action_hash drifted from selected decision before attestation".into(),
        ));
    }
    let governance = governance_admission_witness_v1(state)?;

    Ok(AttestationReadyBundle {
        token,
        decision,
        state,
        governance,
    })
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
    /// Preferred RC1 path: attest from an already-validated token/decision/state packet.
    ///
    /// Postconditions:
    /// - Returned bundle commitments are consistent with the admitted attestation inputs.
    fn attest_ready(
        &self,
        ready: &AttestationReadyBundle<'_>,
        candidates: &[CandidateAction],
    ) -> Result<ProofBundle>;

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
    ) -> Result<ProofBundle> {
        let ready = prepare_attestation_ready(token, decision, state)?;
        self.attest_ready(&ready, candidates)
    }
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
        candidate.candidate_hash =
            hash::hash_candidate_preimage_v1(&hash::candidate_hash_preimage(&candidate));
        candidate
    }

    fn governance_policy_inputs(
        update_kind: GovernanceUpdateKindV1,
        profile_app_ok: bool,
        profile_safety_ok: bool,
        link_ok: bool,
    ) -> HashMap<String, Vec<u8>> {
        let (is_policy_tweak, is_safety_change, is_cap_expand) = match update_kind {
            GovernanceUpdateKindV1::PolicyTweak => (true, false, false),
            GovernanceUpdateKindV1::SafetyRuleChange => (false, true, false),
            GovernanceUpdateKindV1::AgentCapabilityExpand => (false, false, true),
        };
        let enc = |b: bool| if b { b"1".to_vec() } else { b"0".to_vec() };
        HashMap::from([
            (
                GOVERNANCE_INPUT_IS_POLICY_TWEAK_V1.into(),
                enc(is_policy_tweak),
            ),
            (
                GOVERNANCE_INPUT_IS_SAFETY_CHANGE_V1.into(),
                enc(is_safety_change),
            ),
            (GOVERNANCE_INPUT_IS_CAP_EXPAND_V1.into(), enc(is_cap_expand)),
            (
                GOVERNANCE_INPUT_PROFILE_APP_OK_V1.into(),
                enc(profile_app_ok),
            ),
            (
                GOVERNANCE_INPUT_PROFILE_SAFETY_OK_V1.into(),
                enc(profile_safety_ok),
            ),
            (GOVERNANCE_INPUT_LINK_OK_V1.into(), enc(link_ok)),
        ])
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
        assert_eq!(
            ready.boundary().limits_binding().limits(),
            &limits::LimitsV1::default()
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
        assert!(matches!(err, MprdError::InvalidInput(_)));
    }

    #[test]
    fn prepare_attestation_ready_accepts_aligned_inputs() {
        let candidate = valid_http_call_candidate();
        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate.clone(),
            policy_hash: dummy_hash(16),
            decision_commitment: dummy_hash(17),
        };
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(18),
            state_ref: StateRef {
                state_source_id: dummy_hash(19),
                state_epoch: 2,
                state_attestation_hash: dummy_hash(20),
            },
        };
        let token = DecisionToken {
            policy_hash: decision.policy_hash,
            policy_ref: PolicyRef {
                policy_epoch: 1,
                registry_root: dummy_hash(21),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: hash::hash_candidate(&decision.chosen_action),
            nonce_or_tx_hash: dummy_hash(22),
            timestamp_ms: 0,
            signature: vec![],
        };

        let ready = prepare_attestation_ready(&token, &decision, &state).expect("ready");
        assert_eq!(ready.token(), &token);
        assert_eq!(ready.decision(), &decision);
        assert_eq!(ready.state(), &state);
        assert!(ready.governance().is_none());
    }

    #[test]
    fn prepare_attestation_ready_accepts_governance_admitted_inputs() {
        let candidate = valid_http_call_candidate();
        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate.clone(),
            policy_hash: dummy_hash(31),
            decision_commitment: dummy_hash(32),
        };
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: governance_policy_inputs(
                GovernanceUpdateKindV1::AgentCapabilityExpand,
                true,
                true,
                true,
            ),
            state_hash: dummy_hash(33),
            state_ref: StateRef {
                state_source_id: dummy_hash(34),
                state_epoch: 4,
                state_attestation_hash: dummy_hash(35),
            },
        };
        let token = DecisionToken {
            policy_hash: decision.policy_hash,
            policy_ref: PolicyRef {
                policy_epoch: 2,
                registry_root: dummy_hash(36),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: hash::hash_candidate(&decision.chosen_action),
            nonce_or_tx_hash: dummy_hash(37),
            timestamp_ms: 0,
            signature: vec![],
        };

        let ready = prepare_attestation_ready(&token, &decision, &state).expect("ready");
        let governance = ready.governance().expect("governance witness");
        assert_eq!(
            governance.update_kind(),
            GovernanceUpdateKindV1::AgentCapabilityExpand
        );
        assert!(governance.profile_app_ok());
        assert!(governance.profile_safety_ok());
        assert!(governance.link_ok());
    }

    #[test]
    fn prepare_attestation_ready_accepts_safety_rule_change_governance_inputs() {
        let candidate = valid_http_call_candidate();
        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate.clone(),
            policy_hash: dummy_hash(48),
            decision_commitment: dummy_hash(49),
        };
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: governance_policy_inputs(
                GovernanceUpdateKindV1::SafetyRuleChange,
                false,
                true,
                true,
            ),
            state_hash: dummy_hash(50),
            state_ref: StateRef {
                state_source_id: dummy_hash(51),
                state_epoch: 7,
                state_attestation_hash: dummy_hash(52),
            },
        };
        let token = DecisionToken {
            policy_hash: decision.policy_hash,
            policy_ref: PolicyRef {
                policy_epoch: 4,
                registry_root: dummy_hash(53),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: hash::hash_candidate(&decision.chosen_action),
            nonce_or_tx_hash: dummy_hash(54),
            timestamp_ms: 0,
            signature: vec![],
        };

        let ready = prepare_attestation_ready(&token, &decision, &state).expect("ready");
        let governance = ready.governance().expect("governance witness");
        assert_eq!(
            governance.update_kind(),
            GovernanceUpdateKindV1::SafetyRuleChange
        );
        assert!(!governance.profile_app_ok());
        assert!(governance.profile_safety_ok());
        assert!(governance.link_ok());
    }

    #[test]
    fn prepare_attestation_ready_rejects_chosen_action_hash_drift() {
        let candidate = valid_http_call_candidate();
        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate,
            policy_hash: dummy_hash(23),
            decision_commitment: dummy_hash(24),
        };
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(25),
            state_ref: StateRef {
                state_source_id: dummy_hash(26),
                state_epoch: 3,
                state_attestation_hash: dummy_hash(27),
            },
        };
        let token = DecisionToken {
            policy_hash: decision.policy_hash,
            policy_ref: PolicyRef {
                policy_epoch: 1,
                registry_root: dummy_hash(28),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: dummy_hash(29),
            nonce_or_tx_hash: dummy_hash(30),
            timestamp_ms: 0,
            signature: vec![],
        };

        let err = prepare_attestation_ready(&token, &decision, &state).unwrap_err();
        assert!(
            matches!(err, MprdError::InvalidInput(message) if message == "token chosen_action_hash drifted from selected decision before attestation")
        );
    }

    #[test]
    fn prepare_attestation_ready_rejects_governance_inputs_without_link_ok() {
        let candidate = valid_http_call_candidate();
        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate.clone(),
            policy_hash: dummy_hash(38),
            decision_commitment: dummy_hash(39),
        };
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: governance_policy_inputs(
                GovernanceUpdateKindV1::PolicyTweak,
                true,
                false,
                false,
            ),
            state_hash: dummy_hash(40),
            state_ref: StateRef {
                state_source_id: dummy_hash(41),
                state_epoch: 5,
                state_attestation_hash: dummy_hash(42),
            },
        };
        let token = DecisionToken {
            policy_hash: decision.policy_hash,
            policy_ref: PolicyRef {
                policy_epoch: 3,
                registry_root: dummy_hash(43),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: hash::hash_candidate(&decision.chosen_action),
            nonce_or_tx_hash: dummy_hash(44),
            timestamp_ms: 0,
            signature: vec![],
        };

        let err = prepare_attestation_ready(&token, &decision, &state).unwrap_err();
        assert!(
            matches!(err, MprdError::InvalidInput(message) if message == "governance admission requires link_ok")
        );
    }

    #[test]
    fn governance_admission_witness_rejects_non_one_hot_prepared_lane() {
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::from([
                (GOVERNANCE_INPUT_IS_POLICY_TWEAK_V1.into(), b"1".to_vec()),
                (GOVERNANCE_INPUT_IS_SAFETY_CHANGE_V1.into(), b"1".to_vec()),
                (GOVERNANCE_INPUT_IS_CAP_EXPAND_V1.into(), b"0".to_vec()),
                (GOVERNANCE_INPUT_PROFILE_APP_OK_V1.into(), b"1".to_vec()),
                (GOVERNANCE_INPUT_PROFILE_SAFETY_OK_V1.into(), b"1".to_vec()),
                (GOVERNANCE_INPUT_LINK_OK_V1.into(), b"1".to_vec()),
            ]),
            state_hash: dummy_hash(45),
            state_ref: StateRef {
                state_source_id: dummy_hash(46),
                state_epoch: 6,
                state_attestation_hash: dummy_hash(47),
            },
        };

        let err = governance_admission_witness_v1(&state).unwrap_err();
        assert!(
            matches!(err, MprdError::InvalidInput(message) if message == "governance prepared lane is not one-hot")
        );
    }

    #[test]
    fn governance_admission_witness_rejects_zero_hot_prepared_lane() {
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::from([
                (GOVERNANCE_INPUT_IS_POLICY_TWEAK_V1.into(), b"0".to_vec()),
                (GOVERNANCE_INPUT_IS_SAFETY_CHANGE_V1.into(), b"0".to_vec()),
                (GOVERNANCE_INPUT_IS_CAP_EXPAND_V1.into(), b"0".to_vec()),
                (GOVERNANCE_INPUT_PROFILE_APP_OK_V1.into(), b"0".to_vec()),
                (GOVERNANCE_INPUT_PROFILE_SAFETY_OK_V1.into(), b"0".to_vec()),
                (GOVERNANCE_INPUT_LINK_OK_V1.into(), b"1".to_vec()),
            ]),
            state_hash: dummy_hash(55),
            state_ref: StateRef {
                state_source_id: dummy_hash(56),
                state_epoch: 8,
                state_attestation_hash: dummy_hash(57),
            },
        };

        let err = governance_admission_witness_v1(&state).unwrap_err();
        assert!(
            matches!(err, MprdError::InvalidInput(message) if message == "governance prepared lane is not one-hot")
        );
    }

    #[test]
    fn governance_admission_witness_rejects_whitespace_padded_ascii_bool() {
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::from([
                (GOVERNANCE_INPUT_IS_POLICY_TWEAK_V1.into(), b" 1 ".to_vec()),
                (GOVERNANCE_INPUT_IS_SAFETY_CHANGE_V1.into(), b"0".to_vec()),
                (GOVERNANCE_INPUT_IS_CAP_EXPAND_V1.into(), b"0".to_vec()),
                (GOVERNANCE_INPUT_PROFILE_APP_OK_V1.into(), b"1".to_vec()),
                (GOVERNANCE_INPUT_PROFILE_SAFETY_OK_V1.into(), b"0".to_vec()),
                (GOVERNANCE_INPUT_LINK_OK_V1.into(), b"1".to_vec()),
            ]),
            state_hash: dummy_hash(58),
            state_ref: StateRef {
                state_source_id: dummy_hash(59),
                state_epoch: 9,
                state_attestation_hash: dummy_hash(60),
            },
        };

        let err = governance_admission_witness_v1(&state).unwrap_err();
        assert!(
            matches!(err, MprdError::InvalidInput(message) if message == "unsupported governance policy input bool encoding:  1 ")
        );
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
        verify_token_policy_authority_v1(&authority, &token).expect("aligned token should pass");
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
        assert!(
            matches!(err, MprdError::InvalidInput(message) if message == "token policy_ref drifted from authorized policy context")
        );
    }

    #[test]
    fn decision_token_binding_witness_carries_authority_and_state_identity() {
        let policy_hash = dummy_hash(26);
        let policy_ref = PolicyRef {
            policy_epoch: 9,
            registry_root: dummy_hash(27),
        };
        let authority =
            policy_authority_witness_v1(&policy_hash, &policy_ref).expect("authority witness");
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(28),
            state_ref: StateRef {
                state_source_id: dummy_hash(29),
                state_epoch: 3,
                state_attestation_hash: dummy_hash(30),
            },
        };
        let state_binding = crate::state_provenance::state_binding_witness_v1(&state);
        let candidate = valid_http_call_candidate();
        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate.clone(),
            policy_hash,
            decision_commitment: dummy_hash(31),
        };

        let binding = decision_token_binding_witness_v1(&authority, &state_binding, &decision);
        assert_eq!(binding.policy_hash(), &policy_hash);
        assert_eq!(binding.policy_ref(), &policy_ref);
        assert_eq!(binding.state_hash(), &state.state_hash);
        assert_eq!(binding.state_ref(), &state.state_ref);
        assert_eq!(
            binding.chosen_action_hash(),
            &crate::hash::hash_candidate(&candidate)
        );
    }
}
