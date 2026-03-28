use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
#[allow(clippy::module_inception)]
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
#[must_use]
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

/// Typed packet for the concrete binding half of the abstract execution-boundary witness.
///
/// This is the smallest grouped language for the verified-decision tuple that the orchestrator
/// had in hand immediately before execution.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionBindingVectorPacketV1 {
    decision_commitment: Hash32,
    policy_hash: PolicyHash,
    policy_ref: PolicyRef,
    state_ref: StateRef,
    state_hash: StateHash,
    candidate_set_hash: Hash32,
    chosen_action_hash: Hash32,
    nonce_or_tx_hash: NonceHash,
    limits_hash: Hash32,
}

impl ExecutionBindingVectorPacketV1 {
    pub fn decision_commitment(&self) -> &Hash32 {
        &self.decision_commitment
    }

    pub fn policy_hash(&self) -> &PolicyHash {
        &self.policy_hash
    }

    pub fn policy_ref(&self) -> &PolicyRef {
        &self.policy_ref
    }

    pub fn state_ref(&self) -> &StateRef {
        &self.state_ref
    }

    pub fn state_hash(&self) -> &StateHash {
        &self.state_hash
    }

    pub fn candidate_set_hash(&self) -> &Hash32 {
        &self.candidate_set_hash
    }

    pub fn chosen_action_hash(&self) -> &Hash32 {
        &self.chosen_action_hash
    }

    pub fn nonce_or_tx_hash(&self) -> &NonceHash {
        &self.nonce_or_tx_hash
    }

    pub fn limits_hash(&self) -> &Hash32 {
        &self.limits_hash
    }
}

/// Typed packet for the concrete refinement artifact at the live execute boundary.
///
/// This groups the exact ready-packet hash with the verified proof attestation-metadata hash,
/// instead of leaving the top-level refinement artifact as two adjacent hashes by convention.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionBoundaryRefinementPacketV1 {
    execution_ready_packet_hash: Hash32,
    attestation_metadata_hash: Hash32,
}

impl ExecutionBoundaryRefinementPacketV1 {
    pub fn execution_ready_packet_hash(&self) -> &Hash32 {
        &self.execution_ready_packet_hash
    }

    pub fn attestation_metadata_hash(&self) -> &Hash32 {
        &self.attestation_metadata_hash
    }
}

/// Constructor-gated runtime packet carried into the live execute boundary on the RC1 path.
///
/// This groups the concrete execution boundary witness with the optional orchestrator
/// authorization and signed-registry bridge facts, so the shipped runtime no longer carries
/// those as three unrelated adjacent fields.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionReadyPacketV1 {
    boundary: ExecutionBoundaryWitnessV1,
    authorization: Option<ExecutionAuthorizationWitnessV1>,
    bridge: Option<ExecutionRegistryBridgeWitnessV1>,
    executor_admission: Option<ExecutionExecutorAdmissionWitnessV1>,
}

impl ExecutionReadyPacketV1 {
    pub fn boundary(&self) -> &ExecutionBoundaryWitnessV1 {
        &self.boundary
    }

    pub fn authorization(&self) -> Option<&ExecutionAuthorizationWitnessV1> {
        self.authorization.as_ref()
    }

    pub fn bridge(&self) -> Option<&ExecutionRegistryBridgeWitnessV1> {
        self.bridge.as_ref()
    }

    pub fn executor_admission(&self) -> Option<&ExecutionExecutorAdmissionWitnessV1> {
        self.executor_admission.as_ref()
    }
}

/// A locally verified bundle that is also admitted through the concrete execution boundary.
#[derive(Clone, Debug)]
pub struct ExecutionReadyBundle<'a> {
    verified: VerifiedBundle<'a>,
    packet: ExecutionReadyPacketV1,
}

impl<'a> ExecutionReadyBundle<'a> {
    pub fn verified(&self) -> &VerifiedBundle<'a> {
        &self.verified
    }

    pub fn packet(&self) -> &ExecutionReadyPacketV1 {
        &self.packet
    }

    pub fn boundary(&self) -> &ExecutionBoundaryWitnessV1 {
        self.packet.boundary()
    }

    pub fn authorization(&self) -> Option<&ExecutionAuthorizationWitnessV1> {
        self.packet.authorization()
    }

    pub fn bridge(&self) -> Option<&ExecutionRegistryBridgeWitnessV1> {
        self.packet.bridge()
    }

    pub fn executor_admission(&self) -> Option<&ExecutionExecutorAdmissionWitnessV1> {
        self.packet.executor_admission()
    }

    pub fn token(&self) -> &'a DecisionToken {
        self.verified.token()
    }

    pub fn proof(&self) -> &'a ProofBundle {
        self.verified.proof()
    }
}

/// A token/decision/state packet admitted for attestation after fail-closed identity checks.
#[derive(Clone, Debug)]
pub struct AttestationReadyBundle<'a> {
    token: &'a DecisionToken,
    decision: &'a Decision,
    state: &'a StateSnapshot,
    governance: Option<GovernanceAdmissionWitnessV1>,
    execution_authorization: ExecutionAuthorizationAttestationV1,
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

    pub fn execution_authorization(&self) -> &ExecutionAuthorizationAttestationV1 {
        &self.execution_authorization
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

    pub fn from_str_v1(value: &str) -> Result<Self> {
        match value {
            "policy_tweak" => Ok(Self::PolicyTweak),
            "safety_rule_change" => Ok(Self::SafetyRuleChange),
            "agent_capability_expand" => Ok(Self::AgentCapabilityExpand),
            _ => Err(MprdError::InvalidInput(
                "invalid governance_update_kind attestation metadata".into(),
            )),
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

pub const GOVERNANCE_ATTESTATION_METADATA_UPDATE_KIND_V1: &str = "governance_update_kind";
pub const GOVERNANCE_ATTESTATION_METADATA_PROFILE_APP_OK_V1: &str = "governance_profile_app_ok";
pub const GOVERNANCE_ATTESTATION_METADATA_PROFILE_SAFETY_OK_V1: &str =
    "governance_profile_safety_ok";
pub const GOVERNANCE_ATTESTATION_METADATA_LINK_OK_V1: &str = "governance_link_ok";
pub const EXECUTION_AUTH_ATTESTATION_METADATA_HASH_V1: &str = "execution_authorization_hash_v1";
const EXECUTION_AUTH_ATTESTATION_METADATA_DOMAIN_V1: &[u8] =
    b"MPRD_EXECUTION_AUTH_METADATA_HASH_V1";
const REGISTRY_AUTHORIZATION_ATTESTATION_DOMAIN_V1: &[u8] =
    b"MPRD_REGISTRY_AUTHORIZATION_ATTESTATION_V1";
const EXECUTION_READY_PACKET_HASH_DOMAIN_V1: &[u8] = b"MPRD_EXECUTION_READY_PACKET_HASH_V1";
const EXECUTION_BOUNDARY_REFINEMENT_HASH_DOMAIN_V1: &[u8] =
    b"MPRD_EXECUTION_BOUNDARY_REFINEMENT_HASH_V1";
const EXECUTION_BINDING_VECTOR_HASH_DOMAIN_V1: &[u8] = b"MPRD_EXECUTION_BINDING_VECTOR_HASH_V1";

/// Concrete policy authority witness carried on the RC1 path.
///
/// This binds the exact `(policy_hash, policy_ref)` pair the orchestrator was authorized to use
/// and lets downstream stages fail closed on any selector/token drift.
#[must_use]
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

/// Concrete execution-authorization witness carried into the executor boundary on the RC1 path.
///
/// This preserves the orchestrator's admitted policy/state/governance identity beyond
/// attestation, so execution no longer relies only on transcript-local bindings.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionAuthorizationWitnessV1 {
    policy_authority: PolicyAuthorityWitnessV1,
    state_binding: crate::state_provenance::StateBindingWitnessV1,
    governance: Option<GovernanceAdmissionWitnessV1>,
}

impl ExecutionAuthorizationWitnessV1 {
    pub fn policy_authority(&self) -> &PolicyAuthorityWitnessV1 {
        &self.policy_authority
    }

    pub fn state_binding(&self) -> &crate::state_provenance::StateBindingWitnessV1 {
        &self.state_binding
    }

    pub fn governance(&self) -> Option<&GovernanceAdmissionWitnessV1> {
        self.governance.as_ref()
    }
}

/// Typed execution-authorization attestation packet reconstructed from proof metadata.
///
/// This is the smallest concrete audit packet for the attested policy/state/governance identity:
/// it preserves the exact authorization fields that are hashed into
/// `execution_authorization_hash_v1` without requiring consumers to reverse-engineer them from
/// unrelated hashes or raw metadata.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionAuthorizationAttestationV1 {
    policy_hash: PolicyHash,
    policy_ref: PolicyRef,
    state_hash: StateHash,
    state_ref: StateRef,
    governance: Option<GovernanceAdmissionWitnessV1>,
}

impl ExecutionAuthorizationAttestationV1 {
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

    pub fn governance(&self) -> Option<&GovernanceAdmissionWitnessV1> {
        self.governance.as_ref()
    }
}

/// Concrete signed-registry bridge witness carried into the live execute path.
///
/// This preserves the exact concrete registry authorization tuple and optional checkpoint binding
/// beyond the local bridge helper, so side-effecting adapters do not have to recover those facts
/// only from generic proof metadata.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryAuthorizationWitnessV1 {
    resolution_hash: Hash32,
    exec_kind_id: crate::artifact_repo::Id32,
    exec_version_id: crate::artifact_repo::Id32,
    image_id: crate::artifact_repo::Id32,
    policy_source_kind_id: Option<crate::artifact_repo::Id32>,
    policy_source_hash: Option<Hash32>,
}

impl RegistryAuthorizationWitnessV1 {
    pub fn resolution_hash(&self) -> &Hash32 {
        &self.resolution_hash
    }

    pub fn exec_kind_id(&self) -> &crate::artifact_repo::Id32 {
        &self.exec_kind_id
    }

    pub fn exec_version_id(&self) -> &crate::artifact_repo::Id32 {
        &self.exec_version_id
    }

    pub fn image_id(&self) -> &crate::artifact_repo::Id32 {
        &self.image_id
    }

    pub fn policy_source_kind_id(&self) -> Option<&crate::artifact_repo::Id32> {
        self.policy_source_kind_id.as_ref()
    }

    pub fn policy_source_hash(&self) -> Option<&Hash32> {
        self.policy_source_hash.as_ref()
    }
}

/// Typed registry-authorization attestation packet reconstructed from the bridge tuple.
///
/// This is the smallest concrete audit packet for the resolved registry authorization surface:
/// exact resolution hash plus the exec/image/source tuple it commits to.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryAuthorizationAttestationV1 {
    resolution_hash: Hash32,
    exec_kind_id: crate::artifact_repo::Id32,
    exec_version_id: crate::artifact_repo::Id32,
    image_id: crate::artifact_repo::Id32,
    policy_source_kind_id: Option<crate::artifact_repo::Id32>,
    policy_source_hash: Option<Hash32>,
}

impl RegistryAuthorizationAttestationV1 {
    pub fn resolution_hash(&self) -> &Hash32 {
        &self.resolution_hash
    }

    pub fn exec_kind_id(&self) -> &crate::artifact_repo::Id32 {
        &self.exec_kind_id
    }

    pub fn exec_version_id(&self) -> &crate::artifact_repo::Id32 {
        &self.exec_version_id
    }

    pub fn image_id(&self) -> &crate::artifact_repo::Id32 {
        &self.image_id
    }

    pub fn policy_source_kind_id(&self) -> Option<&crate::artifact_repo::Id32> {
        self.policy_source_kind_id.as_ref()
    }

    pub fn policy_source_hash(&self) -> Option<&Hash32> {
        self.policy_source_hash.as_ref()
    }
}

/// Typed bridge attestation packet reconstructed from the live signed-registry bridge witness.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionRegistryBridgeAttestationV1 {
    registry_authorization: RegistryAuthorizationAttestationV1,
    registry_checkpoint_attestation_hash: Option<Hash32>,
}

impl ExecutionRegistryBridgeAttestationV1 {
    pub fn registry_authorization(&self) -> &RegistryAuthorizationAttestationV1 {
        &self.registry_authorization
    }

    pub fn registry_checkpoint_attestation_hash(&self) -> Option<&Hash32> {
        self.registry_checkpoint_attestation_hash.as_ref()
    }
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionRegistryBridgeWitnessV1 {
    registry_authorization: RegistryAuthorizationWitnessV1,
    registry_checkpoint_attestation_hash: Option<Hash32>,
}

impl ExecutionRegistryBridgeWitnessV1 {
    pub fn registry_authorization(&self) -> &RegistryAuthorizationWitnessV1 {
        &self.registry_authorization
    }

    pub fn registry_authorization_hash(&self) -> &Hash32 {
        self.registry_authorization.resolution_hash()
    }

    pub fn registry_checkpoint_attestation_hash(&self) -> Option<&Hash32> {
        self.registry_checkpoint_attestation_hash.as_ref()
    }
}

/// Concrete executor-side admission witnesses accumulated at the live `execute_ready` boundary.
///
/// These witnesses are produced by runtime guard wrappers such as signature and state-provenance
/// admission. They remain separate from orchestrator authorization because they depend on local
/// executor configuration rather than only on the attested protocol objects.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExecutionExecutorAdmissionWitnessV1 {
    signature: Option<crate::crypto::SignatureAdmissionWitnessV1>,
    state_provenance: Option<crate::state_provenance::StateProvenanceWitnessV1>,
    replay_clearance: Option<crate::anti_replay::ReplayClearanceWitnessV1>,
}

impl ExecutionExecutorAdmissionWitnessV1 {
    pub fn signature(&self) -> Option<&crate::crypto::SignatureAdmissionWitnessV1> {
        self.signature.as_ref()
    }

    pub fn state_provenance(&self) -> Option<&crate::state_provenance::StateProvenanceWitnessV1> {
        self.state_provenance.as_ref()
    }

    pub fn replay_clearance(&self) -> Option<&crate::anti_replay::ReplayClearanceWitnessV1> {
        self.replay_clearance.as_ref()
    }

    fn with_signature(mut self, signature: crate::crypto::SignatureAdmissionWitnessV1) -> Self {
        self.signature = Some(signature);
        self
    }

    fn with_state_provenance(
        mut self,
        state_provenance: crate::state_provenance::StateProvenanceWitnessV1,
    ) -> Self {
        self.state_provenance = Some(state_provenance);
        self
    }

    fn with_replay_clearance(
        mut self,
        replay_clearance: crate::anti_replay::ReplayClearanceWitnessV1,
    ) -> Self {
        self.replay_clearance = Some(replay_clearance);
        self
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

/// Construct a concrete governance-admission witness from canonical governance gate fields.
///
/// This is the single RC1 admission rule once the update kind and gate booleans have been parsed
/// from any concrete source.
pub fn governance_admission_witness_from_fields_v1(
    update_kind: GovernanceUpdateKindV1,
    profile_app_ok: bool,
    profile_safety_ok: bool,
    link_ok: bool,
) -> Result<GovernanceAdmissionWitnessV1> {
    if !link_ok {
        return Err(MprdError::InvalidInput(
            "governance admission requires link_ok".into(),
        ));
    }

    match update_kind {
        GovernanceUpdateKindV1::PolicyTweak => {
            if !profile_app_ok {
                return Err(MprdError::InvalidInput(
                    "governance policy_tweak admission requires profile_app_ok".into(),
                ));
            }
        }
        GovernanceUpdateKindV1::SafetyRuleChange => {
            if !profile_safety_ok {
                return Err(MprdError::InvalidInput(
                    "governance safety_rule_change admission requires profile_safety_ok".into(),
                ));
            }
        }
        GovernanceUpdateKindV1::AgentCapabilityExpand => {
            if !(profile_app_ok && profile_safety_ok) {
                return Err(MprdError::InvalidInput(
                    "governance agent_capability_expand admission requires both profile thresholds"
                        .into(),
                ));
            }
        }
    }

    Ok(GovernanceAdmissionWitnessV1 {
        update_kind,
        profile_app_ok,
        profile_safety_ok,
        link_ok,
    })
}

fn governance_attestation_bool_v1(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn governance_attestation_bool_from_str_v1(key: &'static str, value: &str) -> Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(MprdError::InvalidInput(format!(
            "invalid {key} attestation metadata bool"
        ))),
    }
}

/// Emit canonical governance attestation metadata for the admitted governance witness.
pub fn insert_governance_attestation_metadata_v1(
    metadata: &mut HashMap<String, String>,
    governance: &GovernanceAdmissionWitnessV1,
) {
    metadata.insert(
        GOVERNANCE_ATTESTATION_METADATA_UPDATE_KIND_V1.into(),
        governance.update_kind().as_str().into(),
    );
    metadata.insert(
        GOVERNANCE_ATTESTATION_METADATA_PROFILE_APP_OK_V1.into(),
        governance_attestation_bool_v1(governance.profile_app_ok()).into(),
    );
    metadata.insert(
        GOVERNANCE_ATTESTATION_METADATA_PROFILE_SAFETY_OK_V1.into(),
        governance_attestation_bool_v1(governance.profile_safety_ok()).into(),
    );
    metadata.insert(
        GOVERNANCE_ATTESTATION_METADATA_LINK_OK_V1.into(),
        governance_attestation_bool_v1(governance.link_ok()).into(),
    );
}

/// Reconstruct the admitted governance witness from canonical proof metadata.
///
/// This is used by audit and export surfaces that must expose governance provenance as a typed
/// object instead of burying it inside the raw metadata map.
pub fn governance_admission_witness_from_attestation_metadata_v1(
    metadata: &HashMap<String, String>,
) -> Result<Option<GovernanceAdmissionWitnessV1>> {
    let update_kind = metadata.get(GOVERNANCE_ATTESTATION_METADATA_UPDATE_KIND_V1);
    let profile_app_ok = metadata.get(GOVERNANCE_ATTESTATION_METADATA_PROFILE_APP_OK_V1);
    let profile_safety_ok = metadata.get(GOVERNANCE_ATTESTATION_METADATA_PROFILE_SAFETY_OK_V1);
    let link_ok = metadata.get(GOVERNANCE_ATTESTATION_METADATA_LINK_OK_V1);

    let present_count = usize::from(update_kind.is_some())
        + usize::from(profile_app_ok.is_some())
        + usize::from(profile_safety_ok.is_some())
        + usize::from(link_ok.is_some());
    if present_count == 0 {
        return Ok(None);
    }
    if present_count != 4 {
        return Err(MprdError::InvalidInput(
            "partial governance attestation metadata cannot reconstruct admitted governance".into(),
        ));
    }

    let update_kind =
        GovernanceUpdateKindV1::from_str_v1(update_kind.expect("checked above").as_str())?;
    let profile_app_ok = governance_attestation_bool_from_str_v1(
        GOVERNANCE_ATTESTATION_METADATA_PROFILE_APP_OK_V1,
        profile_app_ok.expect("checked above").as_str(),
    )?;
    let profile_safety_ok = governance_attestation_bool_from_str_v1(
        GOVERNANCE_ATTESTATION_METADATA_PROFILE_SAFETY_OK_V1,
        profile_safety_ok.expect("checked above").as_str(),
    )?;
    let link_ok = governance_attestation_bool_from_str_v1(
        GOVERNANCE_ATTESTATION_METADATA_LINK_OK_V1,
        link_ok.expect("checked above").as_str(),
    )?;

    governance_admission_witness_from_fields_v1(
        update_kind,
        profile_app_ok,
        profile_safety_ok,
        link_ok,
    )
    .map(Some)
}

fn require_governance_attestation_metadata_value_v1<'a>(
    metadata: &'a HashMap<String, String>,
    key: &'static str,
) -> Result<&'a str> {
    metadata
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| MprdError::InvalidInput(format!("missing {key} attestation metadata")))
}

/// Verify that proof metadata preserved the same admitted governance witness.
pub fn verify_governance_attestation_metadata_v1(
    proof: &ProofBundle,
    governance: &GovernanceAdmissionWitnessV1,
) -> Result<()> {
    let metadata = &proof.attestation_metadata;
    let expected_update_kind = governance.update_kind().as_str();
    let actual_update_kind = require_governance_attestation_metadata_value_v1(
        metadata,
        GOVERNANCE_ATTESTATION_METADATA_UPDATE_KIND_V1,
    )?;
    if actual_update_kind != expected_update_kind {
        return Err(MprdError::InvalidInput(
            "governance_update_kind attestation metadata drifted from admitted governance".into(),
        ));
    }

    let expected_profile_app_ok = governance_attestation_bool_v1(governance.profile_app_ok());
    let actual_profile_app_ok = require_governance_attestation_metadata_value_v1(
        metadata,
        GOVERNANCE_ATTESTATION_METADATA_PROFILE_APP_OK_V1,
    )?;
    if actual_profile_app_ok != expected_profile_app_ok {
        return Err(MprdError::InvalidInput(
            "governance_profile_app_ok attestation metadata drifted from admitted governance"
                .into(),
        ));
    }

    let expected_profile_safety_ok = governance_attestation_bool_v1(governance.profile_safety_ok());
    let actual_profile_safety_ok = require_governance_attestation_metadata_value_v1(
        metadata,
        GOVERNANCE_ATTESTATION_METADATA_PROFILE_SAFETY_OK_V1,
    )?;
    if actual_profile_safety_ok != expected_profile_safety_ok {
        return Err(MprdError::InvalidInput(
            "governance_profile_safety_ok attestation metadata drifted from admitted governance"
                .into(),
        ));
    }

    let expected_link_ok = governance_attestation_bool_v1(governance.link_ok());
    let actual_link_ok = require_governance_attestation_metadata_value_v1(
        metadata,
        GOVERNANCE_ATTESTATION_METADATA_LINK_OK_V1,
    )?;
    if actual_link_ok != expected_link_ok {
        return Err(MprdError::InvalidInput(
            "governance_link_ok attestation metadata drifted from admitted governance".into(),
        ));
    }

    Ok(())
}

pub fn execution_authorization_attestation_hash_from_fields_v1(
    policy_hash: &PolicyHash,
    policy_ref: &PolicyRef,
    state_hash: &Hash32,
    state_ref: &StateRef,
    governance: Option<&GovernanceAdmissionWitnessV1>,
) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(EXECUTION_AUTH_ATTESTATION_METADATA_DOMAIN_V1);
    hasher.update(policy_hash.0);
    hasher.update(policy_ref.policy_epoch.to_le_bytes());
    hasher.update(policy_ref.registry_root.0);
    hasher.update(state_hash.0);
    hasher.update(state_ref.state_source_id.0);
    hasher.update(state_ref.state_epoch.to_le_bytes());
    hasher.update(state_ref.state_attestation_hash.0);
    match governance {
        Some(governance) => {
            hasher.update([1u8]);
            hasher.update(governance.update_kind().as_str().as_bytes());
            hasher.update([u8::from(governance.profile_app_ok())]);
            hasher.update([u8::from(governance.profile_safety_ok())]);
            hasher.update([u8::from(governance.link_ok())]);
        }
        None => hasher.update([0u8]),
    }
    Hash32(hasher.finalize().into())
}

/// Construct the typed execution-authorization attestation packet from exact fields.
pub fn execution_authorization_attestation_from_fields_v1(
    policy_hash: &PolicyHash,
    policy_ref: &PolicyRef,
    state_hash: &StateHash,
    state_ref: &StateRef,
    governance: Option<GovernanceAdmissionWitnessV1>,
) -> ExecutionAuthorizationAttestationV1 {
    ExecutionAuthorizationAttestationV1 {
        policy_hash: *policy_hash,
        policy_ref: policy_ref.clone(),
        state_hash: *state_hash,
        state_ref: state_ref.clone(),
        governance,
    }
}

/// Project the live execution-authorization witness into the exact attestation packet language.
pub fn execution_authorization_attestation_from_witness_v1(
    authorization: &ExecutionAuthorizationWitnessV1,
) -> ExecutionAuthorizationAttestationV1 {
    execution_authorization_attestation_from_fields_v1(
        authorization.policy_authority().policy_hash(),
        authorization.policy_authority().policy_ref(),
        authorization.state_binding().state_hash(),
        authorization.state_binding().state_ref(),
        authorization.governance().cloned(),
    )
}

/// Compute the canonical attestation hash from the grouped execution-authorization packet.
pub fn execution_authorization_attestation_hash_from_packet_v1(
    execution_authorization: &ExecutionAuthorizationAttestationV1,
) -> Hash32 {
    execution_authorization_attestation_hash_from_fields_v1(
        execution_authorization.policy_hash(),
        execution_authorization.policy_ref(),
        execution_authorization.state_hash(),
        execution_authorization.state_ref(),
        execution_authorization.governance(),
    )
}

/// Reconstruct and verify the typed execution-authorization attestation packet from proof metadata.
pub fn execution_authorization_attestation_from_attestation_metadata_v1(
    metadata: &HashMap<String, String>,
    policy_hash: &PolicyHash,
    policy_ref: &PolicyRef,
    state_hash: &StateHash,
    state_ref: &StateRef,
) -> Result<Option<ExecutionAuthorizationAttestationV1>> {
    let Some(actual) = metadata.get(EXECUTION_AUTH_ATTESTATION_METADATA_HASH_V1) else {
        return Ok(None);
    };
    let governance = governance_admission_witness_from_attestation_metadata_v1(metadata)?;
    let expected = execution_authorization_attestation_hash_from_fields_v1(
        policy_hash,
        policy_ref,
        state_hash,
        state_ref,
        governance.as_ref(),
    );
    if actual != &hex::encode(expected.0) {
        return Err(MprdError::InvalidInput(
            "execution_authorization_hash_v1 attestation metadata drifted from admitted execution authorization".into(),
        ));
    }
    Ok(Some(execution_authorization_attestation_from_fields_v1(
        policy_hash,
        policy_ref,
        state_hash,
        state_ref,
        governance,
    )))
}

pub fn registry_authorization_attestation_hash_from_fields_v1(
    policy_hash: &PolicyHash,
    exec_kind_id: &crate::artifact_repo::Id32,
    exec_version_id: &crate::artifact_repo::Id32,
    image_id: &crate::artifact_repo::Id32,
    policy_source_kind_id: Option<&crate::artifact_repo::Id32>,
    policy_source_hash: Option<&Hash32>,
) -> Result<Hash32> {
    match (policy_source_kind_id, policy_source_hash) {
        (None, None) | (Some(_), Some(_)) => {}
        _ => {
            return Err(MprdError::InvalidInput(
                "registry authorization hash requires policy_source_kind_id and policy_source_hash to be both set or both unset".into(),
            ))
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(REGISTRY_AUTHORIZATION_ATTESTATION_DOMAIN_V1);
    hasher.update(policy_hash.0);
    hasher.update(exec_kind_id.as_bytes());
    hasher.update(exec_version_id.as_bytes());
    hasher.update(image_id.as_bytes());
    match policy_source_kind_id {
        Some(kind_id) => {
            hasher.update([1u8]);
            hasher.update(kind_id.as_bytes());
        }
        None => hasher.update([0u8]),
    }
    match policy_source_hash {
        Some(source_hash) => {
            hasher.update([1u8]);
            hasher.update(source_hash.0);
        }
        None => hasher.update([0u8]),
    }
    Ok(Hash32(hasher.finalize().into()))
}

/// Construct the typed registry-authorization attestation packet from exact fields.
pub fn registry_authorization_attestation_from_fields_v1(
    resolution_hash: Hash32,
    exec_kind_id: crate::artifact_repo::Id32,
    exec_version_id: crate::artifact_repo::Id32,
    image_id: crate::artifact_repo::Id32,
    policy_source_kind_id: Option<crate::artifact_repo::Id32>,
    policy_source_hash: Option<Hash32>,
) -> RegistryAuthorizationAttestationV1 {
    RegistryAuthorizationAttestationV1 {
        resolution_hash,
        exec_kind_id,
        exec_version_id,
        image_id,
        policy_source_kind_id,
        policy_source_hash,
    }
}

/// Recompute the canonical registry-authorization resolution hash from the grouped packet.
pub fn registry_authorization_attestation_hash_from_packet_v1(
    policy_hash: &PolicyHash,
    registry_authorization: &RegistryAuthorizationAttestationV1,
) -> Result<Hash32> {
    registry_authorization_attestation_hash_from_fields_v1(
        policy_hash,
        registry_authorization.exec_kind_id(),
        registry_authorization.exec_version_id(),
        registry_authorization.image_id(),
        registry_authorization.policy_source_kind_id(),
        registry_authorization.policy_source_hash(),
    )
}

/// Project the live registry authorization witness into the grouped attestation packet language.
pub fn registry_authorization_attestation_from_witness_v1(
    registry_authorization: &RegistryAuthorizationWitnessV1,
) -> RegistryAuthorizationAttestationV1 {
    registry_authorization_attestation_from_fields_v1(
        *registry_authorization.resolution_hash(),
        *registry_authorization.exec_kind_id(),
        *registry_authorization.exec_version_id(),
        *registry_authorization.image_id(),
        registry_authorization.policy_source_kind_id().copied(),
        registry_authorization.policy_source_hash().copied(),
    )
}

/// Project the live signed-registry bridge witness into one grouped bridge attestation packet.
pub fn execution_registry_bridge_attestation_from_witness_v1(
    bridge: &ExecutionRegistryBridgeWitnessV1,
) -> ExecutionRegistryBridgeAttestationV1 {
    ExecutionRegistryBridgeAttestationV1 {
        registry_authorization: registry_authorization_attestation_from_witness_v1(
            bridge.registry_authorization(),
        ),
        registry_checkpoint_attestation_hash: bridge
            .registry_checkpoint_attestation_hash()
            .copied(),
    }
}

fn update_state_ref_hash_v1(hasher: &mut Sha256, state_ref: &StateRef) {
    hasher.update(state_ref.state_source_id.0);
    hasher.update(state_ref.state_epoch.to_le_bytes());
    hasher.update(state_ref.state_attestation_hash.0);
}

/// Emit a deterministic digest over the grouped `ExecutionReadyPacketV1`.
///
/// This gives the runtime/operator surface one stable hash for the exact constructor-gated packet
/// that reached `execute_ready(...)`.
pub fn execution_ready_packet_hash_v1(packet: &ExecutionReadyPacketV1) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(EXECUTION_READY_PACKET_HASH_DOMAIN_V1);

    let boundary = packet.boundary();
    hasher.update((boundary.chosen_action_preimage().len() as u32).to_le_bytes());
    hasher.update(boundary.chosen_action_preimage());

    let limits = boundary.limits_binding().limits();
    match limits.mpb_fuel_limit {
        Some(limit) => {
            hasher.update([1u8]);
            hasher.update(limit.to_le_bytes());
        }
        None => hasher.update([0u8]),
    }
    match limits.mode_c_encryption_ctx_hash {
        Some(ctx_hash) => {
            hasher.update([1u8]);
            hasher.update(ctx_hash.0);
        }
        None => hasher.update([0u8]),
    }

    match packet.authorization() {
        Some(authorization) => {
            hasher.update([1u8]);
            hasher.update(
                execution_authorization_attestation_hash_from_packet_v1(
                    &execution_authorization_attestation_from_witness_v1(authorization),
                )
                .0,
            );
        }
        None => hasher.update([0u8]),
    }

    match packet.bridge() {
        Some(bridge) => {
            let bridge_packet = execution_registry_bridge_attestation_from_witness_v1(bridge);
            hasher.update([1u8]);
            hasher.update(bridge_packet.registry_authorization().resolution_hash().0);
            match bridge_packet.registry_checkpoint_attestation_hash() {
                Some(checkpoint_hash) => {
                    hasher.update([1u8]);
                    hasher.update(checkpoint_hash.0);
                }
                None => hasher.update([0u8]),
            }
        }
        None => hasher.update([0u8]),
    }

    match packet.executor_admission() {
        Some(executor_admission) => {
            hasher.update([1u8]);
            match executor_admission.signature() {
                Some(signature) => {
                    hasher.update([1u8]);
                    hasher.update(signature.signer_pubkey());
                }
                None => hasher.update([0u8]),
            }
            match executor_admission.state_provenance() {
                Some(state_provenance) => {
                    hasher.update([1u8]);
                    update_state_ref_hash_v1(&mut hasher, state_provenance.state_ref());
                }
                None => hasher.update([0u8]),
            }
            match executor_admission.replay_clearance() {
                Some(replay_clearance) => {
                    hasher.update([1u8]);
                    let claim_tag = match replay_clearance.claim() {
                        crate::anti_replay::NonceClaim::NotClaimed => 1u8,
                        crate::anti_replay::NonceClaim::Claimed => 2u8,
                    };
                    hasher.update([claim_tag]);
                }
                None => hasher.update([0u8]),
            }
        }
        None => hasher.update([0u8]),
    }

    Hash32(hasher.finalize().into())
}

/// Emit a deterministic digest over the concrete runtime artifact used by the top-level
/// execution-boundary refinement story.
///
/// This binds the grouped `ExecutionReadyPacketV1` to the verified proof metadata that reached the
/// live `execute_ready(...)` boundary, so the operator surface can audit one concrete refinement
/// artifact rather than only a local stack object plus separate metadata.
pub fn execution_boundary_refinement_packet_from_ready_v1(
    ready: &ExecutionReadyBundle<'_>,
) -> ExecutionBoundaryRefinementPacketV1 {
    ExecutionBoundaryRefinementPacketV1 {
        execution_ready_packet_hash: execution_ready_packet_hash_v1(ready.packet()),
        attestation_metadata_hash: crate::decision_log::attestation_metadata_hash_v1(
            &ready.proof().attestation_metadata,
        ),
    }
}

/// Compute the deterministic refinement hash from the grouped refinement packet.
pub fn execution_boundary_refinement_hash_from_packet_v1(
    packet: &ExecutionBoundaryRefinementPacketV1,
) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(EXECUTION_BOUNDARY_REFINEMENT_HASH_DOMAIN_V1);
    hasher.update(packet.execution_ready_packet_hash().0);
    hasher.update(packet.attestation_metadata_hash().0);
    Hash32(hasher.finalize().into())
}

pub fn execution_boundary_refinement_hash_v1(ready: &ExecutionReadyBundle<'_>) -> Hash32 {
    execution_boundary_refinement_hash_from_packet_v1(
        &execution_boundary_refinement_packet_from_ready_v1(ready),
    )
}

/// Construct the grouped binding-vector packet from the concrete verified-decision tuple.
pub fn execution_binding_vector_packet_from_verified_decision_v1(
    token: &DecisionToken,
    proof: &ProofBundle,
    state: &StateSnapshot,
    candidates: &[CandidateAction],
    verdicts: &[RuleVerdict],
    decision: &Decision,
) -> Result<ExecutionBindingVectorPacketV1> {
    if token.policy_hash != proof.policy_hash || token.policy_hash != decision.policy_hash {
        return Err(MprdError::InvalidInput(
            "policy binding drifted before execution binding hash".into(),
        ));
    }
    if token.state_hash != proof.state_hash || token.state_hash != state.state_hash {
        return Err(MprdError::InvalidInput(
            "state binding drifted before execution binding hash".into(),
        ));
    }
    if token.state_ref != state.state_ref {
        return Err(MprdError::InvalidInput(
            "state provenance drifted before execution binding hash".into(),
        ));
    }
    if proof.candidate_set_hash != hash::hash_candidate_set(candidates) {
        return Err(MprdError::InvalidInput(
            "candidate_set_hash drifted before execution binding hash".into(),
        ));
    }
    let selected = candidates.get(decision.chosen_index).ok_or_else(|| {
        MprdError::InvalidInput("chosen_index out of bounds for execution binding hash".into())
    })?;
    if selected != &decision.chosen_action {
        return Err(MprdError::InvalidInput(
            "selected candidate drifted before execution binding hash".into(),
        ));
    }
    let chosen_verdict = verdicts.get(decision.chosen_index).ok_or_else(|| {
        MprdError::InvalidInput("missing selected verdict for execution binding hash".into())
    })?;
    if !chosen_verdict.allowed {
        return Err(MprdError::InvalidInput(
            "selected verdict was not allowed for execution binding hash".into(),
        ));
    }
    let chosen_action_hash = hash::hash_candidate(&decision.chosen_action);
    if token.chosen_action_hash != proof.chosen_action_hash
        || token.chosen_action_hash != chosen_action_hash
    {
        return Err(MprdError::InvalidInput(
            "chosen_action_hash drifted before execution binding hash".into(),
        ));
    }
    if decision.decision_commitment != hash::hash_decision(decision) {
        return Err(MprdError::InvalidInput(
            "decision_commitment drifted before execution binding hash".into(),
        ));
    }
    if proof.limits_hash != limits::limits_hash_v1(&proof.limits_bytes) {
        return Err(MprdError::InvalidInput(
            "limits_hash drifted before execution binding hash".into(),
        ));
    }

    Ok(ExecutionBindingVectorPacketV1 {
        decision_commitment: decision.decision_commitment,
        policy_hash: token.policy_hash,
        policy_ref: token.policy_ref.clone(),
        state_ref: token.state_ref.clone(),
        state_hash: token.state_hash,
        candidate_set_hash: proof.candidate_set_hash,
        chosen_action_hash: token.chosen_action_hash,
        nonce_or_tx_hash: token.nonce_or_tx_hash,
        limits_hash: proof.limits_hash,
    })
}

/// Compute the deterministic binding-vector hash from the grouped packet language.
pub fn execution_binding_vector_hash_from_packet_v1(
    packet: &ExecutionBindingVectorPacketV1,
) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(EXECUTION_BINDING_VECTOR_HASH_DOMAIN_V1);
    hasher.update(packet.decision_commitment().0);
    hasher.update(packet.policy_hash().0);
    hasher.update(packet.policy_ref().policy_epoch.to_le_bytes());
    hasher.update(packet.policy_ref().registry_root.0);
    hasher.update(packet.state_ref().state_source_id.0);
    hasher.update(packet.state_ref().state_epoch.to_le_bytes());
    hasher.update(packet.state_ref().state_attestation_hash.0);
    hasher.update(packet.state_hash().0);
    hasher.update(packet.candidate_set_hash().0);
    hasher.update(packet.chosen_action_hash().0);
    hasher.update(packet.nonce_or_tx_hash().0);
    hasher.update(packet.limits_hash().0);
    Hash32(hasher.finalize().into())
}

/// Emit a deterministic digest over the concrete verified-decision tuple corresponding to the
/// binding half of the abstract execution-boundary witness.
///
/// This constructor-gated helper re-checks the concrete tuple the orchestrator had in hand right
/// after verification and before execution:
/// policy/state identity, state provenance, candidate-set membership, selected allowed verdict,
/// chosen-action binding, canonical decision commitment, limits-byte binding, and the nonce.
pub fn execution_binding_vector_hash_v1(
    token: &DecisionToken,
    proof: &ProofBundle,
    state: &StateSnapshot,
    candidates: &[CandidateAction],
    verdicts: &[RuleVerdict],
    decision: &Decision,
) -> Result<Hash32> {
    Ok(execution_binding_vector_hash_from_packet_v1(
        &execution_binding_vector_packet_from_verified_decision_v1(
            token, proof, state, candidates, verdicts, decision,
        )?,
    ))
}

/// Emit a deterministic authorization hash over the exact policy/state/governance packet that the
/// attestation was constructed from.
pub fn insert_execution_authorization_attestation_metadata_v1(
    metadata: &mut HashMap<String, String>,
    token: &DecisionToken,
    state: &StateSnapshot,
    governance: Option<&GovernanceAdmissionWitnessV1>,
) {
    let digest = execution_authorization_attestation_hash_from_fields_v1(
        &token.policy_hash,
        &token.policy_ref,
        &state.state_hash,
        &state.state_ref,
        governance,
    );
    metadata.insert(
        EXECUTION_AUTH_ATTESTATION_METADATA_HASH_V1.into(),
        hex::encode(digest.0),
    );
}

/// Emit canonical execution-authorization attestation metadata from the constructor-gated packet.
pub fn insert_execution_authorization_attestation_from_packet_v1(
    metadata: &mut HashMap<String, String>,
    execution_authorization: &ExecutionAuthorizationAttestationV1,
) {
    let digest = execution_authorization_attestation_hash_from_packet_v1(execution_authorization);
    metadata.insert(
        EXECUTION_AUTH_ATTESTATION_METADATA_HASH_V1.into(),
        hex::encode(digest.0),
    );
}

/// Verify that proof metadata preserved the same concrete execution-authorization packet.
pub fn verify_execution_authorization_attestation_metadata_v1(
    proof: &ProofBundle,
    authority: &PolicyAuthorityWitnessV1,
    state_binding: &crate::state_provenance::StateBindingWitnessV1,
    governance: Option<&GovernanceAdmissionWitnessV1>,
) -> Result<()> {
    let actual = require_governance_attestation_metadata_value_v1(
        &proof.attestation_metadata,
        EXECUTION_AUTH_ATTESTATION_METADATA_HASH_V1,
    )?;
    let expected = execution_authorization_attestation_hash_from_packet_v1(
        &execution_authorization_attestation_from_fields_v1(
            authority.policy_hash(),
            authority.policy_ref(),
            state_binding.state_hash(),
            state_binding.state_ref(),
            governance.cloned(),
        ),
    );
    if actual != hex::encode(expected.0) {
        return Err(MprdError::InvalidInput(
            "execution_authorization_hash_v1 attestation metadata drifted from admitted execution authorization".into(),
        ));
    }
    Ok(())
}

/// Attach canonical governance attestation metadata to a proof when governance is modeled.
pub fn attach_governance_attestation_to_proof_v1(
    proof: &mut ProofBundle,
    ready: &AttestationReadyBundle<'_>,
) {
    if let Some(governance) = ready.governance() {
        insert_governance_attestation_metadata_v1(&mut proof.attestation_metadata, governance);
    }
    insert_execution_authorization_attestation_from_packet_v1(
        &mut proof.attestation_metadata,
        ready.execution_authorization(),
    );
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

    let update_kind = if is_policy_tweak {
        GovernanceUpdateKindV1::PolicyTweak
    } else if is_safety_change {
        GovernanceUpdateKindV1::SafetyRuleChange
    } else {
        GovernanceUpdateKindV1::AgentCapabilityExpand
    };

    governance_admission_witness_from_fields_v1(
        update_kind,
        profile_app_ok,
        profile_safety_ok,
        link_ok,
    )
    .map(Some)
}

/// Construct the concrete token-binding witness from the orchestrator's authority, state, and
/// selected action.
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

/// Construct the concrete execution-authorization witness for the live RC1 execute path.
pub fn execution_authorization_witness_v1(
    verified: &VerifiedBundle<'_>,
    authority: &PolicyAuthorityWitnessV1,
    state_binding: &crate::state_provenance::StateBindingWitnessV1,
    governance: Option<GovernanceAdmissionWitnessV1>,
) -> Result<ExecutionAuthorizationWitnessV1> {
    verify_token_policy_authority_v1(authority, verified.token())?;
    crate::state_provenance::verify_token_state_binding_v1(state_binding, verified.token())?;
    if let Some(governance) = governance.as_ref() {
        verify_governance_attestation_metadata_v1(verified.proof(), governance)?;
    }
    Ok(ExecutionAuthorizationWitnessV1 {
        policy_authority: authority.clone(),
        state_binding: state_binding.clone(),
        governance,
    })
}

/// Construct the concrete registry-authorization witness carried on the RC1 bridge path.
pub fn registry_authorization_witness_v1(
    resolution_hash: Hash32,
    exec_kind_id: crate::artifact_repo::Id32,
    exec_version_id: crate::artifact_repo::Id32,
    image_id: crate::artifact_repo::Id32,
    policy_source_kind_id: Option<crate::artifact_repo::Id32>,
    policy_source_hash: Option<Hash32>,
) -> Result<RegistryAuthorizationWitnessV1> {
    match (&policy_source_kind_id, &policy_source_hash) {
        (None, None) | (Some(_), Some(_)) => {}
        _ => {
            return Err(MprdError::InvalidInput(
                "registry authorization witness requires policy_source_kind_id and policy_source_hash to be both set or both unset".into(),
            ))
        }
    }

    Ok(RegistryAuthorizationWitnessV1 {
        resolution_hash,
        exec_kind_id,
        exec_version_id,
        image_id,
        policy_source_kind_id,
        policy_source_hash,
    })
}

/// Construct the concrete registry-bridge witness for the live execute path.
pub fn execution_registry_bridge_witness_v1(
    policy_hash: &PolicyHash,
    registry_authorization: RegistryAuthorizationWitnessV1,
    registry_checkpoint_attestation_hash: Option<Hash32>,
) -> Result<ExecutionRegistryBridgeWitnessV1> {
    let expected_registry_authorization_hash =
        registry_authorization_attestation_hash_from_packet_v1(
            policy_hash,
            &registry_authorization_attestation_from_witness_v1(&registry_authorization),
        )?;
    if registry_authorization.resolution_hash() != &expected_registry_authorization_hash {
        return Err(MprdError::InvalidInput(
            "registry bridge witness drifted from admitted registry authorization tuple".into(),
        ));
    }
    Ok(ExecutionRegistryBridgeWitnessV1 {
        registry_authorization,
        registry_checkpoint_attestation_hash,
    })
}

/// Upgrade a verified bundle into an execution-ready bundle carrying the concrete boundary witness.
pub fn prepare_execution_ready<'a>(
    verified: VerifiedBundle<'a>,
) -> Result<ExecutionReadyBundle<'a>> {
    let boundary = execution_boundary_witness_v1(&verified)?;
    Ok(ExecutionReadyBundle {
        verified,
        packet: ExecutionReadyPacketV1 {
            boundary,
            authorization: None,
            bridge: None,
            executor_admission: None,
        },
    })
}

/// Upgrade a verified bundle into an execution-ready bundle carrying both transcript binding and
/// the orchestrator's admitted authorization context.
pub fn prepare_execution_ready_with_authorization<'a>(
    verified: VerifiedBundle<'a>,
    authority: &PolicyAuthorityWitnessV1,
    state_binding: &crate::state_provenance::StateBindingWitnessV1,
    governance: Option<GovernanceAdmissionWitnessV1>,
) -> Result<ExecutionReadyBundle<'a>> {
    let authorization =
        execution_authorization_witness_v1(&verified, authority, state_binding, governance)?;
    let boundary = execution_boundary_witness_v1(&verified)?;
    Ok(ExecutionReadyBundle {
        verified,
        packet: ExecutionReadyPacketV1 {
            boundary,
            authorization: Some(authorization),
            bridge: None,
            executor_admission: None,
        },
    })
}

/// Enrich an execution-ready bundle with a constructor-gated concrete registry-bridge witness.
pub fn prepare_execution_ready_with_registry_bridge<'a>(
    ready: &ExecutionReadyBundle<'a>,
    bridge: ExecutionRegistryBridgeWitnessV1,
) -> Result<ExecutionReadyBundle<'a>> {
    let authorization = ready.authorization().ok_or_else(|| {
        MprdError::InvalidInput("registry bridge requires execution authorization witness".into())
    })?;
    verify_execution_authorization_attestation_metadata_v1(
        ready.proof(),
        authorization.policy_authority(),
        authorization.state_binding(),
        authorization.governance(),
    )?;
    let bridge_packet = execution_registry_bridge_attestation_from_witness_v1(&bridge);
    let expected_registry_authorization_hash =
        registry_authorization_attestation_hash_from_packet_v1(
            authorization.policy_authority().policy_hash(),
            bridge_packet.registry_authorization(),
        )?;
    if bridge_packet.registry_authorization().resolution_hash()
        != &expected_registry_authorization_hash
    {
        return Err(MprdError::InvalidInput(
            "registry bridge witness drifted from admitted registry authorization tuple".into(),
        ));
    }
    let mut enriched = ready.clone();
    enriched.packet.bridge = Some(bridge);
    Ok(enriched)
}

/// Enrich an execution-ready bundle with a constructor-gated signature-admission witness.
pub fn prepare_execution_ready_with_signature<'a>(
    ready: &ExecutionReadyBundle<'a>,
    verifying_key: &crate::crypto::TokenVerifyingKey,
) -> Result<ExecutionReadyBundle<'a>> {
    let signature = verifying_key.signature_witness_v1(ready.token(), &ready.token().signature)?;
    let mut enriched = ready.clone();
    let admission = enriched
        .packet
        .executor_admission
        .take()
        .unwrap_or_default()
        .with_signature(signature);
    enriched.packet.executor_admission = Some(admission);
    Ok(enriched)
}

/// Enrich an execution-ready bundle with a constructor-gated state-provenance admission witness.
pub fn prepare_execution_ready_with_state_provenance<'a>(
    ready: &ExecutionReadyBundle<'a>,
    allowed_state_source_ids: &[Hash32],
) -> Result<ExecutionReadyBundle<'a>> {
    let provenance = crate::state_provenance::state_provenance_witness_v1(
        &ready.token().state_ref,
        allowed_state_source_ids,
    )?;
    let mut enriched = ready.clone();
    let admission = enriched
        .packet
        .executor_admission
        .take()
        .unwrap_or_default()
        .with_state_provenance(provenance);
    enriched.packet.executor_admission = Some(admission);
    Ok(enriched)
}

/// Enrich an execution-ready bundle with a constructor-gated replay-clearance witness.
pub fn prepare_execution_ready_with_replay_clearance<'a>(
    ready: &ExecutionReadyBundle<'a>,
    nonce_validator: &dyn crate::anti_replay::NonceValidator,
) -> Result<(
    ExecutionReadyBundle<'a>,
    crate::anti_replay::ReplayClearanceWitnessV1,
)> {
    let replay = crate::anti_replay::replay_clearance_witness_v1(ready.token(), nonce_validator)?;
    let mut enriched = ready.clone();
    let admission = enriched
        .packet
        .executor_admission
        .take()
        .unwrap_or_default()
        .with_replay_clearance(replay);
    enriched.packet.executor_admission = Some(admission);
    Ok((enriched, replay))
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
    let execution_authorization = execution_authorization_attestation_from_fields_v1(
        &token.policy_hash,
        &token.policy_ref,
        &state.state_hash,
        &state.state_ref,
        governance,
    );

    Ok(AttestationReadyBundle {
        token,
        decision,
        state,
        governance,
        execution_authorization,
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
            policy_hash: *policy_hash,
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
        assert_eq!(ready.packet().boundary(), ready.boundary());
        assert!(ready.authorization().is_none());
        assert!(ready.packet().authorization().is_none());
    }

    #[test]
    fn prepare_execution_ready_with_authorization_accepts_aligned_witnesses() {
        let candidate = valid_http_call_candidate();
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: governance_policy_inputs(
                GovernanceUpdateKindV1::PolicyTweak,
                true,
                false,
                true,
            ),
            state_hash: dummy_hash(6),
            state_ref: StateRef {
                state_source_id: dummy_hash(7),
                state_epoch: 8,
                state_attestation_hash: dummy_hash(9),
            },
        };
        let token = DecisionToken {
            policy_hash: dummy_hash(1),
            policy_ref: PolicyRef {
                policy_epoch: 2,
                registry_root: dummy_hash(3),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
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
        let authority =
            policy_authority_witness_v1(&token.policy_hash, &token.policy_ref).expect("authority");
        let state_binding = crate::state_provenance::state_binding_witness_v1(&state);
        let governance = governance_admission_witness_v1(&state)
            .expect("governance")
            .expect("governance witness");
        let mut proof = proof;
        insert_governance_attestation_metadata_v1(&mut proof.attestation_metadata, &governance);

        let ready = prepare_execution_ready_with_authorization(
            VerifiedBundle::new(&token, &proof),
            &authority,
            &state_binding,
            Some(governance),
        )
        .expect("ready");

        let authorization = ready.authorization().expect("authorization");
        assert_eq!(
            authorization.policy_authority().policy_hash(),
            &token.policy_hash
        );
        assert_eq!(
            authorization.policy_authority().policy_ref(),
            &token.policy_ref
        );
        assert_eq!(
            authorization.state_binding().state_hash(),
            &state.state_hash
        );
        assert_eq!(authorization.state_binding().state_ref(), &state.state_ref);
        assert_eq!(
            authorization.governance().map(|g| g.update_kind()),
            Some(GovernanceUpdateKindV1::PolicyTweak)
        );
        assert_eq!(ready.packet().authorization(), Some(authorization));
        assert!(ready.bridge().is_none());
    }

    #[test]
    fn prepare_execution_ready_with_registry_bridge_threads_bridge_witness() {
        let candidate = valid_http_call_candidate();
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(0x73),
            state_ref: StateRef {
                state_source_id: dummy_hash(0x78),
                state_epoch: 2,
                state_attestation_hash: dummy_hash(0x79),
            },
        };
        let token = DecisionToken {
            policy_hash: dummy_hash(0x71),
            policy_ref: PolicyRef {
                policy_epoch: 1,
                registry_root: dummy_hash(0x72),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0x74),
            timestamp_ms: 0,
            signature: vec![],
        };
        let proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(0x75),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };
        let mut proof = proof;
        insert_execution_authorization_attestation_metadata_v1(
            &mut proof.attestation_metadata,
            &token,
            &state,
            None,
        );
        let authority =
            policy_authority_witness_v1(&token.policy_hash, &token.policy_ref).expect("authority");
        let state_binding = crate::state_provenance::state_binding_witness_v1(&state);

        let ready = prepare_execution_ready_with_authorization(
            VerifiedBundle::new(&token, &proof),
            &authority,
            &state_binding,
            None,
        )
        .expect("ready");
        let resolution_hash = registry_authorization_attestation_hash_from_fields_v1(
            &token.policy_hash,
            &crate::artifact_repo::Id32([0xA1; 32]),
            &crate::artifact_repo::Id32([0xA2; 32]),
            &crate::artifact_repo::Id32([0xA3; 32]),
            Some(&crate::artifact_repo::Id32([0xA4; 32])),
            Some(&dummy_hash(0xA5)),
        )
        .expect("resolution hash");
        let registry_authorization = registry_authorization_witness_v1(
            resolution_hash,
            crate::artifact_repo::Id32([0xA1; 32]),
            crate::artifact_repo::Id32([0xA2; 32]),
            crate::artifact_repo::Id32([0xA3; 32]),
            Some(crate::artifact_repo::Id32([0xA4; 32])),
            Some(dummy_hash(0xA5)),
        )
        .expect("registry authorization");
        let bridge = execution_registry_bridge_witness_v1(
            &token.policy_hash,
            registry_authorization.clone(),
            Some(dummy_hash(0x77)),
        )
        .expect("bridge");
        let ready = prepare_execution_ready_with_registry_bridge(&ready, bridge.clone())
            .expect("ready with bridge");

        assert_eq!(ready.bridge(), Some(&bridge));
        assert_eq!(ready.packet().bridge(), Some(&bridge));
        assert_eq!(
            ready.bridge().expect("bridge").registry_authorization(),
            &registry_authorization
        );
    }

    #[test]
    fn execution_registry_bridge_attestation_from_witness_matches_bridge_tuple() {
        let policy_hash = dummy_hash(0xC1);
        let resolution_hash = registry_authorization_attestation_hash_from_fields_v1(
            &policy_hash,
            &crate::artifact_repo::Id32([0xC2; 32]),
            &crate::artifact_repo::Id32([0xC3; 32]),
            &crate::artifact_repo::Id32([0xC4; 32]),
            Some(&crate::artifact_repo::Id32([0xC5; 32])),
            Some(&dummy_hash(0xC6)),
        )
        .expect("resolution hash");
        let registry_authorization = registry_authorization_witness_v1(
            resolution_hash,
            crate::artifact_repo::Id32([0xC2; 32]),
            crate::artifact_repo::Id32([0xC3; 32]),
            crate::artifact_repo::Id32([0xC4; 32]),
            Some(crate::artifact_repo::Id32([0xC5; 32])),
            Some(dummy_hash(0xC6)),
        )
        .expect("registry authorization");
        let bridge = execution_registry_bridge_witness_v1(
            &policy_hash,
            registry_authorization.clone(),
            Some(dummy_hash(0xC7)),
        )
        .expect("bridge");

        let bridge_packet = execution_registry_bridge_attestation_from_witness_v1(&bridge);

        assert_eq!(
            bridge_packet.registry_authorization().resolution_hash(),
            &resolution_hash
        );
        assert_eq!(
            bridge_packet.registry_authorization().exec_kind_id(),
            &crate::artifact_repo::Id32([0xC2; 32])
        );
        assert_eq!(
            bridge_packet.registry_authorization().exec_version_id(),
            &crate::artifact_repo::Id32([0xC3; 32])
        );
        assert_eq!(
            bridge_packet.registry_authorization().image_id(),
            &crate::artifact_repo::Id32([0xC4; 32])
        );
        assert_eq!(
            bridge_packet
                .registry_authorization()
                .policy_source_kind_id(),
            Some(&crate::artifact_repo::Id32([0xC5; 32]))
        );
        assert_eq!(
            bridge_packet.registry_authorization().policy_source_hash(),
            Some(&dummy_hash(0xC6))
        );
        assert_eq!(
            bridge_packet.registry_checkpoint_attestation_hash(),
            Some(&dummy_hash(0xC7))
        );
        assert_eq!(
            registry_authorization_attestation_hash_from_packet_v1(
                &policy_hash,
                bridge_packet.registry_authorization()
            )
            .expect("packet hash"),
            resolution_hash
        );
    }

    #[test]
    fn execution_binding_vector_packet_matches_hash_surface() {
        let candidate = valid_http_call_candidate();
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(0xD1),
            state_ref: StateRef {
                state_source_id: dummy_hash(0xD2),
                state_epoch: 4,
                state_attestation_hash: dummy_hash(0xD3),
            },
        };
        let token = DecisionToken {
            policy_hash: dummy_hash(0xD4),
            policy_ref: PolicyRef {
                policy_epoch: 7,
                registry_root: dummy_hash(0xD5),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0xD6),
            timestamp_ms: 0,
            signature: vec![],
        };
        let proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: hash::hash_candidate_set(std::slice::from_ref(&candidate)),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };
        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate.clone(),
            policy_hash: token.policy_hash,
            decision_commitment: dummy_hash(0),
        };
        let decision = Decision {
            decision_commitment: hash::hash_decision(&decision),
            ..decision
        };
        let verdicts = vec![RuleVerdict {
            allowed: true,
            reasons: vec![],
            limits: HashMap::new(),
        }];
        let candidates = vec![candidate];

        let packet = execution_binding_vector_packet_from_verified_decision_v1(
            &token,
            &proof,
            &state,
            &candidates,
            &verdicts,
            &decision,
        )
        .expect("binding packet");

        assert_eq!(packet.decision_commitment(), &decision.decision_commitment);
        assert_eq!(packet.policy_hash(), &token.policy_hash);
        assert_eq!(packet.policy_ref(), &token.policy_ref);
        assert_eq!(packet.state_ref(), &token.state_ref);
        assert_eq!(packet.state_hash(), &token.state_hash);
        assert_eq!(packet.candidate_set_hash(), &proof.candidate_set_hash);
        assert_eq!(packet.chosen_action_hash(), &token.chosen_action_hash);
        assert_eq!(packet.nonce_or_tx_hash(), &token.nonce_or_tx_hash);
        assert_eq!(packet.limits_hash(), &proof.limits_hash);
        assert_eq!(
            execution_binding_vector_hash_from_packet_v1(&packet),
            execution_binding_vector_hash_v1(
                &token,
                &proof,
                &state,
                &candidates,
                &verdicts,
                &decision
            )
            .expect("binding hash")
        );
    }

    #[test]
    fn execution_boundary_refinement_packet_matches_hash_surface() {
        let candidate = valid_http_call_candidate();
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(0xE1),
            state_ref: StateRef {
                state_source_id: dummy_hash(0xE2),
                state_epoch: 9,
                state_attestation_hash: dummy_hash(0xE3),
            },
        };
        let token = DecisionToken {
            policy_hash: dummy_hash(0xE4),
            policy_ref: PolicyRef {
                policy_epoch: 2,
                registry_root: dummy_hash(0xE5),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0xE6),
            timestamp_ms: 0,
            signature: vec![],
        };
        let mut proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(0xE7),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };
        insert_execution_authorization_attestation_metadata_v1(
            &mut proof.attestation_metadata,
            &token,
            &state,
            None,
        );
        let authority =
            policy_authority_witness_v1(&token.policy_hash, &token.policy_ref).expect("authority");
        let state_binding = crate::state_provenance::state_binding_witness_v1(&state);
        let ready = prepare_execution_ready_with_authorization(
            VerifiedBundle::new(&token, &proof),
            &authority,
            &state_binding,
            None,
        )
        .expect("ready");

        let packet = execution_boundary_refinement_packet_from_ready_v1(&ready);

        assert_eq!(
            packet.execution_ready_packet_hash(),
            &execution_ready_packet_hash_v1(ready.packet())
        );
        assert_eq!(
            packet.attestation_metadata_hash(),
            &crate::decision_log::attestation_metadata_hash_v1(&ready.proof().attestation_metadata)
        );
        assert_eq!(
            execution_boundary_refinement_hash_from_packet_v1(&packet),
            execution_boundary_refinement_hash_v1(&ready)
        );
    }

    #[test]
    fn prepare_execution_ready_with_registry_bridge_rejects_missing_execution_authorization_witness(
    ) {
        let candidate = valid_http_call_candidate();
        let token = DecisionToken {
            policy_hash: dummy_hash(0x7A),
            policy_ref: PolicyRef {
                policy_epoch: 3,
                registry_root: dummy_hash(0x7B),
            },
            state_hash: dummy_hash(0x7C),
            state_ref: StateRef::unknown(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0x7D),
            timestamp_ms: 0,
            signature: vec![],
        };
        let proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(0x7E),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };
        let ready = prepare_execution_ready(VerifiedBundle::new(&token, &proof)).expect("ready");

        let err = prepare_execution_ready_with_registry_bridge(
            &ready,
            execution_registry_bridge_witness_v1(
                &token.policy_hash,
                registry_authorization_witness_v1(
                    registry_authorization_attestation_hash_from_fields_v1(
                        &token.policy_hash,
                        &crate::artifact_repo::Id32([0xA6; 32]),
                        &crate::artifact_repo::Id32([0xA7; 32]),
                        &crate::artifact_repo::Id32([0xA8; 32]),
                        None,
                        None,
                    )
                    .expect("resolution hash"),
                    crate::artifact_repo::Id32([0xA6; 32]),
                    crate::artifact_repo::Id32([0xA7; 32]),
                    crate::artifact_repo::Id32([0xA8; 32]),
                    None,
                    None,
                )
                .expect("registry authorization"),
                Some(dummy_hash(0x80)),
            )
            .expect("bridge"),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            MprdError::InvalidInput(msg)
                if msg == "registry bridge requires execution authorization witness"
        ));
    }

    #[test]
    fn prepare_execution_ready_with_registry_bridge_rejects_missing_execution_authorization_attestation_metadata(
    ) {
        let candidate = valid_http_call_candidate();
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(0x81),
            state_ref: StateRef {
                state_source_id: dummy_hash(0x82),
                state_epoch: 6,
                state_attestation_hash: dummy_hash(0x83),
            },
        };
        let token = DecisionToken {
            policy_hash: dummy_hash(0x84),
            policy_ref: PolicyRef {
                policy_epoch: 4,
                registry_root: dummy_hash(0x85),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0x86),
            timestamp_ms: 0,
            signature: vec![],
        };
        let proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(0x87),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };
        let authority =
            policy_authority_witness_v1(&token.policy_hash, &token.policy_ref).expect("authority");
        let state_binding = crate::state_provenance::state_binding_witness_v1(&state);
        let ready = prepare_execution_ready_with_authorization(
            VerifiedBundle::new(&token, &proof),
            &authority,
            &state_binding,
            None,
        )
        .expect("ready");

        let err = prepare_execution_ready_with_registry_bridge(
            &ready,
            execution_registry_bridge_witness_v1(
                &token.policy_hash,
                registry_authorization_witness_v1(
                    registry_authorization_attestation_hash_from_fields_v1(
                        &token.policy_hash,
                        &crate::artifact_repo::Id32([0xA9; 32]),
                        &crate::artifact_repo::Id32([0xAA; 32]),
                        &crate::artifact_repo::Id32([0xAB; 32]),
                        None,
                        None,
                    )
                    .expect("resolution hash"),
                    crate::artifact_repo::Id32([0xA9; 32]),
                    crate::artifact_repo::Id32([0xAA; 32]),
                    crate::artifact_repo::Id32([0xAB; 32]),
                    None,
                    None,
                )
                .expect("registry authorization"),
                Some(dummy_hash(0x89)),
            )
            .expect("bridge"),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            MprdError::InvalidInput(msg)
                if msg == "missing execution_authorization_hash_v1 attestation metadata"
        ));
    }

    #[test]
    fn registry_authorization_witness_rejects_incomplete_source_mapping() {
        let err = registry_authorization_witness_v1(
            dummy_hash(0x8A),
            crate::artifact_repo::Id32([0xB2; 32]),
            crate::artifact_repo::Id32([0xB3; 32]),
            crate::artifact_repo::Id32([0xB4; 32]),
            Some(crate::artifact_repo::Id32([0xB5; 32])),
            None,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            MprdError::InvalidInput(msg)
                if msg
                    == "registry authorization witness requires policy_source_kind_id and policy_source_hash to be both set or both unset"
        ));
    }

    #[test]
    fn execution_registry_bridge_witness_rejects_registry_authorization_tuple_drift() {
        let candidate = valid_http_call_candidate();
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(0x8B),
            state_ref: StateRef {
                state_source_id: dummy_hash(0x8C),
                state_epoch: 7,
                state_attestation_hash: dummy_hash(0x8D),
            },
        };
        let token = DecisionToken {
            policy_hash: dummy_hash(0x8E),
            policy_ref: PolicyRef {
                policy_epoch: 5,
                registry_root: dummy_hash(0x8F),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0x90),
            timestamp_ms: 0,
            signature: vec![],
        };
        let mut proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(0x91),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };
        insert_execution_authorization_attestation_metadata_v1(
            &mut proof.attestation_metadata,
            &token,
            &state,
            None,
        );
        let authority =
            policy_authority_witness_v1(&token.policy_hash, &token.policy_ref).expect("authority");
        let state_binding = crate::state_provenance::state_binding_witness_v1(&state);
        let _ready = prepare_execution_ready_with_authorization(
            VerifiedBundle::new(&token, &proof),
            &authority,
            &state_binding,
            None,
        )
        .expect("ready");
        let err = execution_registry_bridge_witness_v1(
            &token.policy_hash,
            registry_authorization_witness_v1(
                dummy_hash(0x92),
                crate::artifact_repo::Id32([0xB6; 32]),
                crate::artifact_repo::Id32([0xB7; 32]),
                crate::artifact_repo::Id32([0xB8; 32]),
                None,
                None,
            )
            .expect("registry authorization"),
            Some(dummy_hash(0x93)),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            MprdError::InvalidInput(msg)
                if msg == "registry bridge witness drifted from admitted registry authorization tuple"
        ));
    }

    #[test]
    fn execution_authorization_attestation_metadata_accepts_aligned_inputs() {
        let candidate = valid_http_call_candidate();
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: governance_policy_inputs(
                GovernanceUpdateKindV1::PolicyTweak,
                true,
                false,
                true,
            ),
            state_hash: dummy_hash(0x6A),
            state_ref: StateRef {
                state_source_id: dummy_hash(0x6B),
                state_epoch: 8,
                state_attestation_hash: dummy_hash(0x6C),
            },
        };
        let token = DecisionToken {
            policy_hash: dummy_hash(0x6D),
            policy_ref: PolicyRef {
                policy_epoch: 3,
                registry_root: dummy_hash(0x6E),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0x6F),
            timestamp_ms: 0,
            signature: vec![],
        };
        let mut proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(0x70),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };
        let authority =
            policy_authority_witness_v1(&token.policy_hash, &token.policy_ref).expect("authority");
        let state_binding = crate::state_provenance::state_binding_witness_v1(&state);
        let governance = governance_admission_witness_v1(&state)
            .expect("governance")
            .expect("governance witness");
        insert_execution_authorization_attestation_metadata_v1(
            &mut proof.attestation_metadata,
            &token,
            &state,
            Some(&governance),
        );

        verify_execution_authorization_attestation_metadata_v1(
            &proof,
            &authority,
            &state_binding,
            Some(&governance),
        )
        .expect("aligned authorization hash");
    }

    #[test]
    fn execution_authorization_attestation_from_witness_matches_attestation_ready_packet() {
        let candidate = valid_http_call_candidate();
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: governance_policy_inputs(
                GovernanceUpdateKindV1::PolicyTweak,
                true,
                false,
                true,
            ),
            state_hash: dummy_hash(0xAA),
            state_ref: StateRef {
                state_source_id: dummy_hash(0xAB),
                state_epoch: 21,
                state_attestation_hash: dummy_hash(0xAC),
            },
        };
        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate.clone(),
            policy_hash: dummy_hash(0xAD),
            decision_commitment: dummy_hash(0xAE),
        };
        let token = DecisionToken {
            policy_hash: decision.policy_hash,
            policy_ref: PolicyRef {
                policy_epoch: 11,
                registry_root: dummy_hash(0xAF),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0xB0),
            timestamp_ms: 0,
            signature: vec![],
        };
        let proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(0xB1),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };
        let authority =
            policy_authority_witness_v1(&token.policy_hash, &token.policy_ref).expect("authority");
        let state_binding = crate::state_provenance::state_binding_witness_v1(&state);
        let governance = governance_admission_witness_v1(&state)
            .expect("governance")
            .expect("governance witness");
        let mut proof = proof;
        insert_governance_attestation_metadata_v1(&mut proof.attestation_metadata, &governance);

        let attestation_ready =
            prepare_attestation_ready(&token, &decision, &state).expect("attestation ready");
        let execution_ready = prepare_execution_ready_with_authorization(
            VerifiedBundle::new(&token, &proof),
            &authority,
            &state_binding,
            Some(governance),
        )
        .expect("execution ready");

        let projected = execution_authorization_attestation_from_witness_v1(
            execution_ready.authorization().expect("authorization"),
        );

        assert_eq!(projected, *attestation_ready.execution_authorization());
        assert_eq!(
            execution_authorization_attestation_hash_from_packet_v1(&projected),
            execution_authorization_attestation_hash_from_packet_v1(
                attestation_ready.execution_authorization()
            )
        );
    }

    #[test]
    fn execution_authorization_attestation_metadata_rejects_state_binding_drift() {
        let candidate = valid_http_call_candidate();
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(0x74),
            state_ref: StateRef {
                state_source_id: dummy_hash(0x75),
                state_epoch: 12,
                state_attestation_hash: dummy_hash(0x76),
            },
        };
        let token = DecisionToken {
            policy_hash: dummy_hash(0x77),
            policy_ref: PolicyRef {
                policy_epoch: 5,
                registry_root: dummy_hash(0x78),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0x79),
            timestamp_ms: 0,
            signature: vec![],
        };
        let mut proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(0x7A),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };
        insert_execution_authorization_attestation_metadata_v1(
            &mut proof.attestation_metadata,
            &token,
            &state,
            None,
        );
        let drifted_state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: state.state_hash,
            state_ref: StateRef {
                state_source_id: dummy_hash(0x7B),
                state_epoch: state.state_ref.state_epoch,
                state_attestation_hash: state.state_ref.state_attestation_hash,
            },
        };
        let authority =
            policy_authority_witness_v1(&token.policy_hash, &token.policy_ref).expect("authority");
        let drifted_state_binding =
            crate::state_provenance::state_binding_witness_v1(&drifted_state);

        let err = verify_execution_authorization_attestation_metadata_v1(
            &proof,
            &authority,
            &drifted_state_binding,
            None,
        )
        .unwrap_err();

        assert!(
            matches!(err, MprdError::InvalidInput(message) if message == "execution_authorization_hash_v1 attestation metadata drifted from admitted execution authorization")
        );
    }

    #[test]
    fn execution_authorization_attestation_from_metadata_accepts_aligned_metadata() {
        let candidate = valid_http_call_candidate();
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: governance_policy_inputs(
                GovernanceUpdateKindV1::PolicyTweak,
                true,
                false,
                true,
            ),
            state_hash: dummy_hash(0x7C),
            state_ref: StateRef {
                state_source_id: dummy_hash(0x7D),
                state_epoch: 13,
                state_attestation_hash: dummy_hash(0x7E),
            },
        };
        let token = DecisionToken {
            policy_hash: dummy_hash(0x7F),
            policy_ref: PolicyRef {
                policy_epoch: 6,
                registry_root: dummy_hash(0x80),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0x81),
            timestamp_ms: 0,
            signature: vec![],
        };
        let governance = governance_admission_witness_v1(&state)
            .expect("governance")
            .expect("governance witness");
        let mut metadata = HashMap::new();
        insert_governance_attestation_metadata_v1(&mut metadata, &governance);
        insert_execution_authorization_attestation_metadata_v1(
            &mut metadata,
            &token,
            &state,
            Some(&governance),
        );

        let attestation = execution_authorization_attestation_from_attestation_metadata_v1(
            &metadata,
            &token.policy_hash,
            &token.policy_ref,
            &token.state_hash,
            &token.state_ref,
        )
        .expect("attestation")
        .expect("execution auth");

        assert_eq!(attestation.policy_hash(), &token.policy_hash);
        assert_eq!(attestation.policy_ref(), &token.policy_ref);
        assert_eq!(attestation.state_hash(), &token.state_hash);
        assert_eq!(attestation.state_ref(), &token.state_ref);
        assert_eq!(attestation.governance(), Some(&governance));
    }

    #[test]
    fn execution_authorization_attestation_from_metadata_returns_none_when_absent() {
        let attestation = execution_authorization_attestation_from_attestation_metadata_v1(
            &HashMap::new(),
            &dummy_hash(0x82),
            &PolicyRef {
                policy_epoch: 1,
                registry_root: dummy_hash(0x83),
            },
            &dummy_hash(0x84),
            &StateRef {
                state_source_id: dummy_hash(0x85),
                state_epoch: 1,
                state_attestation_hash: dummy_hash(0x86),
            },
        )
        .expect("no attestation");

        assert!(attestation.is_none());
    }

    #[test]
    fn prepare_execution_ready_with_authorization_rejects_missing_governance_metadata() {
        let candidate = valid_http_call_candidate();
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: governance_policy_inputs(
                GovernanceUpdateKindV1::PolicyTweak,
                true,
                false,
                true,
            ),
            state_hash: dummy_hash(0x71),
            state_ref: StateRef {
                state_source_id: dummy_hash(0x72),
                state_epoch: 9,
                state_attestation_hash: dummy_hash(0x73),
            },
        };
        let token = DecisionToken {
            policy_hash: dummy_hash(0x74),
            policy_ref: PolicyRef {
                policy_epoch: 4,
                registry_root: dummy_hash(0x75),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0x76),
            timestamp_ms: 0,
            signature: vec![],
        };
        let proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(0x77),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };
        let authority =
            policy_authority_witness_v1(&token.policy_hash, &token.policy_ref).expect("authority");
        let state_binding = crate::state_provenance::state_binding_witness_v1(&state);
        let governance = governance_admission_witness_v1(&state)
            .expect("governance")
            .expect("governance witness");

        let err = prepare_execution_ready_with_authorization(
            VerifiedBundle::new(&token, &proof),
            &authority,
            &state_binding,
            Some(governance),
        )
        .unwrap_err();

        assert!(
            matches!(err, MprdError::InvalidInput(message) if message == "missing governance_update_kind attestation metadata")
        );
    }

    #[test]
    fn prepare_execution_ready_with_authorization_rejects_governance_metadata_drift() {
        let candidate = valid_http_call_candidate();
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: governance_policy_inputs(
                GovernanceUpdateKindV1::AgentCapabilityExpand,
                true,
                true,
                true,
            ),
            state_hash: dummy_hash(0x81),
            state_ref: StateRef {
                state_source_id: dummy_hash(0x82),
                state_epoch: 10,
                state_attestation_hash: dummy_hash(0x83),
            },
        };
        let token = DecisionToken {
            policy_hash: dummy_hash(0x84),
            policy_ref: PolicyRef {
                policy_epoch: 5,
                registry_root: dummy_hash(0x85),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0x86),
            timestamp_ms: 0,
            signature: vec![],
        };
        let mut proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(0x87),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };
        let authority =
            policy_authority_witness_v1(&token.policy_hash, &token.policy_ref).expect("authority");
        let state_binding = crate::state_provenance::state_binding_witness_v1(&state);
        let governance = governance_admission_witness_v1(&state)
            .expect("governance")
            .expect("governance witness");
        insert_governance_attestation_metadata_v1(&mut proof.attestation_metadata, &governance);
        proof.attestation_metadata.insert(
            GOVERNANCE_ATTESTATION_METADATA_PROFILE_SAFETY_OK_V1.into(),
            "false".into(),
        );

        let err = prepare_execution_ready_with_authorization(
            VerifiedBundle::new(&token, &proof),
            &authority,
            &state_binding,
            Some(governance),
        )
        .unwrap_err();

        assert!(
            matches!(err, MprdError::InvalidInput(message) if message == "governance_profile_safety_ok attestation metadata drifted from admitted governance")
        );
    }

    #[test]
    fn prepare_execution_ready_with_authorization_rejects_governance_update_kind_drift() {
        let candidate = valid_http_call_candidate();
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: governance_policy_inputs(
                GovernanceUpdateKindV1::PolicyTweak,
                true,
                false,
                true,
            ),
            state_hash: dummy_hash(0x91),
            state_ref: StateRef {
                state_source_id: dummy_hash(0x92),
                state_epoch: 11,
                state_attestation_hash: dummy_hash(0x93),
            },
        };
        let token = DecisionToken {
            policy_hash: dummy_hash(0x94),
            policy_ref: PolicyRef {
                policy_epoch: 6,
                registry_root: dummy_hash(0x95),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0x96),
            timestamp_ms: 0,
            signature: vec![],
        };
        let mut proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(0x97),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };
        let authority =
            policy_authority_witness_v1(&token.policy_hash, &token.policy_ref).expect("authority");
        let state_binding = crate::state_provenance::state_binding_witness_v1(&state);
        let governance = governance_admission_witness_v1(&state)
            .expect("governance")
            .expect("governance witness");
        insert_governance_attestation_metadata_v1(&mut proof.attestation_metadata, &governance);
        proof.attestation_metadata.insert(
            GOVERNANCE_ATTESTATION_METADATA_UPDATE_KIND_V1.into(),
            GovernanceUpdateKindV1::SafetyRuleChange.as_str().into(),
        );

        let err = prepare_execution_ready_with_authorization(
            VerifiedBundle::new(&token, &proof),
            &authority,
            &state_binding,
            Some(governance),
        )
        .unwrap_err();

        assert!(
            matches!(err, MprdError::InvalidInput(message) if message == "governance_update_kind attestation metadata drifted from admitted governance")
        );
    }

    #[test]
    fn prepare_execution_ready_with_authorization_rejects_policy_authority_drift() {
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
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };
        let wrong_authority = policy_authority_witness_v1(
            &dummy_hash(16),
            &PolicyRef {
                policy_epoch: token.policy_ref.policy_epoch,
                registry_root: token.policy_ref.registry_root,
            },
        )
        .expect("authority");
        let aligned_state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: token.state_hash,
            state_ref: token.state_ref.clone(),
        };
        let state_binding = crate::state_provenance::state_binding_witness_v1(&aligned_state);

        let err = prepare_execution_ready_with_authorization(
            VerifiedBundle::new(&token, &proof),
            &wrong_authority,
            &state_binding,
            None,
        )
        .unwrap_err();

        assert!(
            matches!(err, MprdError::InvalidInput(message) if message == "token policy_hash drifted from authorized policy context")
        );
    }

    #[test]
    fn prepare_execution_ready_with_authorization_rejects_state_binding_drift() {
        let candidate = valid_http_call_candidate();
        let token = DecisionToken {
            policy_hash: dummy_hash(21),
            policy_ref: PolicyRef {
                policy_epoch: 1,
                registry_root: dummy_hash(22),
            },
            state_hash: dummy_hash(23),
            state_ref: StateRef::unknown(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(24),
            timestamp_ms: 0,
            signature: vec![],
        };
        let proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(25),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };
        let authority =
            policy_authority_witness_v1(&token.policy_hash, &token.policy_ref).expect("authority");
        let drifted_state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(26),
            state_ref: token.state_ref.clone(),
        };
        let drifted_state_binding =
            crate::state_provenance::state_binding_witness_v1(&drifted_state);

        let err = prepare_execution_ready_with_authorization(
            VerifiedBundle::new(&token, &proof),
            &authority,
            &drifted_state_binding,
            None,
        )
        .unwrap_err();

        assert!(
            matches!(err, MprdError::InvalidInput(message) if message == "token state_hash drifted from observed state snapshot")
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
    fn prepare_execution_ready_with_signature_and_state_provenance_accumulates_executor_admission()
    {
        let signing_key = crate::crypto::TokenSigningKey::from_seed(&[0x22; 32]);
        let verifying_key = signing_key.verifying_key();
        let candidate = valid_http_call_candidate();
        let state_source_id = dummy_hash(0x61);
        let token = DecisionToken {
            policy_hash: dummy_hash(0x51),
            policy_ref: PolicyRef {
                policy_epoch: 1,
                registry_root: dummy_hash(0x52),
            },
            state_hash: dummy_hash(0x53),
            state_ref: StateRef {
                state_source_id,
                state_epoch: 9,
                state_attestation_hash: dummy_hash(0x54),
            },
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0x55),
            timestamp_ms: 0,
            signature: vec![],
        };
        let mut token = token;
        token.signature = signing_key.sign_token(&token).to_vec();
        let proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(0x56),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };

        let ready = prepare_execution_ready(VerifiedBundle::new(&token, &proof)).expect("ready");
        let ready = prepare_execution_ready_with_signature(&ready, &verifying_key)
            .expect("signature witness");
        let ready = prepare_execution_ready_with_state_provenance(&ready, &[state_source_id])
            .expect("provenance witness");

        let admission = ready.executor_admission().expect("executor admission");
        assert_eq!(
            admission.signature().expect("signature").signer_pubkey(),
            &verifying_key.to_bytes()
        );
        assert_eq!(ready.packet().executor_admission(), Some(admission));
        assert_eq!(
            admission
                .state_provenance()
                .expect("state provenance")
                .state_ref(),
            &token.state_ref
        );
    }

    #[test]
    fn prepare_execution_ready_with_replay_clearance_accumulates_executor_admission() {
        #[derive(Clone, Copy)]
        struct AcceptingNonceValidator;

        impl crate::anti_replay::NonceValidator for AcceptingNonceValidator {
            fn validate(&self, _token: &DecisionToken) -> Result<()> {
                Ok(())
            }

            fn validate_and_claim(
                &self,
                _token: &DecisionToken,
            ) -> Result<crate::anti_replay::NonceClaim> {
                Ok(crate::anti_replay::NonceClaim::NotClaimed)
            }

            fn mark_used(&self, _token: &DecisionToken) -> Result<()> {
                Ok(())
            }

            fn cleanup(&self) {}
        }

        let candidate = valid_http_call_candidate();
        let token = DecisionToken {
            policy_hash: dummy_hash(0x61),
            policy_ref: PolicyRef {
                policy_epoch: 1,
                registry_root: dummy_hash(0x62),
            },
            state_hash: dummy_hash(0x63),
            state_ref: StateRef {
                state_source_id: dummy_hash(0x64),
                state_epoch: 2,
                state_attestation_hash: dummy_hash(0x65),
            },
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0x66),
            timestamp_ms: 0,
            signature: vec![],
        };
        let proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(0x67),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };

        let ready = prepare_execution_ready(VerifiedBundle::new(&token, &proof)).expect("ready");
        let (ready, replay) =
            prepare_execution_ready_with_replay_clearance(&ready, &AcceptingNonceValidator)
                .expect("replay witness");

        let admission = ready.executor_admission().expect("executor admission");
        assert_eq!(
            admission.replay_clearance().expect("replay").claim(),
            replay.claim()
        );
        assert_eq!(ready.packet().executor_admission(), Some(admission));
        assert_eq!(
            admission.replay_clearance().expect("replay").claim(),
            crate::anti_replay::NonceClaim::NotClaimed
        );
    }

    #[test]
    fn execution_ready_packet_hash_changes_when_packet_membership_changes() {
        let candidate = valid_http_call_candidate();
        let token = DecisionToken {
            policy_hash: dummy_hash(0xB0),
            policy_ref: PolicyRef {
                policy_epoch: 9,
                registry_root: dummy_hash(0xB1),
            },
            state_hash: dummy_hash(0xB2),
            state_ref: StateRef::unknown(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0xB3),
            timestamp_ms: 0,
            signature: vec![],
        };
        let proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(0xB4),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: token.state_hash,
            state_ref: StateRef {
                state_source_id: dummy_hash(0xB7),
                state_epoch: 4,
                state_attestation_hash: dummy_hash(0xB8),
            },
        };
        let token = DecisionToken {
            state_ref: state.state_ref.clone(),
            ..token
        };
        let mut proof = proof;
        insert_execution_authorization_attestation_metadata_v1(
            &mut proof.attestation_metadata,
            &token,
            &state,
            None,
        );
        let authority =
            policy_authority_witness_v1(&token.policy_hash, &token.policy_ref).expect("authority");
        let state_binding = crate::state_provenance::state_binding_witness_v1(&state);
        let ready = prepare_execution_ready_with_authorization(
            VerifiedBundle::new(&token, &proof),
            &authority,
            &state_binding,
            None,
        )
        .expect("ready");
        let base_hash = execution_ready_packet_hash_v1(ready.packet());
        assert_eq!(base_hash, execution_ready_packet_hash_v1(ready.packet()));

        let bridged = prepare_execution_ready_with_registry_bridge(
            &ready,
            execution_registry_bridge_witness_v1(
                &token.policy_hash,
                registry_authorization_witness_v1(
                    registry_authorization_attestation_hash_from_fields_v1(
                        &token.policy_hash,
                        &crate::artifact_repo::Id32([0xBC; 32]),
                        &crate::artifact_repo::Id32([0xBD; 32]),
                        &crate::artifact_repo::Id32([0xBE; 32]),
                        None,
                        None,
                    )
                    .expect("resolution hash"),
                    crate::artifact_repo::Id32([0xBC; 32]),
                    crate::artifact_repo::Id32([0xBD; 32]),
                    crate::artifact_repo::Id32([0xBE; 32]),
                    None,
                    None,
                )
                .expect("registry authorization"),
                Some(dummy_hash(0xB6)),
            )
            .expect("bridge"),
        )
        .expect("bridged");

        assert_ne!(base_hash, execution_ready_packet_hash_v1(bridged.packet()));
    }

    #[test]
    fn execution_boundary_refinement_hash_changes_when_ready_packet_or_attestation_changes() {
        let candidate = valid_http_call_candidate();
        let token = DecisionToken {
            policy_hash: dummy_hash(0xC0),
            policy_ref: PolicyRef {
                policy_epoch: 11,
                registry_root: dummy_hash(0xC1),
            },
            state_hash: dummy_hash(0xC2),
            state_ref: StateRef::unknown(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0xC3),
            timestamp_ms: 0,
            signature: vec![],
        };
        let mut proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(0xC4),
            chosen_action_hash: candidate.candidate_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };
        proof
            .attestation_metadata
            .insert("custom".into(), "base".into());

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: token.state_hash,
            state_ref: StateRef {
                state_source_id: dummy_hash(0xC7),
                state_epoch: 5,
                state_attestation_hash: dummy_hash(0xC8),
            },
        };
        let token = DecisionToken {
            state_ref: state.state_ref.clone(),
            ..token
        };
        insert_execution_authorization_attestation_metadata_v1(
            &mut proof.attestation_metadata,
            &token,
            &state,
            None,
        );
        let authority =
            policy_authority_witness_v1(&token.policy_hash, &token.policy_ref).expect("authority");
        let state_binding = crate::state_provenance::state_binding_witness_v1(&state);
        let ready = prepare_execution_ready_with_authorization(
            VerifiedBundle::new(&token, &proof),
            &authority,
            &state_binding,
            None,
        )
        .expect("ready");
        let base_hash = execution_boundary_refinement_hash_v1(&ready);
        assert_eq!(base_hash, execution_boundary_refinement_hash_v1(&ready));

        let bridged = prepare_execution_ready_with_registry_bridge(
            &ready,
            execution_registry_bridge_witness_v1(
                &token.policy_hash,
                registry_authorization_witness_v1(
                    registry_authorization_attestation_hash_from_fields_v1(
                        &token.policy_hash,
                        &crate::artifact_repo::Id32([0xBF; 32]),
                        &crate::artifact_repo::Id32([0xC0; 32]),
                        &crate::artifact_repo::Id32([0xC1; 32]),
                        None,
                        None,
                    )
                    .expect("resolution hash"),
                    crate::artifact_repo::Id32([0xBF; 32]),
                    crate::artifact_repo::Id32([0xC0; 32]),
                    crate::artifact_repo::Id32([0xC1; 32]),
                    None,
                    None,
                )
                .expect("registry authorization"),
                Some(dummy_hash(0xC6)),
            )
            .expect("bridge"),
        )
        .expect("bridged");
        assert_ne!(base_hash, execution_boundary_refinement_hash_v1(&bridged));

        let mut proof_with_metadata_drift = proof.clone();
        proof_with_metadata_drift
            .attestation_metadata
            .insert("custom".into(), "drifted".into());
        let ready_with_metadata_drift = prepare_execution_ready_with_authorization(
            VerifiedBundle::new(&token, &proof_with_metadata_drift),
            &authority,
            &state_binding,
            None,
        )
        .expect("ready with metadata drift");
        assert_ne!(
            base_hash,
            execution_boundary_refinement_hash_v1(&ready_with_metadata_drift)
        );
    }

    #[test]
    fn execution_binding_vector_hash_changes_when_runtime_binding_membership_changes() {
        let candidate = valid_http_call_candidate();
        let candidates = vec![candidate.clone()];
        let verdicts = vec![RuleVerdict {
            allowed: true,
            reasons: vec![],
            limits: HashMap::new(),
        }];
        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate.clone(),
            policy_hash: dummy_hash(0xD0),
            decision_commitment: Hash32([0u8; 32]),
        };
        let decision = Decision {
            decision_commitment: hash::hash_decision(&Decision {
                decision_commitment: Hash32([0u8; 32]),
                ..decision.clone()
            }),
            ..decision
        };
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(0xD1),
            state_ref: StateRef {
                state_source_id: dummy_hash(0xD2),
                state_epoch: 4,
                state_attestation_hash: dummy_hash(0xD3),
            },
        };
        let token = DecisionToken {
            policy_hash: decision.policy_hash,
            policy_ref: PolicyRef {
                policy_epoch: 12,
                registry_root: dummy_hash(0xD4),
            },
            state_hash: state.state_hash,
            state_ref: state.state_ref.clone(),
            chosen_action_hash: candidate.candidate_hash,
            nonce_or_tx_hash: dummy_hash(0xD5),
            timestamp_ms: 0,
            signature: vec![],
        };
        let proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: hash::hash_candidate_set(&candidates),
            chosen_action_hash: token.chosen_action_hash,
            limits_hash: limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage: hash::candidate_hash_preimage(&candidate),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };

        let base_hash = execution_binding_vector_hash_v1(
            &token,
            &proof,
            &state,
            &candidates,
            &verdicts,
            &decision,
        )
        .expect("base hash");

        let changed_token = DecisionToken {
            policy_ref: PolicyRef {
                policy_epoch: 13,
                registry_root: token.policy_ref.registry_root,
            },
            ..token.clone()
        };
        let changed_hash = execution_binding_vector_hash_v1(
            &changed_token,
            &proof,
            &state,
            &candidates,
            &verdicts,
            &decision,
        )
        .expect("changed hash");
        assert_ne!(base_hash, changed_hash);
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
        let execution_authorization = ready.execution_authorization();
        assert_eq!(execution_authorization.policy_hash(), &token.policy_hash);
        assert_eq!(execution_authorization.policy_ref(), &token.policy_ref);
        assert_eq!(execution_authorization.state_hash(), &token.state_hash);
        assert_eq!(execution_authorization.state_ref(), &token.state_ref);
        assert!(execution_authorization.governance().is_none());
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
        let execution_authorization = ready.execution_authorization();
        assert_eq!(execution_authorization.policy_hash(), &token.policy_hash);
        assert_eq!(execution_authorization.policy_ref(), &token.policy_ref);
        assert_eq!(execution_authorization.state_hash(), &token.state_hash);
        assert_eq!(execution_authorization.state_ref(), &token.state_ref);
        assert_eq!(execution_authorization.governance(), Some(governance));
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
    fn governance_admission_witness_from_fields_accepts_policy_tweak() {
        let witness = governance_admission_witness_from_fields_v1(
            GovernanceUpdateKindV1::PolicyTweak,
            true,
            false,
            true,
        )
        .expect("witness");
        assert_eq!(witness.update_kind(), GovernanceUpdateKindV1::PolicyTweak);
        assert!(witness.profile_app_ok());
        assert!(!witness.profile_safety_ok());
        assert!(witness.link_ok());
    }

    #[test]
    fn governance_admission_witness_from_fields_rejects_capability_expand_without_both_profiles() {
        let err = governance_admission_witness_from_fields_v1(
            GovernanceUpdateKindV1::AgentCapabilityExpand,
            true,
            false,
            true,
        )
        .unwrap_err();
        assert!(
            matches!(err, MprdError::InvalidInput(message) if message == "governance agent_capability_expand admission requires both profile thresholds")
        );
    }

    #[test]
    fn governance_admission_witness_from_fields_rejects_safety_change_without_safety_profile() {
        let err = governance_admission_witness_from_fields_v1(
            GovernanceUpdateKindV1::SafetyRuleChange,
            true,
            false,
            true,
        )
        .unwrap_err();
        assert!(
            matches!(err, MprdError::InvalidInput(message) if message == "governance safety_rule_change admission requires profile_safety_ok")
        );
    }

    #[test]
    fn governance_admission_witness_from_fields_rejects_missing_link_ok() {
        let err = governance_admission_witness_from_fields_v1(
            GovernanceUpdateKindV1::PolicyTweak,
            true,
            false,
            false,
        )
        .unwrap_err();
        assert!(
            matches!(err, MprdError::InvalidInput(message) if message == "governance admission requires link_ok")
        );
    }

    #[test]
    fn governance_admission_witness_from_attestation_metadata_accepts_full_metadata() {
        let mut metadata = HashMap::new();
        metadata.insert(
            GOVERNANCE_ATTESTATION_METADATA_UPDATE_KIND_V1.into(),
            GovernanceUpdateKindV1::SafetyRuleChange.as_str().into(),
        );
        metadata.insert(
            GOVERNANCE_ATTESTATION_METADATA_PROFILE_APP_OK_V1.into(),
            "true".into(),
        );
        metadata.insert(
            GOVERNANCE_ATTESTATION_METADATA_PROFILE_SAFETY_OK_V1.into(),
            "true".into(),
        );
        metadata.insert(
            GOVERNANCE_ATTESTATION_METADATA_LINK_OK_V1.into(),
            "true".into(),
        );

        let witness = governance_admission_witness_from_attestation_metadata_v1(&metadata)
            .expect("witness")
            .expect("governance");

        assert_eq!(
            witness.update_kind(),
            GovernanceUpdateKindV1::SafetyRuleChange
        );
        assert!(witness.profile_app_ok());
        assert!(witness.profile_safety_ok());
        assert!(witness.link_ok());
    }

    #[test]
    fn governance_admission_witness_from_attestation_metadata_returns_none_when_absent() {
        let witness = governance_admission_witness_from_attestation_metadata_v1(&HashMap::new())
            .expect("no metadata should be accepted");
        assert!(witness.is_none());
    }

    #[test]
    fn governance_admission_witness_from_attestation_metadata_accepts_false_bool_when_admitted() {
        let mut metadata = HashMap::new();
        metadata.insert(
            GOVERNANCE_ATTESTATION_METADATA_UPDATE_KIND_V1.into(),
            GovernanceUpdateKindV1::PolicyTweak.as_str().into(),
        );
        metadata.insert(
            GOVERNANCE_ATTESTATION_METADATA_PROFILE_APP_OK_V1.into(),
            "true".into(),
        );
        metadata.insert(
            GOVERNANCE_ATTESTATION_METADATA_PROFILE_SAFETY_OK_V1.into(),
            "false".into(),
        );
        metadata.insert(
            GOVERNANCE_ATTESTATION_METADATA_LINK_OK_V1.into(),
            "true".into(),
        );

        let witness = governance_admission_witness_from_attestation_metadata_v1(&metadata)
            .expect("witness")
            .expect("governance");

        assert_eq!(witness.update_kind(), GovernanceUpdateKindV1::PolicyTweak);
        assert!(witness.profile_app_ok());
        assert!(!witness.profile_safety_ok());
        assert!(witness.link_ok());
    }

    #[test]
    fn governance_admission_witness_from_attestation_metadata_rejects_partial_metadata() {
        let mut metadata = HashMap::new();
        metadata.insert(
            GOVERNANCE_ATTESTATION_METADATA_UPDATE_KIND_V1.into(),
            GovernanceUpdateKindV1::PolicyTweak.as_str().into(),
        );

        let err = governance_admission_witness_from_attestation_metadata_v1(&metadata).unwrap_err();

        assert!(
            matches!(err, MprdError::InvalidInput(message) if message == "partial governance attestation metadata cannot reconstruct admitted governance")
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
