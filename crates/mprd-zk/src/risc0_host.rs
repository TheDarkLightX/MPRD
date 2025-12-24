//! Risc0 Host Integration for MPRD
//!
//! This module provides the host-side implementation for generating and
//! verifying ZK proofs using Risc0. It bridges the MPRD core types with
//! the Risc0 zkVM.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │  MPRD Decision  │ --> │  Risc0 Prover   │ --> │  Receipt/Proof  │
//! │  (Host)         │     │  (Guest in VM)  │     │  (Verifiable)   │
//! └─────────────────┘     └─────────────────┘     └─────────────────┘
//! ```
//!
//! # Security Model
//!
//! - The guest program is compiled to RISC-V and has a fixed image ID
//! - The image ID must match during verification (no code substitution)
//! - The journal (public output) is cryptographically bound to the proof
//! - Uses Risc0 zkVM receipts; no simulated proofs are compiled into this module

use mprd_core::{
    hash::{candidate_hash_preimage, candidate_set_hash_preimage, state_hash_preimage},
    CandidateAction, Decision, DecisionToken, Hash32, MprdError, PolicyHash, ProofBundle, Result,
    RuleVerdict, StateSnapshot, VerificationStatus, ZkLocalVerifier,
};
use std::collections::HashMap;
use std::sync::Arc;

use mprd_risc0_shared::{
    action_encoding_id_v1, compute_decision_commitment_v3, limits_bytes_mpb_v1, limits_hash,
    limits_hash_mpb_v1, mpb_register_mapping_id_v1, policy_exec_kind_host_trusted_id_v0,
    policy_exec_kind_mpb_id_v1, policy_exec_kind_tau_compiled_id_v1, policy_exec_version_id_v1,
    state_encoding_id_v1, tau_compiled_policy_hash_v1, GuestInputV3, GuestJournalV3,
    MpbGuestInputV3, MpbVarBindingV1, TauCompiledGuestInputV3, JOURNAL_VERSION,
    MAX_CANDIDATE_PREIMAGE_BYTES_V1, MAX_POLICY_BYTECODE_BYTES_V1, MAX_STATE_PREIMAGE_BYTES_V1,
    MAX_TCV_COMPILED_POLICY_BYTES_V1, MPB_FUEL_LIMIT_V1,
};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

// =============================================================================
// Configuration
// =============================================================================

fn validate_embedded_methods(guest_elf: &'static [u8], image_id: [u8; 32]) -> Result<()> {
    if guest_elf.is_empty() {
        return Err(MprdError::ZkError(
            "Risc0 guest ELF is empty (methods not embedded). Rebuild without RISC0_SKIP_BUILD=1 and ensure the Risc0 toolchain/guest target are installed".into(),
        ));
    }

    if image_id == [0u8; 32] {
        return Err(MprdError::ZkError(
            "Risc0 image_id is all-zero (methods not embedded). Rebuild without RISC0_SKIP_BUILD=1 and ensure the Risc0 toolchain/guest target are installed".into(),
        ));
    }

    Ok(())
}

/// Configuration for the Risc0 host.
#[derive(Clone, Debug)]
pub struct Risc0HostConfig {
    /// The image ID of the guest program.
    /// This is a cryptographic commitment to the guest code.
    pub image_id: [u8; 32],

    /// Maximum proving time in seconds.
    pub max_prove_time_secs: u64,
}

impl Risc0HostConfig {
    /// Create a production config with the given image ID.
    pub fn new(image_id: [u8; 32]) -> Self {
        Self {
            image_id,
            max_prove_time_secs: 300, // 5 minutes
        }
    }
}

// =============================================================================
// ABI v1 (mprd-risc0-shared)
// =============================================================================

// =============================================================================
// Risc0 Attestor (ZK Proofs)
// =============================================================================

/// Risc0 attestor that generates cryptographic ZK proofs.
///
/// # Security
///
/// This attestor generates cryptographic proofs that can be verified by
/// any party with the image ID. The proof guarantees:
/// 1. The selector contract was satisfied
/// 2. The chosen action was in the candidate set
/// 3. The policy allowed the chosen action
///
/// # Usage
///
/// ```rust,ignore
/// use mprd_risc0_methods::{MPRD_GUEST_ELF, MPRD_GUEST_ID};
///
/// let attestor = Risc0Attestor::new(MPRD_GUEST_ELF, MPRD_GUEST_ID);
/// let proof = attestor.attest_with_verdict(&token, &decision, &state, &candidates, &verdict)?;
/// ```
pub struct Risc0Attestor {
    guest_elf: &'static [u8],
    image_id: [u8; 32],
}

impl Risc0Attestor {
    /// Create a new attestor with the guest ELF and image ID.
    ///
    /// # Arguments
    /// * `guest_elf` - Compiled guest program (from mprd-risc0-methods)
    /// * `image_id` - Cryptographic hash of guest program
    pub fn new(guest_elf: &'static [u8], image_id: [u8; 32]) -> Self {
        Self {
            guest_elf,
            image_id,
        }
    }

    /// Prepare guest input from MPRD types.
    ///
    /// # Preconditions
    /// - `decision.chosen_index < candidates.len()`
    /// - `verdict.allowed` reflects policy evaluation result
    fn prepare_input(
        &self,
        token: &DecisionToken,
        decision: &Decision,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
        verdict: &RuleVerdict,
    ) -> Result<GuestInputV3> {
        // Validate bounds (fail closed)
        if decision.chosen_index >= candidates.len() {
            return Err(MprdError::InvalidInput(format!(
                "chosen_index {} out of bounds for {} candidates",
                decision.chosen_index,
                candidates.len()
            )));
        }

        if state.state_ref != token.state_ref {
            return Err(MprdError::InvalidInput(
                "state_ref mismatch between state snapshot and token".into(),
            ));
        }

        let chosen_index: u32 = decision
            .chosen_index
            .try_into()
            .map_err(|_| MprdError::InvalidInput("chosen_index exceeds u32::MAX".into()))?;

        let candidate_count: u32 = candidates
            .len()
            .try_into()
            .map_err(|_| MprdError::InvalidInput("candidate count exceeds u32::MAX".into()))?;

        // Canonical preimages matching `mprd-core` hashing (Option A).
        let state_preimage = state_hash_preimage(state);
        let candidate_set_preimage = candidate_set_hash_preimage(candidates);
        let chosen_action_preimage = candidate_hash_preimage(&decision.chosen_action);

        // Sanity: ensure the preimage layout matches the guest contract (fail closed).
        let expected_len = 4usize + (candidate_count as usize) * 32usize;
        if candidate_set_preimage.len() != expected_len {
            return Err(MprdError::ZkError(
                "candidate_set_preimage length mismatch".into(),
            ));
        }

        Ok(GuestInputV3 {
            policy_hash: decision.policy_hash.0,
            // The current guest does not re-evaluate the policy; it only enforces a minimal
            // selector contract. Mark this execution as host-trusted until in-guest evaluation
            // is implemented.
            policy_exec_kind_id: policy_exec_kind_host_trusted_id_v0(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            state_encoding_id: state_encoding_id_v1(),
            action_encoding_id: action_encoding_id_v1(),
            nonce_or_tx_hash: token.nonce_or_tx_hash.0,
            policy_epoch: token.policy_ref.policy_epoch,
            registry_root: token.policy_ref.registry_root.0,
            state_source_id: token.state_ref.state_source_id.0,
            state_epoch: token.state_ref.state_epoch,
            state_attestation_hash: token.state_ref.state_attestation_hash.0,
            chosen_index,
            chosen_verdict_allowed: verdict.allowed,
            state_preimage,
            candidate_set_preimage,
            chosen_action_preimage,
            limits_bytes: Vec::new(),
        })
    }

    /// Generate a real ZK proof for the decision.
    ///
    /// # Arguments
    /// * `decision` - The decision to prove
    /// * `state` - Current state snapshot
    /// * `candidates` - All candidate actions
    /// * `verdict` - The policy verdict for the chosen action
    pub fn attest_with_verdict(
        &self,
        token: &DecisionToken,
        decision: &Decision,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
        verdict: &RuleVerdict,
    ) -> Result<ProofBundle> {
        validate_embedded_methods(self.guest_elf, self.image_id)?;

        let input = self.prepare_input(token, decision, state, candidates, verdict)?;

        // Build execution environment with input
        let env = ExecutorEnv::builder()
            .write(&input)
            .map_err(|e| MprdError::ZkError(format!("Failed to write input: {}", e)))?
            .build()
            .map_err(|e| MprdError::ZkError(format!("Failed to build env: {}", e)))?;

        // Create prover and generate proof
        let prover = default_prover();
        let prove_info = prover
            .prove(env, self.guest_elf)
            .map_err(|e| MprdError::ZkError(format!("Proving failed: {}", e)))?;

        let receipt = prove_info.receipt;

        // Serialize receipt for storage
        let receipt_bytes = bincode::serialize(&receipt)
            .map_err(|e| MprdError::ZkError(format!("Failed to serialize receipt: {}", e)))?;

        // Extract journal output
        let journal: GuestJournalV3 = receipt
            .journal
            .decode()
            .map_err(|e| MprdError::ZkError(format!("Failed to decode journal: {}", e)))?;

        if journal.journal_version != JOURNAL_VERSION {
            return Err(MprdError::ZkError(format!(
                "Unsupported journal_version {}; expected {}",
                journal.journal_version, JOURNAL_VERSION
            )));
        }

        // Verify decision commitment (fail closed on ABI drift).
        let expected_commitment = compute_decision_commitment_v3(&journal);
        if journal.decision_commitment != expected_commitment {
            return Err(MprdError::ZkError("decision_commitment mismatch".into()));
        }

        // Bind policy authorization context into the proof statement (fail closed).
        if journal.policy_epoch != token.policy_ref.policy_epoch {
            return Err(MprdError::ZkError("policy_epoch mismatch".into()));
        }
        if Hash32(journal.registry_root) != token.policy_ref.registry_root {
            return Err(MprdError::ZkError("registry_root mismatch".into()));
        }

        // Bind state provenance context (fail closed).
        if Hash32(journal.state_source_id) != token.state_ref.state_source_id {
            return Err(MprdError::ZkError("state_source_id mismatch".into()));
        }
        if journal.state_epoch != token.state_ref.state_epoch {
            return Err(MprdError::ZkError("state_epoch mismatch".into()));
        }
        if Hash32(journal.state_attestation_hash) != token.state_ref.state_attestation_hash {
            return Err(MprdError::ZkError("state_attestation_hash mismatch".into()));
        }

        // Bind journal commitments to the token/decision/proof.
        if Hash32(journal.policy_hash) != token.policy_hash {
            return Err(MprdError::ZkError("Policy hash mismatch".into()));
        }
        if Hash32(journal.state_hash) != token.state_hash {
            return Err(MprdError::ZkError("State hash mismatch".into()));
        }
        if Hash32(journal.chosen_action_hash) != token.chosen_action_hash {
            return Err(MprdError::ZkError("Chosen action hash mismatch".into()));
        }
        if Hash32(journal.nonce_or_tx_hash) != token.nonce_or_tx_hash {
            return Err(MprdError::ZkError("nonce_or_tx_hash mismatch".into()));
        }

        // Verify selector contract was satisfied
        if !journal.allowed {
            return Err(MprdError::ZkError(
                "Guest reported selector contract not satisfied".into(),
            ));
        }

        let mut metadata = HashMap::new();
        metadata.insert("zk_backend".into(), "risc0".into());
        metadata.insert("image_id".into(), hex::encode(self.image_id));
        metadata.insert("version".into(), "1.2.0".into());
        metadata.insert("receipt_size".into(), receipt_bytes.len().to_string());
        metadata.insert(
            "journal_version".into(),
            journal.journal_version.to_string(),
        );
        metadata.insert(
            "policy_exec_kind_id".into(),
            hex::encode(journal.policy_exec_kind_id),
        );
        metadata.insert(
            "policy_exec_version_id".into(),
            hex::encode(journal.policy_exec_version_id),
        );
        metadata.insert(
            "state_encoding_id".into(),
            hex::encode(journal.state_encoding_id),
        );
        metadata.insert(
            "action_encoding_id".into(),
            hex::encode(journal.action_encoding_id),
        );
        metadata.insert(
            "nonce_or_tx_hash".into(),
            hex::encode(journal.nonce_or_tx_hash),
        );

        Ok(ProofBundle {
            policy_hash: Hash32(journal.policy_hash),
            state_hash: Hash32(journal.state_hash),
            candidate_set_hash: Hash32(journal.candidate_set_hash),
            chosen_action_hash: Hash32(journal.chosen_action_hash),
            limits_hash: Hash32(journal.limits_hash),
            limits_bytes: Vec::new(),
            chosen_action_preimage: candidate_hash_preimage(&decision.chosen_action),
            risc0_receipt: receipt_bytes,
            attestation_metadata: metadata,
        })
    }

    /// Generate a real ZK proof for the decision, committing caller-provided `limits_bytes`.
    ///
    /// This is used to bind additional execution-relevant metadata (e.g., Mode C encryption
    /// binding context) into the public journal via `limits_hash = H("MPRD_LIMITS_V1" || limits_bytes)`.
    pub fn attest_with_verdict_and_limits_bytes(
        &self,
        token: &DecisionToken,
        decision: &Decision,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
        verdict: &RuleVerdict,
        limits_bytes: Vec<u8>,
    ) -> Result<ProofBundle> {
        validate_embedded_methods(self.guest_elf, self.image_id)?;

        let mut input = self.prepare_input(token, decision, state, candidates, verdict)?;
        input.limits_bytes = limits_bytes.clone();

        // Build execution environment with input
        let env = ExecutorEnv::builder()
            .write(&input)
            .map_err(|e| MprdError::ZkError(format!("Failed to write input: {}", e)))?
            .build()
            .map_err(|e| MprdError::ZkError(format!("Failed to build env: {}", e)))?;

        let prover = default_prover();
        let prove_info = prover
            .prove(env, self.guest_elf)
            .map_err(|e| MprdError::ZkError(format!("Proving failed: {}", e)))?;

        let receipt = prove_info.receipt;
        let receipt_bytes = bincode::serialize(&receipt)
            .map_err(|e| MprdError::ZkError(format!("Failed to serialize receipt: {}", e)))?;

        let journal: GuestJournalV3 = receipt
            .journal
            .decode()
            .map_err(|e| MprdError::ZkError(format!("Failed to decode journal: {}", e)))?;

        if journal.journal_version != JOURNAL_VERSION {
            return Err(MprdError::ZkError(format!(
                "Unsupported journal_version {}; expected {}",
                journal.journal_version, JOURNAL_VERSION
            )));
        }

        // Verify the guest actually committed the provided limits bytes.
        let expected_limits_hash = limits_hash(&limits_bytes);
        if journal.limits_hash != expected_limits_hash {
            return Err(MprdError::ZkError("limits_hash mismatch".into()));
        }

        // Verify decision commitment (fail closed on ABI drift).
        let expected_commitment = compute_decision_commitment_v3(&journal);
        if journal.decision_commitment != expected_commitment {
            return Err(MprdError::ZkError("decision_commitment mismatch".into()));
        }

        // Bind policy authorization context into the proof statement (fail closed).
        if journal.policy_epoch != token.policy_ref.policy_epoch {
            return Err(MprdError::ZkError("policy_epoch mismatch".into()));
        }
        if Hash32(journal.registry_root) != token.policy_ref.registry_root {
            return Err(MprdError::ZkError("registry_root mismatch".into()));
        }

        // Bind state provenance context (fail closed).
        if Hash32(journal.state_source_id) != token.state_ref.state_source_id {
            return Err(MprdError::ZkError("state_source_id mismatch".into()));
        }
        if journal.state_epoch != token.state_ref.state_epoch {
            return Err(MprdError::ZkError("state_epoch mismatch".into()));
        }
        if Hash32(journal.state_attestation_hash) != token.state_ref.state_attestation_hash {
            return Err(MprdError::ZkError("state_attestation_hash mismatch".into()));
        }

        // Bind journal commitments to the token/decision/proof.
        if Hash32(journal.policy_hash) != token.policy_hash {
            return Err(MprdError::ZkError("Policy hash mismatch".into()));
        }
        if Hash32(journal.state_hash) != token.state_hash {
            return Err(MprdError::ZkError("State hash mismatch".into()));
        }
        if Hash32(journal.chosen_action_hash) != token.chosen_action_hash {
            return Err(MprdError::ZkError("Chosen action hash mismatch".into()));
        }
        if Hash32(journal.nonce_or_tx_hash) != token.nonce_or_tx_hash {
            return Err(MprdError::ZkError("nonce_or_tx_hash mismatch".into()));
        }
        if Hash32(journal.chosen_action_hash) != decision.chosen_action.candidate_hash {
            return Err(MprdError::ZkError(
                "chosen_action_hash mismatch vs decision".into(),
            ));
        }

        let mut metadata = HashMap::new();
        metadata.insert("zk_backend".into(), "risc0".into());
        metadata.insert("image_id".into(), hex::encode(self.image_id));
        metadata.insert(
            "journal_version".into(),
            journal.journal_version.to_string(),
        );
        metadata.insert(
            "policy_exec_kind_id".into(),
            hex::encode(journal.policy_exec_kind_id),
        );
        metadata.insert(
            "policy_exec_version_id".into(),
            hex::encode(journal.policy_exec_version_id),
        );

        Ok(ProofBundle {
            policy_hash: Hash32(journal.policy_hash),
            state_hash: Hash32(journal.state_hash),
            candidate_set_hash: Hash32(journal.candidate_set_hash),
            chosen_action_hash: Hash32(journal.chosen_action_hash),
            limits_hash: Hash32(journal.limits_hash),
            limits_bytes,
            chosen_action_preimage: candidate_hash_preimage(&decision.chosen_action),
            risc0_receipt: receipt_bytes,
            attestation_metadata: metadata,
        })
    }
}

// =============================================================================
// MPB-in-Guest Attestor (policy_exec_kind = mpb-v1)
// =============================================================================

/// Canonical MPB policy artifact needed to build an mpb-v1 guest witness.
#[derive(Clone, Debug)]
pub struct MpbPolicyArtifactV1 {
    pub bytecode: Vec<u8>,
    /// Canonical variable bindings in ascending name order.
    pub variables: Vec<(String, u8)>,
}

pub trait MpbPolicyProvider: Send + Sync {
    fn get(&self, policy_hash: &PolicyHash) -> Option<MpbPolicyArtifactV1>;
}

impl MpbPolicyProvider for HashMap<PolicyHash, MpbPolicyArtifactV1> {
    fn get(&self, policy_hash: &PolicyHash) -> Option<MpbPolicyArtifactV1> {
        HashMap::get(self, policy_hash).cloned()
    }
}

// =============================================================================
// Tau-Compiled (TCV) Attestor (policy_exec_kind = tau_compiled_v1)
// =============================================================================

pub trait TauCompiledPolicyProvider: Send + Sync {
    fn get(&self, policy_hash: &PolicyHash) -> Option<Vec<u8>>;
}

impl TauCompiledPolicyProvider for HashMap<PolicyHash, Vec<u8>> {
    fn get(&self, policy_hash: &PolicyHash) -> Option<Vec<u8>> {
        HashMap::get(self, policy_hash).cloned()
    }
}

/// Risc0 attestor that generates cryptographic ZK proofs where the guest
/// evaluates a Tau-compiled policy artifact (TCV circuit) for all candidates and
/// runs deterministic selection in-guest.
pub struct Risc0TauCompiledAttestor {
    guest_elf: &'static [u8],
    image_id: [u8; 32],
    policy_provider: Arc<dyn TauCompiledPolicyProvider>,
}

impl Risc0TauCompiledAttestor {
    pub fn new(
        guest_elf: &'static [u8],
        image_id: [u8; 32],
        policy_provider: Arc<dyn TauCompiledPolicyProvider>,
    ) -> Self {
        Self {
            guest_elf,
            image_id,
            policy_provider,
        }
    }

    fn prepare_input(
        &self,
        token: &DecisionToken,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<TauCompiledGuestInputV3> {
        if candidates.is_empty() {
            return Err(MprdError::InvalidInput("no candidates provided".into()));
        }
        if candidates.len() > mprd_core::MAX_CANDIDATES {
            return Err(MprdError::BoundedValueExceeded(
                "too many candidates".into(),
            ));
        }

        // TCV v2 requires `policy_inputs` be empty so the guest can parse state_preimage
        // as a pure fields-only key/value stream (fail-closed).
        if !state.policy_inputs.is_empty() {
            return Err(MprdError::InvalidInput(
                "tau_compiled_v1 does not support state.policy_inputs; provide empty policy_inputs"
                    .into(),
            ));
        }

        if state.state_ref != token.state_ref {
            return Err(MprdError::InvalidInput(
                "state_ref mismatch between state snapshot and token".into(),
            ));
        }

        let compiled_policy_bytes =
            self.policy_provider
                .get(&token.policy_hash)
                .ok_or_else(|| MprdError::PolicyNotFound {
                    hash: token.policy_hash.clone(),
                })?;

        if compiled_policy_bytes.len() > MAX_TCV_COMPILED_POLICY_BYTES_V1 {
            return Err(MprdError::BoundedValueExceeded(
                "compiled_policy_bytes too large".into(),
            ));
        }

        // Defensive: ensure the policy artifact matches the token policy_hash.
        let computed_policy_hash = tau_compiled_policy_hash_v1(&compiled_policy_bytes);
        if Hash32(computed_policy_hash) != token.policy_hash {
            return Err(MprdError::ZkError(
                "tau_compiled policy_hash mismatch (policy substitution)".into(),
            ));
        }

        let state_preimage = state_hash_preimage(state);
        if state_preimage.len() > MAX_STATE_PREIMAGE_BYTES_V1 {
            return Err(MprdError::BoundedValueExceeded(
                "state_preimage too large".into(),
            ));
        }

        let candidates_preimages: Vec<Vec<u8>> =
            candidates.iter().map(candidate_hash_preimage).collect();
        if candidates_preimages
            .iter()
            .any(|b| b.len() > MAX_CANDIDATE_PREIMAGE_BYTES_V1)
        {
            return Err(MprdError::BoundedValueExceeded(
                "candidate_preimage too large".into(),
            ));
        }

        Ok(TauCompiledGuestInputV3 {
            policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            state_encoding_id: state_encoding_id_v1(),
            action_encoding_id: action_encoding_id_v1(),
            nonce_or_tx_hash: token.nonce_or_tx_hash.0,
            policy_epoch: token.policy_ref.policy_epoch,
            registry_root: token.policy_ref.registry_root.0,
            state_source_id: token.state_ref.state_source_id.0,
            state_epoch: token.state_ref.state_epoch,
            state_attestation_hash: token.state_ref.state_attestation_hash.0,
            compiled_policy_bytes,
            state_preimage,
            candidates_preimages,
            limits_bytes: Vec::new(),
        })
    }

    pub fn attest(
        &self,
        token: &DecisionToken,
        decision: &Decision,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<ProofBundle> {
        validate_embedded_methods(self.guest_elf, self.image_id)?;
        let input = self.prepare_input(token, state, candidates)?;

        let env = ExecutorEnv::builder()
            .write(&input)
            .map_err(|e| MprdError::ZkError(format!("Failed to write input: {}", e)))?
            .build()
            .map_err(|e| MprdError::ZkError(format!("Failed to build env: {}", e)))?;

        let prover = default_prover();
        let prove_info = prover
            .prove(env, self.guest_elf)
            .map_err(|e| MprdError::ZkError(format!("Proving failed: {}", e)))?;
        let receipt = prove_info.receipt;

        let receipt_bytes = bincode::serialize(&receipt)
            .map_err(|e| MprdError::ZkError(format!("Failed to serialize receipt: {}", e)))?;

        let journal: GuestJournalV3 = receipt
            .journal
            .decode()
            .map_err(|e| MprdError::ZkError(format!("Failed to decode journal: {}", e)))?;

        if journal.journal_version != JOURNAL_VERSION {
            return Err(MprdError::ZkError("unsupported journal_version".into()));
        }

        // Fail-closed sanity: the receipt must bind to the expected exec kind.
        if journal.policy_exec_kind_id != policy_exec_kind_tau_compiled_id_v1()
            || journal.policy_exec_version_id != policy_exec_version_id_v1()
        {
            return Err(MprdError::ZkError(
                "unexpected policy_exec_kind/version".into(),
            ));
        }

        // Bind journal commitments to the token/decision/proof.
        if !journal.allowed {
            return Err(MprdError::ZkError(
                "Guest reported selector contract not satisfied".into(),
            ));
        }
        if Hash32(journal.policy_hash) != token.policy_hash {
            return Err(MprdError::ZkError("Policy hash mismatch".into()));
        }
        if journal.policy_epoch != token.policy_ref.policy_epoch {
            return Err(MprdError::ZkError("policy_epoch mismatch".into()));
        }
        if Hash32(journal.registry_root) != token.policy_ref.registry_root {
            return Err(MprdError::ZkError("registry_root mismatch".into()));
        }
        if Hash32(journal.state_hash) != token.state_hash {
            return Err(MprdError::ZkError("State hash mismatch".into()));
        }
        if Hash32(journal.chosen_action_hash) != token.chosen_action_hash {
            return Err(MprdError::ZkError("Chosen action hash mismatch".into()));
        }
        if Hash32(journal.nonce_or_tx_hash) != token.nonce_or_tx_hash {
            return Err(MprdError::ZkError("nonce_or_tx_hash mismatch".into()));
        }
        if Hash32(journal.state_source_id) != token.state_ref.state_source_id {
            return Err(MprdError::ZkError("state_source_id mismatch".into()));
        }
        if journal.state_epoch != token.state_ref.state_epoch {
            return Err(MprdError::ZkError("state_epoch mismatch".into()));
        }
        if Hash32(journal.state_attestation_hash) != token.state_ref.state_attestation_hash {
            return Err(MprdError::ZkError("state_attestation_hash mismatch".into()));
        }
        if Hash32(journal.chosen_action_hash) != decision.chosen_action.candidate_hash {
            return Err(MprdError::ZkError(
                "chosen_action_hash mismatch vs decision".into(),
            ));
        }

        let mut metadata = HashMap::new();
        metadata.insert("zk_backend".into(), "risc0".into());
        metadata.insert("image_id".into(), hex::encode(self.image_id));
        metadata.insert(
            "journal_version".into(),
            journal.journal_version.to_string(),
        );
        metadata.insert(
            "policy_exec_kind_id".into(),
            hex::encode(journal.policy_exec_kind_id),
        );
        metadata.insert(
            "policy_exec_version_id".into(),
            hex::encode(journal.policy_exec_version_id),
        );

        let chosen_index: usize = journal
            .chosen_index
            .try_into()
            .map_err(|_| MprdError::ZkError("journal chosen_index out of range".into()))?;
        let chosen_action_preimage = input
            .candidates_preimages
            .get(chosen_index)
            .cloned()
            .ok_or_else(|| {
                MprdError::ZkError("journal chosen_index out of range for witness".into())
            })?;

        Ok(ProofBundle {
            policy_hash: Hash32(journal.policy_hash),
            state_hash: Hash32(journal.state_hash),
            candidate_set_hash: Hash32(journal.candidate_set_hash),
            chosen_action_hash: Hash32(journal.chosen_action_hash),
            limits_hash: Hash32(journal.limits_hash),
            limits_bytes: Vec::new(),
            // Derive the action bytes from the guest-committed selection, not from host-side selection.
            chosen_action_preimage,
            risc0_receipt: receipt_bytes,
            attestation_metadata: metadata,
        })
    }
}

/// Risc0 attestor that generates cryptographic ZK proofs where the guest
/// re-evaluates MPB for all candidates and runs deterministic selection.
pub struct Risc0MpbAttestor {
    guest_elf: &'static [u8],
    image_id: [u8; 32],
    mpb_fuel_limit: u32,
    mpb_policy_provider: Arc<dyn MpbPolicyProvider>,
}

impl Risc0MpbAttestor {
    pub fn new(
        guest_elf: &'static [u8],
        image_id: [u8; 32],
        mpb_fuel_limit: u32,
        mpb_policy_provider: Arc<dyn MpbPolicyProvider>,
    ) -> Self {
        Self {
            guest_elf,
            image_id,
            mpb_fuel_limit,
            mpb_policy_provider,
        }
    }

    fn prepare_input(
        &self,
        token: &DecisionToken,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<MpbGuestInputV3> {
        // mpb-v1 fuel semantics are pinned; refuse to run with a different setting.
        if self.mpb_fuel_limit != MPB_FUEL_LIMIT_V1 {
            return Err(MprdError::ConfigError(format!(
                "mpb_fuel_limit must be {}; got {}",
                MPB_FUEL_LIMIT_V1, self.mpb_fuel_limit
            )));
        }

        if candidates.is_empty() {
            return Err(MprdError::InvalidInput("no candidates provided".into()));
        }
        if candidates.len() > mprd_core::MAX_CANDIDATES {
            return Err(MprdError::BoundedValueExceeded(
                "too many candidates".into(),
            ));
        }

        if !state.policy_inputs.is_empty() {
            return Err(MprdError::InvalidInput(
                "mpb-v1 guest does not support state.policy_inputs; provide empty policy_inputs"
                    .into(),
            ));
        }

        if state.state_ref != token.state_ref {
            return Err(MprdError::InvalidInput(
                "state_ref mismatch between state snapshot and token".into(),
            ));
        }

        let policy = self
            .mpb_policy_provider
            .get(&token.policy_hash)
            .ok_or_else(|| MprdError::PolicyNotFound {
                hash: token.policy_hash.clone(),
            })?;

        // Canonicalize variable bindings (fail closed if malformed).
        let mut vars = policy.variables;
        vars.sort_by(|a, b| a.0.cmp(&b.0));
        if vars.len() > mprd_mpb::MpbVm::MAX_REGISTERS {
            return Err(MprdError::InvalidInput(
                "mpb policy has too many register bindings".into(),
            ));
        }
        for w in vars.windows(2) {
            if w[0].0 >= w[1].0 {
                return Err(MprdError::InvalidInput(
                    "mpb policy variable bindings must be unique and sorted".into(),
                ));
            }
        }

        let policy_variables: Vec<MpbVarBindingV1> = vars
            .into_iter()
            .map(|(name, reg)| MpbVarBindingV1 {
                name: name.into_bytes(),
                reg,
            })
            .collect();

        // Defensive: ensure the policy artifact matches the token policy_hash.
        let policy_refs: Vec<(&[u8], u8)> = policy_variables
            .iter()
            .map(|b| (b.name.as_slice(), b.reg))
            .collect();
        let computed_policy_hash = mprd_mpb::policy_hash_v1(&policy.bytecode, &policy_refs);
        if Hash32(computed_policy_hash) != token.policy_hash {
            return Err(MprdError::ZkError(
                "mpb policy_hash mismatch (policy substitution)".into(),
            ));
        }

        if policy.bytecode.len() > MAX_POLICY_BYTECODE_BYTES_V1 {
            return Err(MprdError::BoundedValueExceeded(
                "mpb policy bytecode too large".into(),
            ));
        }

        let state_preimage = state_hash_preimage(state);
        if state_preimage.len() > MAX_STATE_PREIMAGE_BYTES_V1 {
            return Err(MprdError::BoundedValueExceeded(
                "state_preimage too large".into(),
            ));
        }

        let candidates_preimages: Vec<Vec<u8>> =
            candidates.iter().map(candidate_hash_preimage).collect();
        if candidates_preimages
            .iter()
            .any(|b| b.len() > MAX_CANDIDATE_PREIMAGE_BYTES_V1)
        {
            return Err(MprdError::BoundedValueExceeded(
                "candidate_preimage too large".into(),
            ));
        }

        Ok(MpbGuestInputV3 {
            policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            mpb_register_mapping_id: mpb_register_mapping_id_v1(),
            state_encoding_id: state_encoding_id_v1(),
            action_encoding_id: action_encoding_id_v1(),
            nonce_or_tx_hash: token.nonce_or_tx_hash.0,
            policy_epoch: token.policy_ref.policy_epoch,
            registry_root: token.policy_ref.registry_root.0,
            state_source_id: token.state_ref.state_source_id.0,
            state_epoch: token.state_ref.state_epoch,
            state_attestation_hash: token.state_ref.state_attestation_hash.0,
            mpb_fuel_limit: MPB_FUEL_LIMIT_V1,
            policy_bytecode: policy.bytecode,
            policy_variables,
            state_preimage,
            candidates_preimages,
        })
    }

    pub fn attest(
        &self,
        token: &DecisionToken,
        decision: &Decision,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<ProofBundle> {
        validate_embedded_methods(self.guest_elf, self.image_id)?;
        let input = self.prepare_input(token, state, candidates)?;

        let env = ExecutorEnv::builder()
            .write(&input)
            .map_err(|e| MprdError::ZkError(format!("Failed to write input: {}", e)))?
            .build()
            .map_err(|e| MprdError::ZkError(format!("Failed to build env: {}", e)))?;

        let prover = default_prover();
        let prove_info = prover
            .prove(env, self.guest_elf)
            .map_err(|e| MprdError::ZkError(format!("Proving failed: {}", e)))?;
        let receipt = prove_info.receipt;

        let receipt_bytes = bincode::serialize(&receipt)
            .map_err(|e| MprdError::ZkError(format!("Failed to serialize receipt: {}", e)))?;

        let journal: GuestJournalV3 = receipt
            .journal
            .decode()
            .map_err(|e| MprdError::ZkError(format!("Failed to decode journal: {}", e)))?;

        if journal.journal_version != JOURNAL_VERSION {
            return Err(MprdError::ZkError(format!(
                "Unsupported journal_version {}; expected {}",
                journal.journal_version, JOURNAL_VERSION
            )));
        }

        if journal.policy_exec_kind_id != policy_exec_kind_mpb_id_v1()
            || journal.policy_exec_version_id != policy_exec_version_id_v1()
        {
            return Err(MprdError::ZkError(
                "Unsupported policy_exec_kind/version".into(),
            ));
        }

        if journal.state_encoding_id != state_encoding_id_v1()
            || journal.action_encoding_id != action_encoding_id_v1()
        {
            return Err(MprdError::ZkError("Unsupported encoding_id".into()));
        }

        if journal.limits_hash != limits_hash_mpb_v1() {
            return Err(MprdError::ZkError("limits_hash mismatch".into()));
        }

        let expected_commitment = compute_decision_commitment_v3(&journal);
        if journal.decision_commitment != expected_commitment {
            return Err(MprdError::ZkError("decision_commitment mismatch".into()));
        }

        // Bind state provenance context (fail closed).
        if Hash32(journal.state_source_id) != token.state_ref.state_source_id {
            return Err(MprdError::ZkError("state_source_id mismatch".into()));
        }
        if journal.state_epoch != token.state_ref.state_epoch {
            return Err(MprdError::ZkError("state_epoch mismatch".into()));
        }
        if Hash32(journal.state_attestation_hash) != token.state_ref.state_attestation_hash {
            return Err(MprdError::ZkError("state_attestation_hash mismatch".into()));
        }

        if !journal.allowed {
            return Err(MprdError::ZkError(
                "Guest reported selector contract not satisfied".into(),
            ));
        }

        // Bind journal commitments to the token/decision/proof.
        if Hash32(journal.policy_hash) != token.policy_hash {
            return Err(MprdError::ZkError("Policy hash mismatch".into()));
        }
        if journal.policy_epoch != token.policy_ref.policy_epoch {
            return Err(MprdError::ZkError("policy_epoch mismatch".into()));
        }
        if Hash32(journal.registry_root) != token.policy_ref.registry_root {
            return Err(MprdError::ZkError("registry_root mismatch".into()));
        }
        if Hash32(journal.state_hash) != token.state_hash {
            return Err(MprdError::ZkError("State hash mismatch".into()));
        }
        if Hash32(journal.chosen_action_hash) != token.chosen_action_hash {
            return Err(MprdError::ZkError("Chosen action hash mismatch".into()));
        }
        if Hash32(journal.nonce_or_tx_hash) != token.nonce_or_tx_hash {
            return Err(MprdError::ZkError("nonce_or_tx_hash mismatch".into()));
        }
        if Hash32(journal.chosen_action_hash) != decision.chosen_action.candidate_hash {
            return Err(MprdError::ZkError(
                "chosen_action_hash mismatch vs decision".into(),
            ));
        }

        let mut metadata = HashMap::new();
        metadata.insert("zk_backend".into(), "risc0".into());
        metadata.insert("image_id".into(), hex::encode(self.image_id));
        metadata.insert(
            "journal_version".into(),
            journal.journal_version.to_string(),
        );
        metadata.insert(
            "policy_exec_kind_id".into(),
            hex::encode(journal.policy_exec_kind_id),
        );
        metadata.insert(
            "policy_exec_version_id".into(),
            hex::encode(journal.policy_exec_version_id),
        );

        let chosen_index: usize = journal
            .chosen_index
            .try_into()
            .map_err(|_| MprdError::ZkError("journal chosen_index out of range".into()))?;
        let chosen_action_preimage = input
            .candidates_preimages
            .get(chosen_index)
            .cloned()
            .ok_or_else(|| {
                MprdError::ZkError("journal chosen_index out of range for witness".into())
            })?;

        Ok(ProofBundle {
            policy_hash: Hash32(journal.policy_hash),
            state_hash: Hash32(journal.state_hash),
            candidate_set_hash: Hash32(journal.candidate_set_hash),
            chosen_action_hash: Hash32(journal.chosen_action_hash),
            limits_hash: Hash32(journal.limits_hash),
            limits_bytes: limits_bytes_mpb_v1().to_vec(),
            // Derive the action bytes from the guest-committed selection, not from host-side selection.
            chosen_action_preimage,
            risc0_receipt: receipt_bytes,
            attestation_metadata: metadata,
        })
    }
}

// =============================================================================
// Risc0 Verifier
// =============================================================================

/// Risc0 verifier for cryptographic proof verification.
///
/// # Security
///
/// The verifier checks:
/// 1. The proof is valid for the claimed image ID
/// 2. The journal (public output) matches expected values
/// 3. The selector contract was satisfied according to the guest
pub struct Risc0Verifier {
    image_id: [u8; 32],
    expected_policy_exec_kind_id: [u8; 32],
    expected_policy_exec_version_id: [u8; 32],
}

impl Risc0Verifier {
    /// Create a new verifier with the expected image ID.
    pub fn new(
        image_id: [u8; 32],
        expected_policy_exec_kind_id: [u8; 32],
        expected_policy_exec_version_id: [u8; 32],
    ) -> Self {
        Self {
            image_id,
            expected_policy_exec_kind_id,
            expected_policy_exec_version_id,
        }
    }

    pub fn host_trusted_v0(image_id: [u8; 32]) -> Self {
        Self::new(
            image_id,
            policy_exec_kind_host_trusted_id_v0(),
            policy_exec_version_id_v1(),
        )
    }

    pub fn mpb_v1(image_id: [u8; 32]) -> Self {
        Self::new(
            image_id,
            policy_exec_kind_mpb_id_v1(),
            policy_exec_version_id_v1(),
        )
    }

    pub(crate) fn verify_decoded_journal(
        &self,
        token: &DecisionToken,
        proof: &ProofBundle,
        journal: &GuestJournalV3,
    ) -> VerificationStatus {
        self.verify_decoded_journal_inner(token, proof, journal)
    }

    #[cfg(any(test, feature = "fuzz-utils"))]
    pub fn verify_decoded_journal_fuzz(
        &self,
        token: &DecisionToken,
        proof: &ProofBundle,
        journal: &GuestJournalV3,
    ) -> VerificationStatus {
        self.verify_decoded_journal_inner(token, proof, journal)
    }

    fn verify_decoded_journal_inner(
        &self,
        token: &DecisionToken,
        proof: &ProofBundle,
        journal: &GuestJournalV3,
    ) -> VerificationStatus {
        if journal.journal_version != JOURNAL_VERSION {
            return VerificationStatus::Failure(format!(
                "Unsupported journal_version {}; expected {}",
                journal.journal_version, JOURNAL_VERSION
            ));
        }

        // Allowlist checks (fail closed)
        if journal.state_encoding_id != state_encoding_id_v1()
            || journal.action_encoding_id != action_encoding_id_v1()
        {
            return VerificationStatus::Failure("Unsupported encoding_id".into());
        }

        if journal.policy_exec_kind_id != self.expected_policy_exec_kind_id
            || journal.policy_exec_version_id != self.expected_policy_exec_version_id
        {
            return VerificationStatus::Failure("Unsupported policy_exec_kind/version".into());
        }

        // Verify decision commitment binds the transcript
        let expected_commitment = compute_decision_commitment_v3(journal);
        if journal.decision_commitment != expected_commitment {
            return VerificationStatus::Failure("decision_commitment mismatch".into());
        }

        // Verify hash consistency with token/proof
        if Hash32(journal.policy_hash) != token.policy_hash {
            return VerificationStatus::Failure("Policy hash mismatch".into());
        }
        if journal.policy_epoch != token.policy_ref.policy_epoch {
            return VerificationStatus::Failure("policy_epoch mismatch".into());
        }
        if Hash32(journal.registry_root) != token.policy_ref.registry_root {
            return VerificationStatus::Failure("registry_root mismatch".into());
        }

        if Hash32(journal.state_source_id) != token.state_ref.state_source_id {
            return VerificationStatus::Failure("state_source_id mismatch".into());
        }
        if journal.state_epoch != token.state_ref.state_epoch {
            return VerificationStatus::Failure("state_epoch mismatch".into());
        }
        if Hash32(journal.state_attestation_hash) != token.state_ref.state_attestation_hash {
            return VerificationStatus::Failure("state_attestation_hash mismatch".into());
        }

        if Hash32(journal.state_hash) != token.state_hash {
            return VerificationStatus::Failure("State hash mismatch".into());
        }

        if Hash32(journal.chosen_action_hash) != token.chosen_action_hash {
            return VerificationStatus::Failure("Chosen action hash mismatch".into());
        }

        if Hash32(journal.candidate_set_hash) != proof.candidate_set_hash {
            return VerificationStatus::Failure("Candidate set hash mismatch".into());
        }

        // Bind nonce / anti-replay into the proof statement
        if Hash32(journal.nonce_or_tx_hash) != token.nonce_or_tx_hash {
            return VerificationStatus::Failure("nonce_or_tx_hash mismatch".into());
        }

        // Enforce deterministic limits hash (fail closed).
        // - host_trusted_v0 commits empty limits (transitional).
        // - mpb_v1 pins fuel semantics via `limits_hash_mpb_v1()`.
        let expected_limits_hash =
            if self.expected_policy_exec_kind_id == policy_exec_kind_mpb_id_v1() {
                limits_hash_mpb_v1()
            } else {
                limits_hash(&[])
            };
        if journal.limits_hash != expected_limits_hash {
            return VerificationStatus::Failure("limits_hash mismatch".into());
        }
        if proof.limits_hash != Hash32(journal.limits_hash) {
            return VerificationStatus::Failure("limits_hash mismatch vs proof".into());
        }
        if Hash32(limits_hash(&proof.limits_bytes)) != proof.limits_hash {
            return VerificationStatus::Failure("limits_bytes hash mismatch".into());
        }
        if self.expected_policy_exec_kind_id == policy_exec_kind_mpb_id_v1()
            && proof.limits_bytes != limits_bytes_mpb_v1().to_vec()
        {
            return VerificationStatus::Failure("limits_bytes mismatch for mpb_v1".into());
        }

        // Verify selector contract was satisfied
        if !journal.allowed {
            return VerificationStatus::Failure(
                "Selector contract not satisfied - action not allowed".into(),
            );
        }

        VerificationStatus::Success
    }
}

impl ZkLocalVerifier for Risc0Verifier {
    fn verify(&self, token: &DecisionToken, proof: &ProofBundle) -> VerificationStatus {
        // Fail-closed binding between token and proof bundle.
        if token.policy_hash != proof.policy_hash {
            return VerificationStatus::Failure("policy_hash mismatch".into());
        }
        if token.state_hash != proof.state_hash {
            return VerificationStatus::Failure("state_hash mismatch".into());
        }
        if token.chosen_action_hash != proof.chosen_action_hash {
            return VerificationStatus::Failure("chosen_action_hash mismatch".into());
        }

        if self.image_id == [0u8; 32] {
            return VerificationStatus::Failure(
                "Invalid (all-zero) image_id: refusing verification to avoid accepting proofs for an unspecified guest".into(),
            );
        }

        // Deserialize the receipt (bounded to prevent DoS)
        let receipt: Receipt = match crate::bounded_deser::deserialize_receipt(&proof.risc0_receipt)
        {
            Ok(r) => r,
            Err(e) => {
                return VerificationStatus::Failure(format!("Failed to deserialize receipt: {}", e))
            }
        };

        // Convert image_id to Risc0 Digest format
        let image_id = risc0_zkvm::sha::Digest::from_bytes(self.image_id);

        // Cryptographically verify the receipt against the image ID
        if let Err(e) = receipt.verify(image_id) {
            return VerificationStatus::Failure(format!("Receipt verification failed: {}", e));
        }

        // Decode the journal to get the guest output
        let journal: GuestJournalV3 = match receipt.journal.decode() {
            Ok(o) => o,
            Err(e) => {
                return VerificationStatus::Failure(format!("Failed to decode journal: {}", e))
            }
        };

        self.verify_decoded_journal(token, proof, &journal)
    }
}

// =============================================================================
// Factory Functions
// =============================================================================

/// Create a Risc0 attestor with the guest ELF.
pub fn create_risc0_attestor(guest_elf: &'static [u8], image_id: [u8; 32]) -> Risc0Attestor {
    Risc0Attestor::new(guest_elf, image_id)
}

/// Create a Risc0 verifier.
pub fn create_risc0_verifier(image_id: [u8; 32]) -> Risc0Verifier {
    Risc0Verifier::host_trusted_v0(image_id)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use mprd_core::hash::{hash_candidate, hash_state};
    use mprd_core::PolicyRef;
    use mprd_core::Score;
    use mprd_generators::{decoded_mpb_v1_fixture, DeterministicGen, GenSeed};

    fn dummy_hash(b: u8) -> Hash32 {
        Hash32([b; 32])
    }

    fn dummy_policy_ref() -> PolicyRef {
        PolicyRef {
            policy_epoch: 1,
            registry_root: dummy_hash(99),
        }
    }

    #[test]
    fn guest_input_validation_rejects_out_of_bounds() {
        let attestor = Risc0Attestor::new(&[], [0u8; 32]);

        let mut state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(4),
            state_ref: mprd_core::StateRef::unknown(),
        };
        state.state_hash = hash_state(&state);

        let decision = Decision {
            chosen_index: 5, // Out of bounds!
            chosen_action: CandidateAction {
                action_type: "TEST".into(),
                params: HashMap::new(),
                score: Score(100),
                candidate_hash: dummy_hash(1),
            },
            policy_hash: dummy_hash(2),
            decision_commitment: dummy_hash(3),
        };

        let candidates = vec![decision.chosen_action.clone()]; // Only 1 candidate
        let token = DecisionToken {
            policy_hash: decision.policy_hash.clone(),
            policy_ref: dummy_policy_ref(),
            state_hash: state.state_hash.clone(),
            state_ref: state.state_ref.clone(),
            chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
            nonce_or_tx_hash: dummy_hash(9),
            timestamp_ms: 0,
            signature: vec![],
        };
        let verdict = RuleVerdict {
            allowed: true,
            reasons: vec![],
            limits: HashMap::new(),
        };

        let result = attestor.prepare_input(&token, &decision, &state, &candidates, &verdict);
        assert!(result.is_err());
    }

    #[test]
    fn guest_input_uses_actual_verdict() {
        let attestor = Risc0Attestor::new(&[], [0u8; 32]);

        let mut state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(4),
            state_ref: mprd_core::StateRef::unknown(),
        };
        state.state_hash = hash_state(&state);

        let mut chosen = CandidateAction {
            action_type: "TEST".into(),
            params: HashMap::new(),
            score: Score(100),
            candidate_hash: dummy_hash(1),
        };
        chosen.candidate_hash = hash_candidate(&chosen);

        let decision = Decision {
            chosen_index: 0,
            chosen_action: chosen,
            policy_hash: dummy_hash(2),
            decision_commitment: dummy_hash(3),
        };

        let candidates = vec![decision.chosen_action.clone()];
        let token = DecisionToken {
            policy_hash: decision.policy_hash.clone(),
            policy_ref: dummy_policy_ref(),
            state_hash: state.state_hash.clone(),
            state_ref: state.state_ref.clone(),
            chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
            nonce_or_tx_hash: dummy_hash(9),
            timestamp_ms: 0,
            signature: vec![],
        };

        // Test with allowed=true
        let verdict_allowed = RuleVerdict {
            allowed: true,
            reasons: vec![],
            limits: HashMap::new(),
        };
        let input = attestor
            .prepare_input(&token, &decision, &state, &candidates, &verdict_allowed)
            .unwrap();
        assert!(input.chosen_verdict_allowed);

        // Test with allowed=false
        let verdict_denied = RuleVerdict {
            allowed: false,
            reasons: vec!["denied".into()],
            limits: HashMap::new(),
        };
        let input = attestor
            .prepare_input(&token, &decision, &state, &candidates, &verdict_denied)
            .unwrap();
        assert!(!input.chosen_verdict_allowed);
    }

    #[test]
    fn sha256_is_deterministic() {
        let data = b"test bytes";
        assert_eq!(
            mprd_risc0_shared::sha256(data),
            mprd_risc0_shared::sha256(data)
        );
    }

    #[test]
    fn attest_with_verdict_fails_closed_when_methods_not_embedded() {
        let attestor = Risc0Attestor::new(&[], [0u8; 32]);

        let mut state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(4),
            state_ref: mprd_core::StateRef::unknown(),
        };
        state.state_hash = hash_state(&state);

        let decision = Decision {
            chosen_index: 0,
            chosen_action: CandidateAction {
                action_type: "TEST".into(),
                params: HashMap::new(),
                score: Score(100),
                candidate_hash: dummy_hash(1),
            },
            policy_hash: dummy_hash(2),
            decision_commitment: dummy_hash(3),
        };

        let candidates = vec![decision.chosen_action.clone()];
        let verdict = RuleVerdict {
            allowed: true,
            reasons: vec![],
            limits: HashMap::new(),
        };

        let token = DecisionToken {
            policy_hash: decision.policy_hash.clone(),
            policy_ref: dummy_policy_ref(),
            state_hash: state.state_hash.clone(),
            state_ref: state.state_ref.clone(),
            chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
            nonce_or_tx_hash: dummy_hash(9),
            timestamp_ms: 0,
            signature: vec![],
        };

        let err = attestor
            .attest_with_verdict(&token, &decision, &state, &candidates, &verdict)
            .expect_err("should fail closed when ELF/image_id are not embedded");
        match err {
            MprdError::ZkError(msg) => assert!(msg.contains("methods not embedded")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn mpb_attestor_fails_closed_on_policy_substitution() {
        let token = DecisionToken {
            policy_hash: Hash32([9u8; 32]),
            policy_ref: dummy_policy_ref(),
            state_hash: Hash32([1u8; 32]),
            state_ref: mprd_core::StateRef::unknown(),
            chosen_action_hash: Hash32([2u8; 32]),
            nonce_or_tx_hash: Hash32([3u8; 32]),
            timestamp_ms: 0,
            signature: vec![],
        };

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: Hash32([1u8; 32]),
            state_ref: mprd_core::StateRef::unknown(),
        };

        let candidates = vec![CandidateAction {
            action_type: "A".into(),
            params: HashMap::new(),
            score: Score(1),
            candidate_hash: Hash32([2u8; 32]),
        }];

        // Provider returns a policy artifact that does NOT hash to token.policy_hash.
        let mut store: HashMap<PolicyHash, MpbPolicyArtifactV1> = HashMap::new();
        store.insert(
            token.policy_hash.clone(),
            MpbPolicyArtifactV1 {
                bytecode: vec![0xFF],
                variables: vec![],
            },
        );

        let attestor = Risc0MpbAttestor::new(
            &[],
            [0u8; 32],
            MPB_FUEL_LIMIT_V1,
            Arc::new(store) as Arc<dyn MpbPolicyProvider>,
        );

        let err = attestor
            .prepare_input(&token, &state, &candidates)
            .expect_err("policy substitution should fail closed");
        match err {
            MprdError::ZkError(msg) => {
                assert_eq!(msg, "mpb policy_hash mismatch (policy substitution)");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    fn assert_accepts(
        token: &DecisionToken,
        proof: &ProofBundle,
        journal: &GuestJournalV3,
        verifier: &Risc0Verifier,
    ) {
        assert!(matches!(
            verifier.verify_decoded_journal(token, proof, journal),
            VerificationStatus::Success
        ));
    }

    fn assert_rejects(
        token: &DecisionToken,
        proof: &ProofBundle,
        journal: &GuestJournalV3,
        verifier: &Risc0Verifier,
    ) {
        assert!(matches!(
            verifier.verify_decoded_journal(token, proof, journal),
            VerificationStatus::Failure(_)
        ));
    }

    #[test]
    fn decoded_journal_metamorphic_mutations_fail_closed() {
        let f = decoded_mpb_v1_fixture(GenSeed::from_u64(1));
        let token = f.token;
        let proof = f.proof;
        let journal = f.journal;
        let verifier = Risc0Verifier::mpb_v1([0u8; 32]);
        assert_accepts(&token, &proof, &journal, &verifier);

        // Decision commitment binding: any change without updating commitment must fail.
        let mut j = journal.clone();
        j.policy_hash = [99u8; 32];
        assert_rejects(&token, &proof, &j, &verifier);

        // Mutations with recomputed commitment must still fail for checked fields.
        let mutate_journal = |mutator: fn(&mut GuestJournalV3)| {
            let mut j = journal.clone();
            mutator(&mut j);
            j.decision_commitment = compute_decision_commitment_v3(&j);
            assert_rejects(&token, &proof, &j, &verifier);
        };

        mutate_journal(|j| j.journal_version = JOURNAL_VERSION + 1);
        mutate_journal(|j| j.state_encoding_id = [1u8; 32]);
        mutate_journal(|j| j.action_encoding_id = [2u8; 32]);
        mutate_journal(|j| j.policy_exec_kind_id = [3u8; 32]);
        mutate_journal(|j| j.policy_exec_version_id = [4u8; 32]);
        mutate_journal(|j| j.policy_hash = [5u8; 32]);
        mutate_journal(|j| j.policy_epoch += 1);
        mutate_journal(|j| j.registry_root = [6u8; 32]);
        mutate_journal(|j| j.state_source_id = [7u8; 32]);
        mutate_journal(|j| j.state_epoch += 1);
        mutate_journal(|j| j.state_attestation_hash = [8u8; 32]);
        mutate_journal(|j| j.state_hash = [9u8; 32]);
        mutate_journal(|j| j.candidate_set_hash = [10u8; 32]);
        mutate_journal(|j| j.chosen_action_hash = [11u8; 32]);
        mutate_journal(|j| j.nonce_or_tx_hash = [12u8; 32]);
        mutate_journal(|j| j.limits_hash = [13u8; 32]);
        mutate_journal(|j| j.allowed = false);

        // chosen_index is not verifier-checkable against token/proof; the commitment binding is what we can enforce.
        let mut j = journal.clone();
        j.chosen_index = 99;
        assert_rejects(&token, &proof, &j, &verifier);

        // Proof mutations must fail closed.
        let mut p = proof.clone();
        p.candidate_set_hash = dummy_hash(33);
        assert_rejects(&token, &p, &journal, &verifier);

        let mut p = proof.clone();
        p.limits_hash = dummy_hash(34);
        assert_rejects(&token, &p, &journal, &verifier);

        let mut p = proof.clone();
        p.limits_bytes = vec![0u8; 3];
        assert_rejects(&token, &p, &journal, &verifier);

        // Token mutations must fail closed.
        let mut t = token.clone();
        t.nonce_or_tx_hash = dummy_hash(35);
        assert_rejects(&t, &proof, &journal, &verifier);

        // Procedural mutations: deterministic pseudo-random mutation sweep.
        let mut gen = DeterministicGen::new(GenSeed::from_u64(2));
        for _ in 0..128 {
            let kind = gen.next_u32(b"mutation_kind") % 3;
            match kind {
                0 => {
                    let mut j = journal.clone();
                    let field = gen.next_u32(b"journal_field") % 10;
                    match field {
                        0 => j.policy_hash = gen.next_id32(b"v"),
                        1 => j.registry_root = gen.next_id32(b"v"),
                        2 => j.state_hash = gen.next_id32(b"v"),
                        3 => j.candidate_set_hash = gen.next_id32(b"v"),
                        4 => j.chosen_action_hash = gen.next_id32(b"v"),
                        5 => j.nonce_or_tx_hash = gen.next_id32(b"v"),
                        6 => j.policy_epoch = gen.next_u64(b"v"),
                        7 => j.state_epoch = gen.next_u64(b"v"),
                        8 => j.allowed = false,
                        _ => j.journal_version = JOURNAL_VERSION + 1,
                    }
                    j.decision_commitment = compute_decision_commitment_v3(&j);
                    assert_rejects(&token, &proof, &j, &verifier);
                }
                1 => {
                    let mut p = proof.clone();
                    let field = gen.next_u32(b"proof_field") % 3;
                    match field {
                        0 => p.candidate_set_hash = gen.next_hash32(b"v"),
                        1 => p.limits_hash = gen.next_hash32(b"v"),
                        _ => p.limits_bytes = gen.next_bytes(b"limits_bytes", 9),
                    }
                    assert_rejects(&token, &p, &journal, &verifier);
                }
                _ => {
                    let mut t = token.clone();
                    let field = gen.next_u32(b"token_field") % 3;
                    match field {
                        0 => t.policy_hash = gen.next_hash32(b"v"),
                        1 => t.state_hash = gen.next_hash32(b"v"),
                        _ => t.nonce_or_tx_hash = gen.next_hash32(b"v"),
                    }
                    assert_rejects(&t, &proof, &journal, &verifier);
                }
            }
        }
    }
}
