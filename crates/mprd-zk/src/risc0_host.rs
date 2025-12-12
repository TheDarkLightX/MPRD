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
    CandidateAction, Decision, DecisionToken, Hash32, MprdError, ProofBundle,
    RuleVerdict, Result, StateSnapshot, VerificationStatus, ZkAttestor, ZkLocalVerifier,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

// =============================================================================
// Configuration
// =============================================================================

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
// Guest I/O Types
// =============================================================================

/// Input to the guest program.
///
/// # Invariants
/// - `chosen_index < candidate_count`
/// - `chosen_verdict_allowed` reflects actual policy evaluation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestInput {
    pub policy_bytes: Vec<u8>,
    pub state_bytes: Vec<u8>,
    pub candidates_bytes: Vec<u8>,
    pub candidate_count: usize,
    pub chosen_index: usize,
    pub chosen_verdict_allowed: bool,
}

/// Output from the guest program (committed to journal).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestOutput {
    pub policy_hash: [u8; 32],
    pub state_hash: [u8; 32],
    pub candidate_set_hash: [u8; 32],
    pub chosen_action_hash: [u8; 32],
    pub decision_commitment: [u8; 32],
    pub selector_contract_satisfied: bool,
}

// =============================================================================
// Hash Utilities (must match guest)
// =============================================================================

fn hash_with_domain(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute expected hashes on the host side for verification.
pub fn compute_expected_hashes(
    policy_bytes: &[u8],
    state_bytes: &[u8],
    candidates_bytes: &[u8],
    chosen_index: usize,
) -> (Hash32, Hash32, Hash32, Hash32) {
    let policy_hash = Hash32(hash_with_domain(b"MPRD_POLICY_V1", policy_bytes));
    let state_hash = Hash32(hash_with_domain(b"MPRD_STATE_V1", state_bytes));
    let candidate_set_hash = Hash32(hash_with_domain(b"MPRD_CANDIDATES_V1", candidates_bytes));
    
    let chosen_action_hash = {
        let mut hasher = Sha256::new();
        hasher.update(b"MPRD_CHOSEN_V1");
        hasher.update(candidates_bytes);
        hasher.update(&chosen_index.to_le_bytes());
        Hash32(hasher.finalize().into())
    };
    
    (policy_hash, state_hash, candidate_set_hash, chosen_action_hash)
}

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
/// let proof = attestor.attest(&decision, &state, &candidates, &verdict)?;
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
        Self { guest_elf, image_id }
    }
    
    /// Prepare guest input from MPRD types.
    ///
    /// # Preconditions
    /// - `decision.chosen_index < candidates.len()`
    /// - `verdict.allowed` reflects policy evaluation result
    fn prepare_input(
        &self,
        decision: &Decision,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
        verdict: &RuleVerdict,
    ) -> Result<GuestInput> {
        // Validate bounds
        if decision.chosen_index >= candidates.len() {
            return Err(MprdError::InvalidInput(format!(
                "chosen_index {} out of bounds for {} candidates",
                decision.chosen_index, candidates.len()
            )));
        }
        
        // Serialize policy
        let policy_bytes = decision.policy_hash.0.to_vec();
        
        // Serialize state
        let state_bytes = serde_json::to_vec(&state.fields)
            .map_err(|e| MprdError::ZkError(format!("Failed to serialize state: {}", e)))?;
        
        // Serialize candidates
        let candidates_bytes = serde_json::to_vec(&candidates.iter().map(|c| {
            (&c.action_type, &c.params, c.score.0)
        }).collect::<Vec<_>>())
            .map_err(|e| MprdError::ZkError(format!("Failed to serialize candidates: {}", e)))?;
        
        Ok(GuestInput {
            policy_bytes,
            state_bytes,
            candidates_bytes,
            candidate_count: candidates.len(),
            chosen_index: decision.chosen_index,
            chosen_verdict_allowed: verdict.allowed, // Use actual verdict, not hardcoded
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
        decision: &Decision,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
        verdict: &RuleVerdict,
    ) -> Result<ProofBundle> {
        let input = self.prepare_input(decision, state, candidates, verdict)?;
        
        // Build execution environment with input
        let env = ExecutorEnv::builder()
            .write(&input)
            .map_err(|e| MprdError::ZkError(format!("Failed to write input: {}", e)))?
            .build()
            .map_err(|e| MprdError::ZkError(format!("Failed to build env: {}", e)))?;
        
        // Create prover and generate proof
        let prover = default_prover();
        let prove_info = prover.prove(env, self.guest_elf)
            .map_err(|e| MprdError::ZkError(format!("Proving failed: {}", e)))?;
        
        let receipt = prove_info.receipt;
        
        // Serialize receipt for storage
        let receipt_bytes = bincode::serialize(&receipt)
            .map_err(|e| MprdError::ZkError(format!("Failed to serialize receipt: {}", e)))?;
        
        // Extract journal output
        let output: GuestOutput = receipt.journal.decode()
            .map_err(|e| MprdError::ZkError(format!("Failed to decode journal: {}", e)))?;
        
        // Verify the selector contract was satisfied
        if !output.selector_contract_satisfied {
            return Err(MprdError::ZkError(
                "Guest reported selector contract not satisfied".into()
            ));
        }
        
        let mut metadata = HashMap::new();
        metadata.insert("zk_backend".into(), "risc0".into());
        metadata.insert("image_id".into(), hex::encode(self.image_id));
        metadata.insert("version".into(), "1.2.0".into());
        metadata.insert("receipt_size".into(), receipt_bytes.len().to_string());
        
        Ok(ProofBundle {
            policy_hash: Hash32(output.policy_hash),
            state_hash: Hash32(output.state_hash),
            candidate_set_hash: Hash32(output.candidate_set_hash),
            chosen_action_hash: Hash32(output.chosen_action_hash),
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
}

impl Risc0Verifier {
    /// Create a new verifier with the expected image ID.
    pub fn new(image_id: [u8; 32]) -> Self {
        Self { image_id }
    }
}

impl ZkLocalVerifier for Risc0Verifier {
    fn verify(&self, token: &DecisionToken, proof: &ProofBundle) -> VerificationStatus {
        // Deserialize the receipt
        let receipt: Receipt = match bincode::deserialize(&proof.risc0_receipt) {
            Ok(r) => r,
            Err(e) => return VerificationStatus::Failure(
                format!("Failed to deserialize receipt: {}", e)
            ),
        };
        
        // Convert image_id to Risc0 Digest format
        let image_id = risc0_zkvm::sha::Digest::from_bytes(self.image_id);
        
        // Cryptographically verify the receipt against the image ID
        if let Err(e) = receipt.verify(image_id) {
            return VerificationStatus::Failure(
                format!("Receipt verification failed: {}", e)
            );
        }
        
        // Decode the journal to get the guest output
        let output: GuestOutput = match receipt.journal.decode() {
            Ok(o) => o,
            Err(e) => return VerificationStatus::Failure(
                format!("Failed to decode journal: {}", e)
            ),
        };
        
        // Verify hash consistency with token
        if Hash32(output.policy_hash) != token.policy_hash {
            return VerificationStatus::Failure("Policy hash mismatch".into());
        }
        
        if Hash32(output.state_hash) != token.state_hash {
            return VerificationStatus::Failure("State hash mismatch".into());
        }
        
        if Hash32(output.chosen_action_hash) != token.chosen_action_hash {
            return VerificationStatus::Failure("Chosen action hash mismatch".into());
        }
        
        // Verify selector contract was satisfied
        if !output.selector_contract_satisfied {
            return VerificationStatus::Failure(
                "Selector contract not satisfied - action not allowed".into()
            );
        }
        
        VerificationStatus::Success
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
    Risc0Verifier::new(image_id)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use mprd_core::Score;
    
    fn dummy_hash(b: u8) -> Hash32 {
        Hash32([b; 32])
    }
    
    #[test]
    fn guest_input_validation_rejects_out_of_bounds() {
        let attestor = Risc0Attestor::new(&[], [0u8; 32]);
        
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
        
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(4),
        };
        
        let candidates = vec![decision.chosen_action.clone()]; // Only 1 candidate
        let verdict = RuleVerdict {
            allowed: true,
            reasons: vec![],
            limits: HashMap::new(),
        };
        
        let result = attestor.prepare_input(&decision, &state, &candidates, &verdict);
        assert!(result.is_err());
    }
    
    #[test]
    fn guest_input_uses_actual_verdict() {
        let attestor = Risc0Attestor::new(&[], [0u8; 32]);
        
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
        
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(4),
        };
        
        let candidates = vec![decision.chosen_action.clone()];
        
        // Test with allowed=true
        let verdict_allowed = RuleVerdict {
            allowed: true,
            reasons: vec![],
            limits: HashMap::new(),
        };
        let input = attestor.prepare_input(&decision, &state, &candidates, &verdict_allowed).unwrap();
        assert!(input.chosen_verdict_allowed);
        
        // Test with allowed=false
        let verdict_denied = RuleVerdict {
            allowed: false,
            reasons: vec!["denied".into()],
            limits: HashMap::new(),
        };
        let input = attestor.prepare_input(&decision, &state, &candidates, &verdict_denied).unwrap();
        assert!(!input.chosen_verdict_allowed);
    }
    
    #[test]
    fn hash_computation_is_deterministic() {
        let policy = b"test policy";
        let state = b"test state";
        let candidates = b"test candidates";
        
        let (h1, h2, h3, h4) = compute_expected_hashes(policy, state, candidates, 0);
        let (h1b, h2b, h3b, h4b) = compute_expected_hashes(policy, state, candidates, 0);
        
        assert_eq!(h1, h1b);
        assert_eq!(h2, h2b);
        assert_eq!(h3, h3b);
        assert_eq!(h4, h4b);
    }
}
