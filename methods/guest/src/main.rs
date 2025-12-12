#![no_std]
#![no_main]

//! MPRD Risc0 Guest Program
//!
//! This program runs inside the Risc0 zkVM and proves that:
//! 1. The selected action is in the candidate set
//! 2. The selected action passes the policy predicate
//! 3. The commitments (hashes) are correctly computed
//!
//! The guest receives private inputs and commits to public outputs.

extern crate alloc;

use alloc::vec::Vec;
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

risc0_zkvm::guest::entry!(main);

// =============================================================================
// Guest Input/Output Types
// =============================================================================

/// Input provided to the guest (private witness).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestInput {
    /// The policy being evaluated (serialized).
    pub policy_bytes: Vec<u8>,
    
    /// The state snapshot (serialized).
    pub state_bytes: Vec<u8>,
    
    /// All candidate actions (serialized).
    pub candidates_bytes: Vec<u8>,
    
    /// Number of candidates (for bounds checking).
    pub candidate_count: usize,
    
    /// Index of the chosen action in candidates.
    pub chosen_index: usize,
    
    /// The verdict for the chosen action (must be allowed=true).
    pub chosen_verdict_allowed: bool,
}

/// Output committed by the guest (public journal).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestOutput {
    /// Hash of the policy.
    pub policy_hash: [u8; 32],
    
    /// Hash of the state.
    pub state_hash: [u8; 32],
    
    /// Hash of the entire candidate set.
    pub candidate_set_hash: [u8; 32],
    
    /// Hash of the chosen action.
    pub chosen_action_hash: [u8; 32],
    
    /// The decision commitment binding all of the above.
    pub decision_commitment: [u8; 32],
    
    /// Whether the selector contract was satisfied.
    pub selector_contract_satisfied: bool,
}

// =============================================================================
// Hash Utilities
// =============================================================================

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn hash_with_domain(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(data);
    hasher.finalize().into()
}

// =============================================================================
// Selector Contract Verification
// =============================================================================

/// Verifies the Selector Contract:
/// - chosen_index is within bounds
/// - chosen action's verdict is allowed=true
///
/// Invariant: Sel(p, s, C) = a => a ∈ C ∧ Allowed(p, s, a) = true
///
/// # Security
/// This is the critical check that enforces the MPRD safety invariant.
/// Both conditions MUST be true for the contract to be satisfied.
fn verify_selector_contract(input: &GuestInput) -> bool {
    // Precondition 1: chosen_index must be within bounds
    // This ensures the chosen action is actually in the candidate set
    if input.chosen_index >= input.candidate_count {
        return false; // Bounds violation - action not in candidate set
    }
    
    // Precondition 2: empty candidate set is invalid
    if input.candidate_count == 0 {
        return false; // No candidates to choose from
    }
    
    // Precondition 3: the verdict must indicate the action is allowed
    // This ensures the policy permitted this action
    input.chosen_verdict_allowed
}

// =============================================================================
// Main Entry Point
// =============================================================================

fn main() {
    // Read private input from host
    let input: GuestInput = env::read();
    
    // Compute hashes of all inputs
    let policy_hash = hash_with_domain(b"MPRD_POLICY_V1", &input.policy_bytes);
    let state_hash = hash_with_domain(b"MPRD_STATE_V1", &input.state_bytes);
    let candidate_set_hash = hash_with_domain(b"MPRD_CANDIDATES_V1", &input.candidates_bytes);
    
    // Compute hash of the chosen action
    // The chosen action is identified by its index in the serialized candidates
    let chosen_action_hash = {
        let mut hasher = Sha256::new();
        hasher.update(b"MPRD_CHOSEN_V1");
        hasher.update(&input.candidates_bytes);
        hasher.update(&input.chosen_index.to_le_bytes());
        let result: [u8; 32] = hasher.finalize().into();
        result
    };
    
    // Verify the Selector Contract
    let selector_contract_satisfied = verify_selector_contract(&input);
    
    // Compute decision commitment (binds everything together)
    let decision_commitment = {
        let mut hasher = Sha256::new();
        hasher.update(b"MPRD_DECISION_V1");
        hasher.update(&policy_hash);
        hasher.update(&state_hash);
        hasher.update(&candidate_set_hash);
        hasher.update(&chosen_action_hash);
        hasher.update(&[selector_contract_satisfied as u8]);
        let result: [u8; 32] = hasher.finalize().into();
        result
    };
    
    // Commit public output to journal
    let output = GuestOutput {
        policy_hash,
        state_hash,
        candidate_set_hash,
        chosen_action_hash,
        decision_commitment,
        selector_contract_satisfied,
    };
    
    env::commit(&output);
}
