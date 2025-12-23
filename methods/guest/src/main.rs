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

use mprd_risc0_shared::{
    compute_decision_commitment_v3, hash_candidate_preimage_v1, hash_candidate_set_preimage_v1,
    hash_state_preimage_v1, limits_hash, GuestInputV3, GuestJournalV3, JOURNAL_VERSION,
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

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
fn parse_candidate_count(candidate_set_preimage: &[u8]) -> Option<u32> {
    let len_bytes: [u8; 4] = candidate_set_preimage.get(0..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(len_bytes))
}

fn candidate_hash_at_index(candidate_set_preimage: &[u8], index: u32) -> Option<[u8; 32]> {
    let count = parse_candidate_count(candidate_set_preimage)?;
    if count == 0 || index >= count {
        return None;
    }

    let start = 4usize + (index as usize) * 32usize;
    let end = start.checked_add(32)?;
    let bytes: [u8; 32] = candidate_set_preimage.get(start..end)?.try_into().ok()?;

    let expected_len = 4usize + (count as usize) * 32usize;
    if candidate_set_preimage.len() != expected_len {
        return None;
    }

    Some(bytes)
}

fn verify_selector_contract(input: &GuestInputV3, chosen_action_hash: [u8; 32]) -> bool {
    candidate_hash_at_index(&input.candidate_set_preimage, input.chosen_index)
        .is_some_and(|expected| expected == chosen_action_hash)
}

// =============================================================================
// Main Entry Point
// =============================================================================

fn main() {
    // Read private input from host
    let input: GuestInputV3 = env::read();

    // Commitments derived from canonical preimage bytes.
    // NOTE: Must match `mprd-core` canonical hashing (domain-separated).
    let state_hash = hash_state_preimage_v1(&input.state_preimage);
    let candidate_set_hash = hash_candidate_set_preimage_v1(&input.candidate_set_preimage);
    let chosen_action_hash = hash_candidate_preimage_v1(&input.chosen_action_preimage);
    let limits_hash = limits_hash(&input.limits_bytes);

    // Selector contract verification (interim).
    // TODO(B): replace host-provided `chosen_verdict_allowed` with in-guest policy evaluation + selection.
    let allowed = input.chosen_verdict_allowed && verify_selector_contract(&input, chosen_action_hash);

    let mut journal = GuestJournalV3 {
        journal_version: JOURNAL_VERSION,
        policy_hash: input.policy_hash,
        policy_exec_kind_id: input.policy_exec_kind_id,
        policy_exec_version_id: input.policy_exec_version_id,
        state_encoding_id: input.state_encoding_id,
        action_encoding_id: input.action_encoding_id,
        policy_epoch: input.policy_epoch,
        registry_root: input.registry_root,
        state_source_id: input.state_source_id,
        state_epoch: input.state_epoch,
        state_attestation_hash: input.state_attestation_hash,
        state_hash,
        candidate_set_hash,
        chosen_action_hash,
        limits_hash,
        nonce_or_tx_hash: input.nonce_or_tx_hash,
        chosen_index: input.chosen_index,
        allowed,
        decision_commitment: [0u8; 32],
    };

    journal.decision_commitment = compute_decision_commitment_v3(&journal);
    env::commit(&journal);
}
