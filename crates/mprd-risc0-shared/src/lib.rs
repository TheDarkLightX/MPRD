//! Shared types between MPRD Risc0 guest and host.
//!
//! These types define the interface for ZK proof generation and verification.

use serde::{Deserialize, Serialize};

/// Input provided to the Risc0 guest (private witness).
///
/// Preconditions:
/// - All byte arrays are valid serialized representations
/// - chosen_index is within bounds of the candidate set
/// - chosen_verdict_allowed accurately reflects policy evaluation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestInput {
    /// The policy being evaluated (serialized).
    pub policy_bytes: Vec<u8>,
    
    /// The state snapshot (serialized).
    pub state_bytes: Vec<u8>,
    
    /// All candidate actions (serialized).
    pub candidates_bytes: Vec<u8>,
    
    /// Index of the chosen action in candidates.
    pub chosen_index: usize,
    
    /// The verdict for the chosen action (must be allowed=true).
    pub chosen_verdict_allowed: bool,
}

/// Output committed by the Risc0 guest (public journal).
///
/// Postconditions:
/// - All hashes are correctly computed from the private inputs
/// - selector_contract_satisfied is true iff the invariant holds
/// - decision_commitment binds all other fields cryptographically
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
    /// 
    /// Invariant: This is true iff:
    /// - chosen_index is within bounds
    /// - Allowed(policy, state, candidates[chosen_index]) = true
    pub selector_contract_satisfied: bool,
}

/// Domain separation constants for hashing.
pub mod domains {
    pub const POLICY: &[u8] = b"MPRD_POLICY_V1";
    pub const STATE: &[u8] = b"MPRD_STATE_V1";
    pub const CANDIDATES: &[u8] = b"MPRD_CANDIDATES_V1";
    pub const CHOSEN: &[u8] = b"MPRD_CHOSEN_V1";
    pub const DECISION: &[u8] = b"MPRD_DECISION_V1";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_input_serializes() {
        let input = GuestInput {
            policy_bytes: vec![1, 2, 3],
            state_bytes: vec![4, 5, 6],
            candidates_bytes: vec![7, 8, 9],
            chosen_index: 0,
            chosen_verdict_allowed: true,
        };
        
        let serialized = bincode::serialize(&input).unwrap();
        let deserialized: GuestInput = bincode::deserialize(&serialized).unwrap();
        
        assert_eq!(input.chosen_index, deserialized.chosen_index);
    }
}
