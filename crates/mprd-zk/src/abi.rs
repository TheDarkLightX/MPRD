//! Shared ABI types between the MPRD host and the Risc0 guest.
//!
//! This must remain in sync with `internal/specs/risc0_guest_abi.md` and the
//! actual `governor_guest` implementation.
//!
//! ## Architecture
//!
//! ```text
//! Host (mprd-zk)                    Guest (governor_guest)
//! ================                  ======================
//!
//! GovernorInput ──────────────────▶ Read public inputs
//!                                        │
//! GovernorWitness ─────────────────▶ Read witness (private)
//!                                        │
//!                                   Verify: H(state) == state_hash
//!                                   Verify: H(candidates) == candidate_set_hash
//!                                        │
//!                                   Re-evaluate policy (Tau logic)
//!                                   Re-run selector (deterministic)
//!                                        │
//!                                   Verify: H(chosen) == chosen_action_hash
//!                                        │
//! GovernorJournal ◀──────────────── Write journal (public outputs)
//! ```

use serde::{Deserialize, Serialize};

/// Public inputs to the governor guest program.
///
/// These are committed to in the Risc0 receipt and verifiable externally.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernorInput {
    /// Hash of the Tau policy used for this decision.
    pub policy_hash: [u8; 32],

    /// Commitment to the normalized state snapshot.
    pub state_hash: [u8; 32],

    /// Commitment to the full candidate list.
    pub candidate_set_hash: [u8; 32],

    /// Hash of the chosen action (from the selector).
    pub chosen_action_hash: [u8; 32],

    /// Nonce or transaction hash for anti-replay.
    pub nonce_or_tx_hash: [u8; 32],
}

/// Private witness data passed to the guest.
///
/// This data is NOT included in the public journal, only used internally.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernorWitness {
    /// Serialized state snapshot (canonical encoding).
    pub state_bytes: Vec<u8>,

    /// Serialized candidates (canonical encoding).
    pub candidates_bytes: Vec<u8>,

    /// Tau policy representation (content or compiled form).
    pub policy_content: Vec<u8>,

    /// Chosen index from the selector (for verification).
    pub chosen_index: u32,
}

/// Journal output from the governor guest.
///
/// Written to the Risc0 journal as public outputs, verifiable by anyone.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernorJournal {
    /// Echo of policy_hash for binding.
    pub policy_hash: [u8; 32],

    /// Echo of state_hash for binding.
    pub state_hash: [u8; 32],

    /// Echo of candidate_set_hash for binding.
    pub candidate_set_hash: [u8; 32],

    /// Echo of chosen_action_hash for binding.
    pub chosen_action_hash: [u8; 32],

    /// Chosen index in the candidate set.
    pub chosen_index: u32,

    /// Whether the chosen action was allowed by the policy.
    pub allowed: bool,
}

impl GovernorJournal {
    /// Verify that journal matches the original input.
    pub fn matches_input(&self, input: &GovernorInput) -> bool {
        self.policy_hash == input.policy_hash
            && self.state_hash == input.state_hash
            && self.candidate_set_hash == input.candidate_set_hash
            && self.chosen_action_hash == input.chosen_action_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_matches_input_when_equal() {
        let input = GovernorInput {
            policy_hash: [1u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            nonce_or_tx_hash: [5u8; 32],
        };

        let journal = GovernorJournal {
            policy_hash: [1u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            chosen_index: 0,
            allowed: true,
        };

        assert!(journal.matches_input(&input));
    }

    #[test]
    fn journal_mismatch_when_hash_differs() {
        let input = GovernorInput {
            policy_hash: [1u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            nonce_or_tx_hash: [5u8; 32],
        };

        let journal = GovernorJournal {
            policy_hash: [99u8; 32], // Different!
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            chosen_index: 0,
            allowed: true,
        };

        assert!(!journal.matches_input(&input));
    }
}
