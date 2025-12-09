/// Shared ABI types between the MPRD host and the Risc0 guest.
///
/// This must remain in sync with `internal/specs/risc0_guest_abi.md` and the
/// actual `governor_guest` implementation.
pub struct GovernorInput {
    pub policy_hash: [u8; 32],
    pub state_hash: [u8; 32],
    pub candidate_set_hash: [u8; 32],
    pub chosen_action_hash: [u8; 32],
    pub nonce_or_tx_hash: [u8; 32],
}
