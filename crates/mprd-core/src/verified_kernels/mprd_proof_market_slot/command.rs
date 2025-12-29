//! Commands for mprd_proof_market_slot.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Commit { deadline: u64, deposit: u64, prover: Claimer },
    Expire,
    Settle { payout: u64 },
    Slash,
    StartProving,
    Tick { dt: u64 },
}
