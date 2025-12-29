//! State struct for mprd_proof_market_slot.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub claimer: Claimer,
    pub claimer0: Claimer,
    pub deadline: u64,
    pub deadline0: u64,
    pub deposit: u64,
    pub job_hash_present: bool,
    pub now: u64,
    pub payee: Claimer,
    pub payout: u64,
    pub phase: Phase,
    pub proof_binds_job: bool,
    pub proof_verified: bool,
    pub protocol_subsidy: u64,
    pub total_deposits: u64,
    pub total_payouts: u64,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            claimer: Claimer::P0,
            claimer0: Claimer::P0,
            deadline: 0,
            deadline0: 0,
            deposit: 0,
            job_hash_present: false,
            now: 0,
            payee: Claimer::P0,
            payout: 0,
            phase: Phase::Idle,
            proof_binds_job: false,
            proof_verified: false,
            protocol_subsidy: 0,
            total_deposits: 0,
            total_payouts: 0,
        }
    }
}
