//! State struct for mprd_operator_mining_round.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub dispute_filed: u64,
    pub phase: Phase,
    pub proof_valid: u64,
    pub rewards_paid: u64,
    pub round_reward: u64,
    pub spec_satisfied: u64,
    pub submissions_count: u64,
    pub valid_count: u64,
    pub verifier_result: VerifierResult,
    pub work_hash: u64,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            phase: Phase::Open,
            submissions_count: 0,
            valid_count: 0,
            rewards_paid: 0,
            round_reward: 1000,
            work_hash: 0,
            proof_valid: 0,
            spec_satisfied: 0,
            dispute_filed: 0,
            verifier_result: VerifierResult::Inconclusive,
        }
    }
}
