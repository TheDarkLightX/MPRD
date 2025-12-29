//! State struct for mprd_work_submission.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub dispute_filed: u64,
    pub phase: Phase,
    pub proof_valid: u64,
    pub spec_satisfied: u64,
    pub verifier_result: VerifierResult,
    pub work_hash: u64,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            phase: Phase::Submitted,
            work_hash: 0,
            proof_valid: 0,
            spec_satisfied: 0,
            dispute_filed: 0,
            verifier_result: VerifierResult::Inconclusive,
        }
    }
}
