use crate::{Hash32, MprdError};

/// Stable identifiers for Tokenomics v6 invariants (used for testing and counterexamples).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvariantIdV6 {
    /// Engine mutated state even though the action returned `Err`.
    NoMutationOnError,

    /// Safety bounds were exceeded (unreachable state).
    BoundsRespected,

    /// Auction carry exceeded `ParamsV6::carry_cap_agrs`.
    AuctionCarryCapped,

    /// Per-operator `bcr_escrow` did not match the sum of bids for that operator.
    EscrowMatchesBids,

    /// `EpochBudgetsV6` violated conservation or internal decompositions.
    BudgetsConserve,

    /// Reward/payout conservation violated (e.g., payroll pool vs payouts).
    RewardConserve,

    /// Active shares tracking disagreed with the sum of active stakes.
    SharesActiveMatchesStakes,

    /// Active shares exceeded the monotone accumulator `total_shares_issued`.
    SharesActiveLeIssuedTotal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvariantViolationV6 {
    pub id: InvariantIdV6,
    pub details: String,
}

impl InvariantViolationV6 {
    pub fn new(id: InvariantIdV6, details: impl Into<String>) -> Self {
        Self {
            id,
            details: details.into(),
        }
    }
}

impl std::fmt::Display for InvariantViolationV6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.id, self.details)
    }
}

impl std::error::Error for InvariantViolationV6 {}

impl From<InvariantViolationV6> for MprdError {
    fn from(v: InvariantViolationV6) -> Self {
        MprdError::ExecutionError(format!("tokenomics_v6 invariant violated: {v}"))
    }
}

/// A reproducible invariant failure with a minimal action trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvariantCounterexampleV6 {
    pub violation: InvariantViolationV6,
    /// Index of the first action that leads to a violated invariant.
    pub at_step: usize,
    /// State hash at the time of detection (for quick comparison / logging).
    pub state_hash: Hash32,
    /// The action prefix that reproduces the violation (includes the failing step).
    pub actions: Vec<super::ActionV6>,
}

impl InvariantCounterexampleV6 {
    pub fn short(&self) -> String {
        format!(
            "Invariant {:?} violated at step {} (state_hash={})",
            self.violation.id,
            self.at_step,
            hex::encode(self.state_hash.0)
        )
    }
}
