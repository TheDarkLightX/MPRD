use super::engine::ServiceTx;
use super::types::{Agrs, AgrsPerBcr, Bcr, Bps, EpochId, OperatorId, StakeId, StakeStartOutcome};
use super::{AuctionOutcome, EpochBudgetsV6, OpsPayrollOutcome, RuntimeBoundsV6};

/// Tokenomics v6 state transition inputs.
///
/// This is the action space that should be governed by an `Allowed_op` policy (Tau),
/// consistent with the MPRD operator paper's control-plane model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionV6 {
    /// Admit a new operator/seat (control-plane membership).
    AdmitOperator { operator: OperatorId },
    /// Credit liquid AGRS (boundary IO; deposits/mints live outside the kernel).
    CreditAgrs { operator: OperatorId, amt: Agrs },
    /// Adjust OPI weight (policy-gated quality/slashing; not market-set).
    SetOpi { operator: OperatorId, opi_bps: Bps },
    /// Update runtime safety bounds (DoS rails; not an economic parameter).
    SetBounds { bounds: RuntimeBoundsV6 },

    StakeStart {
        operator: OperatorId,
        stake_amount: Agrs,
        lock_epochs: u16,
        nonce: crate::Hash32,
    },
    StakeEnd { operator: OperatorId, stake_id: StakeId },
    AccrueBcrDrip,

    ApplyServiceTx(ServiceTx),

    AuctionReveal {
        operator: OperatorId,
        qty_bcr: Bcr,
        min_price: AgrsPerBcr,
        nonce: crate::Hash32,
    },

    FinalizeEpoch,
    SettleOpsPayroll,
    SettleAuction,
    AdvanceEpoch { next_epoch: EpochId },
}

/// Tokenomics v6 action outcomes (the observable "result" of a state transition).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionOutcomeV6 {
    Unit,
    StakeStart(StakeStartOutcome),
    FinalizeEpoch(EpochBudgetsV6),
    SettleOpsPayroll(OpsPayrollOutcome),
    SettleAuction(AuctionOutcome),
}

