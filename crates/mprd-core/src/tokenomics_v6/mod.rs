//! MPRD Tokenomics v6 (implementation — kernel).
//!
//! This module implements the **v6 kernel** described in:
//! - `internal/specs/mprd_tokenomics_v6_idea_spec.md`
//! - `internal/specs/mprd_tokenomics_v6_policies.md`
//! - `internal/specs/mprd_tokenomics_v6_proofs.lean`
//!
//! Design goals:
//! - CBC-first: invalid states unrepresentable (domain types + constructors)
//! - Deterministic and bounded arithmetic (u128 intermediates, floor division)
//! - Fail-closed on malformed/unknown inputs (callers must validate at boundaries)
//! - IO-free core (pure state machine); integration layers provide storage/network/time

pub mod auction;
pub mod bounds;
pub mod engine;
pub mod math;
pub mod types;

pub use auction::{AuctionBid, AuctionClearing, AuctionOutcome};
pub use bounds::RuntimeBoundsV6;
pub use engine::{EpochBudgetsV6, OpsPayrollOutcome, ServiceTx, TokenomicsV6};
pub use types::{
    Agrs, AgrsPerBcr, Bcr, Bps, EpochId, OperatorId, ParamsV6, Shares, StakeId, StakeStartOutcome,
    StakeStatus,
};
