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

pub mod actions;
pub mod auction;
pub mod bounds;
pub mod ceo;
pub mod ceo_lipschitz_ucb;
pub mod engine;
pub mod gate;
pub mod invariant_rail;
pub mod invariants;
#[cfg(kani)]
mod kani_proofs;
pub mod math;
pub mod menu_graph;
pub mod objective;
pub mod pid;
pub mod safety_controller;
pub mod simplex_por_oracle;
pub mod simplex_planner;
pub mod simplex_symmetry_key;
pub mod simplex_ceo;
pub mod simplex_ample_set;
pub mod types;

pub use actions::{ActionOutcomeV6, ActionV6};
pub use auction::{AuctionBid, AuctionClearing, AuctionOutcome};
pub use bounds::RuntimeBoundsV6;
pub use ceo::{CeoDecision, CeoObjective, GreedyCeo};
pub use ceo_lipschitz_ucb::{LipschitzUcbCeo, LipschitzUcbGate};
pub use engine::{EpochBudgetsV6, OpsPayrollOutcome, ServiceTx, TokenomicsV6};
pub use gate::{AllowAllGateV6, DenyAllGateV6, PolicyGateV6};
pub use invariant_rail::{first_invariant_counterexample_v1, minimize_counterexample_v1};
pub use invariants::{InvariantCounterexampleV6, InvariantIdV6, InvariantViolationV6};
pub use simplex_ceo::{
    plan_best, plan_best_linear, SimplexCeoConfig, SimplexCeoDecision, SimplexCeoMode,
};
pub use objective::{
    evaluate_hybrid, evaluate_opi_first, evaluate_profit_utility, ObjectiveConfig,
    ObjectiveConfigState, ObjectiveEvaluator, ObjectiveId, ObjectiveState,
    ValidatedObjectiveConfig,
};
pub use pid::{
    pid_step_bps, propose_v6, PidBpsConfig, PidBpsGains, PidBpsState, TokenomicsPidConfigV6,
    TokenomicsPidProposalV6, TokenomicsPidStateV6,
};
pub use types::{
    Agrs, AgrsPerBcr, Bcr, Bps, EpochId, OperatorId, ParamsV6, Shares, StakeId, StakeStartOutcome,
    StakeStatus,
};
