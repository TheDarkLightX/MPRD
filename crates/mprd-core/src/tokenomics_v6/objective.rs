//! Algorithmic CEO (v6): Operator-selectable objective regimes.
//!
//! This module is IO-free and deterministic. It provides:
//! - an operator-configurable objective regime (`ObjectiveId`),
//! - CBC validation + a validated wrapper (`ValidatedObjectiveConfig`),
//! - objective evaluation helpers (`evaluate_*`),
//! - a `CeoObjective` adapter for `GreedyCeo` target selection.

use crate::{MprdError, Result};

use super::ceo::CeoObjective;
use super::types::{EpochId, MenuNode, BPS_U16};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectiveId {
    ProfitUtility,
    OpiFirst,
    Hybrid {
        profit_weight_bps: u16,
        opi_weight_bps: u16,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectiveConfig {
    pub id: ObjectiveId,
    pub risk_tolerance_bps: u16,
    pub churn_penalty_bps: u16,
    pub reserve_floor_epochs: u8,
}

impl ObjectiveId {
    pub fn validate(&self) -> Result<()> {
        match self {
            ObjectiveId::ProfitUtility | ObjectiveId::OpiFirst => Ok(()),
            ObjectiveId::Hybrid {
                profit_weight_bps,
                opi_weight_bps,
            } => {
                if *profit_weight_bps > BPS_U16 || *opi_weight_bps > BPS_U16 {
                    return Err(MprdError::InvalidInput(
                        "ObjectiveId::Hybrid weights must be in [0, 10_000] bps".into(),
                    ));
                }
                let sum = (*profit_weight_bps as u32).saturating_add(*opi_weight_bps as u32);
                if sum != (BPS_U16 as u32) {
                    return Err(MprdError::InvalidInput(format!(
                        "ObjectiveId::Hybrid weights must sum to 10_000 bps (got {sum})"
                    )));
                }
                Ok(())
            }
        }
    }
}

impl ObjectiveConfig {
    pub fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if self.risk_tolerance_bps > BPS_U16 {
            return Err(MprdError::InvalidInput(
                "ObjectiveConfig.risk_tolerance_bps must be in [0, 10_000]".into(),
            ));
        }
        if self.churn_penalty_bps > BPS_U16 {
            return Err(MprdError::InvalidInput(
                "ObjectiveConfig.churn_penalty_bps must be in [0, 10_000]".into(),
            ));
        }
        Ok(())
    }
}

impl Default for ObjectiveConfig {
    /// Default: ProfitUtility with moderate risk tolerance.
    fn default() -> Self {
        Self {
            id: ObjectiveId::ProfitUtility,
            risk_tolerance_bps: 5_000, // 50% risk tolerance
            churn_penalty_bps: 1_000,  // 10% churn penalty
            reserve_floor_epochs: 3,   // 3 epoch reserve minimum
        }
    }
}

/// CBC gate: validated `ObjectiveConfig` that cannot be mutated into an invalid state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedObjectiveConfig(ObjectiveConfig);

impl ValidatedObjectiveConfig {
    pub fn new(cfg: ObjectiveConfig) -> Result<Self> {
        cfg.validate()?;
        Ok(Self(cfg))
    }

    pub fn id(&self) -> &ObjectiveId {
        &self.0.id
    }

    pub fn risk_tolerance_bps(&self) -> u16 {
        self.0.risk_tolerance_bps
    }

    pub fn churn_penalty_bps(&self) -> u16 {
        self.0.churn_penalty_bps
    }

    pub fn reserve_floor_epochs(&self) -> u8 {
        self.0.reserve_floor_epochs
    }
}

/// Objective evaluation inputs (already summarized/predicted per candidate).
///
/// Units are "score points" and are intentionally abstract: callers may feed real token units,
/// normalized values, or model-based expected returns, as long as they are deterministic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectiveState {
    /// Positive contribution: expected cashflow / utility.
    pub cashflow: i64,
    /// Positive contribution: expected auction utility.
    pub auction: i64,
    /// Positive contribution: expected burn utility.
    pub burn: i64,

    /// Non-negative risk in score units (scaled by `risk_tolerance_bps`).
    pub risk_raw: i64,
    /// Non-negative churn in score units (scaled by `churn_penalty_bps`).
    pub churn_raw: i64,

    /// OPI weight used by `OpiFirst` (in bps).
    pub opi_bps: u16,
    /// Revenue observed/predicted for the epoch.
    pub revenue: i64,
    /// Revenue floor required for OPI-first objective.
    pub revenue_floor: i64,

    /// Reserve coverage estimate (in epochs).
    pub reserve_cover_epochs: u8,
}

const CONSTRAINT_VIOLATION_SCORE: i64 = i64::MIN / 4;

fn mul_bps_i64(x: i64, bps: u16) -> i64 {
    let prod = (x as i128).saturating_mul(bps as i128);
    let scaled = prod / (BPS_U16 as i128);
    scaled.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

fn add_i64_saturating(a: i64, b: i64) -> i64 {
    a.saturating_add(b)
}

fn sub_i64_saturating(a: i64, b: i64) -> i64 {
    a.saturating_sub(b)
}

/// Profit/utility-seeking objective:
/// `cashflow + auction + burn - risk - churn`.
pub fn evaluate_profit_utility(state: ObjectiveState, params: &ValidatedObjectiveConfig) -> i64 {
    if state.reserve_cover_epochs < params.reserve_floor_epochs() {
        return CONSTRAINT_VIOLATION_SCORE;
    }

    let risk_weight_bps = BPS_U16.saturating_sub(params.risk_tolerance_bps());
    let risk_raw = state.risk_raw.max(0);
    let churn_raw = state.churn_raw.max(0);
    let risk = mul_bps_i64(risk_raw, risk_weight_bps);
    let churn = mul_bps_i64(churn_raw, params.churn_penalty_bps());

    let mut score = 0i64;
    score = add_i64_saturating(score, state.cashflow);
    score = add_i64_saturating(score, state.auction);
    score = add_i64_saturating(score, state.burn);
    score = sub_i64_saturating(score, risk);
    score = sub_i64_saturating(score, churn);
    score
}

/// OPI-first objective:
/// - Hard constraint: `revenue >= revenue_floor`
/// - Score: `(cashflow + auction + burn) weighted by OPI - risk - churn`.
pub fn evaluate_opi_first(state: ObjectiveState, params: &ValidatedObjectiveConfig) -> i64 {
    if state.revenue < state.revenue_floor {
        return CONSTRAINT_VIOLATION_SCORE;
    }
    if state.reserve_cover_epochs < params.reserve_floor_epochs() {
        return CONSTRAINT_VIOLATION_SCORE;
    }
    if state.opi_bps > BPS_U16 {
        // Fail-closed: invalid OPI weight input.
        return CONSTRAINT_VIOLATION_SCORE;
    }

    let base = state
        .cashflow
        .saturating_add(state.auction)
        .saturating_add(state.burn);
    let opi_weighted = mul_bps_i64(base, state.opi_bps);

    let risk_weight_bps = BPS_U16.saturating_sub(params.risk_tolerance_bps());
    let risk_raw = state.risk_raw.max(0);
    let churn_raw = state.churn_raw.max(0);
    let risk = mul_bps_i64(risk_raw, risk_weight_bps);
    let churn = mul_bps_i64(churn_raw, params.churn_penalty_bps());

    opi_weighted.saturating_sub(risk).saturating_sub(churn)
}

/// Hybrid objective: weighted combination of profit/utility and OPI-first.
pub fn evaluate_hybrid(
    state: ObjectiveState,
    params: &ValidatedObjectiveConfig,
    profit_weight_bps: u16,
    opi_weight_bps: u16,
) -> i64 {
    // Defensive: Hybrid weights must be validated, but fail-closed if called incorrectly.
    if profit_weight_bps > BPS_U16 || opi_weight_bps > BPS_U16 {
        return CONSTRAINT_VIOLATION_SCORE;
    }
    let sum = (profit_weight_bps as u32).saturating_add(opi_weight_bps as u32);
    if sum != (BPS_U16 as u32) {
        return CONSTRAINT_VIOLATION_SCORE;
    }

    let p = evaluate_profit_utility(state, params);
    let o = evaluate_opi_first(state, params);

    let p_scaled = mul_bps_i64(p, profit_weight_bps);
    let o_scaled = mul_bps_i64(o, opi_weight_bps);
    p_scaled.saturating_add(o_scaled)
}

/// Deterministic scorer adapter for `GreedyCeo`.
pub struct ObjectiveEvaluator<F> {
    cfg: ValidatedObjectiveConfig,
    state_for_node: F,
}

impl<F> ObjectiveEvaluator<F> {
    pub fn new(cfg: ValidatedObjectiveConfig, state_for_node: F) -> Self {
        Self {
            cfg,
            state_for_node,
        }
    }
}

impl<F> CeoObjective for ObjectiveEvaluator<F>
where
    F: Fn(MenuNode) -> ObjectiveState,
{
    fn score(&self, node: MenuNode) -> i64 {
        let state = (self.state_for_node)(node);
        match *self.cfg.id() {
            ObjectiveId::ProfitUtility => evaluate_profit_utility(state, &self.cfg),
            ObjectiveId::OpiFirst => evaluate_opi_first(state, &self.cfg),
            ObjectiveId::Hybrid {
                profit_weight_bps,
                opi_weight_bps,
            } => evaluate_hybrid(state, &self.cfg, profit_weight_bps, opi_weight_bps),
        }
    }
}

/// Objective config with policy-style cooldown gating.
///
/// This is intended to be enforced at the boundary (host/policy layer) and then treated as a
/// trusted invariant by the CEO loop (CBC).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectiveConfigState {
    cfg: ValidatedObjectiveConfig,
    last_changed_epoch: EpochId,
}

impl ObjectiveConfigState {
    pub fn new(initial_cfg: ObjectiveConfig, epoch: EpochId) -> Result<Self> {
        Ok(Self {
            cfg: ValidatedObjectiveConfig::new(initial_cfg)?,
            last_changed_epoch: epoch,
        })
    }

    pub fn config(&self) -> ValidatedObjectiveConfig {
        self.cfg
    }

    pub fn last_changed_epoch(&self) -> EpochId {
        self.last_changed_epoch
    }

    pub fn can_update(&self, now: EpochId, cooldown_epochs: u64) -> bool {
        now.0
            .checked_sub(self.last_changed_epoch.0)
            .is_some_and(|d| d >= cooldown_epochs)
    }

    pub fn try_update(
        &mut self,
        new_cfg: ObjectiveConfig,
        now: EpochId,
        cooldown_epochs: u64,
    ) -> Result<()> {
        if now.0 < self.last_changed_epoch.0 {
            return Err(MprdError::InvalidInput(
                "ObjectiveConfigState::try_update: epoch went backwards".into(),
            ));
        }
        if !self.can_update(now, cooldown_epochs) {
            return Err(MprdError::InvalidInput(
                "ObjectiveConfigState::try_update: objective config cooldown not elapsed".into(),
            ));
        }
        self.cfg = ValidatedObjectiveConfig::new(new_cfg)?;
        self.last_changed_epoch = now;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_hybrid_weights_sum() {
        let bad = ObjectiveConfig {
            id: ObjectiveId::Hybrid {
                profit_weight_bps: 6_000,
                opi_weight_bps: 5_000,
            },
            risk_tolerance_bps: 5_000,
            churn_penalty_bps: 1_000,
            reserve_floor_epochs: 3,
        };
        assert!(matches!(
            bad.validate().unwrap_err(),
            MprdError::InvalidInput(_)
        ));

        let ok = ObjectiveConfig {
            id: ObjectiveId::Hybrid {
                profit_weight_bps: 6_000,
                opi_weight_bps: 4_000,
            },
            risk_tolerance_bps: 5_000,
            churn_penalty_bps: 1_000,
            reserve_floor_epochs: 3,
        };
        ok.validate().unwrap();
    }

    #[test]
    fn profit_utility_enforces_reserve_floor_fail_closed() {
        let cfg = ValidatedObjectiveConfig::new(ObjectiveConfig {
            id: ObjectiveId::ProfitUtility,
            risk_tolerance_bps: 10_000,
            churn_penalty_bps: 0,
            reserve_floor_epochs: 2,
        })
        .unwrap();

        let st = ObjectiveState {
            cashflow: 10,
            auction: 10,
            burn: 10,
            risk_raw: 0,
            churn_raw: 0,
            opi_bps: 10_000,
            revenue: 10,
            revenue_floor: 0,
            reserve_cover_epochs: 1,
        };
        assert_eq!(
            evaluate_profit_utility(st, &cfg),
            CONSTRAINT_VIOLATION_SCORE
        );
    }

    #[test]
    fn opi_first_enforces_revenue_floor_fail_closed() {
        let cfg = ValidatedObjectiveConfig::new(ObjectiveConfig {
            id: ObjectiveId::OpiFirst,
            risk_tolerance_bps: 10_000,
            churn_penalty_bps: 0,
            reserve_floor_epochs: 0,
        })
        .unwrap();

        let st = ObjectiveState {
            cashflow: 10,
            auction: 0,
            burn: 0,
            risk_raw: 0,
            churn_raw: 0,
            opi_bps: 10_000,
            revenue: 9,
            revenue_floor: 10,
            reserve_cover_epochs: 0,
        };
        assert_eq!(evaluate_opi_first(st, &cfg), CONSTRAINT_VIOLATION_SCORE);
    }

    #[test]
    fn objective_config_state_enforces_cooldown() {
        let mut st = ObjectiveConfigState::new(
            ObjectiveConfig {
                id: ObjectiveId::ProfitUtility,
                risk_tolerance_bps: 5_000,
                churn_penalty_bps: 1_000,
                reserve_floor_epochs: 1,
            },
            EpochId(10),
        )
        .unwrap();

        let new_cfg = ObjectiveConfig {
            id: ObjectiveId::OpiFirst,
            risk_tolerance_bps: 5_000,
            churn_penalty_bps: 1_000,
            reserve_floor_epochs: 1,
        };

        assert!(st.try_update(new_cfg, EpochId(11), 2).is_err());
        st.try_update(new_cfg, EpochId(12), 2).unwrap();
        assert_eq!(st.last_changed_epoch(), EpochId(12));
    }
}
