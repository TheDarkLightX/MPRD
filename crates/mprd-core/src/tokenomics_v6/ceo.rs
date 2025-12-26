//! Algorithmic CEO (v6): Deterministic planners on the safe-menu graph.
//!
//! This module is intentionally IO-free and deterministic. It provides small,
//! auditable building blocks that can be composed with:
//! - `MenuGraph` (finite, CBC-validated state space),
//! - `SafetyController` / Tau gates (policy rails),
//! - external metric collection (in higher layers).
//!
//! Key idea: the advanced controller may choose an arbitrary *target* node, but the
//! safety rail advances one step at a time toward that target using `step_towards_key`.

use crate::{MprdError, Result};

use super::menu_graph::MenuGraph;
use super::objective::{ObjectiveConfig, ObjectiveEvaluator, ObjectiveState, ValidatedObjectiveConfig};
use super::types::{ActionId, MenuNode};

/// Upper bound on greedy lookahead (keeps the candidate set bounded).
pub const MAX_GREEDY_HORIZON: u8 = 8; // (2h+1)^3 = 4913 candidates

/// A deterministic scoring function over menu nodes.
///
/// The caller is responsible for ensuring scores are meaningful and bounded.
pub trait CeoObjective {
    fn score(&self, node: MenuNode) -> i64;
}

/// Output of an advanced controller decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CeoDecision {
    /// Target node key selected by the advanced controller.
    pub target_key: u32,

    /// One-step action taken toward `target_key` (always a valid menu action).
    pub action: ActionId,

    /// Next node key after applying `action`.
    pub next_key: u32,

    /// Next node value (setpoints bundle).
    pub next_node: MenuNode,
}

/// Greedy local-search controller over the safe-menu graph.
///
/// Algorithm:
/// 1) Enumerate reachable nodes within a small horizon (L∞ ball).
/// 2) Pick the best-scoring target, tie-breaking deterministically.
/// 3) Take one safe step toward that target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GreedyCeo {
    horizon: u8,
}

impl GreedyCeo {
    pub fn new(horizon: u8) -> Result<Self> {
        if horizon > MAX_GREEDY_HORIZON {
            return Err(MprdError::InvalidInput(format!(
                "GreedyCeo::new: horizon {horizon} exceeds MAX_GREEDY_HORIZON={MAX_GREEDY_HORIZON}"
            )));
        }
        Ok(Self { horizon })
    }

    pub fn horizon(&self) -> u8 {
        self.horizon
    }

    /// Compute the next safe action using the greedy lookahead rule.
    pub fn decide(
        &self,
        graph: &MenuGraph,
        cur_key: u32,
        objective: &impl CeoObjective,
    ) -> Result<CeoDecision> {
        let cur_idx = graph.index_of(cur_key).ok_or_else(|| {
            MprdError::InvalidInput(format!("GreedyCeo::decide: unknown cur_key={cur_key}"))
        })?;

        let candidates = graph.reachable_inf_ball_by_key(cur_key, self.horizon)?;

        let mut best: Option<(i64, u8, u8, u32)> = None; // (score, distInf, l1, key)
        for idx in candidates {
            let node = *graph.node(idx).ok_or_else(|| {
                MprdError::ExecutionError(format!(
                    "GreedyCeo::decide: reachable set contains invalid idx={idx}"
                ))
            })?;
            let key = node.key();

            // Deterministic tie-breakers:
            //   1) higher score
            //   2) smaller distInf from current (fewer epochs to reach)
            //   3) smaller L1 distance (prefer minimal multi-axis movement)
            //   4) smaller key (stable, canonical)
            let score = objective.score(node);
            let dist_inf = graph.dist_inf_keys(cur_key, key)?;
            let l1 = dist_l1_keys(cur_key, key);

            let candidate = (score, dist_inf, l1, key);
            match best {
                None => best = Some(candidate),
                Some((b_score, b_di, b_l1, b_key)) => {
                    let better = (score > b_score)
                        || (score == b_score && dist_inf < b_di)
                        || (score == b_score && dist_inf == b_di && l1 < b_l1)
                        || (score == b_score && dist_inf == b_di && l1 == b_l1 && key < b_key);
                    if better {
                        best = Some(candidate);
                    }
                }
            }
        }

        let Some((_score, _di, _l1, target_key)) = best else {
            return Err(MprdError::ExecutionError(
                "GreedyCeo::decide: reachable set empty (unexpected)".into(),
            ));
        };

        let action = graph.action_towards_keys(cur_key, target_key)?;
        let next_key = graph.step_towards_key(cur_key, target_key)?;
        let next_idx = graph.index_of(next_key).ok_or_else(|| {
            MprdError::ExecutionError(format!(
                "GreedyCeo::decide: step produced unknown next_key={next_key}"
            ))
        })?;
        let next_node = *graph.node(next_idx).ok_or_else(|| {
            MprdError::ExecutionError(format!(
                "GreedyCeo::decide: missing node at next_idx={next_idx}"
            ))
        })?;

        // Quick internal sanity: action must be a graph edge (NoOp allowed).
        if graph.apply_action(cur_idx, action).is_none() {
            return Err(MprdError::ExecutionError(format!(
                "GreedyCeo::decide: produced non-edge action={} from cur_key={cur_key}",
                action.index()
            )));
        }

        Ok(CeoDecision {
            target_key,
            action,
            next_key,
            next_node,
        })
    }

    /// Convenience: decide using an operator-selectable objective regime.
    ///
    /// The caller supplies a deterministic `state_for_node` adapter that summarizes/predicts
    /// the objective inputs for each candidate node.
    pub fn decide_with_objective<F>(
        &self,
        graph: &MenuGraph,
        cur_key: u32,
        objective_cfg: ObjectiveConfig,
        state_for_node: F,
    ) -> Result<CeoDecision>
    where
        F: Fn(MenuNode) -> ObjectiveState,
    {
        let cfg = ValidatedObjectiveConfig::new(objective_cfg)?;
        let evaluator = ObjectiveEvaluator::new(cfg, state_for_node);
        self.decide(graph, cur_key, &evaluator)
    }
}

fn decode_key_units(key: u32) -> (u8, u8, u8) {
    let b = ((key >> 16) & 0xff) as u8;
    let a = ((key >> 8) & 0xff) as u8;
    let d = (key & 0xff) as u8;
    (b, a, d)
}

fn dist_l1_keys(a: u32, b: u32) -> u8 {
    let (ab, aa, ad) = decode_key_units(a);
    let (bb, ba, bd) = decode_key_units(b);
    ab.abs_diff(bb)
        .saturating_add(aa.abs_diff(ba))
        .saturating_add(ad.abs_diff(bd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokenomics_v6::objective::{ObjectiveConfig, ObjectiveId, ObjectiveState};
    use crate::tokenomics_v6::types::{AuctionPct, BurnPct, DripStep, ValidSplit};

    struct DripMaximizer;
    impl CeoObjective for DripMaximizer {
        fn score(&self, node: MenuNode) -> i64 {
            node.drip_bps().get() as i64
        }
    }

    #[test]
    fn greedy_moves_toward_higher_drip_when_available() {
        let graph = MenuGraph::generate().unwrap();
        let ceo = GreedyCeo::new(1).unwrap();

        // Pick a node far from bounds/split cap so drip can increase safely.
        // burn=8000 (units=30), auction=1000 (units=10), drip=50 (units=10).
        let burn = BurnPct::new(30).unwrap();
        let auction = AuctionPct::new(10).unwrap();
        let drip = DripStep::new(10).unwrap();
        let split = ValidSplit::new(burn, auction).unwrap();
        let cur = MenuNode::new(split, drip);

        let cur_key = cur.key();
        assert!(graph.index_of(cur_key).is_some());

        let decision = ceo.decide(&graph, cur_key, &DripMaximizer).unwrap();
        assert_ne!(decision.action, ActionId::NOOP);
        assert_eq!(decision.next_node.drip_bps().get(), 55);
    }

    #[test]
    fn greedy_can_select_target_using_objective_regime() {
        let graph = MenuGraph::generate().unwrap();
        let ceo = GreedyCeo::new(1).unwrap();

        // Node far from bounds/split cap so drip can increase safely.
        let burn = BurnPct::new(30).unwrap();
        let auction = AuctionPct::new(10).unwrap();
        let drip = DripStep::new(10).unwrap();
        let split = ValidSplit::new(burn, auction).unwrap();
        let cur = MenuNode::new(split, drip);

        let cfg = ObjectiveConfig {
            id: ObjectiveId::OpiFirst,
            risk_tolerance_bps: 10_000,
            churn_penalty_bps: 0,
            reserve_floor_epochs: 0,
        };

        let decision = ceo
            .decide_with_objective(&graph, cur.key(), cfg, |node| ObjectiveState {
                cashflow: 1_000,
                auction: 0,
                burn: 0,
                risk_raw: 0,
                churn_raw: 0,
                opi_bps: node.drip_bps().get().saturating_mul(100),
                revenue: 1_000,
                revenue_floor: 0,
                reserve_cover_epochs: 0,
            })
            .unwrap();

        assert_ne!(decision.action, ActionId::NOOP);
        assert_eq!(decision.next_node.drip_bps().get(), 55);
    }
}
