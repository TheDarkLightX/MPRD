//! Algorithmic CEO (v6): Lipschitz-envelope UCB planner on the safe-menu graph.
//!
//! This controller is designed to be:
//! - deterministic (integer-only; no RNG),
//! - bounded (candidate horizon + bounded observation window),
//! - auditable (UB/LB envelopes are explicit and explainable),
//! - safe-by-construction when paired with the menu graph safety rail.
//!
//! Core idea:
//! Given a recent observation window of realized per-epoch rewards `r(o)` attached to menu nodes `o`,
//! define Lipschitz envelopes over the `dist∞` metric on the menu lattice:
//!   UB(x) = min_o ( r(o) + L * dist(o, x) )
//!   LB(x) = max_o ( r(o) - L * dist(o, x) )
//!
//! If the true reward function is L-Lipschitz (and observations are exact), then:
//!   LB(x) ≤ f(x) ≤ UB(x)   for all x
//! and the optional safe gate:
//!   LB(tgt) ≥ UB(base) + margin
//! implies a *provable* improvement:
//!   f(tgt) ≥ f(base) + margin
//!
//! See formalization: `internal/specs/mprd_ceo_lipschitz_ucb_proofs.lean`.

use std::collections::VecDeque;

use crate::{MprdError, Result};

use super::ceo::CeoDecision;
use super::menu_graph::MenuGraph;
use super::types::ActionId;

/// Upper bound on UCB horizon (keeps the candidate set bounded).
pub const MAX_LIPSCHITZ_UCB_HORIZON: u8 = 12; // (2h+1)^3 = 15_625 candidates

/// Gate mode for Lipschitz UCB exploration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LipschitzUcbGate {
    None,
    /// Allow moves only when the Lipschitz LB/UB rails certify improvement:
    /// `LB(target) >= UB(baseline) + margin`.
    SafeImprove { margin: i64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Observation {
    key: u32,
    reward: i64,
}

/// Deterministic Lipschitz-envelope UCB controller over menu nodes.
#[derive(Clone, Debug)]
pub struct LipschitzUcbCeo {
    lipschitz_l: i64,
    horizon: u8,
    window: usize,
    churn_penalty_per_step: i64,
    gate: LipschitzUcbGate,
    obs: VecDeque<Observation>,
}

impl LipschitzUcbCeo {
    pub fn new(
        lipschitz_l: i64,
        horizon: u8,
        window: usize,
        churn_penalty_per_step: i64,
        gate: LipschitzUcbGate,
    ) -> Result<Self> {
        if lipschitz_l < 0 {
            return Err(MprdError::InvalidInput(
                "LipschitzUcbCeo::new: lipschitz_l must be >= 0".into(),
            ));
        }
        if horizon == 0 || horizon > MAX_LIPSCHITZ_UCB_HORIZON {
            return Err(MprdError::InvalidInput(format!(
                "LipschitzUcbCeo::new: horizon must be in [1, {MAX_LIPSCHITZ_UCB_HORIZON}]"
            )));
        }
        if window == 0 {
            return Err(MprdError::InvalidInput(
                "LipschitzUcbCeo::new: window must be > 0".into(),
            ));
        }
        if churn_penalty_per_step < 0 {
            return Err(MprdError::InvalidInput(
                "LipschitzUcbCeo::new: churn_penalty_per_step must be >= 0".into(),
            ));
        }
        if let LipschitzUcbGate::SafeImprove { margin } = gate {
            if margin < 0 {
                return Err(MprdError::InvalidInput(
                    "LipschitzUcbCeo::new: safe-improve margin must be >= 0".into(),
                ));
            }
        }

        Ok(Self {
            lipschitz_l,
            horizon,
            window,
            churn_penalty_per_step,
            gate,
            obs: VecDeque::new(),
        })
    }

    pub fn lipschitz_l(&self) -> i64 {
        self.lipschitz_l
    }

    pub fn horizon(&self) -> u8 {
        self.horizon
    }

    pub fn window(&self) -> usize {
        self.window
    }

    pub fn churn_penalty_per_step(&self) -> i64 {
        self.churn_penalty_per_step
    }

    pub fn gate(&self) -> LipschitzUcbGate {
        self.gate
    }

    pub fn obs_len(&self) -> usize {
        self.obs.len()
    }

    /// Record an observed realized reward for a menu node.
    ///
    /// CBC rail: `node_key` must exist in the provided menu graph.
    pub fn observe(&mut self, graph: &MenuGraph, node_key: u32, reward: i64) -> Result<()> {
        if graph.index_of(node_key).is_none() {
            return Err(MprdError::InvalidInput(format!(
                "LipschitzUcbCeo::observe: unknown node_key={node_key}"
            )));
        }

        self.obs.push_back(Observation {
            key: node_key,
            reward,
        });
        while self.obs.len() > self.window {
            self.obs.pop_front();
        }
        Ok(())
    }

    fn ub_for_key(&self, candidate_key: u32) -> Option<i64> {
        if self.obs.is_empty() {
            return None;
        }
        let mut best: Option<i64> = None;
        for o in &self.obs {
            let dist = dist_inf_keys_fast(o.key, candidate_key) as i64;
            let bump = self.lipschitz_l.saturating_mul(dist);
            let v = o.reward.saturating_add(bump);
            best = Some(match best {
                None => v,
                Some(b) => b.min(v),
            });
        }
        best
    }

    fn lb_for_key(&self, candidate_key: u32) -> Option<i64> {
        if self.obs.is_empty() {
            return None;
        }
        let mut best: Option<i64> = None;
        for o in &self.obs {
            let dist = dist_inf_keys_fast(o.key, candidate_key) as i64;
            let bump = self.lipschitz_l.saturating_mul(dist);
            let v = o.reward.saturating_sub(bump);
            best = Some(match best {
                None => v,
                Some(b) => b.max(v),
            });
        }
        best
    }

    fn interval_for_key(&self, key: u32) -> Option<(i64, i64)> {
        let lb = self.lb_for_key(key)?;
        let ub = self.ub_for_key(key)?;
        Some((lb, ub))
    }

    /// Decide the next safe action.
    ///
    /// Cold start (no observations): returns `NOOP` and keeps the current node.
    pub fn decide(&self, graph: &MenuGraph, cur_key: u32) -> Result<CeoDecision> {
        let cur_idx = graph.index_of(cur_key).ok_or_else(|| {
            MprdError::InvalidInput(format!("LipschitzUcbCeo::decide: unknown cur_key={cur_key}"))
        })?;
        let cur_node = *graph.node(cur_idx).ok_or_else(|| {
            MprdError::ExecutionError(format!(
                "LipschitzUcbCeo::decide: missing node at cur_idx={cur_idx}"
            ))
        })?;

        if self.obs.is_empty() {
            return Ok(CeoDecision {
                target_key: cur_key,
                action: ActionId::NOOP,
                next_key: cur_key,
                next_node: cur_node,
            });
        }

        let candidates = graph.reachable_inf_ball_by_key(cur_key, self.horizon)?;

        // Baseline interval rails (used only for the safe-improve gate).
        let (lb_base, ub_base) = self.interval_for_key(cur_key).ok_or_else(|| {
            MprdError::ExecutionError("LipschitzUcbCeo::decide: obs empty (unexpected)".into())
        })?;

        // Fail-closed on inconsistent envelopes for the baseline node.
        if ub_base < lb_base {
            return Ok(CeoDecision {
                target_key: cur_key,
                action: ActionId::NOOP,
                next_key: cur_key,
                next_node: cur_node,
            });
        }

        let mut best: Option<(i64, i64, u8, u32)> = None; // (score, ub, dist, key)
        for idx in candidates {
            let node = *graph.node(idx).ok_or_else(|| {
                MprdError::ExecutionError(format!(
                    "LipschitzUcbCeo::decide: reachable set contains invalid idx={idx}"
                ))
            })?;
            let key = node.key();

            let Some(ub) = self.ub_for_key(key) else {
                return Err(MprdError::ExecutionError(
                    "LipschitzUcbCeo::decide: obs empty while enumerating".into(),
                ));
            };

            let dist = dist_inf_keys_fast(cur_key, key);
            let churn_penalty = self
                .churn_penalty_per_step
                .saturating_mul(dist as i64);
            let score = ub.saturating_sub(churn_penalty);

            // Deterministic tie-breakers:
            //   1) higher score
            //   2) higher ub
            //   3) smaller dist∞ (fewer epochs to reach)
            //   4) smaller key (stable, canonical)
            let cand = (score, ub, dist, key);
            match best {
                None => best = Some(cand),
                Some((b_score, b_ub, b_dist, b_key)) => {
                    let better = (score > b_score)
                        || (score == b_score && ub > b_ub)
                        || (score == b_score && ub == b_ub && dist < b_dist)
                        || (score == b_score && ub == b_ub && dist == b_dist && key < b_key);
                    if better {
                        best = Some(cand);
                    }
                }
            }
        }

        let Some((_score, _ub, _dist, mut target_key)) = best else {
            return Err(MprdError::ExecutionError(
                "LipschitzUcbCeo::decide: reachable set empty (unexpected)".into(),
            ));
        };

        if let LipschitzUcbGate::SafeImprove { margin } = self.gate {
            match self.interval_for_key(target_key) {
                None => {
                    // No observation window available for envelopes (unexpected under warm start);
                    // fail closed.
                    target_key = cur_key;
                }
                Some((lb_tgt, ub_tgt)) => {
                    // Fail-closed on inconsistent target envelope.
                    if ub_tgt < lb_tgt {
                        target_key = cur_key;
                    } else {
                        // Certified improvement check:
                        // LB(target) >= UB(base) + margin
                        let threshold = ub_base.saturating_add(margin);
                        if lb_tgt < threshold {
                            target_key = cur_key;
                        }
                    }
                }
            };
        }

        let action = graph.action_towards_keys(cur_key, target_key)?;
        let next_key = graph.step_towards_key(cur_key, target_key)?;
        let next_idx = graph.index_of(next_key).ok_or_else(|| {
            MprdError::ExecutionError(format!(
                "LipschitzUcbCeo::decide: step produced unknown next_key={next_key}"
            ))
        })?;
        let next_node = *graph.node(next_idx).ok_or_else(|| {
            MprdError::ExecutionError(format!(
                "LipschitzUcbCeo::decide: missing node at next_idx={next_idx}"
            ))
        })?;

        // Sanity: action must be a graph edge (NoOp allowed).
        if graph.apply_action(cur_idx, action).is_none() {
            return Err(MprdError::ExecutionError(format!(
                "LipschitzUcbCeo::decide: produced non-edge action={} from cur_key={cur_key}",
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
}

fn decode_key_units(key: u32) -> (u8, u8, u8) {
    let b = ((key >> 16) & 0xff) as u8;
    let a = ((key >> 8) & 0xff) as u8;
    let d = (key & 0xff) as u8;
    (b, a, d)
}

/// Fast `dist∞` on packed menu keys (no graph membership checks).
fn dist_inf_keys_fast(a: u32, b: u32) -> u8 {
    let (ab, aa, ad) = decode_key_units(a);
    let (bb, ba, bd) = decode_key_units(b);
    ab.abs_diff(bb).max(aa.abs_diff(ba)).max(ad.abs_diff(bd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokenomics_v6::menu_graph::MenuGraph;
    use proptest::prelude::*;
    use std::sync::LazyLock;

    static GRAPH: LazyLock<MenuGraph> = LazyLock::new(|| MenuGraph::generate().unwrap());

    fn graph() -> &'static MenuGraph {
        &GRAPH
    }

    fn ceo() -> LipschitzUcbCeo {
        LipschitzUcbCeo::new(500, 6, 64, 0, LipschitzUcbGate::None).unwrap()
    }

    #[test]
    fn cold_start_returns_noop() {
        let graph = graph();
        let cur_idx = graph.node_count() / 2;
        let cur_key = graph.node(cur_idx).unwrap().key();

        let ceo = ceo();
        let d = ceo.decide(graph, cur_key).unwrap();
        assert_eq!(d.target_key, cur_key);
        assert_eq!(d.action, ActionId::NOOP);
        assert_eq!(d.next_key, cur_key);
    }

    #[test]
    fn safe_gate_freezes_on_inconsistent_envelope() {
        let graph = graph();
        let cur_idx = graph.node_count() / 2;
        let cur_key = graph.node(cur_idx).unwrap().key();

        let mut ceo =
            LipschitzUcbCeo::new(0, 3, 8, 0, LipschitzUcbGate::SafeImprove { margin: 0 }).unwrap();

        // Two observations at the same key with contradictory rewards and L=0 forces:
        // UB=MIN(r) and LB=MAX(r), so LB > UB => inconsistent.
        ceo.observe(graph, cur_key, 0).unwrap();
        ceo.observe(graph, cur_key, 10).unwrap();

        let d = ceo.decide(graph, cur_key).unwrap();
        assert_eq!(d.action, ActionId::NOOP);
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 32,
            .. ProptestConfig::default()
        })]

        #[test]
        fn decide_always_returns_graph_edge(
            node_offset in 0usize..100_000,
            reward in -10_000i64..10_000i64,
        ) {
            let graph = graph();
            let start_idx = node_offset % graph.node_count();
            let cur_key = graph.node(start_idx).unwrap().key();

            let mut ceo = LipschitzUcbCeo::new(100, 3, 8, 0, LipschitzUcbGate::None).unwrap();
            ceo.observe(graph, cur_key, reward).unwrap(); // ensure warm start

            let d = ceo.decide(graph, cur_key).unwrap();

            let cur_idx = graph.index_of(cur_key).unwrap();
            let next_idx = graph.index_of(d.next_key).unwrap();
            prop_assert_eq!(graph.apply_action(cur_idx, d.action), Some(next_idx));
            prop_assert_eq!(graph.node(next_idx).copied(), Some(d.next_node));
        }
    }
}
