//! Algorithmic CEO: Safety Controller
//!
//! Implements the Simplex safety controller for the Algorithmic CEO:
//! - Uses menu graph to constrain actions to valid transitions
//! - Integrates with PID for smooth setpoint tracking
//! - Provides fail-safe NoOp fallback
//!
//! See: internal/specs/REVIEW__mprd_tokenomics_v6_algorithmic_ceo_menu__codex_gpt-5_2__2025-12-25.md

use crate::{Hash32, MprdError, Result};

use super::menu_graph::MenuGraph;
use super::pid::{pid_step_bps, PidBpsConfig, PidBpsGains, PidBpsState};
use super::types::{ActionId, Bps, MenuNode, Step, BPS_U16};

/// Configuration for the safety controller.
#[derive(Clone, Debug)]
pub struct SafetyControllerConfig {
    /// PID gains for each axis
    pub burn_gains: PidBpsGains,
    pub auction_gains: PidBpsGains,
    pub drip_gains: PidBpsGains,

    /// PID config for each axis (includes step limits)
    pub burn_cfg: PidBpsConfig,
    pub auction_cfg: PidBpsConfig,
    pub drip_cfg: PidBpsConfig,
}

impl SafetyControllerConfig {
    pub fn validate(&self) -> Result<()> {
        self.burn_cfg.validate()?;
        self.auction_cfg.validate()?;
        self.drip_cfg.validate()?;
        Ok(())
    }
}

/// State of the safety controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SafetyControllerState {
    /// Graph identity this state was created for.
    ///
    /// CBC: prevents accidentally reusing a node pointer across graph upgrades.
    graph_version: u32,
    graph_hash: Hash32,

    /// Current position in the menu graph (stable key, not an index).
    current_node_key: u32,

    /// PID state for each axis
    burn_pid: PidBpsState,
    auction_pid: PidBpsState,
    drip_pid: PidBpsState,
}

impl SafetyControllerState {
    /// Create initial state from a graph node key.
    pub fn new(graph: &MenuGraph, node_key: u32) -> Result<Self> {
        let graph_version = graph.version;
        let graph_hash = graph.canonical_hash()?;

        if graph.index_of(node_key).is_none() {
            return Err(MprdError::InvalidInput(format!(
                "SafetyControllerState::new: unknown node_key={node_key}"
            )));
        }

        Ok(Self {
            graph_version,
            graph_hash,
            current_node_key: node_key,
            burn_pid: PidBpsState::default(),
            auction_pid: PidBpsState::default(),
            drip_pid: PidBpsState::default(),
        })
    }

    /// Create initial state from a graph node index (convenience/testing).
    pub fn new_from_idx(graph: &MenuGraph, node_idx: usize) -> Result<Self> {
        let node = graph.node(node_idx).ok_or_else(|| {
            MprdError::InvalidInput(format!(
                "SafetyControllerState::new_from_idx: invalid node_idx={node_idx}"
            ))
        })?;
        Self::new(graph, node.key())
    }

    pub fn graph_version(&self) -> u32 {
        self.graph_version
    }

    pub fn graph_hash(&self) -> Hash32 {
        self.graph_hash
    }

    pub fn current_node_key(&self) -> u32 {
        self.current_node_key
    }
}

/// Proposal from the safety controller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyProposal {
    pub action: ActionId,
    pub next_node_key: u32,
    pub next_node: MenuNode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MenuGraphId {
    version: u32,
    hash: Hash32,
}

/// The safety controller for Algorithmic CEO.
///
/// This is the "safety controller" in Simplex architecture:
/// - Always produces valid actions (graph-constrained)
/// - NoOp is always available as fallback
/// - Deterministic and auditable
pub struct SafetyController<'a> {
    graph: &'a MenuGraph,
    graph_id: MenuGraphId,
    config: SafetyControllerConfig,
}

impl<'a> SafetyController<'a> {
    pub fn new(graph: &'a MenuGraph, config: SafetyControllerConfig) -> Result<Self> {
        if graph.node_count() == 0 {
            return Err(MprdError::InvalidInput(
                "SafetyController::new: menu graph has zero nodes".into(),
            ));
        }
        config.validate()?;

        Ok(Self {
            graph,
            graph_id: MenuGraphId {
                version: graph.version,
                hash: graph.canonical_hash()?,
            },
            config,
        })
    }

    /// Compute the best action given current state and setpoints.
    ///
    /// Uses PID to determine desired direction, then finds the best
    /// valid action in the menu graph that moves toward the setpoint.
    pub fn compute_action(
        &self,
        state: &SafetyControllerState,
        burn_setpoint: Bps,
        auction_setpoint: Bps,
        drip_setpoint: Bps,
    ) -> Result<(SafetyProposal, SafetyControllerState)> {
        if (state.graph_version, state.graph_hash) != (self.graph_id.version, self.graph_id.hash) {
            return Err(MprdError::InvalidInput(format!(
                "SafetyControllerState graph id mismatch: state(v={}, h={:?}) controller(v={}, h={:?})",
                state.graph_version,
                state.graph_hash,
                self.graph_id.version,
                self.graph_id.hash
            )));
        }

        let current_idx = self.graph.index_of(state.current_node_key).ok_or_else(|| {
            MprdError::InvalidInput(format!(
                "SafetyControllerState refers to unknown node_key={} for graph(v={}, h={:?})",
                state.current_node_key, state.graph_version, state.graph_hash
            ))
        })?;
        let current_node = self.graph.node(current_idx).ok_or_else(|| {
            MprdError::InvalidInput("menu graph missing node for resolved index".into())
        })?;

        // Get current values from the node
        let cur_burn = current_node.burn_bps();
        let cur_auction = current_node.auction_bps();
        let cur_drip = current_node.drip_bps();

        // PID proposes bounded next values (continuous bps); the menu graph then quantizes that
        // proposal to a valid one-step transition.
        let (burn_pid_target, burn_pid_state) = pid_step_bps(
            cur_burn,
            burn_setpoint,
            cur_burn,
            self.config.burn_gains,
            self.config.burn_cfg,
            state.burn_pid,
        )?;
        let (auction_pid_target, auction_pid_state) = pid_step_bps(
            cur_auction,
            auction_setpoint,
            cur_auction,
            self.config.auction_gains,
            self.config.auction_cfg,
            state.auction_pid,
        )?;
        let (drip_pid_target, drip_pid_state) = pid_step_bps(
            cur_drip,
            drip_setpoint,
            cur_drip,
            self.config.drip_gains,
            self.config.drip_cfg,
            state.drip_pid,
        )?;

        // Enforce split cap on the *target* (CBC): burn + auction <= 10_000.
        let (burn_pid_target, auction_pid_target) =
            enforce_split_cap_preserve_burn(burn_pid_target, auction_pid_target)?;

        // Dynamic axis weights: prioritize axes with larger errors to the requested setpoints.
        // This avoids getting stuck on split-cap plateaus where one axis must trade off another.
        let burn_w = 1 + bps_abs_i64(burn_setpoint, cur_burn);
        let auction_w = 1 + bps_abs_i64(auction_setpoint, cur_auction);
        let drip_w = 1 + bps_abs_i64(drip_setpoint, cur_drip);

        let mut best: Option<(i64, i64, u8, ActionId, usize, MenuNode)> = None;
        for action in self.graph.valid_actions(current_idx) {
            let Some(next_idx) = self.graph.apply_action(current_idx, action) else {
                return Err(MprdError::ExecutionError(
                    "menu graph returned invalid action in valid_actions()".into(),
                ));
            };
            let next_node = *self.graph.node(next_idx).ok_or_else(|| {
                MprdError::ExecutionError("menu graph edge points to missing node".into())
            })?;

            let pid_dist = weighted_pid_distance(
                (burn_pid_target, auction_pid_target, drip_pid_target),
                (burn_w, auction_w, drip_w),
                next_node,
            );
            let setpoint_dist =
                l1_setpoint_distance((burn_setpoint, auction_setpoint, drip_setpoint), next_node);
            let effort = control_effort(action);

            let key = (pid_dist, setpoint_dist, effort, action.index());
            match best {
                None => best = Some((pid_dist, setpoint_dist, effort, action, next_idx, next_node)),
                Some((b_pid, b_sp, b_eff, b_action, _, _)) => {
                    let best_key = (b_pid, b_sp, b_eff, b_action.index());
                    if key < best_key {
                        best = Some((pid_dist, setpoint_dist, effort, action, next_idx, next_node));
                    }
                }
            }
        }

        let Some((_pid_dist, _sp_dist, _effort, best_action, _best_next_idx, next_node)) = best
        else {
            return Err(MprdError::ExecutionError(
                "menu graph returned zero valid actions (expected at least NoOp)".into(),
            ));
        };

        let best_next_key = next_node.key();

        Ok((
            SafetyProposal {
                action: best_action,
                next_node_key: best_next_key,
                next_node,
            },
            SafetyControllerState {
                graph_version: state.graph_version,
                graph_hash: state.graph_hash,
                current_node_key: best_next_key,
                burn_pid: burn_pid_state,
                auction_pid: auction_pid_state,
                drip_pid: drip_pid_state,
            },
        ))
    }

    /// Compute the one-step action toward a specific *target menu node*.
    ///
    /// This is useful when an advanced controller selects a target node (e.g., via greedy search,
    /// bandits, or other planners), and the safety rail enforces "one safe step per epoch" toward it.
    ///
    /// If the provided `state` is corrupted or refers to a different graph identity, this will
    /// repair the state first (fail-safe), then proceed.
    pub fn compute_action_towards_target(
        &self,
        state: &SafetyControllerState,
        target_key: u32,
    ) -> Result<(SafetyProposal, SafetyControllerState)> {
        // Repair any corrupted/mismatched state first.
        let (_noop, repaired) = self.fallback_to(state)?;

        if self.graph.index_of(target_key).is_none() {
            return Err(MprdError::InvalidInput(format!(
                "SafetyController::compute_action_towards_target: unknown target_key={target_key}"
            )));
        }

        let cur_key = repaired.current_node_key;
        let action = self.graph.action_towards_keys(cur_key, target_key)?;
        let next_key = self.graph.step_towards_key(cur_key, target_key)?;

        let next_idx = self.graph.index_of(next_key).ok_or_else(|| {
            MprdError::ExecutionError(format!(
                "SafetyController::compute_action_towards_target: missing next_key={next_key}"
            ))
        })?;
        let next_node = *self.graph.node(next_idx).ok_or_else(|| {
            MprdError::ExecutionError(format!(
                "SafetyController::compute_action_towards_target: missing node at next_idx={next_idx}"
            ))
        })?;

        Ok((
            SafetyProposal {
                action,
                next_node_key: next_key,
                next_node,
            },
            SafetyControllerState {
                graph_version: repaired.graph_version,
                graph_hash: repaired.graph_hash,
                current_node_key: next_key,
                burn_pid: repaired.burn_pid,
                auction_pid: repaired.auction_pid,
                drip_pid: repaired.drip_pid,
            },
        ))
    }

    /// Fallback-to-noop: always returns a safe, graph-consistent proposal + state.
    ///
    /// If `state` is invalid/corrupted (graph mismatch, missing node key), this repairs the state by
    /// resetting to the first node in the canonical graph ordering.
    pub fn fallback_to(
        &self,
        state: &SafetyControllerState,
    ) -> Result<(SafetyProposal, SafetyControllerState)> {
        let first_node = self.graph.node(0).ok_or_else(|| {
            MprdError::ExecutionError(
                "SafetyController::fallback_to: menu graph has zero nodes (unexpected)".into(),
            )
        })?;
        let default_key = first_node.key();

        let safe_key = if (state.graph_version, state.graph_hash)
            == (self.graph_id.version, self.graph_id.hash)
            && self.graph.index_of(state.current_node_key).is_some()
        {
            state.current_node_key
        } else {
            default_key
        };

        let safe_idx = self.graph.index_of(safe_key).ok_or_else(|| {
            MprdError::ExecutionError(format!(
                "SafetyController::fallback_to: menu graph missing node for safe_key={safe_key}"
            ))
        })?;

        let node = *self.graph.node(safe_idx).ok_or_else(|| {
            MprdError::ExecutionError(format!(
                "SafetyController::fallback_to: menu graph missing node at safe_idx={safe_idx}"
            ))
        })?;

        Ok((
            SafetyProposal {
                action: ActionId::NOOP,
                next_node_key: safe_key,
                next_node: node,
            },
            SafetyControllerState {
                graph_version: self.graph_id.version,
                graph_hash: self.graph_id.hash,
                current_node_key: safe_key,
                burn_pid: state.burn_pid,
                auction_pid: state.auction_pid,
                drip_pid: state.drip_pid,
            },
        ))
    }

    /// Alias for `fallback_to`.
    pub fn fallback(
        &self,
        state: &SafetyControllerState,
    ) -> Result<(SafetyProposal, SafetyControllerState)> {
        self.fallback_to(state)
    }
}

fn bps_abs_i64(a: Bps, b: Bps) -> i64 {
    (a.get() as i64 - b.get() as i64).abs()
}

fn enforce_split_cap_preserve_burn(burn: Bps, auction: Bps) -> Result<(Bps, Bps)> {
    let burn_u = burn.get() as u32;
    let auction_u = auction.get() as u32;
    let cap = BPS_U16 as u32;

    if burn_u.saturating_add(auction_u) <= cap {
        return Ok((burn, auction));
    }

    // With the v6 menu bounds, `burn ∈ [5000, 9500]` so `cap - burn ∈ [500, 5000]` and is always
    // representable as a valid auction bps.
    let auction_proj = cap.saturating_sub(burn_u);
    Ok((burn, Bps::new(auction_proj as u16)?))
}

fn weighted_pid_distance(
    targets: (Bps, Bps, Bps),
    weights: (i64, i64, i64),
    candidate: MenuNode,
) -> i64 {
    let (t_burn, t_auction, t_drip) = targets;
    let (w_burn, w_auction, w_drip) = weights;

    let burn = w_burn.saturating_mul(bps_abs_i64(t_burn, candidate.burn_bps()));
    let auction = w_auction.saturating_mul(bps_abs_i64(t_auction, candidate.auction_bps()));
    let drip = w_drip.saturating_mul(bps_abs_i64(t_drip, candidate.drip_bps()));

    burn.saturating_add(auction).saturating_add(drip)
}

fn l1_setpoint_distance(setpoints: (Bps, Bps, Bps), candidate: MenuNode) -> i64 {
    let (s_burn, s_auction, s_drip) = setpoints;
    bps_abs_i64(s_burn, candidate.burn_bps())
        .saturating_add(bps_abs_i64(s_auction, candidate.auction_bps()))
        .saturating_add(bps_abs_i64(s_drip, candidate.drip_bps()))
}

fn control_effort(action: ActionId) -> u8 {
    let d = action.to_delta();
    let mut effort = 0u8;
    if d.db != Step::Zero {
        effort = effort.saturating_add(1);
    }
    if d.da != Step::Zero {
        effort = effort.saturating_add(1);
    }
    if d.dd != Step::Zero {
        effort = effort.saturating_add(1);
    }
    effort
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokenomics_v6::types::{AuctionPct, BurnPct, DripStep, ValidSplit};
    use proptest::prelude::*;
    use std::sync::LazyLock;

    static GRAPH: LazyLock<MenuGraph> = LazyLock::new(|| MenuGraph::generate().unwrap());

    fn graph() -> &'static MenuGraph {
        &GRAPH
    }

    fn default_config() -> SafetyControllerConfig {
        SafetyControllerConfig {
            burn_gains: PidBpsGains {
                kp: 1,
                ki: 0,
                kd: 0,
            },
            auction_gains: PidBpsGains {
                kp: 1,
                ki: 0,
                kd: 0,
            },
            drip_gains: PidBpsGains {
                kp: 1,
                ki: 0,
                kd: 0,
            },
            burn_cfg: PidBpsConfig {
                min_bps: Bps::new(5000).unwrap(),
                max_bps: Bps::new(9500).unwrap(),
                step_limit_bps: 100,
                i_min: -10000,
                i_max: 10000,
            },
            auction_cfg: PidBpsConfig {
                min_bps: Bps::new(500).unwrap(),
                max_bps: Bps::new(5000).unwrap(),
                step_limit_bps: 100,
                i_min: -10000,
                i_max: 10000,
            },
            drip_cfg: PidBpsConfig {
                min_bps: Bps::new(5).unwrap(),
                max_bps: Bps::new(100).unwrap(),
                step_limit_bps: 5,
                i_min: -10000,
                i_max: 10000,
            },
        }
    }

    #[test]
    fn test_safety_controller_moves_toward_setpoint() {
        let graph = graph();
        let controller = SafetyController::new(graph, default_config()).unwrap();

        // Start at some node
        let start_idx = graph.node_count() / 2;
        let state = SafetyControllerState::new_from_idx(graph, start_idx).unwrap();

        // Set a setpoint that's different from current
        let current_node = graph.node(start_idx).unwrap();
        let burn_setpoint =
            Bps::new(current_node.burn_bps().get().saturating_add(200)).unwrap_or(Bps::MAX);
        let auction_setpoint = current_node.auction_bps();
        let drip_setpoint = current_node.drip_bps();

        let (proposal, _new_state) = controller
            .compute_action(&state, burn_setpoint, auction_setpoint, drip_setpoint)
            .unwrap();

        // Should either move toward setpoint or NoOp if at boundary
        assert!(
            proposal.next_node.burn_bps().get() >= current_node.burn_bps().get()
                || proposal.action == ActionId::NOOP
        );
    }

    #[test]
    fn test_safety_controller_fallback_repairs_invalid_state() {
        let graph = graph();
        let controller = SafetyController::new(graph, default_config()).unwrap();

        // Construct an invalid state (tests are allowed to break invariants).
        let graph0_key = graph.node(0).unwrap().key();
        let state = SafetyControllerState {
            graph_version: 0,
            graph_hash: Hash32([0u8; 32]),
            current_node_key: u32::MAX,
            burn_pid: PidBpsState::default(),
            auction_pid: PidBpsState::default(),
            drip_pid: PidBpsState::default(),
        };

        let (fallback, new_state) = controller.fallback_to(&state).unwrap();
        assert_eq!(fallback.action, ActionId::NOOP);
        assert_eq!(fallback.next_node_key, graph0_key);
        assert_eq!(new_state.current_node_key(), graph0_key);
    }

    #[test]
    fn split_cap_plateau_prefers_axis_with_error() {
        let graph = graph();
        let controller = SafetyController::new(graph, default_config()).unwrap();

        // Choose a node exactly on the split cap: burn=9300, auction=700, drip=50.
        let burn = BurnPct::new(43).unwrap(); // 5000 + 43*100 = 9300
        let auction = AuctionPct::new(7).unwrap(); // 7*100 = 700
        let drip = DripStep::new(10).unwrap(); // 10*5 = 50
        let split = ValidSplit::new(burn, auction).unwrap();
        let node = MenuNode::new(split, drip);

        let state = SafetyControllerState::new(graph, node.key()).unwrap();

        // Burn wants to increase by one step, auction wants to stay; split cap forces auction down.
        let burn_setpoint = Bps::new(9400).unwrap();
        let auction_setpoint = Bps::new(700).unwrap();
        let drip_setpoint = Bps::new(50).unwrap();

        let (proposal, _state2) = controller
            .compute_action(&state, burn_setpoint, auction_setpoint, drip_setpoint)
            .unwrap();

        assert_ne!(proposal.action, ActionId::NOOP);
        assert_eq!(proposal.next_node.burn_bps(), Bps::new(9400).unwrap());
        assert_eq!(proposal.next_node.auction_bps(), Bps::new(600).unwrap());
    }

    #[test]
    fn pid_integrator_can_trigger_quantized_step() {
        let graph = graph();
        let mut cfg = default_config();
        cfg.burn_gains = PidBpsGains {
            kp: 0,
            ki: 1,
            kd: 0,
        };

        let controller = SafetyController::new(graph, cfg).unwrap();

        // burn=8000, auction=1000 (far from split cap), drip=50.
        let burn = BurnPct::new(30).unwrap(); // 8000
        let auction = AuctionPct::new(10).unwrap(); // 1000
        let drip = DripStep::new(10).unwrap(); // 50
        let split = ValidSplit::new(burn, auction).unwrap();
        let node = MenuNode::new(split, drip);

        let state0 = SafetyControllerState::new(graph, node.key()).unwrap();
        let burn_setpoint = Bps::new(8050).unwrap(); // +50 (below a full lattice step)

        let (p1, state1) = controller
            .compute_action(&state0, burn_setpoint, node.auction_bps(), node.drip_bps())
            .unwrap();
        assert_eq!(p1.action, ActionId::NOOP);

        // Second step: integrator accumulates enough to justify a full lattice move.
        let (p2, _state2) = controller
            .compute_action(&state1, burn_setpoint, node.auction_bps(), node.drip_bps())
            .unwrap();
        assert_ne!(p2.action, ActionId::NOOP);
        assert_eq!(p2.next_node.burn_bps(), Bps::new(8100).unwrap());
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 32,
            .. ProptestConfig::default()
        })]

        #[test]
        fn compute_action_always_returns_graph_edge(
            node_offset in 0usize..10_000,
            burn_sp in 0u16..=BPS_U16,
            auction_sp in 0u16..=BPS_U16,
            drip_sp in 0u16..=BPS_U16,
        ) {
            let graph = graph();
            let controller = SafetyController::new(graph, default_config()).unwrap();

            let start_idx = node_offset % graph.node_count();
            let state = SafetyControllerState::new_from_idx(graph, start_idx).unwrap();

            let burn_setpoint = Bps::new(burn_sp).unwrap();
            let auction_setpoint = Bps::new(auction_sp).unwrap();
            let drip_setpoint = Bps::new(drip_sp).unwrap();

            let (proposal, state2) = controller.compute_action(&state, burn_setpoint, auction_setpoint, drip_setpoint).unwrap();

            let cur_idx = graph.index_of(state.current_node_key()).unwrap();
            let next_idx = graph.index_of(proposal.next_node_key).unwrap();

            prop_assert_eq!(
                graph.apply_action(cur_idx, proposal.action),
                Some(next_idx)
            );
            prop_assert_eq!(
                graph.node(next_idx).copied(),
                Some(proposal.next_node)
            );
            prop_assert_eq!(state2.current_node_key(), proposal.next_node_key);
        }
    }

    #[test]
    fn compute_action_towards_target_reaches_target() {
        let graph = graph();
        let controller = SafetyController::new(graph, default_config()).unwrap();

        let n = graph.node_count();
        let cur_idx = n / 3;
        let tgt_idx = (n / 3 + 123) % n;

        let cur_key = graph.node(cur_idx).unwrap().key();
        let tgt_key = graph.node(tgt_idx).unwrap().key();

        let mut state = SafetyControllerState::new(graph, cur_key).unwrap();
        let dist = graph.dist_inf_keys(cur_key, tgt_key).unwrap() as usize;

        for _ in 0..dist {
            let (_proposal, state2) = controller
                .compute_action_towards_target(&state, tgt_key)
                .unwrap();
            state = state2;
        }

        assert_eq!(state.current_node_key(), tgt_key);
    }
}
