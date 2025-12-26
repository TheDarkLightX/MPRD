//! Algorithmic CEO: Menu Graph
//!
//! This module implements the graph-based safe menu for the Algorithmic CEO.
//! The graph contains all valid setpoint configurations as nodes, with edges
//! representing step-feasible transitions.
//!
//! See: internal/specs/REVIEW__mprd_tokenomics_v6_algorithmic_ceo_menu__codex_gpt-5_2__2025-12-25.md

use std::collections::BTreeMap;

use crate::{hash, Hash32, MprdError, Result};

use super::types::{ActionId, AuctionPct, BurnPct, DomainError, DripStep, MenuNode, ValidSplit};

/// Menu graph version (increment on any structural change)
pub const MENU_GRAPH_VERSION: u32 = 1;

/// A precomputed menu graph with all valid nodes and adjacency.
#[derive(Debug, Clone)]
pub struct MenuGraph {
    /// Graph version for audit trail
    pub version: u32,

    /// All valid nodes, sorted by key for determinism
    nodes: Vec<MenuNode>,

    /// Key → index lookup
    index: BTreeMap<u32, usize>,

    /// Adjacency: neighbors[node_idx][action_id] = Some(neighbor_idx)
    neighbors: Vec<[Option<usize>; ActionId::COUNT]>,
}

impl MenuGraph {
    /// Generates the complete menu graph by enumerating all valid nodes.
    ///
    /// Time: O(B × A × D) where B, A, D are the lattice coordinate ranges.
    /// Space: O(N × 27) where N is the number of valid nodes.
    pub fn generate() -> Result<Self> {
        let mut nodes = Vec::new();

        // Enumerate all valid lattice points
        for b in BurnPct::MIN_UNITS..=BurnPct::MAX_UNITS {
            let burn = BurnPct::new(b).map_err(|e| {
                MprdError::ExecutionError(format!("MenuGraph::generate: invalid BurnPct {b}: {e}"))
            })?;

            for a in AuctionPct::MIN_UNITS..=AuctionPct::MAX_UNITS {
                let auction = AuctionPct::new(a).map_err(|e| {
                    MprdError::ExecutionError(format!(
                        "MenuGraph::generate: invalid AuctionPct {a}: {e}"
                    ))
                })?;

                // Check split cap (expected to fail for many lattice points).
                let split = match ValidSplit::new(burn, auction) {
                    Ok(split) => split,
                    Err(DomainError::SplitCapExceeded { .. }) => continue,
                    Err(e) => {
                        return Err(MprdError::ExecutionError(format!(
                            "MenuGraph::generate: unexpected split validation error: {e}"
                        )));
                    }
                };

                for d in DripStep::MIN_UNITS..=DripStep::MAX_UNITS {
                    let drip = DripStep::new(d).map_err(|e| {
                        MprdError::ExecutionError(format!(
                            "MenuGraph::generate: invalid DripStep {d}: {e}"
                        ))
                    })?;

                    let node = MenuNode::new(split, drip);
                    nodes.push(node);
                }
            }
        }

        // Canonical ordering: stable, unique node keys.
        nodes.sort_by_key(|n| n.key());

        let mut index = BTreeMap::new();
        for (idx, node) in nodes.iter().enumerate() {
            let key = node.key();
            if index.insert(key, idx).is_some() {
                return Err(MprdError::ExecutionError(format!(
                    "MenuGraph::generate: duplicate node key {key}"
                )));
            }
        }

        // Build adjacency matrix
        let mut neighbors: Vec<[Option<usize>; ActionId::COUNT]> =
            vec![[None; ActionId::COUNT]; nodes.len()];

        for (idx, node) in nodes.iter().enumerate() {
            for action in ActionId::iter() {
                let action_idx = action.index() as usize;
                let delta = action.to_delta();

                match node.apply_delta(&delta) {
                    Ok(next_node) => {
                        let next_key = next_node.key();
                        let next_idx = index.get(&next_key).copied().ok_or_else(|| {
                            MprdError::ExecutionError(format!(
                                "MenuGraph::generate: missing neighbor node key {next_key} (from_key={} action={})",
                                node.key(),
                                action.index()
                            ))
                        })?;
                        neighbors[idx][action_idx] = Some(next_idx);
                    }
                    Err(
                        DomainError::BurnStepOutOfBounds { .. }
                        | DomainError::AuctionStepOutOfBounds { .. }
                        | DomainError::DripStepOutOfBounds { .. }
                        | DomainError::SplitCapExceeded { .. },
                    ) => {
                        // Not a valid one-step neighbor; the edge is absent (fail-closed).
                    }
                }
            }
        }

        Ok(Self {
            version: MENU_GRAPH_VERSION,
            nodes,
            index,
            neighbors,
        })
    }

    /// Number of nodes in the graph
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get a node by index
    pub fn node(&self, idx: usize) -> Option<&MenuNode> {
        self.nodes.get(idx)
    }

    /// Get a node index by key
    pub fn index_of(&self, key: u32) -> Option<usize> {
        self.index.get(&key).copied()
    }

    /// Get all valid actions from a node
    pub fn valid_actions(&self, node_idx: usize) -> impl Iterator<Item = ActionId> + '_ {
        ActionId::iter().filter_map(move |action| {
            if self
                .neighbors
                .get(node_idx)?
                .get(action.index() as usize)?
                .is_some()
            {
                Some(action)
            } else {
                None
            }
        })
    }

    /// Apply an action, returning the neighbor index if valid
    pub fn apply_action(&self, node_idx: usize, action: ActionId) -> Option<usize> {
        self.neighbors
            .get(node_idx)?
            .get(action.index() as usize)?
            .as_ref()
            .copied()
    }

    /// Compute a canonical hash of the graph for audit/versioning
    pub fn canonical_hash(&self) -> Result<Hash32> {
        const DOMAIN: &[u8] = b"MPRD_CEO_MENU_GRAPH_V1";

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_le_bytes());
        let node_count_u32 = u32::try_from(self.nodes.len()).map_err(|_| {
            MprdError::BoundedValueExceeded(format!(
                "MenuGraph::canonical_hash: node_count {} exceeds u32::MAX",
                self.nodes.len()
            ))
        })?;
        bytes.extend_from_slice(&node_count_u32.to_le_bytes());

        // Include all node keys (deterministic ordering: `nodes` is sorted by key).
        for node in &self.nodes {
            bytes.extend_from_slice(&node.key().to_le_bytes());
        }

        // Include adjacency (sparse: only encode existing edges)
        for (node_idx, node_neighbors) in self.neighbors.iter().enumerate() {
            for (action_idx, neighbor) in node_neighbors.iter().enumerate() {
                if let Some(next_idx) = neighbor {
                    let node_idx_u32 = u32::try_from(node_idx).map_err(|_| {
                        MprdError::BoundedValueExceeded(format!(
                            "MenuGraph::canonical_hash: node_idx {node_idx} exceeds u32::MAX"
                        ))
                    })?;
                    let action_idx_u8 = u8::try_from(action_idx).map_err(|_| {
                        MprdError::BoundedValueExceeded(format!(
                            "MenuGraph::canonical_hash: action_idx {action_idx} exceeds u8::MAX"
                        ))
                    })?;
                    let next_idx_u32 = u32::try_from(*next_idx).map_err(|_| {
                        MprdError::BoundedValueExceeded(format!(
                            "MenuGraph::canonical_hash: next_idx {next_idx} exceeds u32::MAX"
                        ))
                    })?;

                    bytes.extend_from_slice(&node_idx_u32.to_le_bytes());
                    bytes.push(action_idx_u8);
                    bytes.extend_from_slice(&next_idx_u32.to_le_bytes());
                }
            }
        }

        Ok(hash::sha256_domain(DOMAIN, &bytes))
    }

    /// Get statistics about the graph
    pub fn stats(&self) -> MenuGraphStats {
        let mut total_edges = 0;
        let mut min_degree = ActionId::COUNT;
        let mut max_degree = 0usize;

        for node_neighbors in &self.neighbors {
            let degree = node_neighbors.iter().filter(|n| n.is_some()).count();
            total_edges += degree;
            min_degree = min_degree.min(degree);
            max_degree = max_degree.max(degree);
        }

        MenuGraphStats {
            version: self.version,
            node_count: self.nodes.len(),
            edge_count: total_edges,
            min_degree,
            max_degree,
        }
    }

    /// BFS to find all nodes reachable within H steps
    pub fn reachable(&self, start_idx: usize, horizon: u8) -> Vec<usize> {
        use std::collections::VecDeque;

        let mut visited = vec![false; self.nodes.len()];
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        if start_idx >= self.nodes.len() {
            return result;
        }

        queue.push_back((start_idx, 0u8));
        visited[start_idx] = true;

        while let Some((idx, depth)) = queue.pop_front() {
            result.push(idx);

            if depth < horizon {
                for action in ActionId::iter() {
                    if let Some(next_idx) = self.neighbors[idx][action.index() as usize] {
                        if !visited[next_idx] {
                            visited[next_idx] = true;
                            queue.push_back((next_idx, depth + 1));
                        }
                    }
                }
            }
        }

        result
    }

    /// Chebyshev (L∞) distance on the lattice between two *valid* node keys.
    ///
    /// This is the exact shortest-path length in the safe-menu graph for this lattice adjacency
    /// (proved for the step system; Rust uses the graph as the executable artifact).
    pub fn dist_inf_keys(&self, a_key: u32, b_key: u32) -> Result<u8> {
        if self.index_of(a_key).is_none() {
            return Err(MprdError::InvalidInput(format!(
                "MenuGraph::dist_inf_keys: unknown a_key={a_key}"
            )));
        }
        if self.index_of(b_key).is_none() {
            return Err(MprdError::InvalidInput(format!(
                "MenuGraph::dist_inf_keys: unknown b_key={b_key}"
            )));
        }

        let (ab, aa, ad) = decode_key_units(a_key);
        let (bb, ba, bd) = decode_key_units(b_key);

        let db = ab.abs_diff(bb);
        let da = aa.abs_diff(ba);
        let dd = ad.abs_diff(bd);
        Ok(db.max(da).max(dd))
    }

    /// One safe "sign step" action toward the target (keys must exist in this graph).
    ///
    /// If `cur_key == tgt_key`, returns `ActionId::NOOP`.
    pub fn action_towards_keys(&self, cur_key: u32, tgt_key: u32) -> Result<ActionId> {
        if self.index_of(cur_key).is_none() {
            return Err(MprdError::InvalidInput(format!(
                "MenuGraph::action_towards_keys: unknown cur_key={cur_key}"
            )));
        }
        if self.index_of(tgt_key).is_none() {
            return Err(MprdError::InvalidInput(format!(
                "MenuGraph::action_towards_keys: unknown tgt_key={tgt_key}"
            )));
        }

        let (cb, ca, cd) = decode_key_units(cur_key);
        let (tb, ta, td) = decode_key_units(tgt_key);

        let delta = super::types::Delta {
            db: step_dir(cb, tb),
            da: step_dir(ca, ta),
            dd: step_dir(cd, td),
        };
        Ok(ActionId::from_delta(&delta))
    }

    /// Apply the `action_towards_keys` move once, producing the next node key.
    ///
    /// This is the O(1) shortest-path navigation primitive used by higher-level controllers:
    /// they may choose any valid `tgt_key`, and the safety rail moves one step toward it.
    pub fn step_towards_key(&self, cur_key: u32, tgt_key: u32) -> Result<u32> {
        let action = self.action_towards_keys(cur_key, tgt_key)?;
        let cur_idx = self.index_of(cur_key).ok_or_else(|| {
            MprdError::InvalidInput(format!(
                "MenuGraph::step_towards_key: unknown cur_key={cur_key}"
            ))
        })?;
        let next_idx = self.apply_action(cur_idx, action).ok_or_else(|| {
            MprdError::ExecutionError(format!(
                "MenuGraph::step_towards_key: missing edge (cur_key={cur_key} tgt_key={tgt_key} action={})",
                action.index()
            ))
        })?;
        let next_key = self
            .node(next_idx)
            .ok_or_else(|| {
                MprdError::ExecutionError(format!(
                    "MenuGraph::step_towards_key: neighbor index out of range next_idx={next_idx}"
                ))
            })?
            .key();
        Ok(next_key)
    }

    /// Nodes reachable within `horizon` steps from `start_key`, computed as the intersection of the
    /// L∞ ball with the valid lattice region.
    ///
    /// Compared to `reachable` (BFS), this is:
    /// - deterministic (sorted by lattice enumeration),
    /// - bounded by `(2h+1)^3` candidates,
    /// - free of adjacency traversal.
    pub fn reachable_inf_ball_by_key(&self, start_key: u32, horizon: u8) -> Result<Vec<usize>> {
        if self.index_of(start_key).is_none() {
            return Err(MprdError::InvalidInput(format!(
                "MenuGraph::reachable_inf_ball_by_key: unknown start_key={start_key}"
            )));
        }

        let (b0, a0, d0) = decode_key_units(start_key);
        let h = horizon as i32;

        let b_min = (b0 as i32 - h).max(BurnPct::MIN_UNITS as i32);
        let b_max = (b0 as i32 + h).min(BurnPct::MAX_UNITS as i32);
        let a_min = (a0 as i32 - h).max(AuctionPct::MIN_UNITS as i32);
        let a_max = (a0 as i32 + h).min(AuctionPct::MAX_UNITS as i32);
        let d_min = (d0 as i32 - h).max(DripStep::MIN_UNITS as i32);
        let d_max = (d0 as i32 + h).min(DripStep::MAX_UNITS as i32);

        let mut out = Vec::new();
        for b in b_min..=b_max {
            for a in a_min..=a_max {
                // split cap: burn_bps + auction_bps <= 10_000 ↔ b + a <= 50 in lattice units.
                if (b as u32).saturating_add(a as u32) > 50 {
                    continue;
                }
                for d in d_min..=d_max {
                    let key = ((b as u32) << 16) | ((a as u32) << 8) | (d as u32);
                    let idx = self.index_of(key).ok_or_else(|| {
                        MprdError::ExecutionError(format!(
                            "MenuGraph::reachable_inf_ball_by_key: missing node for key={key}"
                        ))
                    })?;
                    out.push(idx);
                }
            }
        }
        Ok(out)
    }
}

fn decode_key_units(key: u32) -> (u8, u8, u8) {
    let b = ((key >> 16) & 0xff) as u8;
    let a = ((key >> 8) & 0xff) as u8;
    let d = (key & 0xff) as u8;
    (b, a, d)
}

fn step_dir(cur: u8, tgt: u8) -> super::types::Step {
    if cur < tgt {
        super::types::Step::Pos
    } else if tgt < cur {
        super::types::Step::Neg
    } else {
        super::types::Step::Zero
    }
}

/// Statistics about a menu graph
#[derive(Debug, Clone)]
pub struct MenuGraphStats {
    pub version: u32,
    pub node_count: usize,
    pub edge_count: usize,
    pub min_degree: usize,
    pub max_degree: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokenomics_v6::types::{Delta, BPS_U16};
    use std::collections::BTreeSet;

    #[test]
    fn test_generate_graph() {
        let graph = MenuGraph::generate().unwrap();
        let stats = graph.stats();

        // Verify reasonable node count (should be tens of thousands)
        assert!(
            stats.node_count > 1000,
            "Expected >1000 nodes, got {}",
            stats.node_count
        );
        assert!(
            stats.node_count < 100_000,
            "Expected <100k nodes, got {}",
            stats.node_count
        );

        // Verify NoOp is always a valid action (self-loop)
        for idx in 0..graph.node_count() {
            let noop_neighbor = graph.apply_action(idx, ActionId::NOOP);
            assert_eq!(
                noop_neighbor,
                Some(idx),
                "NoOp should be a self-loop for node {idx}"
            );
        }

        println!("Graph stats: {:?}", stats);
    }

    #[test]
    fn test_canonical_hash_deterministic() {
        let graph1 = MenuGraph::generate().unwrap();
        let graph2 = MenuGraph::generate().unwrap();

        assert_eq!(
            graph1.canonical_hash().unwrap(),
            graph2.canonical_hash().unwrap(),
            "Same generation should produce same hash"
        );
    }

    #[test]
    fn test_enumerates_all_valid_nodes() {
        let graph = MenuGraph::generate().unwrap();

        let mut expected_keys = BTreeSet::new();
        for b in BurnPct::MIN_UNITS..=BurnPct::MAX_UNITS {
            let burn_bps = BurnPct::MIN_BPS as u32 + (b as u32) * (BurnPct::STEP_BPS as u32);

            for a in AuctionPct::MIN_UNITS..=AuctionPct::MAX_UNITS {
                let auction_bps = (a as u32) * (AuctionPct::STEP_BPS as u32);

                if burn_bps + auction_bps > (BPS_U16 as u32) {
                    continue;
                }

                for d in DripStep::MIN_UNITS..=DripStep::MAX_UNITS {
                    let key = ((b as u32) << 16) | ((a as u32) << 8) | (d as u32);
                    expected_keys.insert(key);
                }
            }
        }

        let graph_keys: BTreeSet<u32> = graph.nodes.iter().map(|n| n.key()).collect();
        assert_eq!(
            graph_keys, expected_keys,
            "graph node set must match lattice definition"
        );

        // Ensure ordering and index map are consistent with keys.
        let mut prev_key: Option<u32> = None;
        for (idx, node) in graph.nodes.iter().enumerate() {
            let key = node.key();
            if let Some(prev) = prev_key {
                assert!(
                    prev < key,
                    "nodes must be strictly increasing by key (idx={idx} prev={prev} key={key})"
                );
            }
            prev_key = Some(key);

            assert_eq!(
                graph.index_of(key),
                Some(idx),
                "index map must point back to node (key={key})"
            );

            // Key must be a canonical packing of the node's unit coordinates.
            let burn_u = node.split().burn().units() as u32;
            let auction_u = node.split().auction().units() as u32;
            let drip_u = node.drip().units() as u32;
            let expected_key = (burn_u << 16) | (auction_u << 8) | drip_u;
            assert_eq!(key, expected_key, "MenuNode::key must be canonical");
        }
    }

    #[test]
    fn test_adjacency_matches_lattice_rules() {
        let graph = MenuGraph::generate().unwrap();

        for (node_idx, node) in graph.nodes.iter().enumerate() {
            let key = node.key();
            let b = ((key >> 16) & 0xff) as i32;
            let a = ((key >> 8) & 0xff) as i32;
            let d = (key & 0xff) as i32;

            for action_idx in 0u8..(ActionId::COUNT as u8) {
                let db = (action_idx / 9) as i32 - 1;
                let da = ((action_idx / 3) % 3) as i32 - 1;
                let dd = (action_idx % 3) as i32 - 1;

                let b2 = b + db;
                let a2 = a + da;
                let d2 = d + dd;

                let within_bounds = (BurnPct::MIN_UNITS as i32..=BurnPct::MAX_UNITS as i32)
                    .contains(&b2)
                    && (AuctionPct::MIN_UNITS as i32..=AuctionPct::MAX_UNITS as i32).contains(&a2)
                    && (DripStep::MIN_UNITS as i32..=DripStep::MAX_UNITS as i32).contains(&d2);

                let split_ok = if within_bounds {
                    let burn_bps =
                        BurnPct::MIN_BPS as u32 + (b2 as u32) * (BurnPct::STEP_BPS as u32);
                    let auction_bps = (a2 as u32) * (AuctionPct::STEP_BPS as u32);
                    burn_bps + auction_bps <= (BPS_U16 as u32)
                } else {
                    false
                };

                let action = ActionId::new(action_idx).unwrap();
                let got = graph.apply_action(node_idx, action);

                if within_bounds && split_ok {
                    let expected_key = ((b2 as u32) << 16) | ((a2 as u32) << 8) | (d2 as u32);
                    let expected_idx = graph.index_of(expected_key);
                    assert_eq!(
                        got, expected_idx,
                        "expected valid edge (from_key={key} action={action_idx} to_key={expected_key})"
                    );
                } else {
                    assert_eq!(
                        got, None,
                        "expected invalid edge to be absent (from_key={key} action={action_idx})"
                    );
                }
            }
        }
    }

    #[test]
    fn test_action_roundtrip() {
        for action in ActionId::iter() {
            let delta = action.to_delta();
            let roundtrip = ActionId::from_delta(&delta);
            assert_eq!(
                action,
                roundtrip,
                "ActionId roundtrip failed for {}",
                action.index()
            );
        }

        // Verify NoOp encoding
        assert_eq!(ActionId::NOOP.index(), 13);
        let noop_delta = ActionId::NOOP.to_delta();
        assert_eq!(noop_delta, Delta::NOOP);
    }

    #[test]
    fn test_reachable() {
        let graph = MenuGraph::generate().unwrap();

        // Find a node in the middle of the graph
        let mid_idx = graph.node_count() / 2;
        let reachable_1 = graph.reachable(mid_idx, 1);
        let reachable_2 = graph.reachable(mid_idx, 2);

        // H=1 should include self + some neighbors
        assert!(reachable_1.contains(&mid_idx));
        assert!(reachable_1.len() <= 27); // At most 26 neighbors + self

        // H=2 should reach more nodes
        assert!(reachable_2.len() >= reachable_1.len());
    }

    #[test]
    fn reachable_inf_ball_matches_bfs_for_small_horizons() {
        use std::collections::BTreeSet;

        let graph = MenuGraph::generate().unwrap();
        let mid_idx = graph.node_count() / 2;
        let start_key = graph.node(mid_idx).unwrap().key();

        for h in 0u8..=3 {
            let bfs: BTreeSet<usize> = graph.reachable(mid_idx, h).into_iter().collect();
            let ball: BTreeSet<usize> = graph
                .reachable_inf_ball_by_key(start_key, h)
                .unwrap()
                .into_iter()
                .collect();
            assert_eq!(bfs, ball, "reachable set mismatch at horizon {h}");
        }
    }

    #[test]
    fn step_towards_key_reaches_target_in_dist() {
        let graph = MenuGraph::generate().unwrap();

        // Deterministic sampling of pairs by index stride.
        let n = graph.node_count();
        for i in 0..25usize {
            let cur_idx = (i * 997) % n;
            let tgt_idx = (i * 1237 + 17) % n;

            let cur_key = graph.node(cur_idx).unwrap().key();
            let tgt_key = graph.node(tgt_idx).unwrap().key();

            let dist = graph.dist_inf_keys(cur_key, tgt_key).unwrap() as usize;
            let mut k = cur_key;
            for _ in 0..dist {
                k = graph.step_towards_key(k, tgt_key).unwrap();
            }
            assert_eq!(k, tgt_key);
        }
    }
}
