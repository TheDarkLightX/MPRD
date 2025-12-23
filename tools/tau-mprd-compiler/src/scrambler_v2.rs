//! KSO v2 (Keyless Structural Obfuscation) transformer for Tau-MPRD v2 DAGs.
//!
//! This module implements the 6-layer scrambling algorithm defined in
//! `internal/specs/circuit_scrambler_v2.md`.
//!
//! **Status:** Experimental. Feature-flagged.

use crate::ir_v2::{CompiledPolicyV2, NodeTypeV2, NodeV2};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;

fn used_input_indices(node_type: NodeTypeV2) -> &'static [usize] {
    match node_type {
        NodeTypeV2::LoadStateU64
        | NodeTypeV2::LoadCandidateU64
        | NodeTypeV2::ConstU64
        | NodeTypeV2::ConstBool => &[],

        NodeTypeV2::MulConst | NodeTypeV2::DivConst | NodeTypeV2::Not => &[0],

        NodeTypeV2::Clamp => &[0, 1, 2],

        NodeTypeV2::Add
        | NodeTypeV2::Sub
        | NodeTypeV2::Min
        | NodeTypeV2::Max
        | NodeTypeV2::Eq
        | NodeTypeV2::Ne
        | NodeTypeV2::Lt
        | NodeTypeV2::Le
        | NodeTypeV2::Gt
        | NodeTypeV2::Ge
        | NodeTypeV2::And
        | NodeTypeV2::Or => &[0, 1],
    }
}

fn is_bool_node_type(node_type: NodeTypeV2) -> bool {
    matches!(
        node_type,
        NodeTypeV2::ConstBool
            | NodeTypeV2::Eq
            | NodeTypeV2::Ne
            | NodeTypeV2::Lt
            | NodeTypeV2::Le
            | NodeTypeV2::Gt
            | NodeTypeV2::Ge
            | NodeTypeV2::And
            | NodeTypeV2::Or
            | NodeTypeV2::Not
    )
}

fn is_u64_node_type(node_type: NodeTypeV2) -> bool {
    matches!(
        node_type,
        NodeTypeV2::LoadStateU64
            | NodeTypeV2::LoadCandidateU64
            | NodeTypeV2::ConstU64
            | NodeTypeV2::Add
            | NodeTypeV2::Sub
            | NodeTypeV2::MulConst
            | NodeTypeV2::DivConst
            | NodeTypeV2::Min
            | NodeTypeV2::Max
            | NodeTypeV2::Clamp
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedundantStrategy {
    /// KSO v2: Merge via an always-true predicate selector (correct but easy to DCE if recognized).
    MergeSelector,
    /// KSO v2.1 (LCO): Inject decoys via min/max lattice absorption: `min(x, max(x, d)) = x`.
    AbsorptionMinMax,
}

/// Configuration for KSO v2 scrambling.
#[derive(Debug, Clone)]
pub struct KSOConfig {
    pub enable_constant_computation: bool,
    pub enable_domain_mixing: bool,
    pub expansion_budget: usize,
    pub enable_polymorphism: bool,
    pub redundant_path_count: usize,
    pub redundant_strategy: RedundantStrategy,
    pub max_expansion: f64,
}

impl Default for KSOConfig {
    fn default() -> Self {
        Self {
            enable_constant_computation: true,
            enable_domain_mixing: true,
            expansion_budget: 0,
            enable_polymorphism: true,
            redundant_path_count: 2,
            redundant_strategy: RedundantStrategy::AbsorptionMinMax,
            max_expansion: 2.5,
        }
    }
}

impl KSOConfig {
    pub fn minimal() -> Self {
        Self {
            enable_constant_computation: false,
            enable_domain_mixing: false,
            expansion_budget: 0,
            enable_polymorphism: false,
            redundant_path_count: 0,
            redundant_strategy: RedundantStrategy::AbsorptionMinMax,
            max_expansion: 1.0,
        }
    }

    pub fn light() -> Self {
        Self {
            enable_constant_computation: true,
            enable_domain_mixing: false,
            expansion_budget: 0,
            enable_polymorphism: true,
            redundant_path_count: 0,
            redundant_strategy: RedundantStrategy::AbsorptionMinMax,
            max_expansion: 1.5,
        }
    }
}

/// KSO v2 scrambler.
struct Scrambler {
    rng: ChaCha20Rng,
    nodes: Vec<NodeV2>,
    next_id: u32,
    max_nodes: usize,
}

impl Scrambler {
    fn new(seed: [u8; 32], initial_nodes: Vec<NodeV2>, max_expansion: f64) -> Self {
        let max_nodes = ((initial_nodes.len() as f64) * max_expansion).ceil() as usize;
        let next_id = initial_nodes.iter().map(|n| n.node_id).max().unwrap_or(0) + 1;
        Self {
            rng: ChaCha20Rng::from_seed(seed),
            nodes: initial_nodes,
            next_id,
            max_nodes,
        }
    }

    fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn can_add(&self, count: usize) -> bool {
        self.nodes.len() + count <= self.max_nodes
    }

    fn add(&mut self, node_type: NodeTypeV2, inputs: [u32; 3], const_value: u64) -> u32 {
        let id = self.alloc_id();
        self.nodes.push(NodeV2 {
            node_type,
            node_id: id,
            inputs,
            key_hash: [0; 32],
            const_value,
        });
        id
    }

    fn find_node_type(&self, node_id: u32) -> Option<NodeTypeV2> {
        self.nodes.iter().find(|n| n.node_id == node_id).map(|n| n.node_type)
    }

    fn remap(&mut self, old_id: u32, new_id: u32, output_node: &mut u32, max_idx: usize) {
        if *output_node == old_id {
            *output_node = new_id;
        }
        // Remap nodes that existed before this transformation to avoid accidentally rewriting
        // references inside the newly created replacement subgraph.
        for i in 0..max_idx.min(self.nodes.len()) {
            let node = &mut self.nodes[i];
            // Skip the node being replaced
            if node.node_id == old_id {
                continue;
            }
            for &slot in used_input_indices(node.node_type) {
                if node.inputs[slot] == old_id {
                    node.inputs[slot] = new_id;
                }
            }
        }
    }

    /// L1: Constant Computation - hide literals via expressions
    fn layer1(&mut self, output: &mut u32) {
        let max_idx = self.nodes.len();
        let anchors: Vec<u32> = self.nodes[..max_idx]
            .iter()
            .filter(|n| matches!(n.node_type, NodeTypeV2::LoadStateU64 | NodeTypeV2::LoadCandidateU64))
            .map(|n| n.node_id)
            .collect();

        let indices: Vec<usize> = (0..max_idx).collect();
        for idx in indices {
            let node = &self.nodes[idx];
            if node.node_type != NodeTypeV2::ConstU64 || !self.rng.gen_bool(0.7) {
                continue;
            }
            let value = node.const_value;
            let orig_id = node.node_id;

            // Prefer a cancellation form that depends on a live input (less trivial to constant-fold):
            //
            //   (t + a) - (t + b) = a - b = value   (wrapping u64 arithmetic)
            //
            // This keeps the subgraph "live" (depends on inputs) without introducing unsafe ops.
            if !anchors.is_empty() && self.rng.gen_bool(0.7) {
                // Worst-case cost: 2 const + 2 add + 1 sub = 5 nodes.
                if !self.can_add(5) {
                    break;
                }
                let t = anchors[self.rng.gen_range(0..anchors.len())];

                let b = self.rng.gen_range(0..=1_000u64);
                let a = value.wrapping_add(b);

                let id_a = self.add(NodeTypeV2::ConstU64, [0; 3], a);
                let id_b = self.add(NodeTypeV2::ConstU64, [0; 3], b);
                let t_plus_a = self.add(NodeTypeV2::Add, [t, id_a, 0], 0);
                let t_plus_b = self.add(NodeTypeV2::Add, [t, id_b, 0], 0);
                let diff = self.add(NodeTypeV2::Sub, [t_plus_a, t_plus_b, 0], 0);
                self.remap(orig_id, diff, output, max_idx);
                continue;
            }

            // Fallback: pure-const decompositions (cheaper but easier to fold).
            if value > 0 && self.rng.gen_bool(0.5) {
                if !self.can_add(3) {
                    break;
                }
                // value = a + b
                let a = self.rng.gen_range(0..value);
                let b = value - a;
                let id_a = self.add(NodeTypeV2::ConstU64, [0; 3], a);
                let id_b = self.add(NodeTypeV2::ConstU64, [0; 3], b);
                let sum = self.add(NodeTypeV2::Add, [id_a, id_b, 0], 0);
                self.remap(orig_id, sum, output, max_idx);
            } else {
                if !self.can_add(3) {
                    break;
                }
                // value = a - b
                let offset = self.rng.gen_range(1..100u64);
                let a = value.wrapping_add(offset);
                let id_a = self.add(NodeTypeV2::ConstU64, [0; 3], a);
                let id_b = self.add(NodeTypeV2::ConstU64, [0; 3], offset);
                let diff = self.add(NodeTypeV2::Sub, [id_a, id_b, 0], 0);
                self.remap(orig_id, diff, output, max_idx);
            }
        }
    }

    /// L2: Boolean-Arithmetic Mixing - embed BoolU64 into arithmetic with diversified encodings.
    fn layer2(&mut self, output: &mut u32) {
        let max_idx = self.nodes.len();
        let indices: Vec<usize> = (0..max_idx).collect();
        for idx in indices {
            if !self.can_add(4) {
                break;
            }
            let node = self.nodes[idx].clone();
            if !self.rng.gen_bool(0.5) {
                continue;
            }

            match node.node_type {
                NodeTypeV2::And => {
                    let (a, b) = (node.inputs[0], node.inputs[1]);
                    let Some(ta) = self.find_node_type(a) else { continue };
                    let Some(tb) = self.find_node_type(b) else { continue };
                    if !(is_bool_node_type(ta) && is_bool_node_type(tb)) {
                        continue;
                    }

                    let roll: u8 = self.rng.gen_range(0..=1);
                    match roll {
                        0 => {
                            // AND(a,b) = Ne(Min(a,b), 0)
                            let min = self.add(NodeTypeV2::Min, [a, b, 0], 0);
                            let zero = self.add(NodeTypeV2::ConstU64, [0; 3], 0);
                            let ne = self.add(NodeTypeV2::Ne, [min, zero, 0], 0);
                            self.remap(node.node_id, ne, output, max_idx);
                        }
                        _ => {
                            // AND(a,b) = Eq(Add(a,b), 2)  for a,b ∈ {0,1}
                            let sum = self.add(NodeTypeV2::Add, [a, b, 0], 0);
                            let two = self.add(NodeTypeV2::ConstU64, [0; 3], 2);
                            let eq = self.add(NodeTypeV2::Eq, [sum, two, 0], 0);
                            self.remap(node.node_id, eq, output, max_idx);
                        }
                    }
                }
                NodeTypeV2::Or => {
                    let (a, b) = (node.inputs[0], node.inputs[1]);
                    let Some(ta) = self.find_node_type(a) else { continue };
                    let Some(tb) = self.find_node_type(b) else { continue };
                    if !(is_bool_node_type(ta) && is_bool_node_type(tb)) {
                        continue;
                    }

                    let roll: u8 = self.rng.gen_range(0..=1);
                    match roll {
                        0 => {
                            // OR(a,b) = Ne(Max(a,b), 0)
                            let max = self.add(NodeTypeV2::Max, [a, b, 0], 0);
                            let zero = self.add(NodeTypeV2::ConstU64, [0; 3], 0);
                            let ne = self.add(NodeTypeV2::Ne, [max, zero, 0], 0);
                            self.remap(node.node_id, ne, output, max_idx);
                        }
                        _ => {
                            // OR(a,b) = Ne(Add(a,b), 0) for a,b ∈ {0,1}
                            let sum = self.add(NodeTypeV2::Add, [a, b, 0], 0);
                            let zero = self.add(NodeTypeV2::ConstU64, [0; 3], 0);
                            let ne = self.add(NodeTypeV2::Ne, [sum, zero, 0], 0);
                            self.remap(node.node_id, ne, output, max_idx);
                        }
                    }
                }
                NodeTypeV2::Not => {
                    // Only apply the 1-x encoding if the input is boolean-typed (BoolU64 invariant).
                    // This holds for compiler-produced DAGs, but we fail-closed for arbitrary DAGs.
                    let input_id = node.inputs[0];
                    let Some(input_node) = self.nodes.iter().find(|n| n.node_id == input_id) else {
                        continue;
                    };
                    if !is_bool_node_type(input_node.node_type) {
                        continue;
                    }

                    let roll: u8 = self.rng.gen_range(0..=1);
                    match roll {
                        0 => {
                            // NOT(a) = Ne(1-a, 0)
                            let one = self.add(NodeTypeV2::ConstU64, [0; 3], 1);
                            let sub = self.add(NodeTypeV2::Sub, [one, input_id, 0], 0);
                            let zero = self.add(NodeTypeV2::ConstU64, [0; 3], 0);
                            let ne = self.add(NodeTypeV2::Ne, [sub, zero, 0], 0);
                            self.remap(node.node_id, ne, output, max_idx);
                        }
                        _ => {
                            // NOT(a) = Eq(a, 0)
                            let zero = self.add(NodeTypeV2::ConstU64, [0; 3], 0);
                            let eq = self.add(NodeTypeV2::Eq, [input_id, zero, 0], 0);
                            self.remap(node.node_id, eq, output, max_idx);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// L3: Expression Expansion - algebraic identity rewrites
    fn layer3(&mut self, budget: usize, output: &mut u32) {
        let max_idx = self.nodes.len();
        let mut expanded = 0;
        let mut indices: Vec<usize> = (0..max_idx).collect();
        for i in (1..indices.len()).rev() {
            let j = self.rng.gen_range(0..=i);
            indices.swap(i, j);
        }

        for idx in indices {
            if expanded >= budget || !self.can_add(2) {
                break;
            }
            if !self.rng.gen_bool(0.4) {
                continue;
            }

            let node = self.nodes[idx].clone();
            match node.node_type {
                NodeTypeV2::Ge => {
                    // a >= b → NOT(a < b)
                    let lt = self.add(NodeTypeV2::Lt, [node.inputs[0], node.inputs[1], 0], 0);
                    let not = self.add(NodeTypeV2::Not, [lt, 0, 0], 0);
                    self.remap(node.node_id, not, output, max_idx);
                    expanded += 2;
                }
                NodeTypeV2::Le => {
                    // a <= b → NOT(a > b)
                    let gt = self.add(NodeTypeV2::Gt, [node.inputs[0], node.inputs[1], 0], 0);
                    let not = self.add(NodeTypeV2::Not, [gt, 0, 0], 0);
                    self.remap(node.node_id, not, output, max_idx);
                    expanded += 2;
                }
                NodeTypeV2::Gt => {
                    // a > b → b < a
                    let lt = self.add(NodeTypeV2::Lt, [node.inputs[1], node.inputs[0], 0], 0);
                    self.remap(node.node_id, lt, output, max_idx);
                    expanded += 1;
                }
                _ => {}
            }
        }
    }

    /// L4: Node Type Polymorphism - De Morgan rewrites
    fn layer4(&mut self, output: &mut u32) {
        let max_idx = self.nodes.len();
        let indices: Vec<usize> = (0..max_idx).collect();
        for idx in indices {
            if !self.can_add(4) {
                break;
            }
            if !self.rng.gen_bool(0.3) {
                continue;
            }

            let node = self.nodes[idx].clone();
            match node.node_type {
                NodeTypeV2::And => {
                    // AND(a,b) → NOT(OR(NOT(a), NOT(b)))
                    let not_a = self.add(NodeTypeV2::Not, [node.inputs[0], 0, 0], 0);
                    let not_b = self.add(NodeTypeV2::Not, [node.inputs[1], 0, 0], 0);
                    let or = self.add(NodeTypeV2::Or, [not_a, not_b, 0], 0);
                    let not_or = self.add(NodeTypeV2::Not, [or, 0, 0], 0);
                    self.remap(node.node_id, not_or, output, max_idx);
                }
                NodeTypeV2::Or => {
                    // OR(a,b) → NOT(AND(NOT(a), NOT(b)))
                    let not_a = self.add(NodeTypeV2::Not, [node.inputs[0], 0, 0], 0);
                    let not_b = self.add(NodeTypeV2::Not, [node.inputs[1], 0, 0], 0);
                    let and = self.add(NodeTypeV2::And, [not_a, not_b, 0], 0);
                    let not_and = self.add(NodeTypeV2::Not, [and, 0, 0], 0);
                    self.remap(node.node_id, not_and, output, max_idx);
                }
                _ => {}
            }
        }
    }

    /// L5: Topological Shuffling - reorder nodes within valid ranges
    fn layer5(&mut self) {
        // Deterministic randomized topological sort (Kahn), using RNG tie-breaking.
        //
        // This avoids relying on sentinel values in unused input slots (node_id 0 is valid),
        // and guarantees the resulting order is still a valid topological order.

        let n = self.nodes.len();
        if n <= 1 {
            return;
        }

        let id_to_idx: HashMap<u32, usize> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, node)| (node.node_id, i))
            .collect();

        let mut indeg = vec![0u32; n];
        let mut out_edges: Vec<Vec<usize>> = vec![Vec::new(); n];

        for (i, node) in self.nodes.iter().enumerate() {
            for &slot in used_input_indices(node.node_type) {
                let dep_id = node.inputs[slot];
                if let Some(&dep_idx) = id_to_idx.get(&dep_id) {
                    if dep_idx == i {
                        // Self-dependency indicates invalid DAG; ignore shuffling (fail-closed).
                        return;
                    }
                    indeg[i] = indeg[i].saturating_add(1);
                    out_edges[dep_idx].push(i);
                }
            }
        }

        let mut ready: Vec<usize> = indeg
            .iter()
            .enumerate()
            .filter_map(|(i, &d)| if d == 0 { Some(i) } else { None })
            .collect();

        // Deterministic selection from `ready` using the seeded RNG.
        let mut order: Vec<usize> = Vec::with_capacity(n);
        while !ready.is_empty() {
            let pick = self.rng.gen_range(0..ready.len());
            let i = ready.swap_remove(pick);
            order.push(i);
            for &j in &out_edges[i] {
                indeg[j] = indeg[j].saturating_sub(1);
                if indeg[j] == 0 {
                    ready.push(j);
                }
            }
        }

        if order.len() != n {
            // Cycle detected; refuse to shuffle.
            return;
        }

        let mut new_nodes: Vec<NodeV2> = Vec::with_capacity(n);
        for idx in order {
            new_nodes.push(self.nodes[idx].clone());
        }
        self.nodes = new_nodes;
    }

    /// L6: Redundant Path Injection - add alternative computations
    fn layer6(&mut self, count: usize, output: &mut u32, strategy: RedundantStrategy) {
        match strategy {
            RedundantStrategy::MergeSelector => self.layer6_merge_selector(count, output),
            RedundantStrategy::AbsorptionMinMax => self.layer6_absorption_minmax(count, output),
        }
    }

    fn layer6_absorption_minmax(&mut self, count: usize, output: &mut u32) {
        let max_idx = self.nodes.len();

        let mut refcount: HashMap<u32, u32> = HashMap::new();
        refcount.insert(*output, 1);
        for node in &self.nodes[..max_idx] {
            for &slot in used_input_indices(node.node_type) {
                *refcount.entry(node.inputs[slot]).or_insert(0) += 1;
            }
        }

        let targets: Vec<usize> = self.nodes[..max_idx]
            .iter()
            .enumerate()
            .filter(|(_, n)| is_u64_node_type(n.node_type))
            .filter(|(_, n)| *refcount.get(&n.node_id).unwrap_or(&0) > 0)
            .map(|(i, _)| i)
            .collect();

        if targets.is_empty() {
            return;
        }

        // IMPORTANT: only use "atomic" u64 sources for decoys (loads/constants), so the decoy
        // cannot depend (transitively) on the target `x` and accidentally form a cycle when
        // we remap `x -> absorbed`.
        let base_u64_nodes: Vec<u32> = self.nodes[..max_idx]
            .iter()
            .filter(|n| {
                matches!(
                    n.node_type,
                    NodeTypeV2::LoadStateU64 | NodeTypeV2::LoadCandidateU64 | NodeTypeV2::ConstU64
                )
            })
            .map(|n| n.node_id)
            .collect();

        for _ in 0..count {
            // Worst-case for one injection: 2 absorption nodes + up to 3 decoy nodes.
            if !self.can_add(5) {
                break;
            }

            let target_idx = targets[self.rng.gen_range(0..targets.len())];
            let target = self.nodes[target_idx].clone();
            let x = target.node_id;

            let Some(d) = self.make_u64_decoy(&base_u64_nodes) else {
                break;
            };

            // min(x, max(x, d)) = x  or  max(x, min(x, d)) = x
            let roll: u8 = self.rng.gen_range(0..=1);
            let absorbed = if roll == 0 {
                let max = self.add(NodeTypeV2::Max, [x, d, 0], 0);
                self.add(NodeTypeV2::Min, [x, max, 0], 0)
            } else {
                let min = self.add(NodeTypeV2::Min, [x, d, 0], 0);
                self.add(NodeTypeV2::Max, [x, min, 0], 0)
            };

            self.remap(x, absorbed, output, max_idx);
        }
    }

    fn make_u64_decoy(&mut self, base: &[u32]) -> Option<u32> {
        if base.is_empty() {
            return None;
        }

        let roll: u8 = self.rng.gen_range(0..=4);
        match roll {
            0 => {
                // Reuse an existing u64 node.
                Some(base[self.rng.gen_range(0..base.len())])
            }
            1 => {
                // MulConst(x, k)
                if !self.can_add(1) {
                    return Some(base[self.rng.gen_range(0..base.len())]);
                }
                let x = base[self.rng.gen_range(0..base.len())];
                let k = self.rng.gen_range(2..=1_000u64);
                Some(self.add(NodeTypeV2::MulConst, [x, 0, 0], k))
            }
            2 => {
                // DivConst(x, k)
                if !self.can_add(1) {
                    return Some(base[self.rng.gen_range(0..base.len())]);
                }
                let x = base[self.rng.gen_range(0..base.len())];
                let k = self.rng.gen_range(1..=1_000u64);
                Some(self.add(NodeTypeV2::DivConst, [x, 0, 0], k))
            }
            3 => {
                // Min(a,b) or Max(a,b)
                if !self.can_add(1) {
                    return Some(base[self.rng.gen_range(0..base.len())]);
                }
                let a = base[self.rng.gen_range(0..base.len())];
                let b = base[self.rng.gen_range(0..base.len())];
                if self.rng.gen_bool(0.5) {
                    Some(self.add(NodeTypeV2::Min, [a, b, 0], 0))
                } else {
                    Some(self.add(NodeTypeV2::Max, [a, b, 0], 0))
                }
            }
            _ => {
                // Add(x, const)
                // 1 const + 1 add = 2 nodes.
                if !self.can_add(2) {
                    return Some(base[self.rng.gen_range(0..base.len())]);
                }
                let x = base[self.rng.gen_range(0..base.len())];
                let k = self.rng.gen_range(0..=1_000u64);
                let c = self.add(NodeTypeV2::ConstU64, [0; 3], k);
                Some(self.add(NodeTypeV2::Add, [x, c, 0], 0))
            }
        }
    }

    fn layer6_merge_selector(&mut self, count: usize, output: &mut u32) {
        let max_idx = self.nodes.len();
        for _ in 0..count {
            // Find a comparison or boolean node to duplicate
            let targets: Vec<usize> = self.nodes.iter().enumerate()
                .filter(|(_, n)| matches!(n.node_type, 
                    NodeTypeV2::Ge | NodeTypeV2::Le | NodeTypeV2::Gt | NodeTypeV2::Lt |
                    NodeTypeV2::Eq | NodeTypeV2::Ne | NodeTypeV2::And | NodeTypeV2::Or))
                .map(|(i, _)| i)
                .collect();

            if targets.is_empty() {
                break;
            }

            let target_idx = targets[self.rng.gen_range(0..targets.len())];
            let target = self.nodes[target_idx].clone();
            let orig_id = target.node_id;

            // Create structural selector (always true): x >= 0 for unsigned
            let u64_nodes: Vec<u32> = self.nodes.iter()
                .filter(|n| matches!(n.node_type, NodeTypeV2::LoadStateU64 | NodeTypeV2::LoadCandidateU64 | NodeTypeV2::ConstU64))
                .map(|n| n.node_id)
                .collect();

            if u64_nodes.is_empty() {
                continue;
            }

            // Worst-case node cost for one injection (with an orig clone) is 12 nodes.
            if !self.can_add(12) {
                break;
            }

            // Clone the original node so the merge can still reference the old semantics after remap.
            let orig_clone_id = self.alloc_id();
            self.nodes.push(NodeV2 {
                node_type: target.node_type,
                node_id: orig_clone_id,
                inputs: target.inputs,
                key_hash: target.key_hash,
                const_value: target.const_value,
            });

            // Create alternative computation (equivalent, fail-closed).
            let alt_id = match target.node_type {
                NodeTypeV2::Ge => {
                    // NOT(Lt(a, b))
                    let lt = self.add(NodeTypeV2::Lt, [target.inputs[0], target.inputs[1], 0], 0);
                    self.add(NodeTypeV2::Not, [lt, 0, 0], 0)
                }
                NodeTypeV2::Le => {
                    // NOT(Gt(a, b))
                    let gt = self.add(NodeTypeV2::Gt, [target.inputs[0], target.inputs[1], 0], 0);
                    self.add(NodeTypeV2::Not, [gt, 0, 0], 0)
                }
                NodeTypeV2::Gt => {
                    // Lt(b, a)
                    self.add(NodeTypeV2::Lt, [target.inputs[1], target.inputs[0], 0], 0)
                }
                NodeTypeV2::Lt => {
                    // Gt(b, a)
                    self.add(NodeTypeV2::Gt, [target.inputs[1], target.inputs[0], 0], 0)
                }
                NodeTypeV2::Eq => {
                    // AND(Le(a,b), Ge(a,b))
                    let le = self.add(NodeTypeV2::Le, [target.inputs[0], target.inputs[1], 0], 0);
                    let ge = self.add(NodeTypeV2::Ge, [target.inputs[0], target.inputs[1], 0], 0);
                    self.add(NodeTypeV2::And, [le, ge, 0], 0)
                }
                NodeTypeV2::Ne => {
                    // OR(Lt(a,b), Gt(a,b))
                    let lt = self.add(NodeTypeV2::Lt, [target.inputs[0], target.inputs[1], 0], 0);
                    let gt = self.add(NodeTypeV2::Gt, [target.inputs[0], target.inputs[1], 0], 0);
                    self.add(NodeTypeV2::Or, [lt, gt, 0], 0)
                }
                NodeTypeV2::And => {
                    // NOT(OR(NOT(a), NOT(b)))
                    let not_a = self.add(NodeTypeV2::Not, [target.inputs[0], 0, 0], 0);
                    let not_b = self.add(NodeTypeV2::Not, [target.inputs[1], 0, 0], 0);
                    let or = self.add(NodeTypeV2::Or, [not_a, not_b, 0], 0);
                    self.add(NodeTypeV2::Not, [or, 0, 0], 0)
                }
                NodeTypeV2::Or => {
                    // NOT(AND(NOT(a), NOT(b)))
                    let not_a = self.add(NodeTypeV2::Not, [target.inputs[0], 0, 0], 0);
                    let not_b = self.add(NodeTypeV2::Not, [target.inputs[1], 0, 0], 0);
                    let and = self.add(NodeTypeV2::And, [not_a, not_b, 0], 0);
                    self.add(NodeTypeV2::Not, [and, 0, 0], 0)
                }
                _ => continue,
            };

            let selector = self.make_structural_true_selector(&u64_nodes);

            // Merge: (selector AND orig) OR (NOT(selector) AND alt)
            let s_and_o = self.add(NodeTypeV2::And, [selector, orig_clone_id, 0], 0);
            let not_s = self.add(NodeTypeV2::Not, [selector, 0, 0], 0);
            let ns_and_a = self.add(NodeTypeV2::And, [not_s, alt_id, 0], 0);
            let merged = self.add(NodeTypeV2::Or, [s_and_o, ns_and_a, 0], 0);

            self.remap(orig_id, merged, output, max_idx);
        }
    }

    fn make_structural_true_selector(&mut self, u64_nodes: &[u32]) -> u32 {
        let roll: u8 = self.rng.gen_range(0..=2);
        match roll {
            0 => {
                // x == x
                let x = u64_nodes[self.rng.gen_range(0..u64_nodes.len())];
                self.add(NodeTypeV2::Eq, [x, x, 0], 0)
            }
            1 => {
                // (a <= b) OR (a > b)  (trichotomy)
                let a = u64_nodes[self.rng.gen_range(0..u64_nodes.len())];
                let b = u64_nodes[self.rng.gen_range(0..u64_nodes.len())];
                let le = self.add(NodeTypeV2::Le, [a, b, 0], 0);
                let gt = self.add(NodeTypeV2::Gt, [a, b, 0], 0);
                self.add(NodeTypeV2::Or, [le, gt, 0], 0)
            }
            _ => {
                // x >= 0 for unsigned
                let x = u64_nodes[self.rng.gen_range(0..u64_nodes.len())];
                let zero = self.add(NodeTypeV2::ConstU64, [0; 3], 0);
                self.add(NodeTypeV2::Ge, [x, zero, 0], 0)
            }
        }
    }

    fn finish(self) -> Vec<NodeV2> {
        self.nodes
    }
}

/// Apply KSO v2 scrambling to a compiled policy.
///
/// # Arguments
/// - `dag`: The compiled policy DAG
/// - `seed`: 32-byte seed for deterministic randomness
/// - `config`: Scrambling configuration
///
/// # Returns
/// Scrambled policy with identical semantics.
pub fn scramble_v2(
    mut dag: CompiledPolicyV2,
    seed: [u8; 32],
    config: &KSOConfig,
) -> CompiledPolicyV2 {
    let mut scrambler = Scrambler::new(seed, dag.nodes, config.max_expansion);
    let mut output = dag.output_node;

    if config.enable_constant_computation {
        scrambler.layer1(&mut output);
    }

    if config.enable_domain_mixing {
        scrambler.layer2(&mut output);
    }

    if config.expansion_budget > 0 {
        scrambler.layer3(config.expansion_budget, &mut output);
    }

    if config.enable_polymorphism {
        scrambler.layer4(&mut output);
    }

    // L5 always runs
    scrambler.layer5();

    if config.redundant_path_count > 0 {
        scrambler.layer6(
            config.redundant_path_count,
            &mut output,
            config.redundant_strategy,
        );
        // Layer-6 remaps can introduce new dependencies; re-toposort to preserve a valid order
        // for sequential evaluators (e.g., future no_std guest execution).
        scrambler.layer5();
    }

    dag.nodes = scrambler.finish();
    dag.output_node = output;

    // Renumber nodes for canonical output
    renumber_nodes(&mut dag);

    dag
}

fn renumber_nodes(dag: &mut CompiledPolicyV2) {
    let mut id_map: HashMap<u32, u32> = HashMap::new();
    for (new_id, node) in dag.nodes.iter().enumerate() {
        id_map.insert(node.node_id, new_id as u32);
    }

    for node in &mut dag.nodes {
        node.node_id = *id_map.get(&node.node_id).unwrap_or(&node.node_id);
        for &slot in used_input_indices(node.node_type) {
            let old = node.inputs[slot];
            node.inputs[slot] = *id_map.get(&old).unwrap_or(&old);
        }
    }

    dag.output_node = *id_map.get(&dag.output_node).unwrap_or(&dag.output_node);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_topologically_ordered(dag: &CompiledPolicyV2) {
        // After renumbering, node_id corresponds to its index in `nodes`.
        // Enforce that every used input references a strictly earlier node_id.
        for node in &dag.nodes {
            for &slot in used_input_indices(node.node_type) {
                let dep = node.inputs[slot];
                assert!(
                    dep < node.node_id,
                    "not topologically ordered: node {} depends on {}",
                    node.node_id,
                    dep
                );
            }
        }
    }

    fn make_simple_dag() -> CompiledPolicyV2 {
        // Build: state.x >= 100
        let nodes = vec![
            NodeV2 {
                node_type: NodeTypeV2::LoadStateU64,
                node_id: 0,
                inputs: [0; 3],
                key_hash: [1; 32],
                const_value: 0,
            },
            NodeV2 {
                node_type: NodeTypeV2::ConstU64,
                node_id: 1,
                inputs: [0; 3],
                key_hash: [0; 32],
                const_value: 100,
            },
            NodeV2 {
                node_type: NodeTypeV2::Ge,
                node_id: 2,
                inputs: [0, 1, 0],
                key_hash: [0; 32],
                const_value: 0,
            },
        ];

        CompiledPolicyV2 {
            version: 2,
            nodes,
            output_node: 2,
            temporal_fields: vec![],
            state_keys: std::collections::BTreeMap::new(),
            candidate_keys: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn scramble_minimal_preserves_output() {
        let dag = make_simple_dag();
        let seed = [0u8; 32];
        let scrambled = scramble_v2(dag.clone(), seed, &KSOConfig::minimal());

        // Output node should still exist
        assert!(scrambled.nodes.iter().any(|n| n.node_id == scrambled.output_node));
        assert_topologically_ordered(&scrambled);
    }

    #[test]
    fn scramble_increases_nodes() {
        let dag = make_simple_dag();
        let original_count = dag.nodes.len();
        let seed = [42u8; 32];
        let scrambled = scramble_v2(dag, seed, &KSOConfig::default());

        assert!(scrambled.nodes.len() >= original_count);
        assert_topologically_ordered(&scrambled);
    }

    #[test]
    fn scramble_deterministic() {
        let dag = make_simple_dag();
        let seed = [99u8; 32];

        let s1 = scramble_v2(dag.clone(), seed, &KSOConfig::default());
        let s2 = scramble_v2(dag, seed, &KSOConfig::default());

        assert_eq!(s1.nodes.len(), s2.nodes.len());
        assert_eq!(s1.output_node, s2.output_node);
        assert_topologically_ordered(&s1);
        assert_topologically_ordered(&s2);
    }
}
