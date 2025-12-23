//! Intermediate Representation for Tau-MPRD v2.
//!
//! V2 uses a DAG of typed nodes instead of gates.

use crate::ast_v2::*;
use crate::error::{CompileError, CompileResult};
use crate::limits::{MAX_KEY_LENGTH_V1, MAX_LOOKBACK_V1, MAX_TEMPORAL_FIELDS_V1};
use std::collections::BTreeMap;

/// Hash a key name with domain separation.
pub fn hash_key(name: &str) -> [u8; 32] {
    mprd_risc0_shared::tcv_key_hash_v1(name.as_bytes())
}

/// Node type in the expression DAG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NodeTypeV2 {
    // Loads
    LoadStateU64 = 0,
    LoadCandidateU64 = 1,
    
    // Constants
    ConstU64 = 2,
    ConstBool = 3,
    
    // Arithmetic (checked)
    Add = 10,
    Sub = 11,
    MulConst = 12,
    DivConst = 13,
    Min = 14,
    Max = 15,
    Clamp = 16,
    
    // Comparisons
    Eq = 20,
    Ne = 21,
    Lt = 22,
    Le = 23,
    Gt = 24,
    Ge = 25,
    
    // Boolean
    And = 30,
    Or = 31,
    Not = 32,
}

/// A node in the expression DAG.
#[derive(Debug, Clone)]
pub struct NodeV2 {
    pub node_type: NodeTypeV2,
    pub node_id: u32,
    
    /// Input node IDs (up to 3 for clamp)
    pub inputs: [u32; 3],
    
    /// For loads: key_hash
    pub key_hash: [u8; 32],
    
    /// For constants: value (u64 or bool as 0/1)
    pub const_value: u64,
}

impl NodeV2 {
    fn load_state(node_id: u32, key_hash: [u8; 32]) -> Self {
        Self {
            node_type: NodeTypeV2::LoadStateU64,
            node_id,
            inputs: [0; 3],
            key_hash,
            const_value: 0,
        }
    }
    
    fn load_candidate(node_id: u32, key_hash: [u8; 32]) -> Self {
        Self {
            node_type: NodeTypeV2::LoadCandidateU64,
            node_id,
            inputs: [0; 3],
            key_hash,
            const_value: 0,
        }
    }
    
    fn const_u64(node_id: u32, value: u64) -> Self {
        Self {
            node_type: NodeTypeV2::ConstU64,
            node_id,
            inputs: [0; 3],
            key_hash: [0; 32],
            const_value: value,
        }
    }
    
    fn const_bool(node_id: u32, value: bool) -> Self {
        Self {
            node_type: NodeTypeV2::ConstBool,
            node_id,
            inputs: [0; 3],
            key_hash: [0; 32],
            const_value: if value { 1 } else { 0 },
        }
    }
    
    fn binary(node_type: NodeTypeV2, node_id: u32, left: u32, right: u32) -> Self {
        Self {
            node_type,
            node_id,
            inputs: [left, right, 0],
            key_hash: [0; 32],
            const_value: 0,
        }
    }
    
    fn unary(node_type: NodeTypeV2, node_id: u32, input: u32) -> Self {
        Self {
            node_type,
            node_id,
            inputs: [input, 0, 0],
            key_hash: [0; 32],
            const_value: 0,
        }
    }
    
    fn with_const(node_type: NodeTypeV2, node_id: u32, input: u32, const_val: u64) -> Self {
        Self {
            node_type,
            node_id,
            inputs: [input, 0, 0],
            key_hash: [0; 32],
            const_value: const_val,
        }
    }
    
    fn ternary(node_type: NodeTypeV2, node_id: u32, a: u32, b: u32, c: u32) -> Self {
        Self {
            node_type,
            node_id,
            inputs: [a, b, c],
            key_hash: [0; 32],
            const_value: 0,
        }
    }
}

/// Temporal field specification (for state fields with lookback).
#[derive(Debug, Clone)]
pub struct TemporalFieldSpecV2 {
    pub field_name: String,
    pub current_key_hash: [u8; 32],
    pub max_lookback: usize,
    pub lookback_key_hashes: Vec<[u8; 32]>,
}

/// Compiled policy v2 artifact.
#[derive(Debug, Clone)]
pub struct CompiledPolicyV2 {
    /// Version = 2
    pub version: u32,
    
    /// Expression DAG nodes (topologically ordered)
    pub nodes: Vec<NodeV2>,
    
    /// Output node ID (must be boolean)
    pub output_node: u32,
    
    /// Temporal fields referenced
    pub temporal_fields: Vec<TemporalFieldSpecV2>,
    
    /// State key schema (name → hash)
    pub state_keys: BTreeMap<String, [u8; 32]>,
    
    /// Candidate key schema (name → hash)
    pub candidate_keys: BTreeMap<String, [u8; 32]>,
}

/// IR builder for v2.
struct IrBuilderV2 {
    nodes: Vec<NodeV2>,
    next_id: u32,
    state_fields: BTreeMap<String, usize>,  // name → max temporal offset
    candidate_fields: BTreeMap<String, ()>,
}

impl IrBuilderV2 {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            next_id: 0,
            state_fields: BTreeMap::new(),
            candidate_fields: BTreeMap::new(),
        }
    }
    
    fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
    
    fn add_node(&mut self, node: NodeV2) -> u32 {
        let id = node.node_id;
        self.nodes.push(node);
        id
    }
    
    fn lower_expr(&mut self, expr: &ExprV2) -> CompileResult<u32> {
        match expr {
            // Boolean operations
            ExprV2::And(left, right) => {
                let l = self.lower_expr(left)?;
                let r = self.lower_expr(right)?;
                let id = self.alloc_id();
                Ok(self.add_node(NodeV2::binary(NodeTypeV2::And, id, l, r)))
            }
            ExprV2::Or(left, right) => {
                let l = self.lower_expr(left)?;
                let r = self.lower_expr(right)?;
                let id = self.alloc_id();
                Ok(self.add_node(NodeV2::binary(NodeTypeV2::Or, id, l, r)))
            }
            ExprV2::Not(inner) => {
                let i = self.lower_expr(inner)?;
                let id = self.alloc_id();
                Ok(self.add_node(NodeV2::unary(NodeTypeV2::Not, id, i)))
            }
            ExprV2::BoolLit(v) => {
                let id = self.alloc_id();
                Ok(self.add_node(NodeV2::const_bool(id, *v)))
            }
            
            // Comparisons
            ExprV2::Compare(op, left, right) => {
                let l = self.lower_expr(left)?;
                let r = self.lower_expr(right)?;
                let id = self.alloc_id();
                let node_type = match op {
                    CompareOp::Eq => NodeTypeV2::Eq,
                    CompareOp::Ne => NodeTypeV2::Ne,
                    CompareOp::Lt => NodeTypeV2::Lt,
                    CompareOp::Le => NodeTypeV2::Le,
                    CompareOp::Gt => NodeTypeV2::Gt,
                    CompareOp::Ge => NodeTypeV2::Ge,
                };
                Ok(self.add_node(NodeV2::binary(node_type, id, l, r)))
            }
            
            // Arithmetic
            ExprV2::Add(left, right) => {
                let l = self.lower_expr(left)?;
                let r = self.lower_expr(right)?;
                let id = self.alloc_id();
                Ok(self.add_node(NodeV2::binary(NodeTypeV2::Add, id, l, r)))
            }
            ExprV2::Sub(left, right) => {
                let l = self.lower_expr(left)?;
                let r = self.lower_expr(right)?;
                let id = self.alloc_id();
                Ok(self.add_node(NodeV2::binary(NodeTypeV2::Sub, id, l, r)))
            }
            ExprV2::MulConst(inner, c) => {
                let i = self.lower_expr(inner)?;
                let id = self.alloc_id();
                Ok(self.add_node(NodeV2::with_const(NodeTypeV2::MulConst, id, i, *c)))
            }
            ExprV2::DivConst(inner, c) => {
                let i = self.lower_expr(inner)?;
                let id = self.alloc_id();
                Ok(self.add_node(NodeV2::with_const(NodeTypeV2::DivConst, id, i, *c)))
            }
            ExprV2::Min(left, right) => {
                let l = self.lower_expr(left)?;
                let r = self.lower_expr(right)?;
                let id = self.alloc_id();
                Ok(self.add_node(NodeV2::binary(NodeTypeV2::Min, id, l, r)))
            }
            ExprV2::Max(left, right) => {
                let l = self.lower_expr(left)?;
                let r = self.lower_expr(right)?;
                let id = self.alloc_id();
                Ok(self.add_node(NodeV2::binary(NodeTypeV2::Max, id, l, r)))
            }
            ExprV2::Clamp(x, lo, hi) => {
                let x_id = self.lower_expr(x)?;
                let lo_id = self.lower_expr(lo)?;
                let hi_id = self.lower_expr(hi)?;
                let id = self.alloc_id();
                Ok(self.add_node(NodeV2::ternary(NodeTypeV2::Clamp, id, x_id, lo_id, hi_id)))
            }
            ExprV2::U64Lit(v) => {
                let id = self.alloc_id();
                Ok(self.add_node(NodeV2::const_u64(id, *v)))
            }
            
            // References
            ExprV2::StateField(field) => {
                if field.temporal_offset > MAX_LOOKBACK_V1 {
                    return Err(CompileError::LookbackExceeded {
                        lookback: field.temporal_offset,
                        max: MAX_LOOKBACK_V1,
                    });
                }

                // Track field and max temporal offset
                let entry = self.state_fields.entry(field.name.clone()).or_insert(0);
                *entry = (*entry).max(field.temporal_offset);
                
                // Generate key name (with temporal suffix if offset > 0)
                let key_name = if field.temporal_offset > 0 {
                    format!("{}_t_{}", field.name, field.temporal_offset)
                } else {
                    field.name.clone()
                };

                if key_name.len() > MAX_KEY_LENGTH_V1 {
                    return Err(CompileError::KeyTooLong {
                        key: key_name,
                        max: MAX_KEY_LENGTH_V1,
                    });
                }
                
                let key_hash = hash_key(&key_name);
                let id = self.alloc_id();
                Ok(self.add_node(NodeV2::load_state(id, key_hash)))
            }
            ExprV2::CandidateField(field) => {
                self.candidate_fields.insert(field.name.clone(), ());
                let key_hash = hash_key(&field.name);
                let id = self.alloc_id();
                Ok(self.add_node(NodeV2::load_candidate(id, key_hash)))
            }
        }
    }
    
    fn build(mut self, spec: &TauMprdSpecV2) -> CompileResult<CompiledPolicyV2> {
        let output_node = self.lower_expr(&spec.body)?;
        
        // Build temporal field specs
        let mut temporal_fields = Vec::new();
        for (name, &max_offset) in &self.state_fields {
            if max_offset > 0 {
                let current_key_hash = hash_key(name);
                let mut lookback_key_hashes = Vec::new();
                for i in 1..=max_offset {
                    let key_name = format!("{}_t_{}", name, i);
                    lookback_key_hashes.push(hash_key(&key_name));
                }
                temporal_fields.push(TemporalFieldSpecV2 {
                    field_name: name.clone(),
                    current_key_hash,
                    max_lookback: max_offset,
                    lookback_key_hashes,
                });
            }
        }

        if temporal_fields.len() > MAX_TEMPORAL_FIELDS_V1 {
            return Err(CompileError::TemporalFieldCountExceeded {
                count: temporal_fields.len(),
                max: MAX_TEMPORAL_FIELDS_V1,
            });
        }
        
        // Build key schemas
        let mut state_keys = BTreeMap::new();
        for (name, &max_offset) in &self.state_fields {
            state_keys.insert(name.clone(), hash_key(name));
            for i in 1..=max_offset {
                let key_name = format!("{}_t_{}", name, i);
                state_keys.insert(key_name.clone(), hash_key(&key_name));
            }
        }
        
        let mut candidate_keys = BTreeMap::new();
        for name in self.candidate_fields.keys() {
            candidate_keys.insert(name.clone(), hash_key(name));
        }
        
        Ok(CompiledPolicyV2 {
            version: 2,
            nodes: self.nodes,
            output_node,
            temporal_fields,
            state_keys,
            candidate_keys,
        })
    }
}

/// Lower AST to IR v2.
pub fn lower_v2(spec: &TauMprdSpecV2) -> CompileResult<CompiledPolicyV2> {
    let builder = IrBuilderV2::new();
    builder.build(spec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer_v2::tokenize_v2;
    use crate::parser_v2::parse_v2;
    
    fn lower_source(source: &str) -> CompileResult<CompiledPolicyV2> {
        let tokens = tokenize_v2(source)?;
        let ast = parse_v2(&tokens)?;
        lower_v2(&ast)
    }
    
    #[test]
    fn lower_simple() {
        let ir = lower_source("always (state.x >= 100)").unwrap();
        assert_eq!(ir.version, 2);
        assert!(!ir.nodes.is_empty());
    }
    
    #[test]
    fn lower_arithmetic() {
        let ir = lower_source("always (state.a + state.b >= state.threshold)").unwrap();
        assert!(ir.nodes.iter().any(|n| n.node_type == NodeTypeV2::Add));
    }
    
    #[test]
    fn lower_weighted_voting() {
        let ir = lower_source(
            "always (state.w0 * 1 + state.w1 * 1 >= state.threshold)"
        ).unwrap();
        
        // Should have MulConst nodes
        assert!(ir.nodes.iter().any(|n| n.node_type == NodeTypeV2::MulConst));
        
        // Should have Add node
        assert!(ir.nodes.iter().any(|n| n.node_type == NodeTypeV2::Add));
        
        // Should have Ge node
        assert!(ir.nodes.iter().any(|n| n.node_type == NodeTypeV2::Ge));
    }
    
    #[test]
    fn lower_min_max() {
        let ir = lower_source("always (min(state.a, state.b) >= 0)").unwrap();
        assert!(ir.nodes.iter().any(|n| n.node_type == NodeTypeV2::Min));
    }
    
    #[test]
    fn temporal_fields_tracked() {
        let ir = lower_source("always (state.x[t-2] < state.x)").unwrap();
        assert_eq!(ir.temporal_fields.len(), 1);
        assert_eq!(ir.temporal_fields[0].max_lookback, 2);
    }
}
