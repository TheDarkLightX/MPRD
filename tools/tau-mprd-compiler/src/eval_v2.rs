//! Evaluator for CompiledPolicyV2 DAGs.
//!
//! Used for testing scrambler correctness: `eval(original) == eval(scrambled)`.

use crate::ir_v2::{CompiledPolicyV2, NodeTypeV2, NodeV2};
use std::collections::HashMap;

/// Evaluation context providing state and candidate values.
#[derive(Debug, Clone, Default)]
pub struct EvalContext {
    /// key_hash → u64 value for state fields
    pub state: HashMap<[u8; 32], u64>,
    /// key_hash → u64 value for candidate fields
    pub candidate: HashMap<[u8; 32], u64>,
}

/// Evaluation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    MissingStateKey([u8; 32]),
    MissingCandidateKey([u8; 32]),
    DivisionByZero,
    InvalidNodeId(u32),
    TypeMismatch(&'static str),
}

/// Evaluated value (either u64 or bool).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    U64(u64),
    Bool(bool),
}

impl Value {
    fn as_u64(self) -> Result<u64, EvalError> {
        match self {
            Value::U64(v) => Ok(v),
            Value::Bool(b) => Ok(if b { 1 } else { 0 }),
        }
    }

    fn as_bool(self) -> Result<bool, EvalError> {
        match self {
            Value::Bool(b) => Ok(b),
            Value::U64(v) => Ok(v != 0),
        }
    }
}

/// Evaluate a compiled policy DAG.
///
/// # Returns
/// - `Ok(true)` if policy accepts
/// - `Ok(false)` if policy rejects
/// - `Err(_)` on evaluation error (fail-closed = reject)
pub fn evaluate(dag: &CompiledPolicyV2, ctx: &EvalContext) -> Result<bool, EvalError> {
    let mut cache: HashMap<u32, Value> = HashMap::new();

    // Build node lookup
    let node_map: HashMap<u32, &NodeV2> = dag.nodes.iter().map(|n| (n.node_id, n)).collect();

    fn eval_node(
        node_id: u32,
        node_map: &HashMap<u32, &NodeV2>,
        ctx: &EvalContext,
        cache: &mut HashMap<u32, Value>,
    ) -> Result<Value, EvalError> {
        if let Some(&v) = cache.get(&node_id) {
            return Ok(v);
        }

        let node = node_map.get(&node_id).ok_or(EvalError::InvalidNodeId(node_id))?;

        let result = match node.node_type {
            NodeTypeV2::LoadStateU64 => {
                let v = ctx.state.get(&node.key_hash)
                    .copied()
                    .ok_or(EvalError::MissingStateKey(node.key_hash))?;
                Value::U64(v)
            }
            NodeTypeV2::LoadCandidateU64 => {
                let v = ctx.candidate.get(&node.key_hash)
                    .copied()
                    .ok_or(EvalError::MissingCandidateKey(node.key_hash))?;
                Value::U64(v)
            }
            NodeTypeV2::ConstU64 => Value::U64(node.const_value),
            NodeTypeV2::ConstBool => Value::Bool(node.const_value != 0),

            NodeTypeV2::Add => {
                let a = eval_node(node.inputs[0], node_map, ctx, cache)?.as_u64()?;
                let b = eval_node(node.inputs[1], node_map, ctx, cache)?.as_u64()?;
                Value::U64(a.wrapping_add(b))
            }
            NodeTypeV2::Sub => {
                let a = eval_node(node.inputs[0], node_map, ctx, cache)?.as_u64()?;
                let b = eval_node(node.inputs[1], node_map, ctx, cache)?.as_u64()?;
                Value::U64(a.wrapping_sub(b))
            }
            NodeTypeV2::MulConst => {
                let a = eval_node(node.inputs[0], node_map, ctx, cache)?.as_u64()?;
                Value::U64(a.wrapping_mul(node.const_value))
            }
            NodeTypeV2::DivConst => {
                if node.const_value == 0 {
                    return Err(EvalError::DivisionByZero);
                }
                let a = eval_node(node.inputs[0], node_map, ctx, cache)?.as_u64()?;
                Value::U64(a / node.const_value)
            }
            NodeTypeV2::Min => {
                let a = eval_node(node.inputs[0], node_map, ctx, cache)?.as_u64()?;
                let b = eval_node(node.inputs[1], node_map, ctx, cache)?.as_u64()?;
                Value::U64(a.min(b))
            }
            NodeTypeV2::Max => {
                let a = eval_node(node.inputs[0], node_map, ctx, cache)?.as_u64()?;
                let b = eval_node(node.inputs[1], node_map, ctx, cache)?.as_u64()?;
                Value::U64(a.max(b))
            }
            NodeTypeV2::Clamp => {
                let x = eval_node(node.inputs[0], node_map, ctx, cache)?.as_u64()?;
                let lo = eval_node(node.inputs[1], node_map, ctx, cache)?.as_u64()?;
                let hi = eval_node(node.inputs[2], node_map, ctx, cache)?.as_u64()?;
                Value::U64(x.clamp(lo, hi))
            }

            NodeTypeV2::Eq => {
                let a = eval_node(node.inputs[0], node_map, ctx, cache)?.as_u64()?;
                let b = eval_node(node.inputs[1], node_map, ctx, cache)?.as_u64()?;
                Value::Bool(a == b)
            }
            NodeTypeV2::Ne => {
                let a = eval_node(node.inputs[0], node_map, ctx, cache)?.as_u64()?;
                let b = eval_node(node.inputs[1], node_map, ctx, cache)?.as_u64()?;
                Value::Bool(a != b)
            }
            NodeTypeV2::Lt => {
                let a = eval_node(node.inputs[0], node_map, ctx, cache)?.as_u64()?;
                let b = eval_node(node.inputs[1], node_map, ctx, cache)?.as_u64()?;
                Value::Bool(a < b)
            }
            NodeTypeV2::Le => {
                let a = eval_node(node.inputs[0], node_map, ctx, cache)?.as_u64()?;
                let b = eval_node(node.inputs[1], node_map, ctx, cache)?.as_u64()?;
                Value::Bool(a <= b)
            }
            NodeTypeV2::Gt => {
                let a = eval_node(node.inputs[0], node_map, ctx, cache)?.as_u64()?;
                let b = eval_node(node.inputs[1], node_map, ctx, cache)?.as_u64()?;
                Value::Bool(a > b)
            }
            NodeTypeV2::Ge => {
                let a = eval_node(node.inputs[0], node_map, ctx, cache)?.as_u64()?;
                let b = eval_node(node.inputs[1], node_map, ctx, cache)?.as_u64()?;
                Value::Bool(a >= b)
            }

            NodeTypeV2::And => {
                let a = eval_node(node.inputs[0], node_map, ctx, cache)?.as_bool()?;
                let b = eval_node(node.inputs[1], node_map, ctx, cache)?.as_bool()?;
                Value::Bool(a && b)
            }
            NodeTypeV2::Or => {
                let a = eval_node(node.inputs[0], node_map, ctx, cache)?.as_bool()?;
                let b = eval_node(node.inputs[1], node_map, ctx, cache)?.as_bool()?;
                Value::Bool(a || b)
            }
            NodeTypeV2::Not => {
                let a = eval_node(node.inputs[0], node_map, ctx, cache)?.as_bool()?;
                Value::Bool(!a)
            }
        };

        cache.insert(node_id, result);
        Ok(result)
    }

    let output = eval_node(dag.output_node, &node_map, ctx, &mut cache)?;
    output.as_bool()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir_v2::NodeV2;

    fn make_ge_100_dag() -> CompiledPolicyV2 {
        let key_hash = [1u8; 32];
        let nodes = vec![
            NodeV2 {
                node_type: NodeTypeV2::LoadStateU64,
                node_id: 0,
                inputs: [0; 3],
                key_hash,
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
    fn eval_ge_100_accept() {
        let dag = make_ge_100_dag();
        let mut ctx = EvalContext::default();
        ctx.state.insert([1u8; 32], 150);

        assert_eq!(evaluate(&dag, &ctx), Ok(true));
    }

    #[test]
    fn eval_ge_100_reject() {
        let dag = make_ge_100_dag();
        let mut ctx = EvalContext::default();
        ctx.state.insert([1u8; 32], 50);

        assert_eq!(evaluate(&dag, &ctx), Ok(false));
    }

    #[test]
    fn eval_ge_100_boundary() {
        let dag = make_ge_100_dag();
        let mut ctx = EvalContext::default();
        ctx.state.insert([1u8; 32], 100);

        assert_eq!(evaluate(&dag, &ctx), Ok(true));
    }

    #[test]
    fn eval_missing_key_error() {
        let dag = make_ge_100_dag();
        let ctx = EvalContext::default();

        assert!(matches!(evaluate(&dag, &ctx), Err(EvalError::MissingStateKey(_))));
    }
}
