//! Intermediate Representation for Tau-MPRD.
//!
//! Converts checked AST to a circuit representation.

use crate::ast::*;
use crate::error::CompileResult;
use crate::semantic::CheckedSpec;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Domain for key hashing (matches TCV spec).
pub const KEY_HASH_DOMAIN: &[u8] = b"MPRD_KEY_V1";

/// Operand source type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OperandSource {
    State = 0,
    Candidate = 1,
    Constant = 2,
}

/// Value kind for type-safe extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ValueKind {
    U64 = 0,
    Bool = 2,
}

/// Operand path in the compiled artifact.
#[derive(Debug, Clone)]
pub struct OperandPath {
    pub source: OperandSource,
    pub key_hash: [u8; 32],
    pub value_kind: ValueKind,
    pub constant_value: [u8; 8],
}

impl OperandPath {
    pub fn from_state_field(name: &str) -> Self {
        Self {
            source: OperandSource::State,
            key_hash: hash_key(name),
            value_kind: ValueKind::U64,
            constant_value: [0u8; 8],
        }
    }
    
    pub fn from_candidate_field(name: &str) -> Self {
        Self {
            source: OperandSource::Candidate,
            key_hash: hash_key(name),
            value_kind: ValueKind::U64,
            constant_value: [0u8; 8],
        }
    }
    
    pub fn from_constant(value: u64) -> Self {
        Self {
            source: OperandSource::Constant,
            key_hash: [0u8; 32],
            value_kind: ValueKind::U64,
            constant_value: value.to_le_bytes(),
        }
    }
}

/// Hash a key name with domain separation.
pub fn hash_key(name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_HASH_DOMAIN);
    hasher.update(name.as_bytes());
    hasher.finalize().into()
}

/// Arithmetic comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ArithOp {
    LessThan = 0,
    LessThanEq = 1,
    GreaterThan = 2,
    GreaterThanEq = 3,
    Equals = 4,
    NotEquals = 5,
}

impl From<CompareOp> for ArithOp {
    fn from(op: CompareOp) -> Self {
        match op {
            CompareOp::Lt => ArithOp::LessThan,
            CompareOp::Le => ArithOp::LessThanEq,
            CompareOp::Gt => ArithOp::GreaterThan,
            CompareOp::Ge => ArithOp::GreaterThanEq,
            CompareOp::Eq => ArithOp::Equals,
            CompareOp::Ne => ArithOp::NotEquals,
        }
    }
}

/// Predicate specification.
#[derive(Debug, Clone)]
pub struct PredicateSpec {
    pub predicate_idx: u32,
    pub op: ArithOp,
    pub left: OperandPath,
    pub right: OperandPath,
}

/// Gate type in the Boolean circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GateType {
    And = 0,
    Or = 1,
    Not = 2,
    PredicateInput = 3,
    TemporalInput = 4,
    Constant = 5,
}

/// Boolean circuit gate.
#[derive(Debug, Clone)]
pub struct Gate {
    pub gate_type: GateType,
    pub out_wire: u32,
    pub in1: u32,
    pub in2: u32,
}

/// Temporal field specification.
#[derive(Debug, Clone)]
pub struct TemporalFieldSpec {
    pub field_idx: u32,
    pub current_key_hash: [u8; 32],
    pub prev_key_hashes: Vec<[u8; 32]>,
}

/// Compiled policy artifact (matches TCV spec).
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub version: u32,
    pub predicates: Vec<PredicateSpec>,
    pub gates: Vec<Gate>,
    pub output_wire: u32,
    pub temporal_fields: Vec<TemporalFieldSpec>,
}

/// IR builder state.
struct IrBuilder {
    predicates: Vec<PredicateSpec>,
    gates: Vec<Gate>,
    temporal_fields: Vec<TemporalFieldSpec>,
    next_predicate_idx: u32,
    next_wire: u32,
    // Map from (field_name, offset) to temporal field index
    temporal_field_map: HashMap<(String, usize), u32>,
}

impl IrBuilder {
    fn new() -> Self {
        Self {
            predicates: Vec::new(),
            gates: Vec::new(),
            temporal_fields: Vec::new(),
            next_predicate_idx: 0,
            next_wire: 0,
            temporal_field_map: HashMap::new(),
        }
    }
    
    fn alloc_wire(&mut self) -> u32 {
        let wire = self.next_wire;
        self.next_wire += 1;
        wire
    }
    
    fn add_predicate(&mut self, op: ArithOp, left: OperandPath, right: OperandPath) -> u32 {
        let idx = self.next_predicate_idx;
        self.next_predicate_idx += 1;
        
        self.predicates.push(PredicateSpec {
            predicate_idx: idx,
            op,
            left,
            right,
        });
        
        // Create a gate that loads this predicate result
        let wire = self.alloc_wire();
        self.gates.push(Gate {
            gate_type: GateType::PredicateInput,
            out_wire: wire,
            in1: idx,
            in2: 0,
        });
        
        wire
    }
    
    fn add_constant_gate(&mut self, value: bool) -> u32 {
        let wire = self.alloc_wire();
        self.gates.push(Gate {
            gate_type: GateType::Constant,
            out_wire: wire,
            in1: if value { 1 } else { 0 },
            in2: 0,
        });
        wire
    }
    
    fn add_and_gate(&mut self, in1: u32, in2: u32) -> u32 {
        let wire = self.alloc_wire();
        self.gates.push(Gate {
            gate_type: GateType::And,
            out_wire: wire,
            in1,
            in2,
        });
        wire
    }
    
    fn add_or_gate(&mut self, in1: u32, in2: u32) -> u32 {
        let wire = self.alloc_wire();
        self.gates.push(Gate {
            gate_type: GateType::Or,
            out_wire: wire,
            in1,
            in2,
        });
        wire
    }
    
    fn add_not_gate(&mut self, in1: u32) -> u32 {
        let wire = self.alloc_wire();
        self.gates.push(Gate {
            gate_type: GateType::Not,
            out_wire: wire,
            in1,
            in2: 0,
        });
        wire
    }
    
    fn register_temporal_field(&mut self, name: &str, max_offset: usize) -> u32 {
        let key = (name.to_string(), max_offset);
        if let Some(&idx) = self.temporal_field_map.get(&key) {
            return idx;
        }
        
        let idx = self.temporal_fields.len() as u32;
        
        // Generate key hashes for current and previous values
        let current_key_hash = hash_key(name);
        let mut prev_key_hashes = Vec::new();
        for i in 1..=max_offset {
            let prev_name = format!("{}_t_{}", name, i);
            prev_key_hashes.push(hash_key(&prev_name));
        }
        
        self.temporal_fields.push(TemporalFieldSpec {
            field_idx: idx,
            current_key_hash,
            prev_key_hashes,
        });
        
        self.temporal_field_map.insert(key, idx);
        idx
    }
    
    fn lower_operand(&mut self, operand: &Operand) -> OperandPath {
        match operand {
            Operand::StateField(field) => {
                if field.temporal_offset > 0 {
                    // Generate key hash for the specific offset
                    let key_name = if field.temporal_offset == 0 {
                        field.name.clone()
                    } else {
                        format!("{}_t_{}", field.name, field.temporal_offset)
                    };
                    
                    OperandPath {
                        source: OperandSource::State,
                        key_hash: hash_key(&key_name),
                        value_kind: ValueKind::U64,
                        constant_value: [0u8; 8],
                    }
                } else {
                    OperandPath::from_state_field(&field.name)
                }
            }
            Operand::CandidateField(field) => {
                OperandPath::from_candidate_field(&field.name)
            }
            Operand::Constant(value) => {
                OperandPath::from_constant(*value)
            }
        }
    }
    
    fn lower_comparison(&mut self, cmp: &Comparison) -> u32 {
        let left = self.lower_operand(&cmp.left);
        let right = self.lower_operand(&cmp.right);
        let op = ArithOp::from(cmp.op);
        
        self.add_predicate(op, left, right)
    }
    
    fn lower_local_spec(&mut self, spec: &LocalSpec) -> u32 {
        match spec {
            LocalSpec::And(left, right) => {
                let left_wire = self.lower_local_spec(left);
                let right_wire = self.lower_local_spec(right);
                self.add_and_gate(left_wire, right_wire)
            }
            LocalSpec::Or(left, right) => {
                let left_wire = self.lower_local_spec(left);
                let right_wire = self.lower_local_spec(right);
                self.add_or_gate(left_wire, right_wire)
            }
            LocalSpec::Not(inner) => {
                let inner_wire = self.lower_local_spec(inner);
                self.add_not_gate(inner_wire)
            }
            LocalSpec::Compare(cmp) => {
                self.lower_comparison(cmp)
            }
            LocalSpec::True => {
                self.add_constant_gate(true)
            }
            LocalSpec::False => {
                self.add_constant_gate(false)
            }
        }
    }
    
    fn lower(&mut self, spec: &CheckedSpec) -> CompileResult<CompiledPolicy> {
        // Register all temporal fields with their max offsets
        for (name, &max_offset) in spec.state_fields.iter() {
            if max_offset > 0 {
                self.register_temporal_field(name, max_offset);
            }
        }
        
        // Lower the body to circuit
        let output_wire = self.lower_local_spec(&spec.spec.body);
        
        // Sort predicates by index
        self.predicates.sort_by_key(|p| p.predicate_idx);
        
        // Sort temporal fields by index
        self.temporal_fields.sort_by_key(|t| t.field_idx);
        
        Ok(CompiledPolicy {
            version: 1,
            predicates: self.predicates.clone(),
            gates: self.gates.clone(),
            output_wire,
            temporal_fields: self.temporal_fields.clone(),
        })
    }
}

/// Lower checked AST to IR.
pub fn lower(spec: &CheckedSpec) -> CompileResult<CompiledPolicy> {
    let mut builder = IrBuilder::new();
    builder.lower(spec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::tokenize;
    use crate::parser::parse;
    use crate::semantic::analyze;
    
    fn lower_source(source: &str) -> CompileResult<CompiledPolicy> {
        let tokens = tokenize(source)?;
        let ast = parse(&tokens)?;
        let checked = analyze(&ast)?;
        lower(&checked)
    }
    
    #[test]
    fn lower_simple_comparison() {
        let policy = lower_source("always (state.x >= 100)").unwrap();
        assert_eq!(policy.version, 1);
        assert_eq!(policy.predicates.len(), 1);
        assert_eq!(policy.predicates[0].op, ArithOp::GreaterThanEq);
    }
    
    #[test]
    fn lower_compound_and() {
        let policy = lower_source("always (state.a < 10 && state.b > 0)").unwrap();
        assert_eq!(policy.predicates.len(), 2);
        // Should have AND gate
        assert!(policy.gates.iter().any(|g| g.gate_type == GateType::And));
    }
    
    #[test]
    fn lower_compound_or() {
        let policy = lower_source("always (state.a = 1 || state.b = 2)").unwrap();
        assert!(policy.gates.iter().any(|g| g.gate_type == GateType::Or));
    }
    
    #[test]
    fn lower_not() {
        let policy = lower_source("always !(state.x = 0)").unwrap();
        assert!(policy.gates.iter().any(|g| g.gate_type == GateType::Not));
    }
    
    #[test]
    fn lower_temporal_field() {
        let policy = lower_source("always (state.x[t-2] < state.x)").unwrap();
        assert_eq!(policy.temporal_fields.len(), 1);
        assert_eq!(policy.temporal_fields[0].prev_key_hashes.len(), 2);
    }
    
    #[test]
    fn lower_constant() {
        let policy = lower_source("always (candidate.amount <= 1000000)").unwrap();
        assert_eq!(policy.predicates[0].right.source, OperandSource::Constant);
        let value = u64::from_le_bytes(policy.predicates[0].right.constant_value);
        assert_eq!(value, 1000000);
    }
}
