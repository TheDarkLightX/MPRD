//! Canonical serialization for Tau-MPRD compiled artifacts.
//!
//! Produces deterministic byte output for hashing.

use crate::error::{CompileError, CompileResult};
use crate::ir::{
    ArithOp, CompiledPolicy, Gate, GateType, OperandPath, OperandSource,
    PredicateSpec, TemporalFieldSpec, ValueKind,
};
use crate::limits::{
    MAX_ARTIFACT_BYTES_V1, MAX_GATES_V1, MAX_LOOKBACK_V1, MAX_PREDICATES_V1, MAX_TEMPORAL_FIELDS_V1,
};

/// Maximum compiled policy artifact size.
pub const MAX_ARTIFACT_BYTES: usize = MAX_ARTIFACT_BYTES_V1;

/// Serialize a compiled policy to canonical bytes.
///
/// Format (all integers are little-endian):
/// - version: u32
/// - predicate_count: u32
/// - predicates: [PredicateSpec]
/// - gate_count: u32
/// - gates: [Gate]
/// - output_wire: u32
/// - temporal_field_count: u32
/// - temporal_fields: [TemporalFieldSpec]
pub fn to_canonical_bytes(policy: &CompiledPolicy) -> CompileResult<Vec<u8>> {
    // Fail-closed: enforce canonical ordering assumptions.
    for w in policy.predicates.windows(2) {
        if w[0].predicate_idx >= w[1].predicate_idx {
            return Err(CompileError::internal(
                "predicates must be strictly increasing by predicate_idx".to_string(),
            ));
        }
    }
    for w in policy.temporal_fields.windows(2) {
        if w[0].field_idx >= w[1].field_idx {
            return Err(CompileError::internal(
                "temporal_fields must be strictly increasing by field_idx".to_string(),
            ));
        }
    }
    for tf in &policy.temporal_fields {
        if tf.prev_key_hashes.len() > MAX_LOOKBACK_V1 {
            return Err(CompileError::internal(
                "temporal prev_key_hashes exceeds MAX_LOOKBACK".to_string(),
            ));
        }
    }

    let mut buf = Vec::new();
    
    // Version
    buf.extend_from_slice(&policy.version.to_le_bytes());
    
    // Predicates
    buf.extend_from_slice(&(policy.predicates.len() as u32).to_le_bytes());
    for pred in &policy.predicates {
        serialize_predicate(&mut buf, pred);
    }
    
    // Gates
    buf.extend_from_slice(&(policy.gates.len() as u32).to_le_bytes());
    for gate in &policy.gates {
        serialize_gate(&mut buf, gate);
    }
    
    // Output wire
    buf.extend_from_slice(&policy.output_wire.to_le_bytes());
    
    // Temporal fields
    buf.extend_from_slice(&(policy.temporal_fields.len() as u32).to_le_bytes());
    for tf in &policy.temporal_fields {
        serialize_temporal_field(&mut buf, tf);
    }
    
    // Check size bound
    if buf.len() > MAX_ARTIFACT_BYTES {
        return Err(CompileError::ArtifactTooLarge {
            size: buf.len(),
            max: MAX_ARTIFACT_BYTES,
        });
    }
    
    Ok(buf)
}

fn serialize_predicate(buf: &mut Vec<u8>, pred: &PredicateSpec) {
    buf.extend_from_slice(&pred.predicate_idx.to_le_bytes());
    buf.push(pred.op as u8);
    serialize_operand_path(buf, &pred.left);
    serialize_operand_path(buf, &pred.right);
}

fn serialize_operand_path(buf: &mut Vec<u8>, path: &OperandPath) {
    buf.push(path.source as u8);
    buf.extend_from_slice(&path.key_hash);
    buf.push(path.value_kind as u8);
    buf.extend_from_slice(&path.constant_value);
}

fn serialize_gate(buf: &mut Vec<u8>, gate: &Gate) {
    buf.push(gate.gate_type as u8);
    buf.extend_from_slice(&gate.out_wire.to_le_bytes());
    buf.extend_from_slice(&gate.in1.to_le_bytes());
    buf.extend_from_slice(&gate.in2.to_le_bytes());
}

fn serialize_temporal_field(buf: &mut Vec<u8>, tf: &TemporalFieldSpec) {
    buf.extend_from_slice(&tf.field_idx.to_le_bytes());
    buf.extend_from_slice(&tf.current_key_hash);
    buf.extend_from_slice(&(tf.prev_key_hashes.len() as u32).to_le_bytes());
    for kh in &tf.prev_key_hashes {
        buf.extend_from_slice(kh);
    }
}

/// Deserialize a compiled policy from canonical bytes.
///
/// Used for testing and verification.
pub fn from_canonical_bytes(bytes: &[u8]) -> CompileResult<CompiledPolicy> {
    if bytes.len() > MAX_ARTIFACT_BYTES_V1 {
        return Err(CompileError::ArtifactTooLarge {
            size: bytes.len(),
            max: MAX_ARTIFACT_BYTES_V1,
        });
    }
    let mut cursor = 0;
    
    // Version
    let version = read_u32(bytes, &mut cursor)?;
    if version != 1 {
        return Err(CompileError::UnsupportedArtifactVersion { version });
    }
    
    // Predicates
    let predicate_count = read_u32(bytes, &mut cursor)? as usize;
    if predicate_count > MAX_PREDICATES_V1 {
        return Err(CompileError::PredicateCountExceeded {
            count: predicate_count,
            max: MAX_PREDICATES_V1,
        });
    }
    let mut predicates = Vec::with_capacity(predicate_count);
    for _ in 0..predicate_count {
        predicates.push(deserialize_predicate(bytes, &mut cursor)?);
    }
    
    // Gates
    let gate_count = read_u32(bytes, &mut cursor)? as usize;
    if gate_count > MAX_GATES_V1 {
        return Err(CompileError::GateCountExceeded {
            count: gate_count,
            max: MAX_GATES_V1,
        });
    }
    let mut gates = Vec::with_capacity(gate_count);
    for _ in 0..gate_count {
        gates.push(deserialize_gate(bytes, &mut cursor)?);
    }
    
    // Output wire
    let output_wire = read_u32(bytes, &mut cursor)?;
    
    // Temporal fields
    let tf_count = read_u32(bytes, &mut cursor)? as usize;
    if tf_count > MAX_TEMPORAL_FIELDS_V1 {
        return Err(CompileError::TemporalFieldCountExceeded {
            count: tf_count,
            max: MAX_TEMPORAL_FIELDS_V1,
        });
    }
    let mut temporal_fields = Vec::with_capacity(tf_count);
    for _ in 0..tf_count {
        temporal_fields.push(deserialize_temporal_field(bytes, &mut cursor)?);
    }

    if cursor != bytes.len() {
        return Err(CompileError::TrailingBytes {
            remaining: bytes.len().saturating_sub(cursor),
        });
    }
    
    Ok(CompiledPolicy {
        version,
        predicates,
        gates,
        output_wire,
        temporal_fields,
    })
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> CompileResult<u32> {
    if *cursor + 4 > bytes.len() {
        return Err(CompileError::internal("unexpected end of artifact bytes"));
    }
    let value = u32::from_le_bytes(bytes[*cursor..*cursor + 4].try_into().unwrap());
    *cursor += 4;
    Ok(value)
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> CompileResult<u8> {
    if *cursor >= bytes.len() {
        return Err(CompileError::internal("unexpected end of artifact bytes"));
    }
    let value = bytes[*cursor];
    *cursor += 1;
    Ok(value)
}

fn read_bytes<const N: usize>(bytes: &[u8], cursor: &mut usize) -> CompileResult<[u8; N]> {
    if *cursor + N > bytes.len() {
        return Err(CompileError::internal("unexpected end of artifact bytes"));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    Ok(arr)
}

fn deserialize_predicate(bytes: &[u8], cursor: &mut usize) -> CompileResult<PredicateSpec> {
    let predicate_idx = read_u32(bytes, cursor)?;
    let op_byte = read_u8(bytes, cursor)?;
    let op = match op_byte {
        0 => ArithOp::LessThan,
        1 => ArithOp::LessThanEq,
        2 => ArithOp::GreaterThan,
        3 => ArithOp::GreaterThanEq,
        4 => ArithOp::Equals,
        5 => ArithOp::NotEquals,
        _ => return Err(CompileError::internal(format!("invalid ArithOp: {}", op_byte))),
    };
    let left = deserialize_operand_path(bytes, cursor)?;
    let right = deserialize_operand_path(bytes, cursor)?;
    
    Ok(PredicateSpec { predicate_idx, op, left, right })
}

fn deserialize_operand_path(bytes: &[u8], cursor: &mut usize) -> CompileResult<OperandPath> {
    let source_byte = read_u8(bytes, cursor)?;
    let source = match source_byte {
        0 => OperandSource::State,
        1 => OperandSource::Candidate,
        2 => OperandSource::Constant,
        _ => return Err(CompileError::internal(format!("invalid OperandSource: {}", source_byte))),
    };
    let key_hash = read_bytes::<32>(bytes, cursor)?;
    let value_kind_byte = read_u8(bytes, cursor)?;
    let value_kind = match value_kind_byte {
        0 => ValueKind::U64,
        2 => ValueKind::Bool,
        _ => return Err(CompileError::internal(format!("invalid ValueKind: {}", value_kind_byte))),
    };
    let constant_value = read_bytes::<8>(bytes, cursor)?;
    
    Ok(OperandPath { source, key_hash, value_kind, constant_value })
}

fn deserialize_gate(bytes: &[u8], cursor: &mut usize) -> CompileResult<Gate> {
    let gate_type_byte = read_u8(bytes, cursor)?;
    let gate_type = match gate_type_byte {
        0 => GateType::And,
        1 => GateType::Or,
        2 => GateType::Not,
        3 => GateType::PredicateInput,
        4 => GateType::TemporalInput,
        5 => GateType::Constant,
        _ => return Err(CompileError::internal(format!("invalid GateType: {}", gate_type_byte))),
    };
    let out_wire = read_u32(bytes, cursor)?;
    let in1 = read_u32(bytes, cursor)?;
    let in2 = read_u32(bytes, cursor)?;
    
    Ok(Gate { gate_type, out_wire, in1, in2 })
}

fn deserialize_temporal_field(bytes: &[u8], cursor: &mut usize) -> CompileResult<TemporalFieldSpec> {
    let field_idx = read_u32(bytes, cursor)?;
    let current_key_hash = read_bytes::<32>(bytes, cursor)?;
    let prev_count = read_u32(bytes, cursor)? as usize;
    if prev_count > MAX_LOOKBACK_V1 {
        return Err(CompileError::LookbackExceeded {
            lookback: prev_count,
            max: MAX_LOOKBACK_V1,
        });
    }
    let mut prev_key_hashes = Vec::with_capacity(prev_count);
    for _ in 0..prev_count {
        prev_key_hashes.push(read_bytes::<32>(bytes, cursor)?);
    }
    
    Ok(TemporalFieldSpec { field_idx, current_key_hash, prev_key_hashes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::tokenize;
    use crate::parser::parse;
    use crate::semantic::analyze;
    use crate::ir::lower;
    use crate::codegen::generate;
    
    fn compile_to_bytes(source: &str) -> CompileResult<Vec<u8>> {
        let tokens = tokenize(source)?;
        let ast = parse(&tokens)?;
        let checked = analyze(&ast)?;
        let ir = lower(&checked)?;
        let policy = generate(&ir)?;
        to_canonical_bytes(&policy)
    }
    
    #[test]
    fn roundtrip_simple() {
        let bytes = compile_to_bytes("always (state.x >= 100)").unwrap();
        let policy = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(policy.version, 1);
        assert_eq!(policy.predicates.len(), 1);
    }
    
    #[test]
    fn roundtrip_compound() {
        let bytes = compile_to_bytes(
            "always ((state.a < 10 && state.b > 0) || !(state.c = 1))"
        ).unwrap();
        let policy = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(policy.predicates.len(), 3);
    }
    
    #[test]
    fn roundtrip_temporal() {
        let bytes = compile_to_bytes("always (state.x[t-2] < state.x)").unwrap();
        let policy = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(policy.temporal_fields.len(), 1);
        assert_eq!(policy.temporal_fields[0].prev_key_hashes.len(), 2);
    }
    
    #[test]
    fn deterministic_output() {
        let source = "always (state.balance >= candidate.amount && state.rate > 0)";
        let bytes1 = compile_to_bytes(source).unwrap();
        let bytes2 = compile_to_bytes(source).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn reject_trailing_bytes() {
        let mut bytes = compile_to_bytes("always (state.x >= 100)").unwrap();
        bytes.push(0u8);
        let err = from_canonical_bytes(&bytes).unwrap_err();
        assert!(matches!(err, CompileError::TrailingBytes { .. }));
    }
}
