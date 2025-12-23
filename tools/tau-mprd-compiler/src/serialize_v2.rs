//! Canonical serialization for Tau-MPRD v2 compiled artifacts.

use crate::error::{CompileError, CompileResult};
use crate::ir_v2::{CompiledPolicyV2, NodeTypeV2, NodeV2, TemporalFieldSpecV2};
use crate::limits::{MAX_KEY_LENGTH_V1, MAX_LOOKBACK_V1, MAX_TEMPORAL_FIELDS_V1};

/// Maximum artifact size for v2.
pub const MAX_ARTIFACT_BYTES_V2: usize = 128 * 1024;

/// Maximum nodes in v2 artifact.
pub const MAX_NODES_V2: usize = 4096;

/// Serialize v2 compiled policy to canonical bytes.
///
/// Format (all integers are little-endian):
/// - version: u32 (= 2)
/// - node_count: u32
/// - nodes: [NodeV2]
/// - output_node: u32
/// - temporal_field_count: u32
/// - temporal_fields: [TemporalFieldSpecV2]
pub fn to_canonical_bytes_v2(policy: &CompiledPolicyV2) -> CompileResult<Vec<u8>> {
    if policy.version != 2 {
        return Err(CompileError::UnsupportedArtifactVersion {
            version: policy.version,
        });
    }

    // Validate bounds
    if policy.nodes.len() > MAX_NODES_V2 {
        return Err(CompileError::NodeCountExceeded {
            count: policy.nodes.len(),
            max: MAX_NODES_V2,
        });
    }
    if policy.temporal_fields.len() > MAX_TEMPORAL_FIELDS_V1 {
        return Err(CompileError::TemporalFieldCountExceeded {
            count: policy.temporal_fields.len(),
            max: MAX_TEMPORAL_FIELDS_V1,
        });
    }
    
    let mut buf = Vec::new();
    
    // Version
    buf.extend_from_slice(&policy.version.to_le_bytes());
    
    // Nodes
    buf.extend_from_slice(&(policy.nodes.len() as u32).to_le_bytes());
    for node in &policy.nodes {
        serialize_node(&mut buf, node);
    }
    
    // Output node
    buf.extend_from_slice(&policy.output_node.to_le_bytes());
    
    // Temporal fields
    buf.extend_from_slice(&(policy.temporal_fields.len() as u32).to_le_bytes());
    for tf in &policy.temporal_fields {
        if tf.field_name.is_empty() || tf.field_name.len() > MAX_KEY_LENGTH_V1 {
            return Err(CompileError::KeyTooLong {
                key: tf.field_name.clone(),
                max: MAX_KEY_LENGTH_V1,
            });
        }
        if tf.max_lookback == 0 || tf.max_lookback > MAX_LOOKBACK_V1 {
            return Err(CompileError::LookbackExceeded {
                lookback: tf.max_lookback,
                max: MAX_LOOKBACK_V1,
            });
        }
        if tf.lookback_key_hashes.len() != tf.max_lookback {
            return Err(CompileError::internal(
                "temporal field lookback_key_hashes length mismatch",
            ));
        }
        serialize_temporal_field(&mut buf, tf);
    }
    
    // Check size bound
    if buf.len() > MAX_ARTIFACT_BYTES_V2 {
        return Err(CompileError::ArtifactTooLarge {
            size: buf.len(),
            max: MAX_ARTIFACT_BYTES_V2,
        });
    }
    
    Ok(buf)
}

fn serialize_node(buf: &mut Vec<u8>, node: &NodeV2) {
    buf.push(node.node_type as u8);
    buf.extend_from_slice(&node.node_id.to_le_bytes());
    buf.extend_from_slice(&node.inputs[0].to_le_bytes());
    buf.extend_from_slice(&node.inputs[1].to_le_bytes());
    buf.extend_from_slice(&node.inputs[2].to_le_bytes());
    buf.extend_from_slice(&node.key_hash);
    buf.extend_from_slice(&node.const_value.to_le_bytes());
}

fn serialize_temporal_field(buf: &mut Vec<u8>, tf: &TemporalFieldSpecV2) {
    // field_name length + bytes
    let name_bytes = tf.field_name.as_bytes();
    buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(name_bytes);
    
    // current_key_hash
    buf.extend_from_slice(&tf.current_key_hash);
    
    // max_lookback
    buf.extend_from_slice(&(tf.max_lookback as u32).to_le_bytes());
    
    // lookback_key_hashes
    buf.extend_from_slice(&(tf.lookback_key_hashes.len() as u32).to_le_bytes());
    for kh in &tf.lookback_key_hashes {
        buf.extend_from_slice(kh);
    }
}

/// Deserialize v2 compiled policy from canonical bytes.
pub fn from_canonical_bytes_v2(bytes: &[u8]) -> CompileResult<CompiledPolicyV2> {
    let mut cursor = 0;
    
    // Version
    let version = read_u32(bytes, &mut cursor)?;
    if version != 2 {
        return Err(CompileError::internal(format!("expected version 2, got {}", version)));
    }
    
    // Nodes
    let node_count = read_u32(bytes, &mut cursor)? as usize;
    if node_count > MAX_NODES_V2 {
        return Err(CompileError::NodeCountExceeded {
            count: node_count,
            max: MAX_NODES_V2,
        });
    }
    
    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        nodes.push(deserialize_node(bytes, &mut cursor)?);
    }
    
    // Output node
    let output_node = read_u32(bytes, &mut cursor)?;
    
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
    
    // Build key schemas from nodes
    let mut state_keys = std::collections::BTreeMap::new();
    let candidate_keys = std::collections::BTreeMap::new();
    
    for node in &nodes {
        match node.node_type {
            NodeTypeV2::LoadStateU64 => {
                // We don't have the name, only the hash - schema reconstruction limited
            }
            NodeTypeV2::LoadCandidateU64 => {
                // Same limitation
            }
            _ => {}
        }
    }
    
    // Add temporal field names to state_keys
    for tf in &temporal_fields {
        state_keys.insert(tf.field_name.clone(), tf.current_key_hash);
    }
    
    Ok(CompiledPolicyV2 {
        version,
        nodes,
        output_node,
        temporal_fields,
        state_keys,
        candidate_keys,
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

fn read_u64(bytes: &[u8], cursor: &mut usize) -> CompileResult<u64> {
    if *cursor + 8 > bytes.len() {
        return Err(CompileError::internal("unexpected end of artifact bytes"));
    }
    let value = u64::from_le_bytes(bytes[*cursor..*cursor + 8].try_into().unwrap());
    *cursor += 8;
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

fn deserialize_node(bytes: &[u8], cursor: &mut usize) -> CompileResult<NodeV2> {
    let node_type_byte = read_u8(bytes, cursor)?;
    let node_type = match node_type_byte {
        0 => NodeTypeV2::LoadStateU64,
        1 => NodeTypeV2::LoadCandidateU64,
        2 => NodeTypeV2::ConstU64,
        3 => NodeTypeV2::ConstBool,
        10 => NodeTypeV2::Add,
        11 => NodeTypeV2::Sub,
        12 => NodeTypeV2::MulConst,
        13 => NodeTypeV2::DivConst,
        14 => NodeTypeV2::Min,
        15 => NodeTypeV2::Max,
        16 => NodeTypeV2::Clamp,
        20 => NodeTypeV2::Eq,
        21 => NodeTypeV2::Ne,
        22 => NodeTypeV2::Lt,
        23 => NodeTypeV2::Le,
        24 => NodeTypeV2::Gt,
        25 => NodeTypeV2::Ge,
        30 => NodeTypeV2::And,
        31 => NodeTypeV2::Or,
        32 => NodeTypeV2::Not,
        _ => return Err(CompileError::internal(format!("invalid node type: {}", node_type_byte))),
    };
    
    let node_id = read_u32(bytes, cursor)?;
    let in0 = read_u32(bytes, cursor)?;
    let in1 = read_u32(bytes, cursor)?;
    let in2 = read_u32(bytes, cursor)?;
    let key_hash = read_bytes::<32>(bytes, cursor)?;
    let const_value = read_u64(bytes, cursor)?;
    
    Ok(NodeV2 {
        node_type,
        node_id,
        inputs: [in0, in1, in2],
        key_hash,
        const_value,
    })
}

fn deserialize_temporal_field(bytes: &[u8], cursor: &mut usize) -> CompileResult<TemporalFieldSpecV2> {
    // field_name
    let name_len = read_u32(bytes, cursor)? as usize;
    if *cursor + name_len > bytes.len() {
        return Err(CompileError::internal("unexpected end of artifact bytes"));
    }
    let field_name = String::from_utf8(bytes[*cursor..*cursor + name_len].to_vec())
        .map_err(|_| CompileError::internal("invalid UTF-8 in field name"))?;
    *cursor += name_len;

    if field_name.is_empty() || field_name.len() > MAX_KEY_LENGTH_V1 {
        return Err(CompileError::KeyTooLong {
            key: field_name,
            max: MAX_KEY_LENGTH_V1,
        });
    }
    
    // current_key_hash
    let current_key_hash = read_bytes::<32>(bytes, cursor)?;
    
    // max_lookback
    let max_lookback = read_u32(bytes, cursor)? as usize;
    if max_lookback == 0 || max_lookback > MAX_LOOKBACK_V1 {
        return Err(CompileError::LookbackExceeded {
            lookback: max_lookback,
            max: MAX_LOOKBACK_V1,
        });
    }
    
    // lookback_key_hashes
    let hash_count = read_u32(bytes, cursor)? as usize;
    if hash_count != max_lookback {
        return Err(CompileError::internal(
            "lookback_key_hashes count must equal max_lookback",
        ));
    }
    let mut lookback_key_hashes = Vec::with_capacity(hash_count);
    for _ in 0..hash_count {
        lookback_key_hashes.push(read_bytes::<32>(bytes, cursor)?);
    }
    
    Ok(TemporalFieldSpecV2 {
        field_name,
        current_key_hash,
        max_lookback,
        lookback_key_hashes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer_v2::tokenize_v2;
    use crate::parser_v2::parse_v2;
    use crate::ir_v2::lower_v2;
    
    fn compile_to_bytes(source: &str) -> CompileResult<Vec<u8>> {
        let tokens = tokenize_v2(source)?;
        let ast = parse_v2(&tokens)?;
        let ir = lower_v2(&ast)?;
        to_canonical_bytes_v2(&ir)
    }
    
    #[test]
    fn roundtrip_simple() {
        let bytes = compile_to_bytes("always (state.x >= 100)").unwrap();
        let policy = from_canonical_bytes_v2(&bytes).unwrap();
        assert_eq!(policy.version, 2);
    }
    
    #[test]
    fn roundtrip_arithmetic() {
        let bytes = compile_to_bytes("always (state.a + state.b >= state.threshold)").unwrap();
        let policy = from_canonical_bytes_v2(&bytes).unwrap();
        assert!(policy.nodes.iter().any(|n| n.node_type == NodeTypeV2::Add));
    }
    
    #[test]
    fn roundtrip_temporal() {
        let bytes = compile_to_bytes("always (state.x[t-2] < state.x)").unwrap();
        let policy = from_canonical_bytes_v2(&bytes).unwrap();
        assert_eq!(policy.temporal_fields.len(), 1);
    }
    
    #[test]
    fn deterministic_output() {
        let source = "always (state.w0 * 2 + state.w1 * 3 >= state.threshold)";
        let bytes1 = compile_to_bytes(source).unwrap();
        let bytes2 = compile_to_bytes(source).unwrap();
        assert_eq!(bytes1, bytes2);
    }
}
