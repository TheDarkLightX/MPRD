//! Policy artifact storage and decoding helpers.
//!
//! Production checklist item: policy fetching + authorization anchoring at the pipeline boundary.
//! These helpers allow a deployment to fetch policy artifacts by `policy_hash` (content identity)
//! and fail-closed validate that the bytes match the expected hash/exec kind.

use crate::risc0_host::MpbPolicyArtifactV1;
use mprd_core::{MprdError, Result};
use mprd_risc0_shared::MAX_POLICY_BYTECODE_BYTES_V1;

/// Canonical mpb-v1 policy artifact encoding (must match `mprd_mpb::policy_hash_v1` preimage).
///
/// Layout (little-endian):
/// - `u32` bytecode_len
/// - `bytecode` bytes
/// - `u32` binding_count
/// - for each binding (canonical order by name bytes ascending):
///   - `u32` name_len
///   - `name` bytes (UTF-8)
///   - `u8` reg_index
pub fn decode_mpb_policy_artifact_bytes_v1(bytes: &[u8]) -> Result<MpbPolicyArtifactV1> {
    let mut offset: usize = 0;

    fn read_u32_le(bytes: &[u8], offset: &mut usize) -> Result<u32> {
        let end = offset
            .checked_add(4)
            .ok_or_else(|| MprdError::InvalidInput("mpb policy artifact overflow".into()))?;
        let b: [u8; 4] = bytes
            .get(*offset..end)
            .ok_or_else(|| MprdError::InvalidInput("mpb policy artifact truncated".into()))?
            .try_into()
            .map_err(|_| MprdError::InvalidInput("mpb policy artifact malformed".into()))?;
        *offset = end;
        Ok(u32::from_le_bytes(b))
    }

    fn read_u8(bytes: &[u8], offset: &mut usize) -> Result<u8> {
        let b = *bytes
            .get(*offset)
            .ok_or_else(|| MprdError::InvalidInput("mpb policy artifact truncated".into()))?;
        *offset = offset
            .checked_add(1)
            .ok_or_else(|| MprdError::InvalidInput("mpb policy artifact overflow".into()))?;
        Ok(b)
    }

    fn read_len_prefixed_bytes<'a>(bytes: &'a [u8], offset: &mut usize) -> Result<&'a [u8]> {
        let len = read_u32_le(bytes, offset)? as usize;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| MprdError::InvalidInput("mpb policy artifact overflow".into()))?;
        let out = bytes
            .get(*offset..end)
            .ok_or_else(|| MprdError::InvalidInput("mpb policy artifact truncated".into()))?;
        *offset = end;
        Ok(out)
    }

    let bytecode_len = read_u32_le(bytes, &mut offset)? as usize;
    if bytecode_len > MAX_POLICY_BYTECODE_BYTES_V1 {
        return Err(MprdError::BoundedValueExceeded(
            "mpb policy bytecode too large".into(),
        ));
    }
    let bytecode_end = offset
        .checked_add(bytecode_len)
        .ok_or_else(|| MprdError::InvalidInput("mpb policy artifact overflow".into()))?;
    let bytecode = bytes
        .get(offset..bytecode_end)
        .ok_or_else(|| MprdError::InvalidInput("mpb policy artifact truncated".into()))?
        .to_vec();
    offset = bytecode_end;

    let binding_count = read_u32_le(bytes, &mut offset)? as usize;
    if binding_count > mprd_mpb::MpbVm::MAX_REGISTERS {
        return Err(MprdError::BoundedValueExceeded(
            "mpb policy has too many register bindings".into(),
        ));
    }

    let mut variables: Vec<(String, u8)> = Vec::with_capacity(binding_count);
    for _ in 0..binding_count {
        let name_bytes = read_len_prefixed_bytes(bytes, &mut offset)?;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| MprdError::InvalidInput("mpb policy variable name must be UTF-8".into()))?
            .to_string();
        if name.is_empty() {
            return Err(MprdError::InvalidInput(
                "mpb policy variable name must be non-empty".into(),
            ));
        }
        let reg = read_u8(bytes, &mut offset)?;
        variables.push((name, reg));
    }

    if offset != bytes.len() {
        return Err(MprdError::InvalidInput(
            "mpb policy artifact has trailing bytes".into(),
        ));
    }

    // Fail-closed canonicalization: bindings MUST be unique and sorted by name.
    for w in variables.windows(2) {
        if w[0].0 >= w[1].0 {
            return Err(MprdError::InvalidInput(
                "mpb policy variable bindings must be unique and sorted".into(),
            ));
        }
    }

    Ok(MpbPolicyArtifactV1 {
        bytecode,
        variables,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_mpb_policy_artifact_bytes_v1(bytecode: &[u8], vars: &[(&str, u8)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(bytecode.len() as u32).to_le_bytes());
        out.extend_from_slice(bytecode);
        out.extend_from_slice(&(vars.len() as u32).to_le_bytes());
        for (name, reg) in vars {
            out.extend_from_slice(&(name.len() as u32).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.push(*reg);
        }
        out
    }

    #[test]
    fn mpb_policy_artifact_decode_rejects_unsorted_bindings() {
        let bytes = encode_mpb_policy_artifact_bytes_v1(&[0xFF], &[("b", 0), ("a", 1)]);
        let err = decode_mpb_policy_artifact_bytes_v1(&bytes).expect_err("must reject");
        assert!(matches!(err, mprd_core::MprdError::InvalidInput(_)));
    }

    #[test]
    fn mpb_policy_artifact_decode_roundtrips_basic_fields() {
        let bytes = encode_mpb_policy_artifact_bytes_v1(&[0x01, 0xFF], &[("a", 0), ("b", 1)]);
        let decoded = decode_mpb_policy_artifact_bytes_v1(&bytes).expect("decode");
        assert_eq!(decoded.bytecode, vec![0x01, 0xFF]);
        assert_eq!(decoded.variables.len(), 2);
        assert_eq!(decoded.variables[0], ("a".to_string(), 0));
        assert_eq!(decoded.variables[1], ("b".to_string(), 1));
    }

    #[test]
    fn mpb_policy_artifact_decode_rejects_trailing_bytes() {
        let mut bytes = encode_mpb_policy_artifact_bytes_v1(&[0xFF], &[("a", 0)]);
        bytes.push(0x00);
        let err = decode_mpb_policy_artifact_bytes_v1(&bytes).expect_err("must reject");
        assert!(matches!(err, mprd_core::MprdError::InvalidInput(_)));
    }
}
