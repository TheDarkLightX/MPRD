use crate::{Hash32, MprdError, Result};
use sha2::{Digest, Sha256};

/// Domain separation tag for hashing canonical limits bytes (must match `mprd-risc0-shared`).
pub const LIMITS_DOMAIN_V1: &[u8] = b"MPRD_LIMITS_V1";

/// Canonical limits tags (v1).
pub mod tags {
    /// Tag for the mpb-v1 per-candidate fuel limit.
    pub const MPB_FUEL_LIMIT: u8 = 1;
    /// Tag for Mode C encryption binding context hash (32 bytes).
    pub const MODE_C_ENCRYPTION_CTX_HASH: u8 = 2;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LimitsV1 {
    pub mpb_fuel_limit: Option<u32>,
    pub mode_c_encryption_ctx_hash: Option<Hash32>,
}

/// Domain separation tag for Mode C encryption binding context (v1).
pub const MODE_C_ENCRYPTION_CTX_DOMAIN_V1: &[u8] = b"MPRD_MODE_C_ENCRYPTION_CTX_V1";

/// Hash canonical limits bytes into a commitment compatible with the zk guest journal.
pub fn limits_hash_v1(limits_bytes: &[u8]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(LIMITS_DOMAIN_V1);
    hasher.update(limits_bytes);
    Hash32(hasher.finalize().into())
}

/// Parse canonical limits bytes for v1.
///
/// Encoding:
/// - A sequence of `tag || value` items, ordered by strictly increasing `tag`.
/// - Each known tag has a fixed value width (no length prefixes).
/// - Unknown tags or malformed encodings are rejected (fail-closed).
pub fn parse_limits_v1(limits_bytes: &[u8]) -> Result<LimitsV1> {
    let mut out = LimitsV1::default();
    let mut i = 0usize;
    let mut prev_tag: Option<u8> = None;

    while i < limits_bytes.len() {
        let tag = *limits_bytes
            .get(i)
            .ok_or_else(|| MprdError::InvalidInput("limits_bytes truncated".into()))?;
        i += 1;

        if let Some(prev) = prev_tag {
            if tag <= prev {
                return Err(MprdError::InvalidInput(
                    "limits_bytes tags must be strictly increasing".into(),
                ));
            }
        }
        prev_tag = Some(tag);

        match tag {
            tags::MPB_FUEL_LIMIT => {
                let raw: [u8; 4] = limits_bytes
                    .get(i..i + 4)
                    .ok_or_else(|| {
                        MprdError::InvalidInput("limits_bytes missing mpb_fuel_limit".into())
                    })?
                    .try_into()
                    .map_err(|_| {
                        MprdError::InvalidInput("limits_bytes mpb_fuel_limit malformed".into())
                    })?;
                i += 4;
                out.mpb_fuel_limit = Some(u32::from_le_bytes(raw));
            }
            tags::MODE_C_ENCRYPTION_CTX_HASH => {
                let raw: [u8; 32] = limits_bytes
                    .get(i..i + 32)
                    .ok_or_else(|| {
                        MprdError::InvalidInput(
                            "limits_bytes missing mode_c_encryption_ctx_hash".into(),
                        )
                    })?
                    .try_into()
                    .map_err(|_| {
                        MprdError::InvalidInput(
                            "limits_bytes mode_c_encryption_ctx_hash malformed".into(),
                        )
                    })?;
                i += 32;
                out.mode_c_encryption_ctx_hash = Some(Hash32(raw));
            }
            _ => return Err(MprdError::InvalidInput(format!("unknown limits tag {tag}"))),
        }
    }

    Ok(out)
}

/// Verify `limits_hash` matches `limits_bytes` (fail-closed).
pub fn verify_limits_binding_v1(limits_hash: &Hash32, limits_bytes: &[u8]) -> Result<()> {
    if *limits_hash != limits_hash_v1(limits_bytes) {
        return Err(MprdError::InvalidInput("limits_bytes hash mismatch".into()));
    }
    Ok(())
}

/// Compute a deterministic Mode C encryption context hash (v1).
///
/// This hash is intended to be committed via `limits_hash/limits_bytes` so verifiers can
/// fail-closed bind the encrypted payload to the same decision transcript.
pub fn mode_c_encryption_ctx_hash_v1(
    state_hash: &Hash32,
    nonce_or_tx_hash: &Hash32,
    key_id: &str,
    algorithm: &str,
    encryption_nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Hash32 {
    let ciphertext_hash = crate::hash::sha256(ciphertext);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MODE_C_ENCRYPTION_CTX_DOMAIN_V1);
    bytes.extend_from_slice(&state_hash.0);
    bytes.extend_from_slice(&nonce_or_tx_hash.0);
    bytes.extend_from_slice(&(key_id.len() as u32).to_le_bytes());
    bytes.extend_from_slice(key_id.as_bytes());
    bytes.extend_from_slice(&(algorithm.len() as u32).to_le_bytes());
    bytes.extend_from_slice(algorithm.as_bytes());
    bytes.extend_from_slice(encryption_nonce);
    bytes.extend_from_slice(&ciphertext_hash.0);
    crate::hash::sha256(&bytes)
}

/// Canonical limits bytes for Mode C encryption binding (v1).
pub fn limits_bytes_mode_c_encryption_ctx_v1(ctx_hash: &Hash32) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32);
    out.push(tags::MODE_C_ENCRYPTION_CTX_HASH);
    out.extend_from_slice(&ctx_hash.0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn empty_limits_parse_and_hash() {
        let bytes = Vec::new();
        let h = limits_hash_v1(&bytes);
        verify_limits_binding_v1(&h, &bytes).expect("binding");
        let parsed = parse_limits_v1(&bytes).expect("parse");
        assert_eq!(parsed, LimitsV1::default());
    }

    #[test]
    fn mpb_fuel_limit_parses() {
        let fuel: u32 = 10_000;
        let mut bytes = vec![tags::MPB_FUEL_LIMIT];
        bytes.extend_from_slice(&fuel.to_le_bytes());
        let parsed = parse_limits_v1(&bytes).expect("parse");
        assert_eq!(parsed.mpb_fuel_limit, Some(fuel));
    }

    #[test]
    fn unknown_tag_is_rejected() {
        let bytes = vec![0xFF, 0x00];
        assert!(parse_limits_v1(&bytes).is_err());
    }

    #[test]
    fn mode_c_encryption_ctx_hash_parses() {
        let ctx = Hash32([7u8; 32]);
        let mut bytes = vec![tags::MODE_C_ENCRYPTION_CTX_HASH];
        bytes.extend_from_slice(&ctx.0);
        let parsed = parse_limits_v1(&bytes).expect("parse");
        assert_eq!(parsed.mode_c_encryption_ctx_hash, Some(ctx));
    }

    #[test]
    fn limits_tags_must_be_strictly_increasing() {
        let ctx = Hash32([7u8; 32]);
        let mut bytes = vec![tags::MODE_C_ENCRYPTION_CTX_HASH];
        bytes.extend_from_slice(&ctx.0);
        bytes.push(tags::MODE_C_ENCRYPTION_CTX_HASH);
        bytes.extend_from_slice(&ctx.0);
        assert!(parse_limits_v1(&bytes).is_err());
    }

    proptest! {
        #[test]
        fn parse_limits_never_panics_for_small_inputs(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_limits_v1(&bytes);
        }

        #[test]
        fn verify_limits_binding_accepts_self_hash(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let h = limits_hash_v1(&bytes);
            verify_limits_binding_v1(&h, &bytes).expect("self binding");
        }

        #[test]
        fn verify_limits_binding_rejects_modified_hash(
            bytes in proptest::collection::vec(any::<u8>(), 0..512),
            flip in 0usize..32,
        ) {
            let mut h = limits_hash_v1(&bytes);
            h.0[flip] ^= 0x01;
            prop_assert!(verify_limits_binding_v1(&h, &bytes).is_err());
        }

        #[test]
        fn mode_c_ctx_limits_roundtrip(ctx in any::<[u8; 32]>()) {
            let ctx = Hash32(ctx);
            let bytes = limits_bytes_mode_c_encryption_ctx_v1(&ctx);
            let parsed = parse_limits_v1(&bytes).expect("parse");
            prop_assert_eq!(parsed.mode_c_encryption_ctx_hash, Some(ctx));
        }
    }
}
