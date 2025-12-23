//! MPRD wire envelope (MPRDPACK v1).
//!
//! This is a small, fracpack-inspired building block:
//! - **Zero-copy**: parsing yields a payload subslice.
//! - **Fail-closed**: strict bounds + integrity checks.
//! - **Forward-compatible**: a header length allows safe extensions.
//!
//! Design goals:
//! - Make "validated bytes" a first-class concept.
//! - Provide a stable, versioned wrapper for binary blobs (receipts, artifacts, etc.).
//! - Preserve backwards compatibility by supporting legacy (unenveloped) payloads.

use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAGIC: [u8; 4] = *b"MPRD";
pub const VERSION_V1: u8 = 1;
pub const MIN_HEADER_BYTES_V1: usize = 16 + 32; // prefix + sha256(payload)
pub const MAX_HEADER_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WireKind {
    Unknown = 0,
    ZkReceiptBincode = 1,
    MpbArtifactBincode = 2,
    ProofBundleBincode = 3,
}

impl WireKind {
    fn from_u8(v: u8) -> Result<Self, WireError> {
        Ok(match v {
            0 => Self::Unknown,
            1 => Self::ZkReceiptBincode,
            2 => Self::MpbArtifactBincode,
            3 => Self::ProofBundleBincode,
            other => return Err(WireError::UnknownKind(other)),
        })
    }
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error("input too short")]
    TooShort,
    #[error("bad magic")]
    BadMagic,
    #[error("unsupported wire version: {0}")]
    UnsupportedVersion(u8),
    #[error("header_len out of bounds: {0}")]
    HeaderLenOutOfBounds(u16),
    #[error("header too short for v1: {0}")]
    HeaderTooShort(u16),
    #[error("payload length mismatch")]
    PayloadLenMismatch,
    #[error("sha256 mismatch")]
    DigestMismatch,
    #[error("unknown kind: {0}")]
    UnknownKind(u8),
    #[error("unexpected kind: expected {expected:?}, got {actual:?}")]
    UnexpectedKind {
        expected: WireKind,
        actual: WireKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeHeaderV1 {
    pub kind: WireKind,
    pub flags: u16,
    pub header_len: u16,
    pub payload_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeView<'a> {
    pub header: EnvelopeHeaderV1,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedPayload<'a> {
    Enveloped(EnvelopeView<'a>),
    Legacy(&'a [u8]),
}

fn read_u16_le(input: &[u8]) -> u16 {
    u16::from_le_bytes([input[0], input[1]])
}

fn read_u32_le(input: &[u8]) -> u32 {
    u32::from_le_bytes([input[0], input[1], input[2], input[3]])
}

/// Wrap a payload in an MPRDPACK v1 envelope.
///
/// The envelope includes:
/// - magic `MPRD`
/// - version (1)
/// - kind
/// - flags
/// - header length (allows extension fields)
/// - payload length
/// - sha256(payload)
pub fn wrap_v1(kind: WireKind, flags: u16, payload: &[u8]) -> Vec<u8> {
    let header_len: u16 = MIN_HEADER_BYTES_V1 as u16;
    let payload_len_u32: u32 = payload.len() as u32;

    let mut out = Vec::with_capacity(MIN_HEADER_BYTES_V1 + payload.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION_V1);
    out.push(kind as u8);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&payload_len_u32.to_le_bytes());

    let digest = Sha256::digest(payload);
    out.extend_from_slice(digest.as_slice());

    out.extend_from_slice(payload);
    out
}

pub fn parse_envelope_v1(input: &[u8]) -> Result<EnvelopeView<'_>, WireError> {
    if input.len() < MIN_HEADER_BYTES_V1 {
        return Err(WireError::TooShort);
    }
    if input[0..4] != MAGIC {
        return Err(WireError::BadMagic);
    }
    let version = input[4];
    if version != VERSION_V1 {
        return Err(WireError::UnsupportedVersion(version));
    }

    let kind = WireKind::from_u8(input[5])?;
    let flags = read_u16_le(&input[6..8]);
    let header_len = read_u16_le(&input[8..10]);
    // input[10..12] reserved
    let payload_len = read_u32_le(&input[12..16]);

    if header_len as usize > MAX_HEADER_BYTES {
        return Err(WireError::HeaderLenOutOfBounds(header_len));
    }
    if (header_len as usize) < MIN_HEADER_BYTES_V1 {
        return Err(WireError::HeaderTooShort(header_len));
    }
    if input.len() < header_len as usize {
        return Err(WireError::TooShort);
    }

    let header_ext = &input[16..header_len as usize];
    if header_ext.len() < 32 {
        return Err(WireError::HeaderTooShort(header_len));
    }
    let expected_digest = &header_ext[0..32];

    let payload_start = header_len as usize;
    let payload_end = payload_start
        .checked_add(payload_len as usize)
        .ok_or(WireError::PayloadLenMismatch)?;
    if payload_end != input.len() {
        return Err(WireError::PayloadLenMismatch);
    }

    let payload = &input[payload_start..payload_end];
    let actual_digest = Sha256::digest(payload);
    if actual_digest.as_slice() != expected_digest {
        return Err(WireError::DigestMismatch);
    }

    Ok(EnvelopeView {
        header: EnvelopeHeaderV1 {
            kind,
            flags,
            header_len,
            payload_len,
        },
        payload,
    })
}

/// Peek the envelope header (and structural bounds) without computing the payload digest.
///
/// This is useful for cheap pre-validation at API boundaries:
/// - verifies magic, version, header_len bounds
/// - verifies `payload_end == input.len()` to prevent length confusion
pub fn peek_envelope_v1(input: &[u8]) -> Result<EnvelopeHeaderV1, WireError> {
    if input.len() < 16 {
        return Err(WireError::TooShort);
    }
    if input[0..4] != MAGIC {
        return Err(WireError::BadMagic);
    }
    let version = input[4];
    if version != VERSION_V1 {
        return Err(WireError::UnsupportedVersion(version));
    }
    let kind = WireKind::from_u8(input[5])?;
    let flags = read_u16_le(&input[6..8]);
    let header_len = read_u16_le(&input[8..10]);
    let payload_len = read_u32_le(&input[12..16]);

    if header_len as usize > MAX_HEADER_BYTES {
        return Err(WireError::HeaderLenOutOfBounds(header_len));
    }
    if (header_len as usize) < MIN_HEADER_BYTES_V1 {
        return Err(WireError::HeaderTooShort(header_len));
    }
    if input.len() < header_len as usize {
        return Err(WireError::TooShort);
    }
    let payload_start = header_len as usize;
    let payload_end = payload_start
        .checked_add(payload_len as usize)
        .ok_or(WireError::PayloadLenMismatch)?;
    if payload_end != input.len() {
        return Err(WireError::PayloadLenMismatch);
    }

    Ok(EnvelopeHeaderV1 {
        kind,
        flags,
        header_len,
        payload_len,
    })
}

/// Parse an envelope if present; otherwise treat bytes as a legacy payload.
///
/// This is the recommended integration pattern for incremental rollout:
/// - accept both old and new encodings
/// - allow callers to enforce a specific kind when enveloped
pub fn parse_or_legacy<'a>(
    input: &'a [u8],
    expected_kind: Option<WireKind>,
) -> Result<ParsedPayload<'a>, WireError> {
    if input.len() < 5 || input[0..4] != MAGIC {
        return Ok(ParsedPayload::Legacy(input));
    }

    let env = parse_envelope_v1(input)?;
    if let Some(expected) = expected_kind {
        if env.header.kind != expected {
            return Err(WireError::UnexpectedKind {
                expected,
                actual: env.header.kind,
            });
        }
    }
    Ok(ParsedPayload::Enveloped(env))
}

/// Like `parse_or_legacy`, but bounds total input size and envelope header size to be DoS-safe.
pub fn parse_or_legacy_bounded<'a>(
    input: &'a [u8],
    expected_kind: Option<WireKind>,
    max_payload_bytes: u64,
) -> Result<ParsedPayload<'a>, WireError> {
    // Fast-path: legacy bytes, enforce payload bound directly.
    if input.len() < 5 || input[0..4] != MAGIC {
        if input.len() as u64 > max_payload_bytes {
            return Err(WireError::PayloadLenMismatch);
        }
        return Ok(ParsedPayload::Legacy(input));
    }

    // Envelope: cap total size by payload bound + max header.
    if input.len() as u64 > max_payload_bytes.saturating_add(MAX_HEADER_BYTES as u64) {
        return Err(WireError::PayloadLenMismatch);
    }

    let env = parse_envelope_v1(input)?;
    if env.payload.len() as u64 > max_payload_bytes {
        return Err(WireError::PayloadLenMismatch);
    }
    if let Some(expected) = expected_kind {
        if env.header.kind != expected {
            return Err(WireError::UnexpectedKind {
                expected,
                actual: env.header.kind,
            });
        }
    }
    Ok(ParsedPayload::Enveloped(env))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn roundtrip_wrap_parse_v1() {
        let payload = b"hello";
        let bytes = wrap_v1(WireKind::ZkReceiptBincode, 7, payload);
        let env = parse_envelope_v1(&bytes).expect("parse");
        assert_eq!(env.header.kind, WireKind::ZkReceiptBincode);
        assert_eq!(env.header.flags, 7);
        assert_eq!(env.payload, payload);
    }

    #[test]
    fn parse_or_legacy_accepts_legacy() {
        let payload = b"raw";
        let out = parse_or_legacy(payload, None).expect("parse");
        assert!(matches!(out, ParsedPayload::Legacy(p) if p == payload));
    }

    #[test]
    fn parse_or_legacy_rejects_kind_mismatch() {
        let payload = b"x";
        let bytes = wrap_v1(WireKind::MpbArtifactBincode, 0, payload);
        let err = parse_or_legacy(&bytes, Some(WireKind::ZkReceiptBincode)).unwrap_err();
        assert!(matches!(err, WireError::UnexpectedKind { .. }));
    }

    #[test]
    fn rejects_digest_mismatch() {
        let payload = b"hi";
        let mut bytes = wrap_v1(WireKind::Unknown, 0, payload);
        *bytes.last_mut().unwrap() ^= 0x01;
        let err = parse_envelope_v1(&bytes).unwrap_err();
        assert!(matches!(err, WireError::DigestMismatch));
    }

    #[test]
    fn peek_header_matches_parse_header() {
        let payload = b"abc";
        let bytes = wrap_v1(WireKind::MpbArtifactBincode, 2, payload);
        let peek = peek_envelope_v1(&bytes).expect("peek");
        let parsed = parse_envelope_v1(&bytes).expect("parse");
        assert_eq!(peek, parsed.header);
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            .. ProptestConfig::default()
        })]

        #[test]
        fn parse_never_panics_on_small_inputs(input in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_or_legacy(&input, None);
        }

        #[test]
        fn wrap_parse_roundtrips(
            kind in prop_oneof![
                Just(WireKind::Unknown),
                Just(WireKind::ZkReceiptBincode),
                Just(WireKind::MpbArtifactBincode),
                Just(WireKind::ProofBundleBincode),
            ],
            flags in any::<u16>(),
            payload in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let bytes = wrap_v1(kind, flags, &payload);
            let env = parse_envelope_v1(&bytes).expect("parse");
            prop_assert_eq!(env.header.kind, kind);
            prop_assert_eq!(env.header.flags, flags);
            prop_assert_eq!(env.payload, payload);
        }

        // --- Additional bounds tests for parse_or_legacy_bounded ---

        #[test]
        fn bounded_rejects_oversized_legacy(
            payload in proptest::collection::vec(any::<u8>(), 1..512),
        ) {
            // When payload exceeds max_payload_bytes, bounded parse should reject
            if payload.len() > 10 {
                let result = parse_or_legacy_bounded(&payload, None, 10);
                prop_assert!(result.is_err());
            }
        }

        #[test]
        fn bounded_accepts_within_limit_legacy(
            payload in proptest::collection::vec(any::<u8>(), 0..100),
        ) {
            // Legacy payloads within limit should be accepted
            // Skip if starts with MPRD magic
            if payload.len() >= 4 && payload[0..4] == *b"MPRD" {
                return Ok(());
            }
            let limit = (payload.len() as u64).saturating_add(1);
            let result = parse_or_legacy_bounded(&payload, None, limit);
            prop_assert!(result.is_ok());
        }

        #[test]
        fn bounded_rejects_oversized_enveloped(
            small_payload in proptest::collection::vec(any::<u8>(), 0..50),
        ) {
            // Create an envelope, then try to parse with too-small limit
            let bytes = wrap_v1(WireKind::Unknown, 0, &small_payload);
            if small_payload.len() > 5 {
                let result = parse_or_legacy_bounded(&bytes, None, 5);
                prop_assert!(result.is_err());
            }
        }

        #[test]
        fn bounded_never_panics_on_arbitrary_bytes(
            input in proptest::collection::vec(any::<u8>(), 0..1024),
            max_bytes in 0u64..=10_000,
        ) {
            // Should never panic, regardless of input
            let _ = parse_or_legacy_bounded(&input, None, max_bytes);
        }

        #[test]
        fn bounded_handles_u64_max_gracefully(
            payload in proptest::collection::vec(any::<u8>(), 0..100),
        ) {
            // u64::MAX as limit should accept anything that fits in memory
            // Skip if starts with MPRD magic
            if payload.len() >= 4 && payload[0..4] == *b"MPRD" {
                return Ok(());
            }
            let result = parse_or_legacy_bounded(&payload, None, u64::MAX);
            prop_assert!(result.is_ok());
        }

        #[test]
        fn bounded_with_zero_limit_rejects_nonempty(
            payload in proptest::collection::vec(any::<u8>(), 1..100),
        ) {
            // Zero limit should reject any non-empty payload
            let result = parse_or_legacy_bounded(&payload, None, 0);
            prop_assert!(result.is_err());
        }
    }
}
