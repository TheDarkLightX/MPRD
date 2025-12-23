//! Bounded deserialization utilities for security-critical code paths.
//!
//! # Security
//!
//! Unbounded `bincode::deserialize` is a DoS vector: an attacker can craft input
//! that causes huge memory allocations. All deserialization of untrusted data
//! MUST use the bounded variants in this module.
//!
//! # Usage
//!
//! ```rust,ignore
//! use mprd_zk::bounded_deser::{deserialize_receipt, deserialize_mpb_artifact};
//!
//! let receipt = deserialize_receipt(&bytes)?;
//! let artifact = deserialize_mpb_artifact(&bytes)?;
//! ```

use bincode::Options;
use serde::de::DeserializeOwned;
use thiserror::Error;

use mprd_core::wire::{self, WireKind};

/// Maximum size for Risc0 receipts (16 MiB).
///
/// Receipts can be large due to STARK proofs; 16 MiB is generous but bounded.
pub const MAX_RECEIPT_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum size for MPB lite artifacts (1 MiB).
///
/// MPB artifacts include bytecode + trace data; 1 MiB is ample.
pub const MAX_MPB_ARTIFACT_BYTES: u64 = 1024 * 1024;

/// Maximum size for proof bundles (2 MiB).
pub const MAX_PROOF_BUNDLE_BYTES: u64 = 2 * 1024 * 1024;

/// Bounded deserialization error.
#[derive(Debug, Error)]
pub enum BoundedDeserError {
    #[error("input size {len} exceeds maximum {max} bytes")]
    InputTooLarge { len: u64, max: u64 },
    #[error("wire envelope error: {0}")]
    Wire(String),
    #[error("bincode error ({kind:?}): {message}")]
    Bincode {
        kind: BincodeErrorKind,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BincodeErrorKind {
    SizeLimit,
    Io,
    Custom,
    Other,
}

/// Deserialize with a size limit (fail-closed on oversized input).
///
/// # Security
///
/// - Rejects inputs larger than `max_bytes` before attempting deserialization.
/// - Uses standard `bincode::deserialize` compatible with `bincode::serialize`.
pub fn deserialize_bounded<T: DeserializeOwned>(
    bytes: &[u8],
    max_bytes: u64,
) -> Result<T, BoundedDeserError> {
    // Pre-check: reject obviously oversized input before parsing.
    // This is the primary DoS protection - prevents allocating huge buffers.
    if bytes.len() as u64 > max_bytes {
        return Err(BoundedDeserError::InputTooLarge {
            len: bytes.len() as u64,
            max: max_bytes,
        });
    }

    // SECURITY: Use bincode's internal size limit as well.
    //
    // `with_limit(max_bytes)` bounds the total number of bytes that bincode will attempt to read
    // for length-prefixed buffers (e.g., strings/byte buffers), providing defense-in-depth beyond
    // the top-level `bytes.len()` check.
    //
    // Match the configuration used by `bincode::serialize` / `bincode::deserialize`:
    // - fixint encoding
    // - allow trailing bytes
    // then apply a hard limit to prevent allocation DoS.
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(max_bytes)
        .deserialize(bytes)
        .map_err(|e| {
            let kind = match e.as_ref() {
                bincode::ErrorKind::SizeLimit => BincodeErrorKind::SizeLimit,
                bincode::ErrorKind::Io(_) => BincodeErrorKind::Io,
                bincode::ErrorKind::Custom(_) => BincodeErrorKind::Custom,
                _ => BincodeErrorKind::Other,
            };
            BoundedDeserError::Bincode {
                kind,
                message: e.to_string(),
            }
        })
}

pub fn deserialize_receipt<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, BoundedDeserError> {
    // Fail-closed, but classify oversize cleanly:
    // - Legacy bytes must be <= MAX_* exactly.
    // - Enveloped bytes may exceed MAX_* by header overhead, but payload must still be <= MAX_*.
    let len = bytes.len() as u64;
    if bytes.starts_with(&wire::MAGIC) {
        if len > MAX_RECEIPT_BYTES.saturating_add(wire::MAX_HEADER_BYTES as u64) {
            return Err(BoundedDeserError::InputTooLarge {
                len,
                max: MAX_RECEIPT_BYTES,
            });
        }
        if let Ok(h) = wire::peek_envelope_v1(bytes) {
            if (h.payload_len as u64) > MAX_RECEIPT_BYTES {
                return Err(BoundedDeserError::InputTooLarge {
                    len,
                    max: MAX_RECEIPT_BYTES,
                });
            }
        }
    } else if len > MAX_RECEIPT_BYTES {
        return Err(BoundedDeserError::InputTooLarge {
            len,
            max: MAX_RECEIPT_BYTES,
        });
    }

    let payload = match wire::parse_or_legacy_bounded(
        bytes,
        Some(WireKind::ZkReceiptBincode),
        MAX_RECEIPT_BYTES,
    ) {
        Ok(wire::ParsedPayload::Enveloped(env)) => env.payload,
        Ok(wire::ParsedPayload::Legacy(p)) => p,
        Err(e) => return Err(BoundedDeserError::Wire(e.to_string())),
    };
    deserialize_bounded(payload, MAX_RECEIPT_BYTES)
}

/// Deserialize an MPB lite artifact with bounded size.
///
/// # Security
///
/// Limits input to `MAX_MPB_ARTIFACT_BYTES` (1 MiB) to prevent DoS.
pub fn deserialize_mpb_artifact<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, BoundedDeserError> {
    let len = bytes.len() as u64;
    if bytes.starts_with(&wire::MAGIC) {
        if len > MAX_MPB_ARTIFACT_BYTES.saturating_add(wire::MAX_HEADER_BYTES as u64) {
            return Err(BoundedDeserError::InputTooLarge {
                len,
                max: MAX_MPB_ARTIFACT_BYTES,
            });
        }
        if let Ok(h) = wire::peek_envelope_v1(bytes) {
            if (h.payload_len as u64) > MAX_MPB_ARTIFACT_BYTES {
                return Err(BoundedDeserError::InputTooLarge {
                    len,
                    max: MAX_MPB_ARTIFACT_BYTES,
                });
            }
        }
    } else if len > MAX_MPB_ARTIFACT_BYTES {
        return Err(BoundedDeserError::InputTooLarge {
            len,
            max: MAX_MPB_ARTIFACT_BYTES,
        });
    }

    let payload = match wire::parse_or_legacy_bounded(
        bytes,
        Some(WireKind::MpbArtifactBincode),
        MAX_MPB_ARTIFACT_BYTES,
    ) {
        Ok(wire::ParsedPayload::Enveloped(env)) => env.payload,
        Ok(wire::ParsedPayload::Legacy(p)) => p,
        Err(e) => return Err(BoundedDeserError::Wire(e.to_string())),
    };
    deserialize_bounded(payload, MAX_MPB_ARTIFACT_BYTES)
}

/// Deserialize a proof bundle with bounded size.
///
/// # Security
///
/// Limits input to `MAX_PROOF_BUNDLE_BYTES` (2 MiB) to prevent DoS.
pub fn deserialize_proof_bundle<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, BoundedDeserError> {
    let len = bytes.len() as u64;
    if bytes.starts_with(&wire::MAGIC) {
        if len > MAX_PROOF_BUNDLE_BYTES.saturating_add(wire::MAX_HEADER_BYTES as u64) {
            return Err(BoundedDeserError::InputTooLarge {
                len,
                max: MAX_PROOF_BUNDLE_BYTES,
            });
        }
        if let Ok(h) = wire::peek_envelope_v1(bytes) {
            if (h.payload_len as u64) > MAX_PROOF_BUNDLE_BYTES {
                return Err(BoundedDeserError::InputTooLarge {
                    len,
                    max: MAX_PROOF_BUNDLE_BYTES,
                });
            }
        }
    } else if len > MAX_PROOF_BUNDLE_BYTES {
        return Err(BoundedDeserError::InputTooLarge {
            len,
            max: MAX_PROOF_BUNDLE_BYTES,
        });
    }

    let payload = match wire::parse_or_legacy_bounded(
        bytes,
        Some(WireKind::ProofBundleBincode),
        MAX_PROOF_BUNDLE_BYTES,
    ) {
        Ok(wire::ParsedPayload::Enveloped(env)) => env.payload,
        Ok(wire::ParsedPayload::Legacy(p)) => p,
        Err(e) => return Err(BoundedDeserError::Wire(e.to_string())),
    };
    deserialize_bounded(payload, MAX_PROOF_BUNDLE_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        value: u64,
        data: Vec<u8>,
    }

    /// Serialize using standard bincode (same as deserialize_bounded uses).
    fn serialize_for_test<T: serde::Serialize>(value: &T) -> Vec<u8> {
        bincode::serialize(value).unwrap()
    }

    #[test]
    fn bounded_deserialize_accepts_valid_input() {
        let input = TestStruct {
            value: 42,
            data: vec![1, 2, 3],
        };
        let bytes = serialize_for_test(&input);

        let result: TestStruct = deserialize_bounded(&bytes, 1024).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn bounded_deserialize_rejects_oversized_input() {
        let large_data = vec![0u8; 1000];
        let input = TestStruct {
            value: 42,
            data: large_data,
        };
        let bytes = serialize_for_test(&input);
        let len = bytes.len() as u64;

        // Limit smaller than actual size
        let result: Result<TestStruct, _> = deserialize_bounded(&bytes, 100);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BoundedDeserError::InputTooLarge { len: l, max: 100 } if l == len
        ));
    }

    #[test]
    fn receipt_deserialize_uses_correct_limit() {
        let small_input = TestStruct {
            value: 1,
            data: vec![],
        };
        let bytes = serialize_for_test(&small_input);

        // Should succeed for small input
        let result: Result<TestStruct, _> = deserialize_receipt(&bytes);
        assert!(result.is_ok());

        // Should also succeed for a reasonably-sized payload well under 16 MiB.
        // This catches accidental misconfiguration of MAX_RECEIPT_BYTES.
        let medium_input = TestStruct {
            value: 2,
            data: vec![0u8; 4096],
        };
        let bytes = serialize_for_test(&medium_input);
        assert!(bytes.len() > 64);
        let out: TestStruct = deserialize_receipt(&bytes).expect("deserialize_receipt");
        assert_eq!(out, medium_input);

        // Enveloped payload should also work (incremental rollout safety).
        let env = mprd_core::wire::wrap_v1(mprd_core::wire::WireKind::ZkReceiptBincode, 0, &bytes);
        let out_env: TestStruct = deserialize_receipt(&env).expect("enveloped deserialize_receipt");
        assert_eq!(out_env, medium_input);
    }

    #[test]
    fn mpb_artifact_deserialize_uses_correct_limit() {
        let small_input = TestStruct {
            value: 1,
            data: vec![],
        };
        let bytes = serialize_for_test(&small_input);

        // Should succeed for small input
        let result: Result<TestStruct, _> = deserialize_mpb_artifact(&bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn mpb_artifact_deserialize_classifies_legacy_oversize_as_input_too_large() {
        let bytes = vec![0u8; (MAX_MPB_ARTIFACT_BYTES as usize) + 1];
        let err = deserialize_mpb_artifact::<TestStruct>(&bytes).expect_err("should reject");
        assert!(matches!(
            err,
            BoundedDeserError::InputTooLarge {
                len,
                max: MAX_MPB_ARTIFACT_BYTES
            } if len == bytes.len() as u64
        ));
    }

    #[test]
    fn mpb_artifact_deserialize_classifies_enveloped_oversize_payload_as_input_too_large() {
        let payload = vec![0u8; (MAX_MPB_ARTIFACT_BYTES as usize) + 1];
        let bytes = wire::wrap_v1(WireKind::MpbArtifactBincode, 0, &payload);
        let err = deserialize_mpb_artifact::<TestStruct>(&bytes).expect_err("should reject");
        assert!(matches!(
            err,
            BoundedDeserError::InputTooLarge {
                len,
                max: MAX_MPB_ARTIFACT_BYTES
            } if len == bytes.len() as u64
        ));
    }

    #[test]
    fn receipt_deserialize_rejects_kind_mismatch_as_wire_error() {
        let input = TestStruct {
            value: 1,
            data: vec![1, 2, 3],
        };
        let payload = serialize_for_test(&input);
        let bytes = wire::wrap_v1(WireKind::MpbArtifactBincode, 0, &payload);

        let err = deserialize_receipt::<TestStruct>(&bytes).expect_err("should reject");
        assert!(matches!(err, BoundedDeserError::Wire(_)));
    }

    #[test]
    fn receipt_deserialize_rejects_bad_digest_as_wire_error() {
        let input = TestStruct {
            value: 1,
            data: vec![1, 2, 3],
        };
        let payload = serialize_for_test(&input);
        let mut bytes = wire::wrap_v1(WireKind::ZkReceiptBincode, 0, &payload);
        *bytes.last_mut().unwrap() ^= 0x01;

        let err = deserialize_receipt::<TestStruct>(&bytes).expect_err("should reject");
        assert!(matches!(err, BoundedDeserError::Wire(_)));
    }

    #[test]
    fn bounded_deserialize_fails_closed_on_large_len_prefix_even_when_input_is_small() {
        // Craft attacker-controlled bytes that claim a large `Vec<u8>` length while keeping the
        // actual input small. This must fail closed (never panic), even though the top-level
        // `bytes.len()` pre-check passes.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u64.to_le_bytes()); // TestStruct.value
        bytes.extend_from_slice(&1_000u64.to_le_bytes()); // TestStruct.data length

        let err = deserialize_bounded::<TestStruct>(&bytes, 64).expect_err("should reject");
        assert!(
            matches!(err, BoundedDeserError::Bincode { .. }),
            "expected bincode error, got: {err:?}"
        );
    }

    proptest! {
        #[test]
        fn bounded_deserialize_roundtrips(
            value in any::<u64>(),
            data in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let input = TestStruct { value, data };
            let bytes = serialize_for_test(&input);
            let out: TestStruct = deserialize_bounded(&bytes, 1024 * 1024).expect("deserialize");
            prop_assert_eq!(out, input);
        }

        #[test]
        fn bounded_deserialize_rejects_when_len_exceeds_limit(bytes in proptest::collection::vec(any::<u8>(), 257..2048)) {
            let max = 256u64;
            let err = deserialize_bounded::<TestStruct>(&bytes, max).expect_err("oversize");
            prop_assert!(
                matches!(err, BoundedDeserError::InputTooLarge { max: m, .. } if m == max),
                "expected InputTooLarge with max={max}, got: {err:?}"
            );
        }
    }
}
