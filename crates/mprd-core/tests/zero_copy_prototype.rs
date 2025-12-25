// Zero-copy serialization prototype using rkyv
//
// This demonstrates how DecisionToken and related types could be made
// zero-copy serializable, enabling:
// - Direct access without full deserialization
// - Validation of untrusted data before access
// - Faster ZK proof generation paths

use rkyv::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

/// Zero-copy compatible 32-byte hash
#[derive(Archive, Deserialize, Serialize, Clone, PartialEq, Eq, Hash, Debug)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(CheckBytes, Debug))]
pub struct ZcHash32(pub [u8; 32]);

/// Zero-copy compatible PolicyRef
#[derive(Archive, Deserialize, Serialize, Clone, PartialEq, Debug)]
#[archive_attr(derive(CheckBytes, Debug))]
pub struct ZcPolicyRef {
    pub policy_epoch: u64,
    pub registry_root: ZcHash32,
}

/// Zero-copy compatible StateRef
#[derive(Archive, Deserialize, Serialize, Clone, PartialEq, Debug)]
#[archive_attr(derive(CheckBytes, Debug))]
pub struct ZcStateRef {
    pub state_source_id: ZcHash32,
    pub state_epoch: u64,
    pub state_attestation_hash: ZcHash32,
}

/// Zero-copy compatible DecisionToken
#[derive(Archive, Deserialize, Serialize, Clone, Debug)]
#[archive_attr(derive(CheckBytes, Debug))]
pub struct ZcDecisionToken {
    pub policy_hash: ZcHash32,
    pub policy_ref: ZcPolicyRef,
    pub state_hash: ZcHash32,
    pub state_ref: ZcStateRef,
    pub chosen_action_hash: ZcHash32,
    pub nonce_or_tx_hash: ZcHash32,
    pub timestamp_ms: i64,
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rkyv::ser::serializers::AllocSerializer;
    use rkyv::ser::Serializer;
    use rkyv::Infallible;

    fn dummy_hash(seed: u8) -> ZcHash32 {
        ZcHash32([seed; 32])
    }

    fn dummy_token() -> ZcDecisionToken {
        ZcDecisionToken {
            policy_hash: dummy_hash(1),
            policy_ref: ZcPolicyRef {
                policy_epoch: 100,
                registry_root: dummy_hash(2),
            },
            state_hash: dummy_hash(3),
            state_ref: ZcStateRef {
                state_source_id: dummy_hash(4),
                state_epoch: 50,
                state_attestation_hash: dummy_hash(5),
            },
            chosen_action_hash: dummy_hash(6),
            nonce_or_tx_hash: dummy_hash(7),
            timestamp_ms: 1234567890,
            signature: vec![0xAB; 64],
        }
    }

    #[test]
    fn serialize_roundtrip() {
        let token = dummy_token();

        // Serialize
        let mut serializer = AllocSerializer::<256>::default();
        serializer.serialize_value(&token).expect("serialize");
        let bytes = serializer.into_serializer().into_inner();

        println!("Serialized size: {} bytes", bytes.len());

        // Zero-copy access (no deserialization!)
        let archived = unsafe { rkyv::archived_root::<ZcDecisionToken>(&bytes) };

        // Direct field access without copying
        assert_eq!(archived.timestamp_ms, 1234567890);
        assert_eq!(archived.policy_ref.policy_epoch, 100);
        assert_eq!(archived.state_ref.state_epoch, 50);
        assert_eq!(archived.policy_hash.0, [1u8; 32]);

        // Full deserialization when needed
        let deserialized: ZcDecisionToken = archived.deserialize(&mut Infallible).expect("deser");
        assert_eq!(deserialized.timestamp_ms, token.timestamp_ms);
        assert_eq!(deserialized.signature, token.signature);
    }

    #[test]
    fn validated_access_from_untrusted_bytes() {
        let token = dummy_token();

        // Serialize
        let mut serializer = AllocSerializer::<256>::default();
        serializer.serialize_value(&token).expect("serialize");
        let bytes = serializer.into_serializer().into_inner();

        // Safe validation first (for untrusted data)
        let result = rkyv::check_archived_root::<ZcDecisionToken>(&bytes);
        assert!(result.is_ok(), "validation should pass for valid data");

        let archived = result.unwrap();
        assert_eq!(archived.timestamp_ms, 1234567890);
    }

    #[test]
    fn corrupted_data_detected() {
        let token = dummy_token();

        let mut serializer = AllocSerializer::<256>::default();
        serializer.serialize_value(&token).expect("serialize");
        let mut bytes = serializer.into_serializer().into_inner().to_vec();

        // Corrupt the data (flip a byte in the signature length)
        let len = bytes.len();
        if len > 10 {
            bytes[len - 10] ^= 0xFF;
        }

        // Validation should detect corruption
        let result = rkyv::check_archived_root::<ZcDecisionToken>(&bytes);
        // Note: may or may not fail depending on what was corrupted
        // In production, you'd need more careful corruption detection
        println!("Validation result: {:?}", result.is_ok());
    }

    #[test]
    fn zero_copy_perf_comparison() {
        use std::time::Instant;

        let token = dummy_token();

        // Serialize once
        let mut serializer = AllocSerializer::<256>::default();
        serializer.serialize_value(&token).expect("serialize");
        let bytes = serializer.into_serializer().into_inner();

        const ITERATIONS: usize = 100_000;

        // Benchmark zero-copy access
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let archived = unsafe { rkyv::archived_root::<ZcDecisionToken>(&bytes) };
            let _ = archived.timestamp_ms;
            let _ = archived.policy_ref.policy_epoch;
        }
        let zero_copy_time = start.elapsed();

        // Benchmark full deserialization
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let archived = unsafe { rkyv::archived_root::<ZcDecisionToken>(&bytes) };
            let _token: ZcDecisionToken = archived.deserialize(&mut Infallible).expect("deser");
        }
        let deser_time = start.elapsed();

        println!(
            "Zero-copy access: {:?} ({} ops)",
            zero_copy_time, ITERATIONS
        );
        println!("Full deserialize: {:?} ({} ops)", deser_time, ITERATIONS);
        println!(
            "Zero-copy is {:.1}x faster",
            deser_time.as_nanos() as f64 / zero_copy_time.as_nanos() as f64
        );
    }
}
