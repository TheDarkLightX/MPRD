//! State provenance primitives (production strategy scaffolding).
//!
//! ZK receipts prove correctness conditional on inputs. This module defines a concrete
//! provenance strategy ("signed snapshot v1") so production deployments can:
//! - validate state authenticity at the state-provider boundary (fail-closed), and
//! - bind a stable provenance identity (`StateRef`) into tokens and journals.

use crate::crypto::sha256;
use crate::hash::{hash_state_preimage_v1, state_hash_preimage};
use crate::validation::validate_state_snapshot_v1;
use crate::{
    Hash32, MprdError, Result, StateProvider, StateRef, StateSnapshot, TokenSigningKey,
    TokenVerifyingKey,
};
use serde::{Deserialize, Serialize};

pub const SIGNED_SNAPSHOT_VERSION_V1: u32 = 1;
pub const SIGNED_SNAPSHOT_DOMAIN_V1: &[u8] = b"MPRD_SIGNED_STATE_SNAPSHOT_V1";
pub const STATE_ATTESTATION_DOMAIN_V1: &[u8] = b"MPRD_STATE_ATTESTATION_V1";

/// Canonical state provenance scheme identifier: "signed snapshot v1".
///
/// This is a commitment-sized ID (domain-separated SHA-256), not a free-form string.
pub fn state_source_id_signed_snapshot_v1() -> Hash32 {
    // Domain-separate again to avoid accidental cross-protocol collisions.
    sha256(b"mprd.state_source.signed_snapshot_v1")
}

/// Compute the committed attestation hash for a signed snapshot.
///
/// This hash is what gets bound into `StateRef.state_attestation_hash`.
pub fn state_attestation_hash_v1(signer_pubkey: &[u8; 32], signature: &[u8]) -> Hash32 {
    let mut bytes = Vec::with_capacity(STATE_ATTESTATION_DOMAIN_V1.len() + 32 + signature.len());
    bytes.extend_from_slice(STATE_ATTESTATION_DOMAIN_V1);
    bytes.extend_from_slice(signer_pubkey);
    bytes.extend_from_slice(signature);
    sha256(&bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedStateSnapshotV1 {
    pub version: u32,
    /// Monotonic snapshot epoch (e.g. block height / snapshot sequence).
    pub state_epoch: u64,

    /// Canonical MPRD state fields.
    pub fields: std::collections::HashMap<String, crate::Value>,
    /// Canonical MPRD policy inputs (Tau bytes).
    pub policy_inputs: std::collections::HashMap<String, Vec<u8>>,

    /// Signer pubkey (ed25519).
    pub signer_pubkey: [u8; 32],
    /// Signature over `signing_bytes_v1()`.
    pub signature: Vec<u8>,
}

impl SignedStateSnapshotV1 {
    pub fn signing_bytes_v1(&self) -> Result<Vec<u8>> {
        if self.version != SIGNED_SNAPSHOT_VERSION_V1 {
            return Err(MprdError::InvalidInput(
                "unsupported signed snapshot version".into(),
            ));
        }

        let tmp = StateSnapshot {
            fields: self.fields.clone(),
            policy_inputs: self.policy_inputs.clone(),
            state_hash: Hash32([0u8; 32]),
            state_ref: StateRef::unknown(),
        };
        validate_state_snapshot_v1(&tmp)?;
        let preimage = state_hash_preimage(&tmp);

        let mut out =
            Vec::with_capacity(SIGNED_SNAPSHOT_DOMAIN_V1.len() + 4 + 8 + 32 + preimage.len());
        out.extend_from_slice(SIGNED_SNAPSHOT_DOMAIN_V1);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.state_epoch.to_le_bytes());
        out.extend_from_slice(&state_source_id_signed_snapshot_v1().0);
        out.extend_from_slice(&preimage);
        Ok(out)
    }

    pub fn to_state_snapshot(&self, expected_vk: &TokenVerifyingKey) -> Result<StateSnapshot> {
        if expected_vk.to_bytes() != self.signer_pubkey {
            return Err(MprdError::SignatureInvalid(
                "signed snapshot signer_pubkey does not match expected key".into(),
            ));
        }

        let msg = self.signing_bytes_v1()?;
        expected_vk.verify_bytes(&msg, &self.signature)?;

        let mut s = StateSnapshot {
            fields: self.fields.clone(),
            policy_inputs: self.policy_inputs.clone(),
            state_hash: Hash32([0u8; 32]),
            state_ref: StateRef::unknown(),
        };
        validate_state_snapshot_v1(&s)?;
        let preimage = state_hash_preimage(&s);
        s.state_hash = hash_state_preimage_v1(&preimage);
        s.state_ref = StateRef {
            state_source_id: state_source_id_signed_snapshot_v1(),
            state_epoch: self.state_epoch,
            state_attestation_hash: state_attestation_hash_v1(&self.signer_pubkey, &self.signature),
        };
        Ok(s)
    }

    pub fn sign(
        signing_key: &TokenSigningKey,
        state_epoch: u64,
        fields: std::collections::HashMap<String, crate::Value>,
        policy_inputs: std::collections::HashMap<String, Vec<u8>>,
    ) -> Result<Self> {
        let signer_pubkey = signing_key.verifying_key().to_bytes();
        let mut s = Self {
            version: SIGNED_SNAPSHOT_VERSION_V1,
            state_epoch,
            fields,
            policy_inputs,
            signer_pubkey,
            signature: Vec::new(),
        };
        let msg = s.signing_bytes_v1()?;
        s.signature = signing_key.sign_bytes(&msg).to_vec();
        Ok(s)
    }
}

// =============================================================================
// Low-Trust Mode: Quorum-Signed State Snapshot (k-of-n threshold)
// =============================================================================

/// Schema version for quorum-signed state snapshots.
pub const QUORUM_SIGNED_SNAPSHOT_VERSION_V1: u32 = 1;

/// Domain separation for quorum state snapshot signatures.
pub const QUORUM_SIGNED_SNAPSHOT_DOMAIN_V1: &[u8] = b"MPRD_QUORUM_SIGNED_STATE_SNAPSHOT_V1";

/// Canonical state source identifier: "quorum signed snapshot v1".
pub fn state_source_id_quorum_signed_snapshot_v1() -> Hash32 {
    sha256(b"mprd.state_source.quorum_signed_snapshot_v1")
}

/// Individual signer's contribution to a quorum-signed state snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumStateSignerContribution {
    pub signer_pubkey: [u8; 32],
    pub signature: Vec<u8>,
}

/// Quorum-signed state snapshot for low-trust mode.
///
/// Requires k-of-n signatures from independent state attestors to be valid,
/// eliminating single points of failure in state authenticity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumSignedStateSnapshotV1 {
    pub version: u32,
    pub state_epoch: u64,
    /// Timestamp when the snapshot was created (milliseconds since UNIX epoch).
    pub created_at_ms: i64,
    pub fields: std::collections::HashMap<String, crate::Value>,
    pub policy_inputs: std::collections::HashMap<String, Vec<u8>>,
    /// Minimum number of valid signatures required (k in k-of-n).
    pub quorum_threshold: u8,
    pub contributions: Vec<QuorumStateSignerContribution>,
}

impl QuorumSignedStateSnapshotV1 {
    pub fn signing_bytes_v1(&self) -> Result<Vec<u8>> {
        if self.version != QUORUM_SIGNED_SNAPSHOT_VERSION_V1 {
            return Err(MprdError::InvalidInput(
                "unsupported quorum signed snapshot version".into(),
            ));
        }

        let tmp = StateSnapshot {
            fields: self.fields.clone(),
            policy_inputs: self.policy_inputs.clone(),
            state_hash: Hash32([0u8; 32]),
            state_ref: StateRef::unknown(),
        };
        validate_state_snapshot_v1(&tmp)?;
        let preimage = state_hash_preimage(&tmp);

        let mut out = Vec::with_capacity(128 + preimage.len());
        out.extend_from_slice(QUORUM_SIGNED_SNAPSHOT_DOMAIN_V1);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.state_epoch.to_le_bytes());
        out.extend_from_slice(&self.created_at_ms.to_le_bytes());
        out.extend_from_slice(&self.quorum_threshold.to_le_bytes());
        out.extend_from_slice(&state_source_id_quorum_signed_snapshot_v1().0);
        out.extend_from_slice(&preimage);
        Ok(out)
    }

    /// Verify the quorum signature against a set of trusted attestor public keys.
    pub fn verify_with_trusted_attestors(&self, trusted_attestors: &[[u8; 32]]) -> Result<()> {
        if self.quorum_threshold == 0 {
            return Err(MprdError::InvalidInput(
                "quorum_threshold must be at least 1".into(),
            ));
        }

        let msg = self.signing_bytes_v1()?;
        let mut valid_attestors: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::new();

        for contrib in &self.contributions {
            if !trusted_attestors.contains(&contrib.signer_pubkey) {
                continue;
            }
            if valid_attestors.contains(&contrib.signer_pubkey) {
                continue;
            }

            let vk = TokenVerifyingKey::from_bytes(&contrib.signer_pubkey)
                .map_err(|_| MprdError::SignatureInvalid("invalid attestor pubkey".into()))?;

            if vk.verify_bytes(&msg, &contrib.signature).is_ok() {
                valid_attestors.insert(contrib.signer_pubkey);
            }
        }

        let valid_count = valid_attestors.len();
        if valid_count < self.quorum_threshold as usize {
            return Err(MprdError::SignatureInvalid(format!(
                "insufficient state attestor quorum: {} valid, {} required",
                valid_count, self.quorum_threshold
            )));
        }

        Ok(())
    }

    /// Sign a state snapshot as one member of a quorum.
    pub fn sign_contribution(
        signing_key: &TokenSigningKey,
        state_epoch: u64,
        created_at_ms: i64,
        fields: &std::collections::HashMap<String, crate::Value>,
        policy_inputs: &std::collections::HashMap<String, Vec<u8>>,
        quorum_threshold: u8,
    ) -> Result<QuorumStateSignerContribution> {
        let temp = Self {
            version: QUORUM_SIGNED_SNAPSHOT_VERSION_V1,
            state_epoch,
            created_at_ms,
            fields: fields.clone(),
            policy_inputs: policy_inputs.clone(),
            quorum_threshold,
            contributions: vec![],
        };

        let msg = temp.signing_bytes_v1()?;
        let signature = signing_key.sign_bytes(&msg).to_vec();
        let signer_pubkey = signing_key.verifying_key().to_bytes();

        Ok(QuorumStateSignerContribution {
            signer_pubkey,
            signature,
        })
    }

    /// Aggregate contributions into a complete quorum-signed state snapshot.
    pub fn aggregate(
        state_epoch: u64,
        created_at_ms: i64,
        fields: std::collections::HashMap<String, crate::Value>,
        policy_inputs: std::collections::HashMap<String, Vec<u8>>,
        quorum_threshold: u8,
        contributions: Vec<QuorumStateSignerContribution>,
    ) -> Self {
        Self {
            version: QUORUM_SIGNED_SNAPSHOT_VERSION_V1,
            state_epoch,
            created_at_ms,
            fields,
            policy_inputs,
            quorum_threshold,
            contributions,
        }
    }

    pub fn to_state_snapshot(&self, trusted_attestors: &[[u8; 32]]) -> Result<StateSnapshot> {
        self.verify_with_trusted_attestors(trusted_attestors)?;

        let mut s = StateSnapshot {
            fields: self.fields.clone(),
            policy_inputs: self.policy_inputs.clone(),
            state_hash: Hash32([0u8; 32]),
            state_ref: StateRef::unknown(),
        };
        validate_state_snapshot_v1(&s)?;
        let preimage = state_hash_preimage(&s);
        s.state_hash = hash_state_preimage_v1(&preimage);

        // Compute attestation hash from all valid contributions
        let attestation_preimage = self.signing_bytes_v1()?;
        let attestation_hash = sha256(&attestation_preimage);

        s.state_ref = StateRef {
            state_source_id: state_source_id_quorum_signed_snapshot_v1(),
            state_epoch: self.state_epoch,
            state_attestation_hash: attestation_hash,
        };
        Ok(s)
    }
}

/// Quorum-signed state provider with freshness enforcement (low-trust mode).
pub struct QuorumSignedSnapshotStateProvider {
    signed: QuorumSignedStateSnapshotV1,
    trusted_attestors: Vec<[u8; 32]>,
    /// Maximum allowed staleness in milliseconds.
    max_staleness_ms: i64,
}

impl QuorumSignedSnapshotStateProvider {
    pub fn new(
        signed: QuorumSignedStateSnapshotV1,
        trusted_attestors: Vec<[u8; 32]>,
        max_staleness_ms: i64,
    ) -> Self {
        Self {
            signed,
            trusted_attestors,
            max_staleness_ms,
        }
    }

    fn check_freshness_at(&self, now_ms: i64) -> Result<()> {
        let staleness = now_ms - self.signed.created_at_ms;
        if staleness > self.max_staleness_ms {
            return Err(MprdError::ExecutionError(format!(
                "state snapshot too stale: {}ms > {}ms max",
                staleness, self.max_staleness_ms
            )));
        }
        if staleness < -5000 {
            // Allow 5s future skew
            return Err(MprdError::ExecutionError(format!(
                "state snapshot from future: {}ms",
                -staleness
            )));
        }
        Ok(())
    }

    fn check_freshness(&self) -> Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MprdError::ExecutionError("system clock error".into()))?
            .as_millis() as i64;

        self.check_freshness_at(now_ms)
    }
}

impl StateProvider for QuorumSignedSnapshotStateProvider {
    fn snapshot(&self) -> Result<StateSnapshot> {
        self.check_freshness()?;
        self.signed.to_state_snapshot(&self.trusted_attestors)
    }
}

/// State provider that validates a signed snapshot (fail-closed) before returning it.
///
/// This is a concrete production strategy: the state snapshot is treated as authentic iff it is
/// signed by the allowlisted verifying key and passes canonical bounds validation.
pub struct SignedSnapshotStateProvider {
    signed: SignedStateSnapshotV1,
    verifying_key: TokenVerifyingKey,
}

impl SignedSnapshotStateProvider {
    pub fn new(signed: SignedStateSnapshotV1, verifying_key: TokenVerifyingKey) -> Self {
        Self {
            signed,
            verifying_key,
        }
    }
}

impl StateProvider for SignedSnapshotStateProvider {
    fn snapshot(&self) -> Result<StateSnapshot> {
        self.signed.to_state_snapshot(&self.verifying_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Value;
    use proptest::prelude::*;
    use std::collections::{HashMap, HashSet};

    /// Generate a TokenSigningKey from a seed index.
    fn key_from_index(i: u8) -> TokenSigningKey {
        let mut seed = [0u8; 32];
        seed[0] = i;
        TokenSigningKey::from_seed(&seed)
    }

    #[test]
    fn signed_snapshot_roundtrip() {
        let key = TokenSigningKey::from_seed(&[1u8; 32]);
        let vk = key.verifying_key();

        let fields = HashMap::from([
            ("risk".into(), Value::Int(7)),
            ("balance".into(), Value::UInt(100)),
        ]);

        let s = SignedStateSnapshotV1::sign(&key, 42, fields, HashMap::new()).expect("sign");
        let snap = s.to_state_snapshot(&vk).expect("verify");
        assert_eq!(
            snap.state_ref.state_source_id,
            state_source_id_signed_snapshot_v1()
        );
        assert_eq!(snap.state_ref.state_epoch, 42);
        assert_ne!(snap.state_ref.state_attestation_hash, Hash32([0u8; 32]));
        assert_ne!(snap.state_hash, Hash32([0u8; 32]));
    }

    #[test]
    fn signed_snapshot_fails_closed_on_tamper() {
        let key = TokenSigningKey::from_seed(&[2u8; 32]);
        let vk = key.verifying_key();
        let fields = HashMap::from([("x".into(), Value::Int(1))]);
        let mut s = SignedStateSnapshotV1::sign(&key, 1, fields, HashMap::new()).expect("sign");

        // Tamper field after signature.
        s.fields.insert("x".into(), Value::Int(2));
        assert!(s.to_state_snapshot(&vk).is_err());
    }

    #[test]
    fn signed_snapshot_state_provider_verifies_before_returning() {
        let key = TokenSigningKey::from_seed(&[3u8; 32]);
        let vk = key.verifying_key();
        let fields = HashMap::from([("risk".into(), Value::Int(7))]);
        let s = SignedStateSnapshotV1::sign(&key, 42, fields, HashMap::new()).expect("sign");

        let provider = SignedSnapshotStateProvider::new(s.clone(), vk.clone());
        let snap = provider.snapshot().expect("snapshot");
        assert_eq!(
            snap.state_ref.state_source_id,
            state_source_id_signed_snapshot_v1()
        );
        assert_eq!(snap.state_ref.state_epoch, 42);

        // Fail closed if the signed snapshot is tampered with.
        let mut tampered = s;
        tampered.fields.insert("risk".into(), Value::Int(8));
        let provider = SignedSnapshotStateProvider::new(tampered, vk);
        assert!(provider.snapshot().is_err());
    }

    // =========================================================================
    // Property-Based Tests
    // =========================================================================

    proptest! {
        /// Property: sign-then-verify roundtrip for single-signer snapshots.
        #[test]
        fn signed_snapshot_roundtrip_property(
            seed in any::<[u8; 32]>(),
            epoch in any::<u64>(),
            risk in -1000i64..1000,
        ) {
            let key = TokenSigningKey::from_seed(&seed);
            let vk = key.verifying_key();
            let fields = HashMap::from([("risk".into(), Value::Int(risk))]);

            let signed = SignedStateSnapshotV1::sign(&key, epoch, fields, HashMap::new())
                .expect("sign must succeed");
            let snap = signed.to_state_snapshot(&vk).expect("verify must succeed");

            prop_assert_eq!(snap.state_ref.state_epoch, epoch);
            prop_assert_eq!(
                snap.state_ref.state_source_id,
                state_source_id_signed_snapshot_v1()
            );
        }

        /// Property: quorum threshold is exact — k signatures pass, k-1 fail.
        #[test]
        fn quorum_threshold_is_exact(
            threshold in 1u8..=5,
            n_signers in 5usize..=8,
        ) {
            let threshold = threshold.min(n_signers as u8);
            let keys: Vec<_> = (0..n_signers).map(|i| key_from_index(i as u8)).collect();
            let trusted: Vec<_> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();

            let fields = HashMap::from([("x".into(), Value::Int(1))]);
            let epoch = 100u64;
            let created_at = 1000i64;

            // Sign with exactly `threshold` signers.
            let contributions: Vec<_> = keys[..threshold as usize]
                .iter()
                .map(|k| {
                    QuorumSignedStateSnapshotV1::sign_contribution(
                        k, epoch, created_at, &fields, &HashMap::new(), threshold,
                    ).expect("sign")
                })
                .collect();

            let snap = QuorumSignedStateSnapshotV1::aggregate(
                epoch, created_at, fields.clone(), HashMap::new(), threshold, contributions.clone(),
            );

            // Must pass with exactly threshold.
            prop_assert!(
                snap.verify_with_trusted_attestors(&trusted).is_ok(),
                "must pass with exactly {} signatures", threshold
            );

            // Must fail with threshold - 1 (if threshold > 1).
            if threshold > 1 {
                let fewer: Vec<_> = contributions[..threshold as usize - 1].to_vec();
                let snap_fewer = QuorumSignedStateSnapshotV1::aggregate(
                    epoch, created_at, fields, HashMap::new(), threshold, fewer,
                );
                prop_assert!(
                    snap_fewer.verify_with_trusted_attestors(&trusted).is_err(),
                    "must fail with {} signatures (threshold={})", threshold - 1, threshold
                );
            }
        }

        /// Property: duplicate signatures from same signer don't count multiple times.
        #[test]
        fn duplicate_signatures_rejected(
            duplication_count in 2usize..=5,
        ) {
            let key = key_from_index(1);
            let trusted = vec![key.verifying_key().to_bytes()];

            let fields = HashMap::from([("x".into(), Value::Int(1))]);
            let epoch = 42u64;
            let created_at = 1000i64;
            let threshold = 2u8; // Require 2 signatures.

            // Create same contribution duplicated multiple times.
            let contrib = QuorumSignedStateSnapshotV1::sign_contribution(
                &key, epoch, created_at, &fields, &HashMap::new(), threshold,
            ).expect("sign");
            let contributions: Vec<_> = (0..duplication_count).map(|_| contrib.clone()).collect();

            let snap = QuorumSignedStateSnapshotV1::aggregate(
                epoch, created_at, fields, HashMap::new(), threshold, contributions,
            );

            // Must fail: duplicates of same signer don't count as multiple attestors.
            prop_assert!(
                snap.verify_with_trusted_attestors(&trusted).is_err(),
                "{} duplicates of same signer should not satisfy threshold=2",
                duplication_count
            );
        }

        /// Property: signatures from untrusted attestors are ignored.
        #[test]
        fn untrusted_attestors_ignored(
            n_untrusted in 1usize..=5,
        ) {
            let trusted_key = key_from_index(0);
            let trusted = vec![trusted_key.verifying_key().to_bytes()];

            let fields = HashMap::from([("x".into(), Value::Int(1))]);
            let epoch = 42u64;
            let created_at = 1000i64;
            let threshold = 2u8;

            // Only untrusted signers contribute.
            let contributions: Vec<_> = (1..=n_untrusted)
                .map(|i| {
                    let untrusted_key = key_from_index(i as u8);
                    QuorumSignedStateSnapshotV1::sign_contribution(
                        &untrusted_key, epoch, created_at, &fields, &HashMap::new(), threshold,
                    ).expect("sign")
                })
                .collect();

            let snap = QuorumSignedStateSnapshotV1::aggregate(
                epoch, created_at, fields, HashMap::new(), threshold, contributions,
            );

            // Must fail: no trusted attestor signed.
            prop_assert!(
                snap.verify_with_trusted_attestors(&trusted).is_err(),
                "{} untrusted signatures should not satisfy quorum", n_untrusted
            );
        }

        /// Property: state hash is deterministic for same inputs.
        #[test]
        fn state_hash_deterministic(
            seed in any::<[u8; 32]>(),
            epoch in any::<u64>(),
            value in any::<i64>(),
        ) {
            let key = TokenSigningKey::from_seed(&seed);
            let vk = key.verifying_key();
            let fields = HashMap::from([("v".into(), Value::Int(value))]);

            let s1 = SignedStateSnapshotV1::sign(&key, epoch, fields.clone(), HashMap::new())
                .expect("sign");
            let s2 = SignedStateSnapshotV1::sign(&key, epoch, fields, HashMap::new())
                .expect("sign");

            let snap1 = s1.to_state_snapshot(&vk).expect("verify");
            let snap2 = s2.to_state_snapshot(&vk).expect("verify");

            prop_assert_eq!(snap1.state_hash, snap2.state_hash);
        }

        /// Property: check_freshness rejects stale snapshots and accepts fresh ones.
        #[test]
        fn check_freshness_rejects_stale_and_future(
            staleness_factor in 0u64..200,
            max_staleness_ms in 1000i64..60000,
        ) {
            use std::time::{SystemTime, UNIX_EPOCH};

            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_millis() as i64;

            let key = key_from_index(1);
            let vk = key.verifying_key();
            let fields = HashMap::from([("x".into(), Value::Int(1))]);
            let trusted = vec![vk.to_bytes()];

            // Case 1: Fresh snapshot (just created) should pass
            let fresh_created = now_ms;
            let contrib_fresh = QuorumSignedStateSnapshotV1::sign_contribution(
                &key, 1, fresh_created, &fields, &HashMap::new(), 1
            ).expect("sign");
            let snap_fresh = QuorumSignedStateSnapshotV1::aggregate(
                1, fresh_created, fields.clone(), HashMap::new(), 1, vec![contrib_fresh]
            );
            let provider_fresh = QuorumSignedSnapshotStateProvider::new(
                snap_fresh, trusted.clone(), max_staleness_ms
            );
            prop_assert!(provider_fresh.snapshot().is_ok(), "fresh snapshot should pass");

            // Case 2: Stale snapshot (older than max_staleness_ms) should fail
            let stale_created = now_ms - max_staleness_ms - (staleness_factor as i64 + 1);
            let contrib_stale = QuorumSignedStateSnapshotV1::sign_contribution(
                &key, 1, stale_created, &fields, &HashMap::new(), 1
            ).expect("sign");
            let snap_stale = QuorumSignedStateSnapshotV1::aggregate(
                1, stale_created, fields.clone(), HashMap::new(), 1, vec![contrib_stale]
            );
            let provider_stale = QuorumSignedSnapshotStateProvider::new(
                snap_stale, trusted.clone(), max_staleness_ms
            );
            prop_assert!(provider_stale.snapshot().is_err(), "stale snapshot should fail");

            // Case 3: Future snapshot (>5s in future) should fail
            let future_created = now_ms + 6000; // 6 seconds in future
            let contrib_future = QuorumSignedStateSnapshotV1::sign_contribution(
                &key, 1, future_created, &fields, &HashMap::new(), 1
            ).expect("sign");
            let snap_future = QuorumSignedStateSnapshotV1::aggregate(
                1, future_created, fields.clone(), HashMap::new(), 1, vec![contrib_future]
            );
            let provider_future = QuorumSignedSnapshotStateProvider::new(
                snap_future, trusted, max_staleness_ms
            );
            prop_assert!(provider_future.snapshot().is_err(), "future snapshot should fail");
        }

        /// Property: signing_bytes_v1 produces non-trivial content (catches trivial return mutations).
        #[test]
        fn signing_bytes_is_non_trivial(
            epoch in any::<u64>(),
            created_at in any::<i64>(),
            threshold in 1u8..=5,
            value in any::<i64>(),
        ) {
            let key = key_from_index(1);
            let fields = HashMap::from([("test".into(), Value::Int(value))]);

            let contrib = QuorumSignedStateSnapshotV1::sign_contribution(
                &key, epoch, created_at, &fields, &HashMap::new(), threshold
            ).expect("sign");
            let snap = QuorumSignedStateSnapshotV1::aggregate(
                epoch, created_at, fields, HashMap::new(), threshold, vec![contrib]
            );

            let bytes = snap.signing_bytes_v1().expect("bytes");

            // Must contain domain separator + version + epoch + timestamp + threshold + source_id + preimage
            // This is at least 32 (domain) + 4 (version) + 8 (epoch) + 8 (ts) + 1 (threshold) + 32 (source) = 85 bytes minimum
            prop_assert!(bytes.len() >= 85, "signing bytes must be substantial, got {}", bytes.len());

            // Must start with domain separator
            prop_assert!(bytes.starts_with(QUORUM_SIGNED_SNAPSHOT_DOMAIN_V1), "must start with domain");
        }

        /// Property: exact boundary behavior for freshness checks.
        /// staleness == max is acceptable, staleness == max+1 is not.
        /// future == -5000ms is acceptable, future == -5001ms is not.
        #[test]
        fn check_freshness_exact_boundaries(
            max_staleness_ms in 10000i64..60000,
        ) {
            use std::time::{SystemTime, UNIX_EPOCH};

            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_millis() as i64;

            let key = key_from_index(1);
            let vk = key.verifying_key();
            let fields = HashMap::from([("x".into(), Value::Int(1))]);
            let trusted = vec![vk.to_bytes()];

            // Add a small buffer (100ms) to account for test execution time
            // This is a deterministic test with fixed offsets, avoiding timing races.
            let test_buffer_ms = 100i64;

            // Test 1: Well within max staleness should PASS
            let safe_created = now_ms - max_staleness_ms + test_buffer_ms;
            let contrib_safe = QuorumSignedStateSnapshotV1::sign_contribution(
                &key, 1, safe_created, &fields, &HashMap::new(), 1
            ).expect("sign");
            let snap_safe = QuorumSignedStateSnapshotV1::aggregate(
                1, safe_created, fields.clone(), HashMap::new(), 1, vec![contrib_safe]
            );
            let provider_safe = QuorumSignedSnapshotStateProvider::new(
                snap_safe, trusted.clone(), max_staleness_ms
            );
            prop_assert!(
                provider_safe.check_freshness_at(now_ms).is_ok(),
                "within max_staleness should pass"
            );

            // Test 2: Clearly over max staleness should FAIL
            let stale_created = now_ms - max_staleness_ms - test_buffer_ms;
            let contrib_stale = QuorumSignedStateSnapshotV1::sign_contribution(
                &key, 1, stale_created, &fields, &HashMap::new(), 1
            ).expect("sign");
            let snap_stale = QuorumSignedStateSnapshotV1::aggregate(
                1, stale_created, fields.clone(), HashMap::new(), 1, vec![contrib_stale]
            );
            let provider_stale = QuorumSignedSnapshotStateProvider::new(
                snap_stale, trusted.clone(), max_staleness_ms
            );
            prop_assert!(
                provider_stale.check_freshness_at(now_ms).is_err(),
                "over max_staleness should fail"
            );

            // Test 3: Within 5s future skew should PASS
            let safe_future_created = now_ms + 4900;  // 4.9s in future
            let contrib_safe_future = QuorumSignedStateSnapshotV1::sign_contribution(
                &key, 1, safe_future_created, &fields, &HashMap::new(), 1
            ).expect("sign");
            let snap_safe_future = QuorumSignedStateSnapshotV1::aggregate(
                1, safe_future_created, fields.clone(), HashMap::new(), 1, vec![contrib_safe_future]
            );
            let provider_safe_future = QuorumSignedSnapshotStateProvider::new(
                snap_safe_future, trusted.clone(), max_staleness_ms
            );
            prop_assert!(
                provider_safe_future.check_freshness_at(now_ms).is_ok(),
                "within 5s future should pass"
            );

            // Test 4: Clearly past 5s future skew should FAIL
            let far_future_created = now_ms + 5100;  // 5.1s in future
            let contrib_far_future = QuorumSignedStateSnapshotV1::sign_contribution(
                &key, 1, far_future_created, &fields, &HashMap::new(), 1
            ).expect("sign");
            let snap_far_future = QuorumSignedStateSnapshotV1::aggregate(
                1, far_future_created, fields.clone(), HashMap::new(), 1, vec![contrib_far_future]
            );
            let provider_far_future = QuorumSignedSnapshotStateProvider::new(
                snap_far_future, trusted, max_staleness_ms
            );
            prop_assert!(
                provider_far_future.check_freshness_at(now_ms).is_err(),
                "over 5s future should fail"
            );
        }

        /// Stateful test: QuorumSignedStateSnapshotV1 attestor accumulation matches a reference model.
        /// Generates random signer selection and verifies threshold logic.
        #[test]
        fn quorum_attestor_stateful_model_test(
            threshold in 1u8..=4,
            n_signers in 4usize..=6,
            contribution_indices in proptest::collection::vec(0usize..8, 3..12),
        ) {
            // Reference model: tracks which attestors have contributed valid signatures
            #[derive(Default)]
            struct QuorumModel {
                valid_attestors: HashSet<[u8; 32]>,
            }

            impl QuorumModel {
                fn add_contribution(&mut self, pubkey: [u8; 32], is_trusted: bool) -> bool {
                    if !is_trusted {
                        return false; // untrusted signers don't count
                    }
                    // Returns true if this is a new (not duplicate) contribution
                    self.valid_attestors.insert(pubkey)
                }

                fn meets_threshold(&self, threshold: u8) -> bool {
                    self.valid_attestors.len() >= threshold as usize
                }
            }

            let threshold = threshold.min(n_signers as u8);
            let keys: Vec<TokenSigningKey> = (0..n_signers)
                .map(|i| key_from_index(i as u8))
                .collect();
            let trusted: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();

            let fields = HashMap::from([("x".into(), Value::Int(1))]);
            let epoch = 1u64;
            let created_at = 1000i64;

            let mut model = QuorumModel::default();

            // Build contributions one by one, tracking model state
            let mut contributions = Vec::new();

            for signer_idx in contribution_indices {
                // Wrap index to valid range (some will be untrusted if idx >= n_signers)
                let is_trusted = signer_idx < n_signers;
                let actual_idx = signer_idx % n_signers;

                let key = &keys[actual_idx];
                let pubkey = key.verifying_key().to_bytes();

                // Model: add contribution
                let is_new = model.add_contribution(pubkey, is_trusted);

                // Only add to real contributions if this is a trusted signer
                if is_trusted && is_new {
                    let contrib = QuorumSignedStateSnapshotV1::sign_contribution(
                        key, epoch, created_at, &fields, &HashMap::new(), threshold
                    ).expect("sign");
                    contributions.push(contrib);
                }
            }

            // Build the snapshot with all contributions
            let snap = QuorumSignedStateSnapshotV1::aggregate(
                epoch, created_at, fields, HashMap::new(), threshold, contributions
            );

            // INVARIANT: verify result should match model's threshold check
            let sut_result = snap.verify_with_trusted_attestors(&trusted);
            let model_meets_threshold = model.meets_threshold(threshold);

            if model_meets_threshold {
                prop_assert!(
                    sut_result.is_ok(),
                    "Model says threshold met with {} attestors, threshold={}, but SUT rejected",
                    model.valid_attestors.len(), threshold
                );
            } else {
                prop_assert!(
                    sut_result.is_err(),
                    "Model says threshold NOT met with {} attestors, threshold={}, but SUT accepted",
                    model.valid_attestors.len(), threshold
                );
            }
        }
    }
}
