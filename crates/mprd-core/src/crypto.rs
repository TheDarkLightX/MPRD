//! Cryptographic primitives for MPRD.
//!
//! Provides ed25519 signing and verification for decision tokens.
//!
//! # Security
//!
//! - Uses ed25519-dalek with verified implementations
//! - Keys should be loaded from secure storage (HSM, Vault, etc.)
//! - Never log or expose private keys

use crate::{DecisionToken, Hash32, MprdError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tracing::{debug, instrument, warn};
use zeroize::Zeroize;

/// 64-byte ed25519 signature.
pub type SignatureBytes = [u8; 64];

/// 32-byte ed25519 public key.
pub type PublicKeyBytes = [u8; 32];

/// 32-byte ed25519 private key seed.
pub type PrivateKeySeed = [u8; 32];

/// Keypair for signing decision tokens.
#[derive(Clone)]
pub struct TokenSigningKey {
    signing_key: SigningKey,
}

impl TokenSigningKey {
    /// Generate a new random keypair.
    ///
    /// # Security
    ///
    /// Uses `OsRng` (operating system CSPRNG) for cryptographically secure
    /// key generation. For production, prefer loading keys from secure
    /// storage (HSM, Vault, KMS) rather than generating at runtime.
    ///
    /// This method is suitable for:
    /// - Testing and development
    /// - Ephemeral keys with short lifetimes
    /// - Bootstrapping when no key storage is available
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Load keypair from seed bytes.
    ///
    /// # Arguments
    /// * `seed` - 32-byte seed for key derivation
    pub fn from_seed(seed: &PrivateKeySeed) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    /// Load keypair from hex-encoded seed.
    ///
    /// # Security
    ///
    /// The seed bytes are zeroized after use to prevent secrets from lingering in memory.
    pub fn from_hex(hex_seed: &str) -> Result<Self> {
        let mut bytes = hex::decode(hex_seed)
            .map_err(|e| MprdError::CryptoError(format!("Invalid hex: {}", e)))?;

        if bytes.len() != 32 {
            bytes.zeroize();
            return Err(MprdError::CryptoError(
                "Seed must be exactly 32 bytes".into(),
            ));
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        bytes.zeroize(); // Zeroize intermediate buffer

        let key = Self::from_seed(&seed);
        seed.zeroize(); // Zeroize seed after use
        Ok(key)
    }

    /// Get the public verifying key.
    pub fn verifying_key(&self) -> TokenVerifyingKey {
        TokenVerifyingKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Sign a decision token.
    ///
    /// Computes: `sign(H(token_bytes))`
    #[instrument(skip(self, token), fields(policy_hash = %hex::encode(&token.policy_hash.0[..8])))]
    pub fn sign_token(&self, token: &DecisionToken) -> SignatureBytes {
        let message = token_to_signing_bytes(token);
        let signature = self.signing_key.sign(&message);
        debug!("Signed token");
        signature.to_bytes()
    }

    /// Sign arbitrary bytes (ed25519).
    pub fn sign_bytes(&self, message: &[u8]) -> SignatureBytes {
        self.signing_key.sign(message).to_bytes()
    }
}

/// Public key for verifying token signatures.
#[derive(Clone)]
pub struct TokenVerifyingKey {
    verifying_key: VerifyingKey,
}

impl TokenVerifyingKey {
    /// Load verifying key from bytes.
    pub fn from_bytes(bytes: &PublicKeyBytes) -> Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(bytes)
            .map_err(|e| MprdError::CryptoError(format!("Invalid public key: {}", e)))?;
        Ok(Self { verifying_key })
    }

    /// Load verifying key from hex.
    pub fn from_hex(hex_key: &str) -> Result<Self> {
        let bytes = hex::decode(hex_key)
            .map_err(|e| MprdError::CryptoError(format!("Invalid hex: {}", e)))?;

        if bytes.len() != 32 {
            return Err(MprdError::CryptoError(
                "Public key must be exactly 32 bytes".into(),
            ));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Self::from_bytes(&key_bytes)
    }

    /// Get raw public key bytes.
    pub fn to_bytes(&self) -> PublicKeyBytes {
        self.verifying_key.to_bytes()
    }

    /// Verify a token signature.
    ///
    /// # Returns
    /// - `Ok(())` if signature is valid
    /// - `Err(MprdError::SignatureInvalid)` if verification fails
    #[instrument(skip(self, token, signature), fields(policy_hash = %hex::encode(&token.policy_hash.0[..8])))]
    pub fn verify_token(&self, token: &DecisionToken, signature: &[u8]) -> Result<()> {
        if signature.len() != 64 {
            warn!("Invalid signature length: {}", signature.len());
            return Err(MprdError::SignatureInvalid(
                "Invalid signature length".into(),
            ));
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);

        let signature = Signature::from_bytes(&sig_bytes);
        let message = token_to_signing_bytes(token);

        self.verifying_key
            .verify(&message, &signature)
            .map_err(|_| {
                warn!("Signature verification failed");
                MprdError::SignatureInvalid("Signature verification failed".into())
            })?;

        debug!("Signature verified");
        Ok(())
    }

    /// Verify a signature over arbitrary bytes (ed25519).
    pub fn verify_bytes(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != 64 {
            return Err(MprdError::SignatureInvalid(
                "Invalid signature length".into(),
            ));
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let signature = Signature::from_bytes(&sig_bytes);

        self.verifying_key
            .verify(message, &signature)
            .map_err(|_| MprdError::SignatureInvalid("Signature verification failed".into()))?;
        Ok(())
    }
}

/// Convert a decision token to bytes for signing.
///
/// Deterministic serialization:
/// `policy_hash || policy_epoch || registry_root || state_hash || state_source_id || state_epoch || state_attestation_hash || chosen_action_hash || nonce || timestamp`
fn token_to_signing_bytes(token: &DecisionToken) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 * 8 + 8 * 3);
    bytes.extend_from_slice(&token.policy_hash.0);
    bytes.extend_from_slice(&token.policy_ref.policy_epoch.to_le_bytes());
    bytes.extend_from_slice(&token.policy_ref.registry_root.0);
    bytes.extend_from_slice(&token.state_hash.0);
    bytes.extend_from_slice(&token.state_ref.state_source_id.0);
    bytes.extend_from_slice(&token.state_ref.state_epoch.to_le_bytes());
    bytes.extend_from_slice(&token.state_ref.state_attestation_hash.0);
    bytes.extend_from_slice(&token.chosen_action_hash.0);
    bytes.extend_from_slice(&token.nonce_or_tx_hash.0);
    bytes.extend_from_slice(&token.timestamp_ms.to_le_bytes());
    bytes
}

/// Compute SHA-256 hash of data (re-export for convenience).
pub fn sha256(data: &[u8]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    Hash32(result.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn make_token() -> DecisionToken {
        DecisionToken {
            policy_hash: dummy_hash(1),
            policy_ref: crate::PolicyRef {
                policy_epoch: 7,
                registry_root: dummy_hash(8),
            },
            state_hash: dummy_hash(2),
            state_ref: crate::StateRef {
                state_source_id: dummy_hash(9),
                state_epoch: 11,
                state_attestation_hash: dummy_hash(10),
            },
            chosen_action_hash: dummy_hash(3),
            nonce_or_tx_hash: dummy_hash(4),
            timestamp_ms: 1234567890,
            signature: vec![],
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let signing_key = TokenSigningKey::from_seed(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let token = make_token();

        let signature = signing_key.sign_token(&token);
        let result = verifying_key.verify_token(&token, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn tampered_token_fails_verification() {
        let signing_key = TokenSigningKey::from_seed(&[2u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let token = make_token();

        let signature = signing_key.sign_token(&token);

        // Tamper with token
        let mut tampered = token.clone();
        tampered.timestamp_ms = 9999999999;

        let result = verifying_key.verify_token(&tampered, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn signature_binds_all_security_relevant_fields() {
        fn flip_policy_hash(t: &mut DecisionToken) {
            t.policy_hash.0[0] ^= 0x01;
        }

        fn bump_policy_epoch(t: &mut DecisionToken) {
            t.policy_ref.policy_epoch = t.policy_ref.policy_epoch.wrapping_add(1);
        }

        fn flip_registry_root(t: &mut DecisionToken) {
            t.policy_ref.registry_root.0[0] ^= 0x01;
        }

        fn flip_state_hash(t: &mut DecisionToken) {
            t.state_hash.0[0] ^= 0x01;
        }

        fn flip_state_source_id(t: &mut DecisionToken) {
            t.state_ref.state_source_id.0[0] ^= 0x01;
        }

        fn bump_state_epoch(t: &mut DecisionToken) {
            t.state_ref.state_epoch = t.state_ref.state_epoch.wrapping_add(1);
        }

        fn flip_state_attestation_hash(t: &mut DecisionToken) {
            t.state_ref.state_attestation_hash.0[0] ^= 0x01;
        }

        fn flip_chosen_action_hash(t: &mut DecisionToken) {
            t.chosen_action_hash.0[0] ^= 0x01;
        }

        fn flip_nonce_or_tx_hash(t: &mut DecisionToken) {
            t.nonce_or_tx_hash.0[0] ^= 0x01;
        }

        fn bump_timestamp_ms(t: &mut DecisionToken) {
            t.timestamp_ms = t.timestamp_ms.wrapping_add(1);
        }

        let signing_key = TokenSigningKey::from_seed(&[9u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let token = make_token();
        let signature = signing_key.sign_token(&token);

        let cases: &[(&str, fn(&mut DecisionToken))] = &[
            ("policy_hash", flip_policy_hash),
            ("policy_epoch", bump_policy_epoch),
            ("registry_root", flip_registry_root),
            ("state_hash", flip_state_hash),
            ("state_source_id", flip_state_source_id),
            ("state_epoch", bump_state_epoch),
            ("state_attestation_hash", flip_state_attestation_hash),
            ("chosen_action_hash", flip_chosen_action_hash),
            ("nonce_or_tx_hash", flip_nonce_or_tx_hash),
            ("timestamp_ms", bump_timestamp_ms),
        ];

        for &(name, mutate) in cases {
            let mut tampered = token.clone();
            mutate(&mut tampered);
            let result = verifying_key.verify_token(&tampered, &signature);
            assert!(
                matches!(result, Err(MprdError::SignatureInvalid(_))),
                "expected SignatureInvalid for tamper case {name}, got: {result:?}"
            );
        }
    }

    #[test]
    fn wrong_key_fails_verification() {
        let signing_key = TokenSigningKey::from_seed(&[3u8; 32]);
        let wrong_key = TokenSigningKey::from_seed(&[4u8; 32]);
        let token = make_token();

        let signature = signing_key.sign_token(&token);
        let result = wrong_key.verifying_key().verify_token(&token, &signature);

        assert!(result.is_err());
    }

    #[test]
    fn key_from_seed_is_deterministic() {
        let seed = [42u8; 32];
        let key1 = TokenSigningKey::from_seed(&seed);
        let key2 = TokenSigningKey::from_seed(&seed);

        assert_eq!(
            key1.verifying_key().to_bytes(),
            key2.verifying_key().to_bytes()
        );
    }

    #[test]
    fn key_from_hex() {
        let hex_seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = TokenSigningKey::from_hex(hex_seed);
        assert!(key.is_ok());
    }

    #[test]
    fn verifying_key_from_hex_roundtrips() {
        let signing_key = TokenSigningKey::from_seed(&[1u8; 32]);
        let expected = signing_key.verifying_key().to_bytes();
        let hex_key = hex::encode(expected);

        let parsed = TokenVerifyingKey::from_hex(&hex_key).expect("valid verifying key");
        assert_eq!(parsed.to_bytes(), expected);
    }

    #[test]
    fn verifying_key_from_hex_rejects_wrong_length() {
        let hex_key = "00".repeat(31);
        let err = match TokenVerifyingKey::from_hex(&hex_key) {
            Ok(_) => panic!("should reject non-32-byte public key"),
            Err(e) => e,
        };
        assert!(matches!(err, MprdError::CryptoError(_)));
    }

    #[test]
    fn invalid_hex_rejected() {
        let result = TokenSigningKey::from_hex("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn signature_deterministic() {
        let seed = [42u8; 32];
        let key = TokenSigningKey::from_seed(&seed);
        let token = make_token();

        let sig1 = key.sign_token(&token);
        let sig2 = key.sign_token(&token);

        assert_eq!(sig1, sig2);
    }

    proptest! {
        #[test]
        fn signing_and_verification_roundtrip_for_random_tokens(
            seed in any::<[u8; 32]>(),
            policy_hash in any::<[u8; 32]>(),
            registry_root in any::<[u8; 32]>(),
            policy_epoch in any::<u64>(),
            state_hash in any::<[u8; 32]>(),
            state_source_id in any::<[u8; 32]>(),
            state_epoch in any::<u64>(),
            state_attestation_hash in any::<[u8; 32]>(),
            chosen_action_hash in any::<[u8; 32]>(),
            nonce in any::<[u8; 32]>(),
            timestamp_ms in any::<i64>(),
        ) {
            let signing_key = TokenSigningKey::from_seed(&seed);
            let verifying_key = signing_key.verifying_key();

            let token = DecisionToken {
                policy_hash: Hash32(policy_hash),
                policy_ref: crate::PolicyRef {
                    policy_epoch,
                    registry_root: Hash32(registry_root),
                },
                state_hash: Hash32(state_hash),
                state_ref: crate::StateRef {
                    state_source_id: Hash32(state_source_id),
                    state_epoch,
                    state_attestation_hash: Hash32(state_attestation_hash),
                },
                chosen_action_hash: Hash32(chosen_action_hash),
                nonce_or_tx_hash: Hash32(nonce),
                timestamp_ms,
                signature: vec![],
            };

            let sig = signing_key.sign_token(&token);
            prop_assert!(verifying_key.verify_token(&token, &sig).is_ok());
        }

        #[test]
        fn token_mutation_fails_signature_verification(
            seed in any::<[u8; 32]>(),
            mutator in 0u8..=9u8,
        ) {
            let signing_key = TokenSigningKey::from_seed(&seed);
            let verifying_key = signing_key.verifying_key();

            let token = make_token();
            let sig = signing_key.sign_token(&token);

            let mut tampered = token.clone();
            match mutator {
                0 => tampered.policy_hash.0[0] ^= 0x01,
                1 => tampered.policy_ref.policy_epoch = tampered.policy_ref.policy_epoch.wrapping_add(1),
                2 => tampered.policy_ref.registry_root.0[0] ^= 0x01,
                3 => tampered.state_hash.0[0] ^= 0x01,
                4 => tampered.state_ref.state_source_id.0[0] ^= 0x01,
                5 => tampered.state_ref.state_epoch = tampered.state_ref.state_epoch.wrapping_add(1),
                6 => tampered.state_ref.state_attestation_hash.0[0] ^= 0x01,
                7 => tampered.chosen_action_hash.0[0] ^= 0x01,
                8 => tampered.nonce_or_tx_hash.0[0] ^= 0x01,
                _ => tampered.timestamp_ms = tampered.timestamp_ms.wrapping_add(1),
            }

            prop_assert!(verifying_key.verify_token(&tampered, &sig).is_err());
        }
    }
}
