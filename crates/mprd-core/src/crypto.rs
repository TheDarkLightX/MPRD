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
use sha2::{Sha256, Digest};
use tracing::{debug, instrument, warn};

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
    /// Use only for testing. Production should load keys from secure storage.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
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
    pub fn from_hex(hex_seed: &str) -> Result<Self> {
        let bytes = hex::decode(hex_seed)
            .map_err(|e| MprdError::CryptoError(format!("Invalid hex: {}", e)))?;

        if bytes.len() != 32 {
            return Err(MprdError::CryptoError(
                "Seed must be exactly 32 bytes".into(),
            ));
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Self::from_seed(&seed))
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
            return Err(MprdError::SignatureInvalid("Invalid signature length".into()));
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
}

/// Convert a decision token to bytes for signing.
///
/// Deterministic serialization:
/// `policy_hash || state_hash || chosen_action_hash || nonce || timestamp`
fn token_to_signing_bytes(token: &DecisionToken) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 * 4 + 8);
    bytes.extend_from_slice(&token.policy_hash.0);
    bytes.extend_from_slice(&token.state_hash.0);
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

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn make_token() -> DecisionToken {
        DecisionToken {
            policy_hash: dummy_hash(1),
            state_hash: dummy_hash(2),
            chosen_action_hash: dummy_hash(3),
            nonce_or_tx_hash: dummy_hash(4),
            timestamp_ms: 1234567890,
            signature: vec![],
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let signing_key = TokenSigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let token = make_token();

        let signature = signing_key.sign_token(&token);
        let result = verifying_key.verify_token(&token, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn tampered_token_fails_verification() {
        let signing_key = TokenSigningKey::generate();
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
    fn wrong_key_fails_verification() {
        let signing_key = TokenSigningKey::generate();
        let wrong_key = TokenSigningKey::generate();
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
}
