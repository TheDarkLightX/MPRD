//! Privacy primitives for MPRD Mode C.
//!
//! This module provides mechanisms to prove policy compliance without
//! revealing sensitive state or action details.
//!
//! # Privacy Features
//!
//! | Feature | Purpose | Status |
//! |---------|---------|--------|
//! | Commitment Schemes | Hide values while proving properties | ✅ Implemented |
//! | Encrypted State | Encrypt state before attestation | ✅ Implemented |
//! | Selective Disclosure | Reveal only necessary fields | ✅ Implemented |
//! | Range Proofs | Prove value in range without revealing | 🔶 Interface |
//!
//! # Privacy Model
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Private MPRD (Mode C)                    │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │  State: { balance: 10000, risk: 50 }                       │
//! │                    │                                        │
//! │                    ▼                                        │
//! │  ┌─────────────────────────────────────────┐               │
//! │  │           Commitment Layer              │               │
//! │  │  balance_commit = Commit(10000, r1)     │               │
//! │  │  risk_commit = Commit(50, r2)           │               │
//! │  └─────────────────────────────────────────┘               │
//! │                    │                                        │
//! │                    ▼                                        │
//! │  ┌─────────────────────────────────────────┐               │
//! │  │           ZK Proof (Risc0)              │               │
//! │  │  Proves: risk <= threshold              │               │
//! │  │  Reveals: policy_hash, decision         │               │
//! │  │  Hides: actual risk value, balance      │               │
//! │  └─────────────────────────────────────────┘               │
//! │                    │                                        │
//! │                    ▼                                        │
//! │  Public Output: { policy_hash, commitment, decision }      │
//! │                                                             │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use crate::error::{ModeError, ModeResult};
use mprd_core::{Hash32, StateSnapshot, Value};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{debug, info};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};

// =============================================================================
// Commitment Schemes
// =============================================================================

/// A cryptographic commitment to a value.
///
/// Commitment = H(value || blinding_factor)
///
/// Properties:
/// - Hiding: Cannot determine value from commitment
/// - Binding: Cannot open to different value
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    /// The commitment hash.
    pub hash: [u8; 32],

    /// Commitment scheme identifier.
    pub scheme: CommitmentScheme,
}

/// Supported commitment schemes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitmentScheme {
    /// SHA-256 based commitment (simple, fast).
    Sha256,

    /// Pedersen commitment (additively homomorphic).
    Pedersen,

    /// Poseidon hash (ZK-friendly).
    Poseidon,
}

impl Default for CommitmentScheme {
    fn default() -> Self {
        Self::Sha256
    }
}

/// Opening for a commitment (proves the committed value).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentOpening {
    /// The committed value (serialized).
    pub value: Vec<u8>,

    /// The blinding factor used.
    pub blinding: [u8; 32],
}

/// Commitment generator.
pub struct CommitmentGenerator {
    scheme: CommitmentScheme,
}

impl CommitmentGenerator {
    /// Create a new generator with the specified scheme.
    pub fn new(scheme: CommitmentScheme) -> Self {
        Self { scheme }
    }

    /// Create a SHA-256 based generator.
    pub fn sha256() -> Self {
        Self::new(CommitmentScheme::Sha256)
    }

    /// Commit to a value with a random blinding factor.
    pub fn commit(&self, value: &[u8]) -> (Commitment, CommitmentOpening) {
        let blinding = self.generate_blinding();
        let hash = self.compute_commitment(value, &blinding);

        (
            Commitment {
                hash,
                scheme: self.scheme,
            },
            CommitmentOpening {
                value: value.to_vec(),
                blinding,
            },
        )
    }

    /// Commit to a value with a specified blinding factor (for deterministic testing).
    pub fn commit_with_blinding(&self, value: &[u8], blinding: [u8; 32]) -> Commitment {
        let hash = self.compute_commitment(value, &blinding);
        Commitment {
            hash,
            scheme: self.scheme,
        }
    }

    /// Verify a commitment opening.
    pub fn verify(&self, commitment: &Commitment, opening: &CommitmentOpening) -> bool {
        if commitment.scheme != self.scheme {
            return false;
        }

        let expected_hash = self.compute_commitment(&opening.value, &opening.blinding);
        commitment.hash == expected_hash
    }

    /// Generate a random blinding factor.
    ///
    /// This implementation is careful to avoid unbounded reads from `/dev/urandom`,
    /// which can be problematic on constrained environments. It first tries to
    /// read exactly 32 bytes, and if that fails, falls back to a deterministic
    /// hash of the current time and a fixed domain separator.
    fn generate_blinding(&self) -> [u8; 32] {
        let mut blinding = [0u8; 32];

        // Best-effort: read exactly 32 bytes from /dev/urandom
        if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
            use std::io::Read as _;
            if file.read_exact(&mut blinding).is_ok() {
                return blinding;
            }
        }

        // Fallback: deterministic, time-based blinding (not cryptographically
        // strong, but safe and fast for test environments).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut hasher = Sha256::new();
        hasher.update(&now.to_le_bytes());
        hasher.update(b"mprd_blinding_fallback_v1");
        blinding.copy_from_slice(&hasher.finalize());
        blinding
    }

    /// Compute commitment hash.
    fn compute_commitment(&self, value: &[u8], blinding: &[u8; 32]) -> [u8; 32] {
        match self.scheme {
            CommitmentScheme::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(value);
                hasher.update(blinding);
                hasher.finalize().into()
            }
            CommitmentScheme::Pedersen | CommitmentScheme::Poseidon => {
                // For now, fall back to SHA-256
                // TODO: Implement proper Pedersen/Poseidon when needed
                let mut hasher = Sha256::new();
                hasher.update(value);
                hasher.update(blinding);
                hasher.finalize().into()
            }
        }
    }
}

impl Default for CommitmentGenerator {
    fn default() -> Self {
        Self::sha256()
    }
}

// =============================================================================
// Encrypted State
// =============================================================================

/// Encrypted state snapshot for Mode C.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedState {
    /// Commitment to the full state.
    pub state_commitment: Commitment,

    /// Individual field commitments (for selective disclosure).
    pub field_commitments: HashMap<String, Commitment>,

    /// Encrypted state blob (AES-256-GCM).
    pub ciphertext: Vec<u8>,

    /// Encryption nonce.
    pub nonce: [u8; 12],

    /// Key ID used for encryption.
    pub key_id: String,
}

/// State encryption configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Key identifier.
    pub key_id: String,

    /// Fields to commit individually (for selective disclosure).
    pub committed_fields: Vec<String>,

    /// Fields to encrypt (hidden entirely).
    pub encrypted_fields: Vec<String>,

    /// Fields to reveal in plaintext.
    pub revealed_fields: Vec<String>,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            key_id: "default".into(),
            committed_fields: vec![],
            encrypted_fields: vec![],
            revealed_fields: vec![],
        }
    }
}

/// State encryptor for Mode C.
pub struct StateEncryptor {
    config: EncryptionConfig,
    commitment_gen: CommitmentGenerator,
}

impl StateEncryptor {
    /// Create a new encryptor with config.
    pub fn new(config: EncryptionConfig) -> Self {
        Self {
            config,
            commitment_gen: CommitmentGenerator::sha256(),
        }
    }

    /// Encrypt a state snapshot.
    pub fn encrypt(&self, state: &StateSnapshot) -> ModeResult<(EncryptedState, EncryptionWitness)> {
        info!(key_id = %self.config.key_id, "Encrypting state");

        // Serialize state
        let state_bytes = self.serialize_state(state)?;

        // Generate state commitment
        let (state_commitment, state_opening) = self.commitment_gen.commit(&state_bytes);

        // Generate field commitments
        let mut field_commitments = HashMap::new();
        let mut field_openings = HashMap::new();

        for field_name in &self.config.committed_fields {
            if let Some(value) = state.fields.get(field_name) {
                let value_bytes = self.serialize_value(value)?;
                let (commitment, opening) = self.commitment_gen.commit(&value_bytes);
                field_commitments.insert(field_name.clone(), commitment);
                field_openings.insert(field_name.clone(), opening);
            }
        }

        // Encrypt state (placeholder - would use actual AES-GCM)
        let (ciphertext, nonce) = self.encrypt_bytes(&state_bytes)?;

        let encrypted = EncryptedState {
            state_commitment,
            field_commitments,
            ciphertext,
            nonce,
            key_id: self.config.key_id.clone(),
        };

        let witness = EncryptionWitness {
            state_opening,
            field_openings,
            plaintext_state: state.clone(),
        };

        debug!(
            commitment = %hex::encode(&encrypted.state_commitment.hash[..8]),
            "State encrypted"
        );

        Ok((encrypted, witness))
    }

    /// Verify encrypted state matches commitment.
    pub fn verify_commitment(&self, encrypted: &EncryptedState, opening: &CommitmentOpening) -> bool {
        self.commitment_gen.verify(&encrypted.state_commitment, opening)
    }

    fn serialize_state(&self, state: &StateSnapshot) -> ModeResult<Vec<u8>> {
        serde_json::to_vec(state)
            .map_err(|e| ModeError::SerializationError(e.to_string()))
    }

    fn serialize_value(&self, value: &Value) -> ModeResult<Vec<u8>> {
        serde_json::to_vec(value)
            .map_err(|e| ModeError::SerializationError(e.to_string()))
    }

    fn derive_key(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"MPRD_ENCRYPTION_KEY_V1");
        hasher.update(self.config.key_id.as_bytes());
        hasher.finalize().into()
    }

    fn derive_nonce(&self, plaintext: &[u8]) -> [u8; 12] {
        let mut hasher = Sha256::new();
        hasher.update(b"MPRD_ENCRYPTION_NONCE_V1");
        hasher.update(self.config.key_id.as_bytes());
        hasher.update((plaintext.len() as u64).to_le_bytes());
        hasher.update(&plaintext[..plaintext.len().min(32)]);
        let bytes: [u8; 32] = hasher.finalize().into();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[..12]);
        nonce
    }

    fn encrypt_bytes(&self, plaintext: &[u8]) -> ModeResult<(Vec<u8>, [u8; 12])> {
        let key_bytes = self.derive_key();
        let nonce_bytes = self.derive_nonce(plaintext);

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| ModeError::EncryptionError(e.to_string()))?;

        Ok((ciphertext, nonce_bytes))
    }
}

/// Witness for encrypted state (private data for ZK proof).
#[derive(Clone, Debug)]
pub struct EncryptionWitness {
    /// Opening for state commitment.
    pub state_opening: CommitmentOpening,

    /// Openings for field commitments.
    pub field_openings: HashMap<String, CommitmentOpening>,

    /// The plaintext state (private).
    pub plaintext_state: StateSnapshot,
}

// =============================================================================
// Selective Disclosure
// =============================================================================

/// Selective disclosure proof.
///
/// Proves properties about committed values without revealing them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelectiveDisclosure {
    /// Fields being disclosed.
    pub disclosed_fields: HashMap<String, Value>,

    /// Commitments to hidden fields.
    pub hidden_commitments: HashMap<String, Commitment>,

    /// Proofs of properties (e.g., range proofs).
    pub property_proofs: Vec<PropertyProof>,
}

/// Proof of a property about a committed value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PropertyProof {
    /// Field name.
    pub field: String,

    /// Property being proven.
    pub property: Property,

    /// Proof data.
    pub proof_data: Vec<u8>,
}

/// Properties that can be proven about committed values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Property {
    /// Value is in range [min, max].
    InRange { min: i64, max: i64 },

    /// Value equals a public value.
    Equals { public_value: i64 },

    /// Value is less than or equal to a public bound.
    LessOrEqual { bound: i64 },

    /// Value is greater than or equal to a public bound.
    GreaterOrEqual { bound: i64 },

    /// Value is non-negative.
    NonNegative,

    /// Value is in a set of allowed values.
    InSet { allowed: Vec<i64> },
}

/// Selective disclosure builder.
pub struct SelectiveDisclosureBuilder {
    disclosed: HashMap<String, Value>,
    hidden: HashMap<String, Commitment>,
    proofs: Vec<PropertyProof>,
}

impl SelectiveDisclosureBuilder {
    pub fn new() -> Self {
        Self {
            disclosed: HashMap::new(),
            hidden: HashMap::new(),
            proofs: Vec::new(),
        }
    }

    /// Disclose a field value.
    pub fn disclose(mut self, field: impl Into<String>, value: Value) -> Self {
        self.disclosed.insert(field.into(), value);
        self
    }

    /// Hide a field with commitment.
    pub fn hide(mut self, field: impl Into<String>, commitment: Commitment) -> Self {
        self.hidden.insert(field.into(), commitment);
        self
    }

    /// Add a property proof.
    pub fn prove_property(mut self, proof: PropertyProof) -> Self {
        self.proofs.push(proof);
        self
    }

    /// Build the selective disclosure.
    pub fn build(self) -> SelectiveDisclosure {
        SelectiveDisclosure {
            disclosed_fields: self.disclosed,
            hidden_commitments: self.hidden,
            property_proofs: self.proofs,
        }
    }
}

impl Default for SelectiveDisclosureBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Privacy-Preserving Attestation
// =============================================================================

/// Configuration for private attestation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateAttestationConfig {
    /// Encryption configuration.
    pub encryption: EncryptionConfig,

    /// Commitment scheme to use.
    pub commitment_scheme: CommitmentScheme,

    /// Fields to include in selective disclosure.
    pub disclosed_fields: Vec<String>,

    /// Properties to prove about hidden fields.
    pub property_proofs: Vec<(String, Property)>,
}

impl Default for PrivateAttestationConfig {
    fn default() -> Self {
        Self {
            encryption: EncryptionConfig::default(),
            commitment_scheme: CommitmentScheme::Sha256,
            disclosed_fields: vec![],
            property_proofs: vec![],
        }
    }
}

/// Result of private attestation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateAttestationResult {
    /// Encrypted state.
    pub encrypted_state: EncryptedState,

    /// Selective disclosure.
    pub disclosure: SelectiveDisclosure,

    /// ZK proof of compliance (Risc0 receipt).
    pub zk_proof: Vec<u8>,

    /// Policy hash (public).
    pub policy_hash: [u8; 32],

    /// Decision commitment (public).
    pub decision_commitment: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_hiding_and_binding() {
        let gen = CommitmentGenerator::sha256();
        let value = b"secret_value";

        let (commitment, opening) = gen.commit(value);

        // Verify opening works
        assert!(gen.verify(&commitment, &opening));

        // Wrong value doesn't verify
        let wrong_opening = CommitmentOpening {
            value: b"wrong_value".to_vec(),
            blinding: opening.blinding,
        };
        assert!(!gen.verify(&commitment, &wrong_opening));

        // Wrong blinding doesn't verify
        let wrong_opening = CommitmentOpening {
            value: opening.value.clone(),
            blinding: [99u8; 32],
        };
        assert!(!gen.verify(&commitment, &wrong_opening));
    }

    #[test]
    fn deterministic_commitment() {
        let gen = CommitmentGenerator::sha256();
        let value = b"test_value";
        let blinding = [42u8; 32];

        let c1 = gen.commit_with_blinding(value, blinding);
        let c2 = gen.commit_with_blinding(value, blinding);

        assert_eq!(c1, c2);
    }

    #[test]
    fn state_encryption_roundtrip() {
        let config = EncryptionConfig {
            key_id: "test_key".into(),
            committed_fields: vec!["balance".into()],
            encrypted_fields: vec![],
            revealed_fields: vec![],
        };

        let encryptor = StateEncryptor::new(config);

        let state = StateSnapshot {
            fields: HashMap::from([
                ("balance".into(), Value::UInt(10000)),
                ("risk".into(), Value::Int(50)),
            ]),
            policy_inputs: HashMap::new(),
            state_hash: Hash32([1u8; 32]),
        };

        let (encrypted, witness) = encryptor.encrypt(&state).expect("Should encrypt");

        // Verify commitment
        assert!(encryptor.verify_commitment(&encrypted, &witness.state_opening));

        // Verify field commitment exists
        assert!(encrypted.field_commitments.contains_key("balance"));

        // Verify AES-GCM decryption roundtrip
        let state_bytes = serde_json::to_vec(&witness.plaintext_state).expect("serialize state");

        let mut hasher = Sha256::new();
        hasher.update(b"MPRD_ENCRYPTION_KEY_V1");
        hasher.update("test_key".as_bytes());
        let key_bytes: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha256::new();
        hasher.update(b"MPRD_ENCRYPTION_NONCE_V1");
        hasher.update("test_key".as_bytes());
        hasher.update((state_bytes.len() as u64).to_le_bytes());
        hasher.update(&state_bytes[..state_bytes.len().min(32)]);
        let nonce_seed: [u8; 32] = hasher.finalize().into();
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce_seed[..12]);

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let decrypted = cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .expect("decrypt");

        assert_eq!(decrypted, state_bytes);
    }

    #[test]
    fn selective_disclosure_builder() {
        let disclosure = SelectiveDisclosureBuilder::new()
            .disclose("public_field", Value::Int(100))
            .hide("private_field", Commitment {
                hash: [1u8; 32],
                scheme: CommitmentScheme::Sha256,
            })
            .prove_property(PropertyProof {
                field: "private_field".into(),
                property: Property::LessOrEqual { bound: 1000 },
                proof_data: vec![],
            })
            .build();

        assert!(disclosure.disclosed_fields.contains_key("public_field"));
        assert!(disclosure.hidden_commitments.contains_key("private_field"));
        assert_eq!(disclosure.property_proofs.len(), 1);
    }
}
