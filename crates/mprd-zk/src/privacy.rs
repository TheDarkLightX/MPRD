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
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use mprd_core::{StateSnapshot, Value};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use tracing::{debug, info};
use zeroize::Zeroize;

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

    /// Generate a cryptographically random blinding factor.
    ///
    /// # Security
    ///
    /// Uses OsRng (operating system CSPRNG) which is cryptographically secure.
    /// Panics if the OS RNG is unavailable, as weak blinding breaks commitment
    /// hiding property.
    fn generate_blinding(&self) -> [u8; 32] {
        let mut blinding = [0u8; 32];
        // SECURITY: Use OsRng for cryptographically secure randomness.
        // This will panic if OS RNG is unavailable, which is the correct
        // fail-closed behavior - weak blinding breaks commitment hiding.
        OsRng.fill_bytes(&mut blinding);
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
            CommitmentScheme::Pedersen => {
                // Ristretto Pedersen commitment:
                //   C = H_value(value) * G + blinding * H
                // where H is a fixed, domain-separated generator.
                //
                // Commitment bytes are the compressed Ristretto point.
                use sha2::Sha512;

                let mut v_bytes = Vec::with_capacity(16 + value.len());
                v_bytes.extend_from_slice(b"MPRD_PEDERSEN_VALUE_V1");
                v_bytes.extend_from_slice(value);
                let v = Scalar::hash_from_bytes::<Sha512>(&v_bytes);
                let r = Scalar::from_bytes_mod_order(*blinding);

                let h_point = RistrettoPoint::hash_from_bytes::<Sha512>(b"MPRD_PEDERSEN_H_V1");
                (RISTRETTO_BASEPOINT_POINT * v + h_point * r)
                    .compress()
                    .to_bytes()
            }
            CommitmentScheme::Poseidon => {
                // Fail fast: Poseidon commitments are not implemented in this crate yet.
                // Returning a SHA-256 fallback would be misleading and could silently weaken privacy assumptions.
                panic!("Poseidon commitment scheme is not implemented")
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

    /// Revealed fields in plaintext.
    #[serde(default)]
    pub revealed_fields: HashMap<String, Value>,

    /// Encrypted state blob (AES-256-GCM).
    pub ciphertext: Vec<u8>,

    /// Encryption nonce.
    pub nonce: [u8; 12],

    /// Key ID used for encryption.
    pub key_id: String,
}

/// State encryption configuration.
///
/// # Security
///
/// The `master_key` field MUST contain actual secret key material from a secure
/// source (HSM, KMS, secure key file). The encryption key is derived from this
/// master key using HKDF, NOT from the key_id alone.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Key identifier (for key management/rotation tracking).
    pub key_id: String,

    /// Master secret key material (32 bytes). MUST be from secure source.
    /// This is NOT serialized to avoid accidental exposure.
    #[serde(skip)]
    pub master_key: Option<[u8; 32]>,

    /// Fields to commit individually (for selective disclosure).
    pub committed_fields: Vec<String>,

    /// Fields to encrypt (hidden entirely).
    pub encrypted_fields: Vec<String>,

    /// Fields to reveal in plaintext.
    pub revealed_fields: Vec<String>,
}

impl std::fmt::Debug for EncryptionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionConfig")
            .field("key_id", &self.key_id)
            .field("master_key", &"[REDACTED]")
            .field("committed_fields", &self.committed_fields)
            .field("encrypted_fields", &self.encrypted_fields)
            .field("revealed_fields", &self.revealed_fields)
            .finish()
    }
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            key_id: "default".into(),
            master_key: None, // MUST be set before use
            committed_fields: vec![],
            encrypted_fields: vec![],
            revealed_fields: vec![],
        }
    }
}

impl EncryptionConfig {
    /// Create a new config with the required master key.
    ///
    /// # Security
    ///
    /// The master_key MUST be cryptographically random, from a secure source
    /// such as HSM, KMS, or OsRng. Never use deterministic or predictable keys.
    pub fn with_master_key(key_id: impl Into<String>, master_key: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            master_key: Some(master_key),
            committed_fields: vec![],
            encrypted_fields: vec![],
            revealed_fields: vec![],
        }
    }

    /// Generate a new config with a random master key (for testing only).
    ///
    /// # Security
    ///
    /// This generates a random key using OsRng. For production, prefer
    /// loading keys from secure storage (HSM, KMS, Vault).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn generate_for_testing(key_id: impl Into<String>) -> Self {
        let mut master_key = [0u8; 32];
        OsRng.fill_bytes(&mut master_key);
        Self::with_master_key(key_id, master_key)
    }
}

/// State encryptor for Mode C.
pub struct StateEncryptor {
    config: EncryptionConfig,
    commitment_gen: CommitmentGenerator,
    nonce_source: Arc<dyn Fn() -> [u8; 12] + Send + Sync>,
}

impl StateEncryptor {
    /// Create a new encryptor with config.
    pub fn new(config: EncryptionConfig, scheme: CommitmentScheme) -> Self {
        Self {
            config,
            commitment_gen: CommitmentGenerator::new(scheme),
            nonce_source: Arc::new(|| {
                let mut nonce = [0u8; 12];
                OsRng.fill_bytes(&mut nonce);
                nonce
            }),
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    fn new_with_nonce_source(
        config: EncryptionConfig,
        scheme: CommitmentScheme,
        nonce_source: Arc<dyn Fn() -> [u8; 12] + Send + Sync>,
    ) -> Self {
        Self {
            config,
            commitment_gen: CommitmentGenerator::new(scheme),
            nonce_source,
        }
    }

    /// Encrypt a state snapshot.
    pub fn encrypt(
        &self,
        state: &StateSnapshot,
    ) -> ModeResult<(EncryptedState, EncryptionWitness)> {
        info!(key_id = %self.config.key_id, "Encrypting state");

        // Serialize state
        let state_bytes = self.serialize_state(state)?;

        // Generate state commitment
        let (state_commitment, state_opening) = self.commitment_gen.commit(&state_bytes);

        let (encrypted_fields, revealed_fields) = self.classify_fields(state)?;
        let committed_fields: BTreeSet<String> = if self.config.committed_fields.is_empty() {
            let mut committed = BTreeSet::new();
            if self.config.encrypted_fields.is_empty() && self.config.revealed_fields.is_empty() {
                committed.extend(state.fields.keys().cloned());
            } else {
                committed.extend(encrypted_fields.keys().cloned());
                committed.extend(revealed_fields.keys().cloned());
            }
            committed
        } else {
            self.config.committed_fields.iter().cloned().collect()
        };

        let mut field_commitments = HashMap::new();
        let mut field_openings = HashMap::new();

        for field_name in committed_fields {
            let value = state.fields.get(&field_name).ok_or_else(|| {
                ModeError::EncryptionError(format!(
                    "Committed field '{field_name}' not present in state"
                ))
            })?;
            let value_bytes = self.serialize_value(value)?;
            let (commitment, opening) = self.commitment_gen.commit(&value_bytes);
            field_commitments.insert(field_name.clone(), commitment);
            field_openings.insert(field_name, opening);
        }

        let encrypted_bytes = self.serialize_encrypted_payload(state, &encrypted_fields)?;
        let (ciphertext, nonce) = self.encrypt_bytes(&encrypted_bytes)?;

        let encrypted = EncryptedState {
            state_commitment,
            field_commitments,
            revealed_fields,
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
    pub fn verify_commitment(
        &self,
        encrypted: &EncryptedState,
        opening: &CommitmentOpening,
    ) -> bool {
        self.commitment_gen
            .verify(&encrypted.state_commitment, opening)
    }

    fn classify_fields(
        &self,
        state: &StateSnapshot,
    ) -> ModeResult<(BTreeMap<String, Value>, HashMap<String, Value>)> {
        let mut revealed = BTreeSet::new();
        for field_name in &self.config.revealed_fields {
            if !revealed.insert(field_name.clone()) {
                return Err(ModeError::EncryptionError(format!(
                    "Duplicate revealed field: {field_name}"
                )));
            }
            if !state.fields.contains_key(field_name) {
                return Err(ModeError::EncryptionError(format!(
                    "Revealed field '{field_name}' not present in state"
                )));
            }
        }

        let mut encrypted = BTreeSet::new();
        if self.config.encrypted_fields.is_empty() {
            for field_name in state.fields.keys() {
                if !revealed.contains(field_name) {
                    encrypted.insert(field_name.clone());
                }
            }
        } else {
            for field_name in &self.config.encrypted_fields {
                if revealed.contains(field_name) {
                    return Err(ModeError::EncryptionError(format!(
                        "Field '{field_name}' configured as both encrypted and revealed"
                    )));
                }
                if !encrypted.insert(field_name.clone()) {
                    return Err(ModeError::EncryptionError(format!(
                        "Duplicate encrypted field: {field_name}"
                    )));
                }
                if !state.fields.contains_key(field_name) {
                    return Err(ModeError::EncryptionError(format!(
                        "Encrypted field '{field_name}' not present in state"
                    )));
                }
            }

            for field_name in state.fields.keys() {
                if !encrypted.contains(field_name) && !revealed.contains(field_name) {
                    return Err(ModeError::EncryptionError(format!(
                        "Field '{field_name}' must be classified as encrypted or revealed"
                    )));
                }
            }
        }

        let mut encrypted_fields = BTreeMap::new();
        for field_name in encrypted {
            let value = state.fields.get(&field_name).ok_or_else(|| {
                ModeError::EncryptionError(format!(
                    "Encrypted field '{field_name}' not present in state"
                ))
            })?;
            encrypted_fields.insert(field_name, value.clone());
        }

        let mut revealed_fields = HashMap::new();
        for field_name in &self.config.revealed_fields {
            let value = state.fields.get(field_name).ok_or_else(|| {
                ModeError::EncryptionError(format!(
                    "Revealed field '{field_name}' not present in state"
                ))
            })?;
            revealed_fields.insert(field_name.clone(), value.clone());
        }

        Ok((encrypted_fields, revealed_fields))
    }

    fn serialize_encrypted_payload(
        &self,
        state: &StateSnapshot,
        encrypted_fields: &BTreeMap<String, Value>,
    ) -> ModeResult<Vec<u8>> {
        #[derive(Serialize)]
        struct EncryptedPayload<'a> {
            fields: &'a BTreeMap<String, Value>,
            policy_inputs: BTreeMap<&'a str, &'a Vec<u8>>,
            state_hash: &'a mprd_core::StateHash,
            state_ref: &'a mprd_core::StateRef,
        }

        let policy_inputs = state
            .policy_inputs
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect::<BTreeMap<_, _>>();

        let payload = EncryptedPayload {
            fields: encrypted_fields,
            policy_inputs,
            state_hash: &state.state_hash,
            state_ref: &state.state_ref,
        };

        serde_json::to_vec(&payload).map_err(|e| ModeError::SerializationError(e.to_string()))
    }

    fn serialize_state(&self, state: &StateSnapshot) -> ModeResult<Vec<u8>> {
        #[derive(Serialize)]
        struct CanonicalStateSnapshot<'a> {
            fields: BTreeMap<&'a str, &'a Value>,
            policy_inputs: BTreeMap<&'a str, &'a Vec<u8>>,
            state_hash: &'a mprd_core::StateHash,
            state_ref: &'a mprd_core::StateRef,
        }

        let fields = state
            .fields
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect::<BTreeMap<_, _>>();
        let policy_inputs = state
            .policy_inputs
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect::<BTreeMap<_, _>>();

        let canonical = CanonicalStateSnapshot {
            fields,
            policy_inputs,
            state_hash: &state.state_hash,
            state_ref: &state.state_ref,
        };

        serde_json::to_vec(&canonical).map_err(|e| ModeError::SerializationError(e.to_string()))
    }

    fn serialize_value(&self, value: &Value) -> ModeResult<Vec<u8>> {
        serde_json::to_vec(value).map_err(|e| ModeError::SerializationError(e.to_string()))
    }

    /// Decrypt an encrypted state back into the original snapshot.
    ///
    /// This is primarily intended for local debugging and verification workflows.
    pub fn decrypt(&self, encrypted: &EncryptedState) -> ModeResult<StateSnapshot> {
        let plaintext = self.decrypt_bytes(&encrypted.ciphertext, &encrypted.nonce)?;
        #[derive(Deserialize)]
        struct EncryptedPayload {
            fields: BTreeMap<String, Value>,
            policy_inputs: BTreeMap<String, Vec<u8>>,
            state_hash: mprd_core::StateHash,
            state_ref: mprd_core::StateRef,
        }

        let payload: EncryptedPayload =
            serde_json::from_slice(&plaintext).map_err(|e| ModeError::SerializationError(e.to_string()))?;

        let mut fields: HashMap<String, Value> = payload.fields.into_iter().collect();
        for (name, value) in &encrypted.revealed_fields {
            if fields.contains_key(name) {
                return Err(ModeError::EncryptionError(format!(
                    "Revealed field '{name}' overlaps encrypted fields"
                )));
            }
            fields.insert(name.clone(), value.clone());
        }

        Ok(StateSnapshot {
            fields,
            policy_inputs: payload.policy_inputs.into_iter().collect(),
            state_hash: payload.state_hash,
            state_ref: payload.state_ref,
        })
    }

    /// Derive encryption key using HKDF from master key.
    ///
    /// # Security
    ///
    /// Uses HKDF-SHA256 with domain separation. The derived key is bound to
    /// the key_id, preventing key confusion attacks.
    fn derive_key(&self) -> ModeResult<[u8; 32]> {
        let master_key = self.config.master_key.ok_or_else(|| {
            ModeError::EncryptionError(
                "Master key not configured. Set EncryptionConfig.master_key before encrypting."
                    .into(),
            )
        })?;

        // HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
        // Using key_id as salt for domain separation
        use hmac::{digest::KeyInit as HmacKeyInit, Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;

        let mut extract_mac =
            <HmacSha256 as HmacKeyInit>::new_from_slice(self.config.key_id.as_bytes())
                .map_err(|e| ModeError::EncryptionError(format!("HMAC init failed: {}", e)))?;
        extract_mac.update(&master_key);
        let prk = extract_mac.finalize().into_bytes();

        // HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
        let mut expand_mac = <HmacSha256 as HmacKeyInit>::new_from_slice(&prk)
            .map_err(|e| ModeError::EncryptionError(format!("HMAC init failed: {}", e)))?;
        expand_mac.update(b"MPRD_AES_KEY_V1");
        expand_mac.update(&[0x01]);
        let okm = expand_mac.finalize().into_bytes();

        let mut derived = [0u8; 32];
        derived.copy_from_slice(&okm);
        Ok(derived)
    }

    fn encrypt_bytes(&self, plaintext: &[u8]) -> ModeResult<(Vec<u8>, [u8; 12])> {
        let mut key_bytes = self.derive_key()?;
        // SECURITY: fresh nonce per encryption (default source uses OsRng)
        let nonce_bytes = (self.nonce_source)();

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| ModeError::EncryptionError(e.to_string()))?;

        // SECURITY: Zeroize key material after use
        key_bytes.zeroize();

        Ok((ciphertext, nonce_bytes))
    }

    fn decrypt_bytes(&self, ciphertext: &[u8], nonce_bytes: &[u8; 12]) -> ModeResult<Vec<u8>> {
        let mut key_bytes = self.derive_key()?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| ModeError::EncryptionError(e.to_string()))?;

        key_bytes.zeroize();
        Ok(plaintext)
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
    use mprd_core::Hash32;
    use proptest::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn counter_nonce_source() -> Arc<dyn Fn() -> [u8; 12] + Send + Sync> {
        let counter = AtomicU64::new(0);
        Arc::new(move || {
            let n = counter.fetch_add(1, Ordering::Relaxed);
            let mut out = [0u8; 12];
            out[..8].copy_from_slice(&n.to_le_bytes());
            out
        })
    }

    fn state_with(
        fields: HashMap<String, Value>,
        policy_inputs: HashMap<String, Vec<u8>>,
    ) -> StateSnapshot {
        StateSnapshot {
            fields,
            policy_inputs,
            state_hash: Hash32([1u8; 32]),
            state_ref: mprd_core::StateRef::unknown(),
        }
    }

    #[test]
    fn commitment_hiding_and_binding() {
        let gen = CommitmentGenerator::sha256();
        let value = b"secret_value";

        let blinding = [7u8; 32];
        let commitment = gen.commit_with_blinding(value, blinding);
        let opening = CommitmentOpening {
            value: value.to_vec(),
            blinding,
        };

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
    fn pedersen_commitment_roundtrips_and_is_binding() {
        let gen = CommitmentGenerator::new(CommitmentScheme::Pedersen);
        let value = b"hello";
        let blinding = [1u8; 32];

        let commitment = gen.commit_with_blinding(value, blinding);
        let opening = CommitmentOpening {
            value: value.to_vec(),
            blinding,
        };
        assert!(gen.verify(&commitment, &opening));

        let wrong_opening = CommitmentOpening {
            value: b"bye".to_vec(),
            blinding,
        };
        assert!(!gen.verify(&commitment, &wrong_opening));
    }

    #[test]
    fn state_encryption_roundtrip() {
        let master_key = [9u8; 32];

        let config = EncryptionConfig {
            key_id: "test_key".into(),
            master_key: Some(master_key),
            committed_fields: vec!["balance".into()],
            encrypted_fields: vec![],
            revealed_fields: vec![],
        };

        let encryptor = StateEncryptor::new_with_nonce_source(
            config.clone(),
            CommitmentScheme::Sha256,
            counter_nonce_source(),
        );

        let state = state_with(
            HashMap::from([
                ("balance".into(), Value::UInt(10000)),
                ("risk".into(), Value::Int(50)),
            ]),
            HashMap::new(),
        );

        let (encrypted, witness) = encryptor.encrypt(&state).expect("Should encrypt");

        // Verify commitment
        assert!(encryptor.verify_commitment(&encrypted, &witness.state_opening));

        // Verify field commitment exists
        assert!(encrypted.field_commitments.contains_key("balance"));
        let roundtrip = encryptor.decrypt(&encrypted).expect("decrypt");
        assert_eq!(roundtrip, state);
    }

    #[test]
    fn encryption_fails_without_master_key() {
        let config = EncryptionConfig::default(); // No master key
        let encryptor = StateEncryptor::new(config, CommitmentScheme::Sha256);

        let state = state_with(HashMap::new(), HashMap::new());

        let result = encryptor.encrypt(&state);
        assert!(matches!(result, Err(ModeError::EncryptionError(_))));
    }

    #[test]
    fn different_encryptions_have_different_nonces() {
        let master_key = [9u8; 32];

        let config = EncryptionConfig::with_master_key("test", master_key);
        let encryptor = StateEncryptor::new_with_nonce_source(
            config,
            CommitmentScheme::Sha256,
            counter_nonce_source(),
        );

        let state = state_with(HashMap::from([("x".into(), Value::Int(1))]), HashMap::new());

        let (enc1, _) = encryptor.encrypt(&state).unwrap();
        let (enc2, _) = encryptor.encrypt(&state).unwrap();

        // Nonces must be fresh per encryption.
        assert_ne!(enc1.nonce, enc2.nonce);
    }

    #[test]
    fn canonical_state_serialization_ignores_map_insertion_order() {
        let encryptor = StateEncryptor::new(EncryptionConfig::default(), CommitmentScheme::Sha256);

        let mut fields_a = HashMap::new();
        fields_a.insert("b".into(), Value::Int(2));
        fields_a.insert("a".into(), Value::Int(1));

        let mut fields_b = HashMap::new();
        fields_b.insert("a".into(), Value::Int(1));
        fields_b.insert("b".into(), Value::Int(2));

        let state_a = state_with(fields_a, HashMap::new());
        let state_b = state_with(fields_b, HashMap::new());

        let a = encryptor.serialize_state(&state_a).expect("serialize");
        let b = encryptor.serialize_state(&state_b).expect("serialize");
        assert_eq!(a, b);
    }

    fn value_strategy() -> impl Strategy<Value = Value> {
        prop_oneof![
            any::<bool>().prop_map(Value::Bool),
            (-1_000_000i64..=1_000_000).prop_map(Value::Int),
            (0u64..=1_000_000).prop_map(Value::UInt),
            "[-_a-zA-Z0-9]{0,32}".prop_map(Value::String),
            proptest::collection::vec(any::<u8>(), 0..64).prop_map(Value::Bytes),
        ]
    }

    proptest! {
        #[test]
        fn canonical_state_serialization_is_order_invariant(
            fields in proptest::collection::btree_map("[-_a-zA-Z0-9]{1,16}", value_strategy(), 0..16),
            policy_inputs in proptest::collection::btree_map("[-_a-zA-Z0-9]{1,16}", proptest::collection::vec(any::<u8>(), 0..64), 0..16),
        ) {
            let encryptor =
                StateEncryptor::new(EncryptionConfig::default(), CommitmentScheme::Sha256);

            let mut a_fields = HashMap::new();
            for (k, v) in fields.iter() {
                a_fields.insert(k.clone(), v.clone());
            }

            let mut b_fields = HashMap::new();
            for (k, v) in fields.iter().rev() {
                b_fields.insert(k.clone(), v.clone());
            }

            let mut a_inputs = HashMap::new();
            for (k, v) in policy_inputs.iter() {
                a_inputs.insert(k.clone(), v.clone());
            }

            let mut b_inputs = HashMap::new();
            for (k, v) in policy_inputs.iter().rev() {
                b_inputs.insert(k.clone(), v.clone());
            }

            let state_a = state_with(a_fields, a_inputs);
            let state_b = state_with(b_fields, b_inputs);

            let sa = encryptor.serialize_state(&state_a).expect("serialize");
            let sb = encryptor.serialize_state(&state_b).expect("serialize");
            prop_assert_eq!(sa, sb);
        }
    }

    #[test]
    fn selective_disclosure_builder() {
        let disclosure = SelectiveDisclosureBuilder::new()
            .disclose("public_field", Value::Int(100))
            .hide(
                "private_field",
                Commitment {
                    hash: [1u8; 32],
                    scheme: CommitmentScheme::Sha256,
                },
            )
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
