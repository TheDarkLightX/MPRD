//! MPB Custom Proof System
//!
//! **⚠️ EXPERIMENTAL - INTERNAL USE ONLY ⚠️**
//!
//! This proof system is designed for high-frequency internal policy checks.
//! It provides computational security (SHA-256) rather than cryptographic
//! zero-knowledge proofs.
//!
//! **DO NOT USE FOR:**
//! - On-chain verification
//! - Trustless external audits
//! - Regulatory compliance requiring cryptographic proofs
//!
//! **USE INSTEAD:** Risc0 zkVM for production trustless verification.
//!
//! ---
//!
//! A specialized proof system for MPRD Policy Bytecode execution.
//! Optimized for MPB's limited opcode set and bounded execution model.
//!
//! # Security Model
//!
//! This system provides **computational soundness**: a malicious prover cannot
//! convince a verifier of a false statement without breaking SHA-256.
//!
//! # Privacy Model
//!
//! - Public: bytecode_hash, input_hash, output
//! - Private: bytecode content, input values, execution trace
//!
//! # Efficiency
//!
//! - Proving: O(n) where n = execution steps
//! - Verification: O(log n) for random spot checks
//! - Proof size: O(log n) Merkle paths

mod challenges;
pub mod integration;
pub mod merkle;
pub mod prover;
pub mod trace;
pub mod tracing_vm;
pub mod verifier;

pub use integration::{
    AttestationError, LocalVerificationResult, MpbAttestor, MpbAttestorConfig, MpbLocalVerifier,
    MpbProofBundle,
};
pub use merkle::{MerkleProof, MerkleTree};
pub use prover::{MpbProof, MpbProver};
pub use trace::{ExecutionTrace, TraceStep};
pub use verifier::{MpbVerifier, VerificationResult};

/// 32-byte hash used throughout the proof system.
pub type Hash256 = [u8; 32];

/// Compute SHA-256 hash of arbitrary data.
pub fn sha256(data: &[u8]) -> Hash256 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Domain separation prefix for leaf nodes in Merkle tree.
/// Prevents second preimage attacks by distinguishing leaves from internal nodes.
pub const MERKLE_LEAF_PREFIX: u8 = 0x00;

/// Domain separation prefix for internal nodes in Merkle tree.
pub const MERKLE_INTERNAL_PREFIX: u8 = 0x01;

/// Compute hash of a leaf value with domain separation.
///
/// # Security
///
/// Uses prefix 0x00 to distinguish leaf hashes from internal node hashes,
/// preventing second preimage attacks where an attacker crafts an internal
/// node that collides with a valid leaf.
pub fn hash_leaf(data: &[u8]) -> Hash256 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update([MERKLE_LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute hash of two child hashes (for internal Merkle tree nodes).
///
/// # Security
///
/// Uses prefix 0x01 to distinguish internal node hashes from leaf hashes,
/// preventing second preimage attacks.
pub fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update([MERKLE_INTERNAL_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_deterministic() {
        let data = b"test data";
        let hash1 = sha256(data);
        let hash2 = sha256(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hash_pair_deterministic() {
        let a = sha256(b"a");
        let b = sha256(b"b");
        let h1 = hash_pair(&a, &b);
        let h2 = hash_pair(&a, &b);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_pair_order_matters() {
        let a = sha256(b"a");
        let b = sha256(b"b");
        let h1 = hash_pair(&a, &b);
        let h2 = hash_pair(&b, &a);
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_leaf_uses_domain_separation() {
        let data = b"test leaf";
        let leaf_hash = hash_leaf(data);
        let raw_hash = sha256(data);
        // Leaf hash should differ from raw hash due to domain prefix
        assert_ne!(leaf_hash, raw_hash);
    }

    #[test]
    fn hash_pair_uses_domain_separation() {
        let a = [1u8; 32];
        let b = [2u8; 32];

        // hash_pair with domain separation
        let pair_hash = hash_pair(&a, &b);

        // Raw concatenation without prefix
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&a);
        combined[32..].copy_from_slice(&b);
        let raw_hash = sha256(&combined);

        // Should differ due to domain prefix
        assert_ne!(pair_hash, raw_hash);
    }

    #[test]
    fn leaf_and_internal_hashes_differ() {
        // Even if the "data" happens to be two concatenated hashes,
        // a leaf hash should not equal an internal node hash
        let a = [1u8; 32];
        let b = [2u8; 32];

        let mut data = [0u8; 64];
        data[..32].copy_from_slice(&a);
        data[32..].copy_from_slice(&b);

        let leaf_hash = hash_leaf(&data);
        let internal_hash = hash_pair(&a, &b);

        // These MUST differ to prevent second preimage attacks
        assert_ne!(leaf_hash, internal_hash);
    }
}
