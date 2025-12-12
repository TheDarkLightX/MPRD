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

pub mod trace;
pub mod merkle;
pub mod prover;
pub mod verifier;
pub mod tracing_vm;
pub mod integration;

pub use trace::{ExecutionTrace, TraceStep};
pub use merkle::{MerkleTree, MerkleProof};
pub use prover::{MpbProver, MpbProof};
pub use verifier::{MpbVerifier, VerificationResult};
pub use integration::{
    MpbAttestor, MpbAttestorConfig, MpbProofBundle,
    MpbLocalVerifier, LocalVerificationResult, AttestationError,
};

/// 32-byte hash used throughout the proof system.
pub type Hash256 = [u8; 32];

/// Compute SHA-256 hash of arbitrary data.
pub fn sha256(data: &[u8]) -> Hash256 {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute hash of two hashes (for Merkle tree).
pub fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    sha256(&combined)
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
}
