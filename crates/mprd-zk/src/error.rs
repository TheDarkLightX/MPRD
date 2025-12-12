//! Error types for MPRD deployment modes.
//!
//! Provides structured, mode-specific error types for better diagnostics
//! and error handling across all deployment modes.

use thiserror::Error;

/// Errors that can occur during mode operations.
#[derive(Debug, Error)]
pub enum ModeError {
    // =========================================================================
    // Configuration Errors
    // =========================================================================
    
    /// Invalid mode configuration.
    #[error("Invalid mode configuration: {0}")]
    InvalidConfig(String),

    /// Mode not available (missing dependencies).
    #[error("Mode {mode:?} not available: {reason}")]
    ModeNotAvailable {
        mode: String,
        reason: String,
    },

    /// Missing required configuration field.
    #[error("Missing required configuration: {field} for mode {mode:?}")]
    MissingConfig {
        mode: String,
        field: String,
    },

    // =========================================================================
    // Attestation Errors
    // =========================================================================
    
    /// Attestation failed.
    #[error("Attestation failed: {0}")]
    AttestationFailed(String),

    /// MPB execution error.
    #[error("MPB execution failed: {0}")]
    MpbExecutionError(String),

    /// Risc0 proving error.
    #[error("Risc0 proving failed: {0}")]
    Risc0ProvingError(String),

    /// Encryption error (Mode C).
    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    // =========================================================================
    // Verification Errors
    // =========================================================================
    
    /// Verification failed.
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Hash mismatch during verification.
    #[error("Hash mismatch: {field} - expected {expected}, got {actual}")]
    HashMismatch {
        field: String,
        expected: String,
        actual: String,
    },

    /// Proof integrity check failed.
    #[error("Proof integrity check failed: {0}")]
    ProofIntegrityError(String),

    /// Journal mismatch (Risc0).
    #[error("Journal mismatch: {0}")]
    JournalMismatch(String),

    // =========================================================================
    // Security Invariant Violations
    // =========================================================================
    
    /// Security invariant violated.
    #[error("Security invariant violated: {invariant} - {details}")]
    InvariantViolation {
        invariant: String,
        details: String,
    },

    /// Replay attack detected.
    #[error("Replay attack detected: token already used")]
    ReplayDetected,

    /// Tampered proof detected.
    #[error("Tampered proof detected: {0}")]
    TamperedProof(String),

    // =========================================================================
    // Serialization Errors
    // =========================================================================
    
    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error.
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
}

impl ModeError {
    /// Create a configuration error.
    pub fn config(msg: impl Into<String>) -> Self {
        Self::InvalidConfig(msg.into())
    }

    /// Create an attestation error.
    pub fn attestation(msg: impl Into<String>) -> Self {
        Self::AttestationFailed(msg.into())
    }

    /// Create a verification error.
    pub fn verification(msg: impl Into<String>) -> Self {
        Self::VerificationFailed(msg.into())
    }

    /// Create an invariant violation error.
    pub fn invariant(invariant: impl Into<String>, details: impl Into<String>) -> Self {
        Self::InvariantViolation {
            invariant: invariant.into(),
            details: details.into(),
        }
    }

    /// Create a hash mismatch error.
    pub fn hash_mismatch(field: impl Into<String>, expected: &[u8], actual: &[u8]) -> Self {
        Self::HashMismatch {
            field: field.into(),
            expected: hex::encode(&expected[..8.min(expected.len())]),
            actual: hex::encode(&actual[..8.min(actual.len())]),
        }
    }
}

/// Result type for mode operations.
pub type ModeResult<T> = std::result::Result<T, ModeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let err = ModeError::config("test error");
        assert!(err.to_string().contains("test error"));

        let err = ModeError::invariant("S1", "action not allowed");
        assert!(err.to_string().contains("S1"));
        assert!(err.to_string().contains("action not allowed"));
    }

    #[test]
    fn hash_mismatch_truncates() {
        let expected = [1u8; 32];
        let actual = [2u8; 32];
        let err = ModeError::hash_mismatch("policy_hash", &expected, &actual);
        
        // Should only show first 8 bytes
        let msg = err.to_string();
        assert!(msg.len() < 200);
    }
}
