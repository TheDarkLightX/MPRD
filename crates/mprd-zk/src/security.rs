//! Security invariant enforcement for MPRD deployment modes.
//!
//! This module provides checks to ensure MPRD's core safety invariants
//! are maintained across all deployment modes.
//!
//! # Core Invariants
//!
//! | ID | Invariant | Description |
//! |----|-----------|-------------|
//! | S1 | Rule-obedience | Every executed action satisfies `Allowed(policy, state, action)` |
//! | S2 | Single path | All execution goes through `ExecutorAdapter` |
//! | S3 | Determinism | Same inputs → same decision |
//! | S4 | Anti-replay | No token reuse |
//! | S5 | Binding | Proof ties policy_hash + state_hash + action_hash |

use crate::error::{ModeError, ModeResult};
use mprd_core::{DecisionToken, Hash32, ProofBundle};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

/// Security invariant identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invariant {
    /// S1: Rule-obedience - every executed action is allowed by policy.
    RuleObedience,

    /// S2: Single execution path - all side effects via ExecutorAdapter.
    SinglePath,

    /// S3: Determinism - same inputs produce same decision.
    Determinism,

    /// S4: Anti-replay - no token can be used twice.
    AntiReplay,

    /// S5: Binding - proof cryptographically binds all commitments.
    Binding,
}

impl Invariant {
    /// Get the invariant identifier string.
    pub fn id(&self) -> &'static str {
        match self {
            Self::RuleObedience => "S1",
            Self::SinglePath => "S2",
            Self::Determinism => "S3",
            Self::AntiReplay => "S4",
            Self::Binding => "S5",
        }
    }

    /// Get the invariant description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::RuleObedience => "Every executed action satisfies Allowed(policy, state, action)",
            Self::SinglePath => "All execution goes through ExecutorAdapter",
            Self::Determinism => "Same inputs produce same decision",
            Self::AntiReplay => "No token can be used twice",
            Self::Binding => "Proof cryptographically binds policy_hash + state_hash + action_hash",
        }
    }
}

/// Security checker for MPRD invariants.
pub struct SecurityChecker {
    /// Whether to fail on invariant violation or just warn.
    strict_mode: bool,
}

impl SecurityChecker {
    /// Create a new security checker in strict mode.
    pub fn strict() -> Self {
        Self { strict_mode: true }
    }

    /// Create a security checker in permissive mode (warnings only).
    pub fn permissive() -> Self {
        Self { strict_mode: false }
    }

    /// Check invariant S5: Binding.
    ///
    /// Verifies that the proof bundle correctly binds the token commitments.
    pub fn check_binding(&self, token: &DecisionToken, proof: &ProofBundle) -> ModeResult<()> {
        debug!(invariant = "S5", "Checking binding invariant");

        // Check policy hash binding
        if token.policy_hash != proof.policy_hash {
            let err = ModeError::InvariantViolation {
                invariant: "S5-policy".into(),
                details: "Token policy_hash doesn't match proof policy_hash".into(),
            };
            if self.strict_mode {
                return Err(err);
            }
            warn!("{}", err);
        }

        // Check state hash binding
        if token.state_hash != proof.state_hash {
            let err = ModeError::InvariantViolation {
                invariant: "S5-state".into(),
                details: "Token state_hash doesn't match proof state_hash".into(),
            };
            if self.strict_mode {
                return Err(err);
            }
            warn!("{}", err);
        }

        // Check action hash binding
        if token.chosen_action_hash != proof.chosen_action_hash {
            let err = ModeError::InvariantViolation {
                invariant: "S5-action".into(),
                details: "Token chosen_action_hash doesn't match proof chosen_action_hash".into(),
            };
            if self.strict_mode {
                return Err(err);
            }
            warn!("{}", err);
        }

        debug!(invariant = "S5", "Binding invariant satisfied");
        Ok(())
    }

    /// Check that all hashes are non-zero (likely valid).
    pub fn check_hash_validity(&self, hash: &Hash32, name: &str) -> ModeResult<()> {
        if hash.0 == [0u8; 32] {
            let err = ModeError::InvariantViolation {
                invariant: "HASH-VALIDITY".into(),
                details: format!("{} is all zeros (likely invalid)", name),
            };
            if self.strict_mode {
                return Err(err);
            }
            warn!("{}", err);
        }
        Ok(())
    }

    /// Verify proof bundle integrity.
    pub fn verify_proof_integrity(&self, proof: &ProofBundle) -> ModeResult<()> {
        debug!("Verifying proof bundle integrity");

        // Check all hashes are valid
        self.check_hash_validity(&proof.policy_hash, "policy_hash")?;
        self.check_hash_validity(&proof.state_hash, "state_hash")?;
        self.check_hash_validity(&proof.candidate_set_hash, "candidate_set_hash")?;
        self.check_hash_validity(&proof.chosen_action_hash, "chosen_action_hash")?;

        // Verify metadata consistency
        if let Some(mode) = proof.attestation_metadata.get("mode") {
            debug!(mode = %mode, "Proof bundle mode marker present");
        }

        Ok(())
    }

    /// Compute a binding commitment for verification.
    pub fn compute_binding_commitment(
        policy_hash: &Hash32,
        state_hash: &Hash32,
        candidate_set_hash: &Hash32,
        chosen_action_hash: &Hash32,
    ) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(policy_hash.0);
        hasher.update(state_hash.0);
        hasher.update(candidate_set_hash.0);
        hasher.update(chosen_action_hash.0);
        Hash32(hasher.finalize().into())
    }
}

impl Default for SecurityChecker {
    fn default() -> Self {
        Self::strict()
    }
}

/// Validate that a decision satisfies invariant S1 (rule-obedience).
///
/// This is typically enforced by the selector, but we can double-check here.
pub fn validate_decision_allowed(
    allowed: bool,
    policy_hash: &Hash32,
    action_hash: &Hash32,
) -> ModeResult<()> {
    if !allowed {
        return Err(ModeError::InvariantViolation {
            invariant: "S1".into(),
            details: format!(
                "Action {} not allowed by policy {}",
                hex::encode(&action_hash.0[..8]),
                hex::encode(&policy_hash.0[..8])
            ),
        });
    }
    Ok(())
}

/// Validate timestamp is within acceptable bounds.
pub fn validate_timestamp(
    timestamp_ms: i64,
    max_age_ms: i64,
    max_future_ms: i64,
) -> ModeResult<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    if timestamp_ms > now + max_future_ms {
        return Err(ModeError::InvariantViolation {
            invariant: "TIMESTAMP-FUTURE".into(),
            details: format!(
                "Token timestamp {} is {} ms in the future",
                timestamp_ms,
                timestamp_ms - now
            ),
        });
    }

    if timestamp_ms < now - max_age_ms {
        return Err(ModeError::InvariantViolation {
            invariant: "TIMESTAMP-EXPIRED".into(),
            details: format!(
                "Token timestamp {} is {} ms old (max: {})",
                timestamp_ms,
                now - timestamp_ms,
                max_age_ms
            ),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    #[test]
    fn binding_check_passes_when_matching() {
        let checker = SecurityChecker::strict();

        let token = DecisionToken {
            policy_hash: dummy_hash(1),
            state_hash: dummy_hash(2),
            chosen_action_hash: dummy_hash(3),
            nonce_or_tx_hash: dummy_hash(4),
            timestamp_ms: 0,
            signature: vec![],
        };

        let proof = ProofBundle {
            policy_hash: dummy_hash(1),
            state_hash: dummy_hash(2),
            candidate_set_hash: dummy_hash(5),
            chosen_action_hash: dummy_hash(3),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };

        assert!(checker.check_binding(&token, &proof).is_ok());
    }

    #[test]
    fn binding_check_fails_when_mismatched() {
        let checker = SecurityChecker::strict();

        let token = DecisionToken {
            policy_hash: dummy_hash(1),
            state_hash: dummy_hash(2),
            chosen_action_hash: dummy_hash(3),
            nonce_or_tx_hash: dummy_hash(4),
            timestamp_ms: 0,
            signature: vec![],
        };

        let proof = ProofBundle {
            policy_hash: dummy_hash(99), // Mismatch!
            state_hash: dummy_hash(2),
            candidate_set_hash: dummy_hash(5),
            chosen_action_hash: dummy_hash(3),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };

        assert!(checker.check_binding(&token, &proof).is_err());
    }

    #[test]
    fn permissive_mode_warns_but_continues() {
        let checker = SecurityChecker::permissive();

        let token = DecisionToken {
            policy_hash: dummy_hash(1),
            state_hash: dummy_hash(2),
            chosen_action_hash: dummy_hash(3),
            nonce_or_tx_hash: dummy_hash(4),
            timestamp_ms: 0,
            signature: vec![],
        };

        let proof = ProofBundle {
            policy_hash: dummy_hash(99), // Mismatch!
            state_hash: dummy_hash(2),
            candidate_set_hash: dummy_hash(5),
            chosen_action_hash: dummy_hash(3),
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };

        // Should not error in permissive mode
        assert!(checker.check_binding(&token, &proof).is_ok());
    }

    #[test]
    fn validate_decision_allowed_rejects_denied() {
        let result = validate_decision_allowed(false, &dummy_hash(1), &dummy_hash(2));
        assert!(result.is_err());
    }

    #[test]
    fn binding_commitment_is_deterministic() {
        let c1 = SecurityChecker::compute_binding_commitment(
            &dummy_hash(1),
            &dummy_hash(2),
            &dummy_hash(3),
            &dummy_hash(4),
        );

        let c2 = SecurityChecker::compute_binding_commitment(
            &dummy_hash(1),
            &dummy_hash(2),
            &dummy_hash(3),
            &dummy_hash(4),
        );

        assert_eq!(c1, c2);

        // Different inputs -> different commitment
        let c3 = SecurityChecker::compute_binding_commitment(
            &dummy_hash(1),
            &dummy_hash(2),
            &dummy_hash(3),
            &dummy_hash(5), // Different
        );

        assert_ne!(c1, c3);
    }
}
