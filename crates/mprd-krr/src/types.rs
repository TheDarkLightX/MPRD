//! Core types for KRR Layer 2
//!
//! All types are content-addressed and implement CBC principles:
//! invalid states are unrepresentable.

use sha2::{Digest, Sha256};
use std::fmt;

/// Content-addressed fact identifier.
/// Computed as H("krr.fact.v1" || canonical_fact_bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FactId(pub [u8; 32]);

impl FactId {
    /// Create a FactId from canonical fact representation.
    pub fn from_canonical(fact: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"krr.fact.v1");
        hasher.update(fact.as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        FactId(bytes)
    }

    /// Get hex representation.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for FactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FactId({}...)", &self.to_hex()[..8])
    }
}

impl fmt::Display for FactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_hex()[..16])
    }
}

/// Rule fingerprint for synthetic rule identification.
/// Computed as H("krr.rule.v1" || conclusion_id || sorted_dep_ids)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuleFingerprint(pub [u8; 32]);

impl RuleFingerprint {
    /// Create fingerprint from conclusion and dependencies.
    pub fn from_derivation(conclusion: &FactId, deps: &[FactId]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"krr.rule.v1");
        hasher.update(conclusion.0);

        // Sort deps for determinism
        let mut sorted_deps: Vec<_> = deps.iter().collect();
        sorted_deps.sort_by_key(|d| d.0);
        for dep in sorted_deps {
            hasher.update(dep.0);
        }

        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        RuleFingerprint(bytes)
    }

    /// Special fingerprint for axioms (base facts).
    pub fn axiom() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"krr.rule.axiom.v1");
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        RuleFingerprint(bytes)
    }
}

impl fmt::Debug for RuleFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rule({}...)", &hex::encode(&self.0[..4]))
    }
}

/// Merkle hash for justification nodes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct JustificationHash(pub [u8; 32]);

impl JustificationHash {
    /// Compute Merkle hash for a justification node.
    pub fn compute(fact: &FactId, rule: &RuleFingerprint, deps: &[JustificationHash]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"krr.just.v1");
        hasher.update(fact.0);
        hasher.update(rule.0);

        // Sort deps for determinism
        let mut sorted_deps: Vec<_> = deps.iter().collect();
        sorted_deps.sort_by_key(|d| d.0);
        for dep in sorted_deps {
            hasher.update(dep.0);
        }

        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        JustificationHash(bytes)
    }
}

impl fmt::Debug for JustificationHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Just({}...)", &hex::encode(&self.0[..4]))
    }
}

/// Trust score in [0.0, 1.0].
/// Enforces valid range at construction time.
#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub struct TrustScore(f64);

impl TrustScore {
    /// Create a trust score, returns None if out of range.
    pub fn new(score: f64) -> Option<Self> {
        if score >= 0.0 && score <= 1.0 {
            Some(TrustScore(score))
        } else {
            None
        }
    }

    /// Create with clamping to valid range.
    pub fn clamped(score: f64) -> Self {
        TrustScore(score.clamp(0.0, 1.0))
    }

    /// Full trust.
    pub fn one() -> Self {
        TrustScore(1.0)
    }

    /// Zero trust.
    pub fn zero() -> Self {
        TrustScore(0.0)
    }

    /// Get the inner value.
    pub fn value(&self) -> f64 {
        self.0
    }
}

impl fmt::Debug for TrustScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Trust({:.3})", self.0)
    }
}

impl fmt::Display for TrustScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.3}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fact_id_deterministic() {
        let id1 = FactId::from_canonical("a(1)");
        let id2 = FactId::from_canonical("a(1)");
        let id3 = FactId::from_canonical("a(2)");

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_trust_score_bounds() {
        assert!(TrustScore::new(0.5).is_some());
        assert!(TrustScore::new(0.0).is_some());
        assert!(TrustScore::new(1.0).is_some());
        assert!(TrustScore::new(-0.1).is_none());
        assert!(TrustScore::new(1.1).is_none());
    }

    #[test]
    fn test_rule_fingerprint_sorted() {
        let conclusion = FactId::from_canonical("c");
        let dep1 = FactId::from_canonical("a");
        let dep2 = FactId::from_canonical("b");

        // Order shouldn't matter
        let fp1 = RuleFingerprint::from_derivation(&conclusion, &[dep1, dep2]);
        let fp2 = RuleFingerprint::from_derivation(&conclusion, &[dep2, dep1]);

        assert_eq!(fp1, fp2);
    }
}
