//! Policy Registry implementation.
//!
//! Maintains a mapping from `PolicyHash` to `TauSpec`, enforcing invariant S6:
//! for a given `policy_hash`, the underlying Tau spec is immutable.

use crate::{hash::sha256, Hash32, MprdError, PolicyHash, Result};
use std::collections::HashMap;
use std::sync::RwLock;

/// Metadata associated with a Tau specification.
#[derive(Clone, Debug, Default)]
pub struct TauSpecMetadata {
    /// Human-readable name.
    pub name: Option<String>,

    /// Version string (semantic versioning).
    pub version: Option<String>,

    /// Description of what this policy enforces.
    pub description: Option<String>,

    /// Timestamp when registered (ms since epoch).
    pub registered_at: Option<i64>,
}

/// A Tau specification with its computed hash.
#[derive(Clone, Debug)]
pub struct TauSpec {
    /// Raw Tau specification content.
    pub content: String,

    /// Computed hash of the content (canonical).
    pub policy_hash: PolicyHash,

    /// Optional metadata.
    pub metadata: TauSpecMetadata,
}

impl TauSpec {
    /// Create a new TauSpec from content.
    ///
    /// Computes the policy_hash deterministically from the content.
    pub fn new(content: impl Into<String>) -> Self {
        let content = content.into();
        let policy_hash = compute_policy_hash(&content);
        Self {
            content,
            policy_hash,
            metadata: TauSpecMetadata::default(),
        }
    }

    /// Create a new TauSpec with metadata.
    pub fn with_metadata(content: impl Into<String>, metadata: TauSpecMetadata) -> Self {
        let content = content.into();
        let policy_hash = compute_policy_hash(&content);
        Self {
            content,
            policy_hash,
            metadata,
        }
    }
}

/// Compute a canonical hash of Tau spec content.
///
/// Currently uses raw content; future versions may normalize whitespace/comments.
fn compute_policy_hash(content: &str) -> PolicyHash {
    sha256(content.as_bytes())
}

/// Trait for policy registries.
pub trait PolicyRegistry: Send + Sync {
    /// Register a new policy. Returns error if hash collision with different content.
    fn register(&self, spec: TauSpec) -> Result<PolicyHash>;

    /// Lookup a policy by hash. Returns None if not found.
    fn get(&self, policy_hash: &PolicyHash) -> Option<TauSpec>;

    /// Check if a policy exists.
    fn contains(&self, policy_hash: &PolicyHash) -> bool;

    /// List all registered policy hashes.
    fn list(&self) -> Vec<PolicyHash>;
}

/// In-memory policy registry for development and testing.
pub struct InMemoryPolicyRegistry {
    specs: RwLock<HashMap<Hash32, TauSpec>>,
}

impl InMemoryPolicyRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            specs: RwLock::new(HashMap::new()),
        }
    }

    /// Create a registry pre-populated with specs.
    pub fn with_specs(specs: Vec<TauSpec>) -> Result<Self> {
        let registry = Self::new();
        for spec in specs {
            registry.register(spec)?;
        }
        Ok(registry)
    }
}

impl Default for InMemoryPolicyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyRegistry for InMemoryPolicyRegistry {
    fn register(&self, spec: TauSpec) -> Result<PolicyHash> {
        let mut specs = self
            .specs
            .write()
            .map_err(|_| MprdError::ExecutionError("Policy registry lock poisoned".into()))?;

        // Check for collision with different content
        if let Some(existing) = specs.get(&spec.policy_hash) {
            if existing.content != spec.content {
                return Err(MprdError::PolicyHashCollision {
                    hash: spec.policy_hash,
                });
            }
            // Same content, same hash — idempotent registration
            return Ok(spec.policy_hash);
        }

        let hash = spec.policy_hash.clone();
        specs.insert(hash.clone(), spec);
        Ok(hash)
    }

    fn get(&self, policy_hash: &PolicyHash) -> Option<TauSpec> {
        let specs = self.specs.read().ok()?;
        specs.get(policy_hash).cloned()
    }

    fn contains(&self, policy_hash: &PolicyHash) -> bool {
        let specs = match self.specs.read() {
            Ok(s) => s,
            Err(_) => return false,
        };
        specs.contains_key(policy_hash)
    }

    fn list(&self) -> Vec<PolicyHash> {
        let specs = match self.specs.read() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        specs.keys().cloned().collect()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_POLICY: &str = r#"
# Simple risk threshold policy
i_risk: bv[16] = in file("inputs/risk.in").
i_max_risk: bv[16] = in file("inputs/max_risk.in").
o_allowed: sbf = out file("outputs/allowed.out").

defs
r (
    (o_allowed[t] = (i_risk[t] <= i_max_risk[t]))
)
n
q
"#;

    #[test]
    fn register_and_retrieve_policy() {
        let registry = InMemoryPolicyRegistry::new();
        let spec = TauSpec::new(SAMPLE_POLICY);
        let hash = spec.policy_hash.clone();

        let registered_hash = registry.register(spec).expect("register should succeed");
        assert_eq!(registered_hash, hash);

        let retrieved = registry.get(&hash).expect("should find policy");
        assert_eq!(retrieved.content, SAMPLE_POLICY);
    }

    #[test]
    fn idempotent_registration() {
        let registry = InMemoryPolicyRegistry::new();
        let spec1 = TauSpec::new(SAMPLE_POLICY);
        let spec2 = TauSpec::new(SAMPLE_POLICY);

        let hash1 = registry.register(spec1).expect("first register");
        let hash2 = registry.register(spec2).expect("second register");

        assert_eq!(hash1, hash2);
        assert_eq!(registry.list().len(), 1);
    }

    #[test]
    fn different_content_different_hash() {
        let registry = InMemoryPolicyRegistry::new();

        let spec1 = TauSpec::new("policy_a");
        let spec2 = TauSpec::new("policy_b");

        let hash1 = registry.register(spec1).expect("register a");
        let hash2 = registry.register(spec2).expect("register b");

        assert_ne!(hash1, hash2);
        assert_eq!(registry.list().len(), 2);
    }

    #[test]
    fn contains_check() {
        let registry = InMemoryPolicyRegistry::new();
        let spec = TauSpec::new(SAMPLE_POLICY);
        let hash = spec.policy_hash.clone();

        assert!(!registry.contains(&hash));
        registry.register(spec).unwrap();
        assert!(registry.contains(&hash));
    }
}
