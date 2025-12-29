//! Policy Registry implementation.
//!
//! Maintains a mapping from `PolicyHash` to `TauSpec`, enforcing invariant S6:
//! for a given `policy_hash`, the underlying Tau spec is immutable.

use crate::{
    hash::{sha256_domain, POLICY_TAU_DOMAIN_V1},
    Hash32, MprdError, PolicyHash, Result,
};
use crate::verified_kernels::policy_registry_gate;
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
    sha256_domain(POLICY_TAU_DOMAIN_V1, content.as_bytes())
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
    inner: RwLock<RegistryInner>,
}

#[derive(Debug)]
struct RegistryInner {
    specs: HashMap<Hash32, TauSpec>,
    gate: policy_registry_gate::State,
    next_block_height: u64,
}

impl RegistryInner {
    fn new() -> Self {
        Self {
            specs: HashMap::new(),
            gate: policy_registry_gate::State::init(),
            next_block_height: 0,
        }
    }

    fn clamp_block_height(raw: u64) -> u64 {
        raw.min(10_000)
    }

    fn alloc_block_height(&mut self, spec: &TauSpec) -> u64 {
        // Prefer explicit caller-provided monotonic context if present (deterministic input).
        // Fall back to an internal monotone counter (deterministic per-process).
        if let Some(ms) = spec.metadata.registered_at {
            let v = u64::try_from(ms).unwrap_or(0);
            return Self::clamp_block_height(v);
        }
        let h = Self::clamp_block_height(self.next_block_height);
        self.next_block_height = self.next_block_height.saturating_add(1);
        h
    }
}

impl InMemoryPolicyRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(RegistryInner::new()),
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

    /// Advance the registry epoch (monotone, fail-closed when frozen).
    ///
    /// This is a governance primitive: deployments SHOULD gate it via authorization.
    pub fn advance_epoch(&self, new_epoch: u64) -> Result<()> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| MprdError::ExecutionError("Policy registry lock poisoned".into()))?;
        let (st, _) = policy_registry_gate::step(
            &inner.gate,
            policy_registry_gate::Command::AdvanceEpoch { new_epoch },
        )
        .map_err(|e| MprdError::ExecutionError(format!("policy_registry_gate rejected advance_epoch: {e}")))?;
        inner.gate = st;
        Ok(())
    }

    /// Freeze the registry (disables further updates, fail-closed).
    pub fn freeze(&self) -> Result<()> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| MprdError::ExecutionError("Policy registry lock poisoned".into()))?;
        let (st, _) =
            policy_registry_gate::step(&inner.gate, policy_registry_gate::Command::Freeze)
                .map_err(|e| MprdError::ExecutionError(format!("policy_registry_gate rejected freeze: {e}")))?;
        inner.gate = st;
        Ok(())
    }

    /// Return the current policy registry gate state (for observability/auditing).
    pub fn gate_state(&self) -> policy_registry_gate::State {
        let inner = self.inner.read().ok();
        inner.map(|g| g.gate.clone()).unwrap_or_else(policy_registry_gate::State::init)
    }
}

impl Default for InMemoryPolicyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyRegistry for InMemoryPolicyRegistry {
    fn register(&self, spec: TauSpec) -> Result<PolicyHash> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| MprdError::ExecutionError("Policy registry lock poisoned".into()))?;

        // Check for collision with different content
        if let Some(existing) = inner.specs.get(&spec.policy_hash) {
            if existing.content != spec.content {
                return Err(MprdError::PolicyHashCollision {
                    hash: spec.policy_hash,
                });
            }
            // Same content, same hash — idempotent registration
            return Ok(spec.policy_hash);
        }

        // CBC governance gate: enforce monotone, bounded update discipline.
        let block_height = inner.alloc_block_height(&spec);
        let (st, _) = policy_registry_gate::step(
            &inner.gate,
            policy_registry_gate::Command::RegisterPolicy { block_height },
        )
        .map_err(|e| MprdError::ExecutionError(format!("policy_registry_gate rejected register: {e}")))?;
        inner.gate = st;

        let hash = spec.policy_hash.clone();
        inner.specs.insert(hash.clone(), spec);
        Ok(hash)
    }

    fn get(&self, policy_hash: &PolicyHash) -> Option<TauSpec> {
        let inner = self.inner.read().ok()?;
        inner.specs.get(policy_hash).cloned()
    }

    fn contains(&self, policy_hash: &PolicyHash) -> bool {
        let inner = match self.inner.read() {
            Ok(s) => s,
            Err(_) => return false,
        };
        inner.specs.contains_key(policy_hash)
    }

    fn list(&self) -> Vec<PolicyHash> {
        let inner = match self.inner.read() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        inner.specs.keys().cloned().collect()
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
