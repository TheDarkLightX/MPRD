//! Justification DAG for tracking derivation proofs.

use crate::types::{FactId, JustificationHash, RuleFingerprint};
use std::collections::HashMap;

/// A single justification node in the DAG.
#[derive(Clone, Debug)]
pub struct Justification {
    /// The fact being justified.
    pub fact: FactId,
    /// Fingerprint of the rule used (or axiom marker).
    pub rule: RuleFingerprint,
    /// Dependencies (antecedent facts).
    pub deps: Vec<FactId>,
    /// Merkle hash of this justification.
    pub hash: JustificationHash,
}

impl Justification {
    /// Create a justification for a derived fact.
    pub fn derived(fact: FactId, deps: Vec<FactId>, dep_hashes: &[JustificationHash]) -> Self {
        let rule = RuleFingerprint::from_derivation(&fact, &deps);
        let hash = JustificationHash::compute(&fact, &rule, dep_hashes);
        Justification {
            fact,
            rule,
            deps,
            hash,
        }
    }

    /// Create a justification for an axiom (base fact).
    pub fn axiom(fact: FactId) -> Self {
        let rule = RuleFingerprint::axiom();
        let hash = JustificationHash::compute(&fact, &rule, &[]);
        Justification {
            fact,
            rule,
            deps: Vec::new(),
            hash,
        }
    }

    /// Check if this is an axiom.
    pub fn is_axiom(&self) -> bool {
        self.deps.is_empty()
    }
}

/// DAG of justifications for all derived facts.
#[derive(Clone, Debug, Default)]
pub struct JustificationDag {
    /// All justification nodes by hash.
    nodes: HashMap<JustificationHash, Justification>,
    /// Best (highest trust or first found) justification for each fact.
    fact_to_best: HashMap<FactId, JustificationHash>,
}

impl JustificationDag {
    /// Create an empty DAG.
    pub fn new() -> Self {
        JustificationDag::default()
    }

    /// Insert a justification node.
    pub fn insert(&mut self, just: Justification) {
        let hash = just.hash;
        let fact = just.fact;
        self.nodes.insert(hash, just);
        // First justification wins (can be replaced by best-trust later)
        self.fact_to_best.entry(fact).or_insert(hash);
    }

    /// Get justification by hash.
    pub fn get(&self, hash: &JustificationHash) -> Option<&Justification> {
        self.nodes.get(hash)
    }

    /// Get best justification for a fact.
    pub fn get_best_for_fact(&self, fact: &FactId) -> Option<&Justification> {
        self.fact_to_best.get(fact).and_then(|h| self.nodes.get(h))
    }

    /// Get all facts in the DAG.
    pub fn facts(&self) -> impl Iterator<Item = &FactId> {
        self.fact_to_best.keys()
    }

    /// Number of facts in the DAG.
    pub fn len(&self) -> usize {
        self.fact_to_best.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.fact_to_best.is_empty()
    }

    /// Get all justification nodes.
    pub fn nodes(&self) -> impl Iterator<Item = &Justification> {
        self.nodes.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_axiom_justification() {
        let fact = FactId::from_canonical("a(1)");
        let just = Justification::axiom(fact);

        assert!(just.is_axiom());
        assert_eq!(just.fact, fact);
        assert!(just.deps.is_empty());
    }

    #[test]
    fn test_derived_justification() {
        let a = FactId::from_canonical("a(1)");
        let b = FactId::from_canonical("b(1)");
        let c = FactId::from_canonical("c(1)");

        let just_a = Justification::axiom(a);
        let just_b = Justification::axiom(b);

        let just_c = Justification::derived(c, vec![a, b], &[just_a.hash, just_b.hash]);

        assert!(!just_c.is_axiom());
        assert_eq!(just_c.deps.len(), 2);
    }

    #[test]
    fn test_dag_insert_and_lookup() {
        let mut dag = JustificationDag::new();

        let a = FactId::from_canonical("a(1)");
        let just_a = Justification::axiom(a);
        dag.insert(just_a.clone());

        assert_eq!(dag.len(), 1);
        assert!(dag.get_best_for_fact(&a).is_some());
    }
}
