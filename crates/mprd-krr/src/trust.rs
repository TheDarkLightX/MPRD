//! Trust propagation via semiring algebra.

use crate::dag::{Justification, JustificationDag};
use crate::types::FactId;
use crate::types::TrustScore;
use std::collections::HashMap;

/// Semiring trait for trust propagation.
///
/// Provides two operations:
/// - `combine`: Combine trust values within a derivation (⊗)
/// - `aggregate`: Combine trust values across derivations (⊕)
pub trait TrustSemiring {
    /// Identity element for combine (usually 1.0).
    fn identity() -> TrustScore;

    /// Zero element for aggregate (usually 0.0).
    fn zero() -> TrustScore;

    /// Combine trust values within a derivation chain (⊗).
    /// E.g., for a rule A ∧ B → C, combine trust(A) and trust(B).
    fn combine(&self, a: TrustScore, b: TrustScore) -> TrustScore;

    /// Aggregate trust values across multiple derivations (⊕).
    /// E.g., if C can be derived two ways, aggregate both trust values.
    fn aggregate(&self, a: TrustScore, b: TrustScore) -> TrustScore;
}

/// Minimum semiring: ⊗ = min, ⊕ = max
///
/// "Chain is as weak as its weakest link"
#[derive(Clone, Copy, Debug, Default)]
pub struct MinSemiring;

impl TrustSemiring for MinSemiring {
    fn identity() -> TrustScore {
        TrustScore::one()
    }

    fn zero() -> TrustScore {
        TrustScore::zero()
    }

    fn combine(&self, a: TrustScore, b: TrustScore) -> TrustScore {
        if a.value() < b.value() {
            a
        } else {
            b
        }
    }

    fn aggregate(&self, a: TrustScore, b: TrustScore) -> TrustScore {
        if a.value() > b.value() {
            a
        } else {
            b
        }
    }
}

/// Product semiring: ⊗ = ×, ⊕ = max
///
/// "Longer chains have lower trust"
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductSemiring;

impl TrustSemiring for ProductSemiring {
    fn identity() -> TrustScore {
        TrustScore::one()
    }

    fn zero() -> TrustScore {
        TrustScore::zero()
    }

    fn combine(&self, a: TrustScore, b: TrustScore) -> TrustScore {
        TrustScore::clamped(a.value() * b.value())
    }

    fn aggregate(&self, a: TrustScore, b: TrustScore) -> TrustScore {
        if a.value() > b.value() {
            a
        } else {
            b
        }
    }
}

/// Noisy-OR semiring: ⊗ = ×, ⊕ = 1 - (1-a)(1-b)
///
/// "Independent derivations compound evidence"
#[derive(Clone, Copy, Debug, Default)]
pub struct NoisyOrSemiring;

impl TrustSemiring for NoisyOrSemiring {
    fn identity() -> TrustScore {
        TrustScore::one()
    }

    fn zero() -> TrustScore {
        TrustScore::zero()
    }

    fn combine(&self, a: TrustScore, b: TrustScore) -> TrustScore {
        TrustScore::clamped(a.value() * b.value())
    }

    fn aggregate(&self, a: TrustScore, b: TrustScore) -> TrustScore {
        TrustScore::clamped(1.0 - (1.0 - a.value()) * (1.0 - b.value()))
    }
}

/// Propagate trust scores through a justification DAG.
///
/// # Arguments
/// * `dag` - The justification DAG
/// * `base_trust` - Trust scores for base facts (axioms)
/// * `semiring` - The trust semiring to use
///
/// # Returns
/// Trust scores for all facts in the DAG.
pub fn propagate_trust<S: TrustSemiring>(
    dag: &JustificationDag,
    base_trust: &HashMap<FactId, TrustScore>,
    semiring: &S,
) -> HashMap<FactId, TrustScore> {
    let mut trust: HashMap<FactId, TrustScore> = HashMap::new();

    // Process nodes in topological order (axioms first)
    // Since our DAG is acyclic, we can use a simple iterative approach
    let mut changed = true;
    while changed {
        changed = false;
        for just in dag.nodes() {
            let new_trust = compute_justification_trust(just, &trust, base_trust, semiring);
            let old_trust = trust.get(&just.fact).copied().unwrap_or(S::zero());
            let aggregated = semiring.aggregate(old_trust, new_trust);

            if aggregated.value() != old_trust.value() {
                trust.insert(just.fact, aggregated);
                changed = true;
            }
        }
    }

    trust
}

/// Compute trust for a single justification.
fn compute_justification_trust<S: TrustSemiring>(
    just: &Justification,
    computed: &HashMap<FactId, TrustScore>,
    base_trust: &HashMap<FactId, TrustScore>,
    semiring: &S,
) -> TrustScore {
    if just.is_axiom() {
        // For axioms, return base trust or full trust if not specified
        return base_trust
            .get(&just.fact)
            .copied()
            .unwrap_or(TrustScore::one());
    }

    // Combine trust of all dependencies
    let mut combined = S::identity();
    for dep in &just.deps {
        let dep_trust = computed
            .get(dep)
            .or_else(|| base_trust.get(dep))
            .copied()
            .unwrap_or(S::zero());
        combined = semiring.combine(combined, dep_trust);
    }

    combined
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::Justification;

    #[test]
    fn test_min_semiring() {
        let s = MinSemiring;
        let a = TrustScore::new(0.9).unwrap();
        let b = TrustScore::new(0.8).unwrap();

        assert_eq!(s.combine(a, b).value(), 0.8);
        assert_eq!(s.aggregate(a, b).value(), 0.9);
    }

    #[test]
    fn test_product_semiring() {
        let s = ProductSemiring;
        let a = TrustScore::new(0.9).unwrap();
        let b = TrustScore::new(0.8).unwrap();

        assert!((s.combine(a, b).value() - 0.72).abs() < 1e-9);
        assert_eq!(s.aggregate(a, b).value(), 0.9);
    }

    #[test]
    fn test_propagate_trust_simple() {
        let mut dag = JustificationDag::new();

        let a = FactId::from_canonical("a(1)");
        let b = FactId::from_canonical("b(1)");
        let c = FactId::from_canonical("c(1)");

        let just_a = Justification::axiom(a);
        let just_b = Justification::axiom(b);
        dag.insert(just_a.clone());
        dag.insert(just_b.clone());

        let just_c = Justification::derived(c, vec![a, b], &[just_a.hash, just_b.hash]);
        dag.insert(just_c);

        let mut base_trust = HashMap::new();
        base_trust.insert(a, TrustScore::new(0.9).unwrap());
        base_trust.insert(b, TrustScore::new(0.8).unwrap());

        // Min semiring
        let trust = propagate_trust(&dag, &base_trust, &MinSemiring);
        assert_eq!(trust.get(&c).unwrap().value(), 0.8);

        // Product semiring
        let trust = propagate_trust(&dag, &base_trust, &ProductSemiring);
        assert!((trust.get(&c).unwrap().value() - 0.72).abs() < 1e-9);
    }
}
