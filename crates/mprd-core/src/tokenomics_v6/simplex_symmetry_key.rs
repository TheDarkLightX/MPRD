//! Research utility: symmetry-class canonical key for simplex states.
//!
//! Motivation:
//! - For k-way simplex planning, many buckets may be *interchangeable* (same cap, same objective weight,
//!   same semantics role). In that case we can quotient the state space by permutations within each
//!   interchangeable class.
//! - The Lean artifact proves transposition equivariance for the guarded transfer semantics; a canonical
//!   representative can be chosen by sorting values within each class deterministically.
//!
//! Safety contract (fail-closed):
//! - Only call this when you have established that the planner's semantics are invariant under
//!   permuting indices within each class (caps + objective weights + observables/gates identical).
//! - If inputs are malformed, we return `None` (do not canonicalize).

use std::collections::BTreeMap;

/// Deterministic canonical key for symmetry quotienting.
///
/// Returns a stable, comparable key as a vector of per-class sorted value-multisets.
///
/// - `x[i]` is the current bucket value
/// - `caps[i]` is the cap for bucket i
/// - `weights[i]` is the objective weight / role discriminator for bucket i (planner-chosen)
///
/// The partition key is `(caps[i], weights[i])`.
pub fn symmetry_key(x: &[u32], caps: &[u32], weights: &[u32]) -> Option<Vec<Vec<u32>>> {
    let n = x.len();
    if n == 0 || caps.len() != n || weights.len() != n {
        return None;
    }
    // Group values by (cap, weight) in a deterministic order.
    let mut groups: BTreeMap<(u32, u32), Vec<u32>> = BTreeMap::new();
    for i in 0..n {
        groups.entry((caps[i], weights[i])).or_default().push(x[i]);
    }
    // Sort within each class for a canonical multiset representation.
    let mut out: Vec<Vec<u32>> = Vec::with_capacity(groups.len());
    for (_k, mut vals) in groups {
        vals.sort_unstable();
        out.push(vals);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetry_key_rejects_bad_shapes() {
        assert!(symmetry_key(&[], &[], &[]).is_none());
        assert!(symmetry_key(&[1], &[], &[0]).is_none());
        assert!(symmetry_key(&[1], &[2], &[]).is_none());
    }

    #[test]
    fn symmetry_key_groups_and_sorts_deterministically() {
        // Two interchangeable buckets (cap=5, w=7), plus two others.
        let x = [3, 1, 9, 2];
        let caps = [5, 5, 10, 10];
        let w = [7, 7, 1, 2];

        let k1 = symmetry_key(&x, &caps, &w).unwrap();

        // Swap the two interchangeable buckets: key must be identical.
        let x2 = [1, 3, 9, 2];
        let k2 = symmetry_key(&x2, &caps, &w).unwrap();
        assert_eq!(k1, k2);

        // Changing weight breaks the class and should change key shape/content.
        let w_bad = [7, 8, 1, 2];
        let k3 = symmetry_key(&x, &caps, &w_bad).unwrap();
        assert_ne!(k1, k3);
    }
}

