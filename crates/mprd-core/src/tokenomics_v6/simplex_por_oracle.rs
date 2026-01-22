//! Research utility: POR-style independence oracle for guarded simplex transfers (failure-as-noop).
//!
//! This module is NOT wired into the production v6 menu (which is currently a small lattice graph),
//! but provides a concrete, executable counterpart to the Lean artifact:
//! `proofs/lean/CEO_SimplexPOR.lean`.
//!
//! Semantics:
//! - A transfer (src→dst) is enabled iff x[src] > 0 and x[dst] < cap[dst]
//! - If enabled: x[src] -= 1; x[dst] += 1
//! - If disabled: no-op (state unchanged)
//!
//! Oracle:
//! `stable_enabled_ineq` is a closed-form sufficient condition for POR commutation:
//! it enforces the “2 units at shared source / 2 slack at shared destination” margins.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transfer {
    pub src: usize,
    pub dst: usize,
}

impl Transfer {
    pub fn new(src: usize, dst: usize) -> Self {
        Self { src, dst }
    }
}

pub fn enabled(x: &[u32], caps: &[u32], a: Transfer) -> bool {
    if a.src >= x.len() || a.dst >= x.len() || x.len() != caps.len() || a.src == a.dst {
        return false;
    }
    x[a.src] > 0 && x[a.dst] < caps[a.dst]
}

pub fn step_or_stay(x: &[u32], caps: &[u32], a: Transfer) -> Vec<u32> {
    if !enabled(x, caps, a) {
        return x.to_vec();
    }
    let mut y = x.to_vec();
    y[a.src] = y[a.src].saturating_sub(1);
    y[a.dst] = y[a.dst].saturating_add(1);
    y
}

/// Closed-form sufficient condition that implies the dynamic POR predicate:
/// enabled(a,x) ∧ enabled(b,x) ∧ enabled(b, a(x)) ∧ enabled(a, b(x)).
///
/// Intuition:
/// - If a.src == b.src, we need at least 2 units at that source so both can fire.
/// - If a.dst == b.dst, we need at least 2 slack at that destination so both can fire.
pub fn stable_enabled_ineq(x: &[u32], caps: &[u32], a: Transfer, b: Transfer) -> bool {
    if !enabled(x, caps, a) || !enabled(x, caps, b) {
        return false;
    }

    if a.src == b.src && x[a.src] < 2 {
        return false;
    }

    if a.dst == b.dst {
        // Need x[dst]+1 < cap[dst]  (i.e., cap - x >= 2)
        if x[a.dst].saturating_add(1) >= caps[a.dst] {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(x: &[u32], caps: &[u32], first: Transfer, second: Transfer) -> Vec<u32> {
        let y = step_or_stay(x, caps, first);
        step_or_stay(&y, caps, second)
    }

    #[test]
    fn shared_source_minimal_counterexample_matches_research() {
        // Witness from Morph/README: x=(1,0,0,9), a=(0->2), b=(0->3)
        let x = [1, 0, 0, 9];
        let caps = [10, 10, 10, 10];
        let a = Transfer::new(0, 2);
        let b = Transfer::new(0, 3);

        assert!(enabled(&x, &caps, a));
        assert!(enabled(&x, &caps, b));
        assert!(!stable_enabled_ineq(&x, &caps, a, b)); // fails margin: shared src needs 2

        let ab = seq(&x, &caps, a, b);
        let ba = seq(&x, &caps, b, a);
        assert_ne!(ab, ba);
        assert_eq!(ab, vec![0, 0, 1, 9]);
        assert_eq!(ba, vec![0, 0, 0, 10]);
    }

    #[test]
    fn shared_source_with_margin_commutes_under_oracle() {
        // Same actions, but src has 2 units => both orders should match.
        let x = [2, 0, 0, 8];
        let caps = [10, 10, 10, 10];
        let a = Transfer::new(0, 2);
        let b = Transfer::new(0, 3);

        assert!(stable_enabled_ineq(&x, &caps, a, b));
        let ab = seq(&x, &caps, a, b);
        let ba = seq(&x, &caps, b, a);
        assert_eq!(ab, ba);
        assert_eq!(ab, vec![0, 0, 1, 9]);
    }

    #[test]
    fn shared_destination_tight_cap_counterexample_matches_research() {
        // Witness from Morph/README: x=(1,1,0,8), caps[2]=1, a=(0->2), b=(1->2)
        let x = [1, 1, 0, 8];
        let caps = [10, 10, 1, 10];
        let a = Transfer::new(0, 2);
        let b = Transfer::new(1, 2);

        assert!(enabled(&x, &caps, a));
        assert!(enabled(&x, &caps, b));
        assert!(!stable_enabled_ineq(&x, &caps, a, b)); // fails margin: shared dst needs 2 slack

        let ab = seq(&x, &caps, a, b);
        let ba = seq(&x, &caps, b, a);
        assert_ne!(ab, ba);
        assert_eq!(ab, vec![0, 1, 1, 8]);
        assert_eq!(ba, vec![1, 0, 1, 8]);
    }
}
