//! Policy Algebra (CBC rail): canonical, bounded, fail-closed boolean policy core.
//!
//! This module provides a small “policy algebra” kernel intended for:
//! - canonicalization (hash-stable policies),
//! - deterministic, bounded evaluation with traces,
//! - compilation targets (e.g., Tau or other decision engines) in higher layers.
//!
//! Design posture:
//! - **Fail-closed** on missing/unknown inputs.
//! - **Deterministic** canonicalization and evaluation order.
//! - **Bounded** arity and trace sizes.

mod ast;
mod canon;
mod eval;
mod hash;
mod trace;

pub use ast::{
    PolicyAtom, PolicyExpr, PolicyKind, PolicyLimits, PolicyOutcome, PolicyOutcomeKind,
};
pub use canon::CanonicalPolicy;
pub use eval::{evaluate, EvalContext, PolicyEvalResult};
pub use hash::{policy_hash_v1, POLICY_ALGEBRA_HASH_DOMAIN_V1};
pub use trace::{PolicyTrace, TraceEntry, TraceReasonCode};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MapCtx {
        map: BTreeMap<String, bool>,
    }

    impl MapCtx {
        fn with(mut self, k: &str, v: bool) -> Self {
            self.map.insert(k.to_string(), v);
            self
        }
    }

    impl EvalContext for MapCtx {
        fn signal(&self, atom: &PolicyAtom) -> Option<bool> {
            self.map.get(atom.as_str()).copied()
        }
    }

    fn lim() -> PolicyLimits {
        PolicyLimits::DEFAULT
    }

    #[test]
    fn canonicalization_is_idempotent() {
        let limits = lim();

        // Messy: nested All/Any, duplicates, identity constants.
        let a = PolicyExpr::atom("a", limits).unwrap();
        let b = PolicyExpr::atom("b", limits).unwrap();
        let deny = PolicyExpr::deny_if("ban", limits).unwrap();
        let inner = PolicyExpr::all(vec![PolicyExpr::True, b.clone(), PolicyExpr::True], limits).unwrap();
        let expr = PolicyExpr::all(
            vec![
                PolicyExpr::True,
                a.clone(),
                PolicyExpr::all(vec![a.clone(), inner], limits).unwrap(),
                deny,
                PolicyExpr::True,
            ],
            limits,
        )
        .unwrap();

        let c1 = CanonicalPolicy::new(expr, limits).unwrap();
        let c2 = CanonicalPolicy::new(c1.expr().clone(), limits).unwrap();

        assert_eq!(c1.hash_v1(), c2.hash_v1());
        assert_eq!(c1.bytes_v1(), c2.bytes_v1());
        assert_eq!(c1.expr(), c2.expr());
    }

    #[test]
    fn commutative_children_order_does_not_change_hash() {
        let limits = lim();
        let a = PolicyExpr::atom("a", limits).unwrap();
        let b = PolicyExpr::atom("b", limits).unwrap();
        let c = PolicyExpr::atom("c", limits).unwrap();

        let p1 = CanonicalPolicy::new(PolicyExpr::any(vec![a.clone(), b.clone(), c.clone()], limits).unwrap(), limits)
            .unwrap();
        let p2 = CanonicalPolicy::new(PolicyExpr::any(vec![c, a, b], limits).unwrap(), limits).unwrap();

        assert_eq!(p1.hash_v1(), p2.hash_v1());
        assert_eq!(p1.bytes_v1(), p2.bytes_v1());
    }

    #[test]
    fn deny_if_is_absorbing_veto_even_if_otherwise_allowed() {
        let limits = lim();
        let ok = PolicyExpr::atom("ok", limits).unwrap();
        let ban = PolicyExpr::deny_if("ban", limits).unwrap();

        // If ban triggers, deny even if ok allows.
        let expr = PolicyExpr::any(vec![ok.clone(), ban], limits).unwrap();
        let canon = CanonicalPolicy::new(expr, limits).unwrap();

        let ctx = MapCtx::default().with("ok", true).with("ban", true);
        let r = evaluate(canon.expr(), &ctx, limits).unwrap();
        assert_eq!(r.outcome, PolicyOutcomeKind::DenyVeto);
        assert!(!r.allowed());

        // If ban is false, ok true allows.
        let ctx = MapCtx::default().with("ok", true).with("ban", false);
        let r = evaluate(canon.expr(), &ctx, limits).unwrap();
        assert_eq!(r.outcome, PolicyOutcomeKind::Allow);
        assert!(r.allowed());

        // Missing ban is fail-closed (veto).
        let ctx = MapCtx::default().with("ok", true);
        let r = evaluate(canon.expr(), &ctx, limits).unwrap();
        assert_eq!(r.outcome, PolicyOutcomeKind::DenyVeto);
    }

    #[test]
    fn trace_is_bounded_fail_closed() {
        let limits = PolicyLimits {
            max_children: 64,
            max_nodes: 1024,
            max_trace_nodes: 3,
            max_atom_len: 64,
        };

        let a = PolicyExpr::atom("a", limits).unwrap();
        let b = PolicyExpr::atom("b", limits).unwrap();
        let c = PolicyExpr::atom("c", limits).unwrap();
        let expr = PolicyExpr::all(vec![a, b, c], limits).unwrap();
        let canon = CanonicalPolicy::new(expr, limits).unwrap();

        // a,b,c plus the root All node will exceed max_trace_nodes=3.
        let ctx = MapCtx::default().with("a", true).with("b", true).with("c", true);
        let err = evaluate(canon.expr(), &ctx, limits).unwrap_err();
        assert!(matches!(err, crate::MprdError::BoundedValueExceeded(_)));
    }
}
