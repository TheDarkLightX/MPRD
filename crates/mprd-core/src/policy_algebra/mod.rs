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
mod bdd;
mod canon;
mod eval;
mod hash;
mod tau_sbf_parse;
mod tau_emit;
mod trace;

pub use ast::{PolicyAtom, PolicyExpr, PolicyKind, PolicyLimits, PolicyOutcome, PolicyOutcomeKind};
pub use bdd::{
    compile_allow_robdd, policy_equiv_robdd, BddEquivResult, Robdd, POLICY_ROBDD_HASH_DOMAIN_V1,
};
pub use canon::CanonicalPolicy;
pub use eval::{evaluate, EvalContext, PolicyEvalResult};
pub use hash::{decode_policy_v1, policy_hash_v1, POLICY_ALGEBRA_HASH_DOMAIN_V1};
pub use tau_sbf_parse::{parse_emitted_tau_gate_allow_expr_v1, parse_tau_sbf_expr_v1};
pub use tau_emit::emit_tau_gate_v1;
pub use trace::{PolicyTrace, TraceEntry, TraceReasonCode};

impl EvalContext for std::collections::BTreeMap<String, bool> {
    fn signal(&self, atom: &PolicyAtom) -> Option<bool> {
        self.get(atom.as_str()).copied()
    }
}

impl EvalContext for std::collections::HashMap<String, bool> {
    fn signal(&self, atom: &PolicyAtom) -> Option<bool> {
        self.get(atom.as_str()).copied()
    }
}

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
        let inner =
            PolicyExpr::all(vec![PolicyExpr::True, b.clone(), PolicyExpr::True], limits).unwrap();
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
    fn encode_decode_roundtrip_preserves_canonical_expr() {
        let limits = lim();
        let a = PolicyExpr::atom("a", limits).unwrap();
        let b = PolicyExpr::atom("b", limits).unwrap();
        let ban = PolicyExpr::deny_if("ban", limits).unwrap();
        let expr = PolicyExpr::all(
            vec![a, PolicyExpr::any(vec![b, ban], limits).unwrap()],
            limits,
        )
        .unwrap();

        let canon = CanonicalPolicy::new(expr, limits).unwrap();
        let decoded = decode_policy_v1(canon.bytes_v1(), limits).unwrap();

        assert_eq!(canon.expr(), &decoded);
        assert_eq!(canon.hash_v1(), policy_hash_v1(&decoded));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let limits = lim();
        let expr = PolicyExpr::atom("a", limits).unwrap();
        let canon = CanonicalPolicy::new(expr, limits).unwrap();

        let mut bytes = canon.bytes_v1().to_vec();
        bytes.push(0xFF);

        let err = decode_policy_v1(&bytes, limits).unwrap_err();
        assert!(err.to_string().contains("trailing bytes"));
    }

    #[test]
    fn tau_emitter_parenthesizes_nested_or_under_and() {
        let limits = lim();
        let a = PolicyExpr::atom("a", limits).unwrap();
        let b = PolicyExpr::atom("b", limits).unwrap();
        let c = PolicyExpr::atom("c", limits).unwrap();

        let expr = PolicyExpr::all(
            vec![a, PolicyExpr::any(vec![b, c], limits).unwrap()],
            limits,
        )
        .unwrap();
        let tau = emit_tau_gate_v1(&expr, "allow", limits).unwrap();

        assert!(tau.contains("i_a[t]"));
        assert!(tau.contains("(i_b[t] | i_c[t])"));
    }

    #[test]
    fn tau_emitter_lifts_deny_if_into_veto_conj() {
        let limits = lim();
        let ok = PolicyExpr::atom("ok", limits).unwrap();
        let ban = PolicyExpr::deny_if("ban", limits).unwrap();
        let expr = PolicyExpr::any(vec![ok, ban], limits).unwrap();

        let tau = emit_tau_gate_v1(&expr, "allow", limits).unwrap();

        // Veto-first semantics should enforce `!ban` as a top-level conjunction.
        assert!(tau.contains("i_ban[t]'"));
    }

    #[test]
    fn commutative_children_order_does_not_change_hash() {
        let limits = lim();
        let a = PolicyExpr::atom("a", limits).unwrap();
        let b = PolicyExpr::atom("b", limits).unwrap();
        let c = PolicyExpr::atom("c", limits).unwrap();

        let p1 = CanonicalPolicy::new(
            PolicyExpr::any(vec![a.clone(), b.clone(), c.clone()], limits).unwrap(),
            limits,
        )
        .unwrap();
        let p2 =
            CanonicalPolicy::new(PolicyExpr::any(vec![c, a, b], limits).unwrap(), limits).unwrap();

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
        let ctx = MapCtx::default()
            .with("a", true)
            .with("b", true)
            .with("c", true);
        let err = evaluate(canon.expr(), &ctx, limits).unwrap_err();
        assert!(matches!(err, crate::MprdError::BoundedValueExceeded(_)));
    }
}
