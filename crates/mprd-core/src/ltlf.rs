//! LTLf (Linear Temporal Logic over finite traces) — minimal, dependency-free monitor.
//!
//! Why this exists in MPRD:
//! - Many security properties are **temporal** (multi-step): "X must happen before Y", "if Z ever
//!   happens then …", etc.
//! - We want these properties **checked in public tests** without relying on private ESSO tooling.
//!
//! This module implements:
//! - A small LTLf fragment in Negation Normal Form (NNF): negation only appears on atoms.
//! - A progression-based monitor (`progress`) plus a last-step evaluator (`eval_last`),
//!   matching standard LTLf end-of-trace semantics:
//!     - `X φ` is false on the last step
//!     - `Xw φ` is true on the last step
//!     - `φ U ψ` on a single-step trace reduces to `ψ` (and similarly for `R`)
//!
//! The goal is not to be a full temporal logic ecosystem; it's to make key ordering guarantees
//! machine-checkable and hard to regress.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::collections::{HashSet, VecDeque};
use std::hash::Hash;

/// Propositional valuation at a single trace step.
///
/// We intentionally use `BTreeSet<String>` for deterministic behavior and stable debugging.
pub type Valuation = BTreeSet<String>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Formula {
    Const(bool),
    /// Atomic proposition (NNF literal). `positive=false` represents `!name`.
    Lit {
        name: String,
        positive: bool,
    },
    And(Vec<Formula>),
    Or(Vec<Formula>),
    Next(Box<Formula>),
    WeakNext(Box<Formula>),
    Until {
        left: Box<Formula>,
        right: Box<Formula>,
    },
    Release {
        left: Box<Formula>,
        right: Box<Formula>,
    },
}

impl Formula {
    pub fn t() -> Self {
        Formula::Const(true)
    }
    pub fn f() -> Self {
        Formula::Const(false)
    }
    pub fn atom(name: impl Into<String>) -> Self {
        Formula::Lit {
            name: name.into(),
            positive: true,
        }
    }
    pub fn not_atom(name: impl Into<String>) -> Self {
        Formula::Lit {
            name: name.into(),
            positive: false,
        }
    }

    pub fn and(items: impl Into<Vec<Formula>>) -> Self {
        Formula::And(items.into())
    }
    pub fn or(items: impl Into<Vec<Formula>>) -> Self {
        Formula::Or(items.into())
    }
    pub fn next(inner: Formula) -> Self {
        Formula::Next(Box::new(inner))
    }
    pub fn weak_next(inner: Formula) -> Self {
        Formula::WeakNext(Box::new(inner))
    }
    pub fn until(left: Formula, right: Formula) -> Self {
        Formula::Until {
            left: Box::new(left),
            right: Box::new(right),
        }
    }
    pub fn release(left: Formula, right: Formula) -> Self {
        Formula::Release {
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// Derived operator: `G φ` (Globally / Always).
    pub fn always(phi: Formula) -> Self {
        // In LTL, G φ ≡ (false R φ)
        Formula::release(Formula::f(), phi)
    }

    /// Derived operator: `F φ` (Eventually).
    pub fn eventually(phi: Formula) -> Self {
        // In LTL, F φ ≡ (true U φ)
        Formula::until(Formula::t(), phi)
    }

    /// "A precedes B" (safety/precedence): B is not allowed to occur before A.
    ///
    /// Equivalent to: `G(!B) ∨ ((!B) U A)`
    ///
    /// This is robust for partial traces: if B never occurs, the property holds.
    pub fn precedence(a: &str, b: &str) -> Self {
        Formula::or(vec![
            Formula::always(Formula::not_atom(b)),
            Formula::until(Formula::not_atom(b), Formula::atom(a)),
        ])
    }

    /// "If A occurs, it must occur before the first B" (optional precedence).
    ///
    /// Useful for optional stages: when A never occurs, the property is vacuously true.
    ///
    /// Equivalent to: `G(!A) ∨ ((!B) U A)`
    pub fn optional_precedence(a: &str, b: &str) -> Self {
        Formula::or(vec![
            Formula::always(Formula::not_atom(a)),
            Formula::until(Formula::not_atom(b), Formula::atom(a)),
        ])
    }
}

// Deterministic ordering (used to sort/dedup And/Or items during simplification).
impl Ord for Formula {
    fn cmp(&self, other: &Self) -> Ordering {
        use Formula::*;
        match (self, other) {
            (Const(a), Const(b)) => a.cmp(b),
            (Const(_), _) => Ordering::Less,
            (_, Const(_)) => Ordering::Greater,

            (
                Lit {
                    name: a,
                    positive: ap,
                },
                Lit {
                    name: b,
                    positive: bp,
                },
            ) => (a, ap).cmp(&(b, bp)),
            (Lit { .. }, _) => Ordering::Less,
            (_, Lit { .. }) => Ordering::Greater,

            (Next(a), Next(b)) => a.cmp(b),
            (Next(_), _) => Ordering::Less,
            (_, Next(_)) => Ordering::Greater,

            (WeakNext(a), WeakNext(b)) => a.cmp(b),
            (WeakNext(_), _) => Ordering::Less,
            (_, WeakNext(_)) => Ordering::Greater,

            (
                Until {
                    left: al,
                    right: ar,
                },
                Until {
                    left: bl,
                    right: br,
                },
            ) => (al, ar).cmp(&(bl, br)),
            (Until { .. }, _) => Ordering::Less,
            (_, Until { .. }) => Ordering::Greater,

            (
                Release {
                    left: al,
                    right: ar,
                },
                Release {
                    left: bl,
                    right: br,
                },
            ) => (al, ar).cmp(&(bl, br)),
            (Release { .. }, _) => Ordering::Less,
            (_, Release { .. }) => Ordering::Greater,

            (And(a), And(b)) => a.cmp(b),
            (And(_), _) => Ordering::Less,
            (_, And(_)) => Ordering::Greater,

            (Or(a), Or(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for Formula {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn flatten(kind_is_and: bool, items: Vec<Formula>) -> Vec<Formula> {
    let mut out = Vec::new();
    for it in items {
        match (kind_is_and, it) {
            (true, Formula::And(xs)) => out.extend(xs),
            (false, Formula::Or(xs)) => out.extend(xs),
            (_, x) => out.push(x),
        }
    }
    out
}

fn has_complementary_lits(items: &[Formula]) -> bool {
    use std::collections::HashMap;
    let mut seen: HashMap<&str, bool> = HashMap::new();
    for it in items {
        let Formula::Lit { name, positive } = it else {
            continue;
        };
        if let Some(prev) = seen.get(name.as_str()) {
            if *prev != *positive {
                return true;
            }
        } else {
            seen.insert(name.as_str(), *positive);
        }
    }
    false
}

pub fn simplify(f: Formula) -> Formula {
    use Formula::*;
    match f {
        Const(_) | Lit { .. } => f,

        Next(inner) => Next(Box::new(simplify(*inner))),
        WeakNext(inner) => WeakNext(Box::new(simplify(*inner))),

        Until { left, right } => {
            let left = simplify(*left);
            let right = simplify(*right);
            if let Const(v) = right {
                return Const(v);
            }
            if let Const(false) = left {
                return right;
            }
            if left == right {
                return left;
            }
            Until {
                left: Box::new(left),
                right: Box::new(right),
            }
        }

        Release { left, right } => {
            let left = simplify(*left);
            let right = simplify(*right);
            if let Const(v) = right {
                return Const(v);
            }
            if let Const(true) = left {
                return right;
            }
            if left == right {
                return left;
            }
            Release {
                left: Box::new(left),
                right: Box::new(right),
            }
        }

        And(items) => {
            let items = flatten(true, items.into_iter().map(simplify).collect());
            if items.iter().any(|x| matches!(x, Const(false))) {
                return Const(false);
            }
            let mut items: Vec<Formula> = items
                .into_iter()
                .filter(|x| !matches!(x, Const(true)))
                .collect();
            if has_complementary_lits(&items) {
                return Const(false);
            }
            items.sort();
            items.dedup();
            if items.is_empty() {
                return Const(true);
            }
            if items.len() == 1 {
                return items.remove(0);
            }
            And(items)
        }

        Or(items) => {
            let items = flatten(false, items.into_iter().map(simplify).collect());
            if items.iter().any(|x| matches!(x, Const(true))) {
                return Const(true);
            }
            let mut items: Vec<Formula> = items
                .into_iter()
                .filter(|x| !matches!(x, Const(false)))
                .collect();
            if has_complementary_lits(&items) {
                return Const(true);
            }
            items.sort();
            items.dedup();
            if items.is_empty() {
                return Const(false);
            }
            if items.len() == 1 {
                return items.remove(0);
            }
            Or(items)
        }
    }
}

pub fn progress(f: &Formula, valuation: &Valuation) -> Formula {
    use Formula::*;
    let f = simplify(f.clone());
    match f {
        Const(_) => f,
        Lit { name, positive } => {
            let mut holds = valuation.contains(&name);
            if !positive {
                holds = !holds;
            }
            Const(holds)
        }
        And(items) => simplify(And(items
            .into_iter()
            .map(|x| progress(&x, valuation))
            .collect())),
        Or(items) => simplify(Or(items
            .into_iter()
            .map(|x| progress(&x, valuation))
            .collect())),
        Next(inner) => simplify(*inner),
        WeakNext(inner) => simplify(*inner),
        Until { left, right } => {
            // δ(φ U ψ, σ) = δ(ψ, σ) ∨ (δ(φ, σ) ∧ (φ U ψ))
            let right_p = progress(&right, valuation);
            let left_p = progress(&left, valuation);
            simplify(Or(vec![right_p, And(vec![left_p, Until { left, right }])]))
        }
        Release { left, right } => {
            // δ(φ R ψ, σ) = δ(ψ, σ) ∧ (δ(φ, σ) ∨ (φ R ψ))
            let right_p = progress(&right, valuation);
            let left_p = progress(&left, valuation);
            simplify(And(vec![
                right_p,
                Or(vec![left_p, Release { left, right }]),
            ]))
        }
    }
}

pub fn eval_last(f: &Formula, valuation: &Valuation) -> bool {
    use Formula::*;
    let f = simplify(f.clone());
    match f {
        Const(v) => v,
        Lit { name, positive } => {
            let mut holds = valuation.contains(&name);
            if !positive {
                holds = !holds;
            }
            holds
        }
        And(items) => items.iter().all(|x| eval_last(x, valuation)),
        Or(items) => items.iter().any(|x| eval_last(x, valuation)),
        Next(_) => false,
        WeakNext(_) => true,
        Until { right, .. } => eval_last(&right, valuation),
        Release { right, .. } => eval_last(&right, valuation),
    }
}

/// Evaluate a formula on a finite trace (length >= 1).
pub fn eval_trace(f: Formula, trace: &[Valuation]) -> bool {
    if trace.is_empty() {
        return false;
    }
    let mut cur = simplify(f);
    for (i, v) in trace.iter().enumerate() {
        let is_last = i + 1 == trace.len();
        if is_last {
            return eval_last(&cur, v);
        }
        cur = progress(&cur, v);
    }
    false
}

#[derive(Clone, Debug)]
pub struct BmcViolation {
    pub trace: Vec<Valuation>,
}

/// Bounded explicit-state model checking for LTLf (finite traces).
///
/// The transition relation is provided by `step(state)`, which returns a set of possible
/// labeled transitions:
/// - `valuation`: propositional atoms observed at this step
/// - `next_state`: successor state (ignored when `is_end=true`)
/// - `is_end`: whether the trace ends after this step
///
/// Semantics:
/// - Non-final steps update the formula using `progress`.
/// - Final steps evaluate the current formula using `eval_last`.
///
/// Returns a counterexample trace (as valuations) if the formula can be violated within `max_steps`.
pub fn bmc_find_violation<S, StepFn>(
    spec: Formula,
    initial: S,
    max_steps: usize,
    step: StepFn,
) -> Option<BmcViolation>
where
    S: Clone + Eq + Hash,
    StepFn: Fn(&S) -> Vec<(Valuation, S, bool)>,
{
    #[derive(Clone)]
    struct Node<S> {
        state: S,
        formula: Formula,
        trace: Vec<Valuation>,
        steps: usize,
    }

    let spec0 = simplify(spec);
    let mut q: VecDeque<Node<S>> = VecDeque::new();
    q.push_back(Node {
        state: initial,
        formula: spec0,
        trace: Vec::new(),
        steps: 0,
    });

    let mut seen: HashSet<(S, Formula)> = HashSet::new();

    while let Some(n) = q.pop_front() {
        if n.steps >= max_steps {
            continue;
        }

        // Avoid re-exploring equivalent (state, formula) pairs.
        if !seen.insert((n.state.clone(), n.formula.clone())) {
            continue;
        }

        for (val, next_state, is_end) in step(&n.state) {
            if is_end {
                if !eval_last(&n.formula, &val) {
                    let mut t = n.trace.clone();
                    t.push(val);
                    return Some(BmcViolation { trace: t });
                }
                continue;
            }
            let next_formula = progress(&n.formula, &val);
            let mut t = n.trace.clone();
            t.push(val);
            q.push_back(Node {
                state: next_state,
                formula: next_formula,
                trace: t,
                steps: n.steps + 1,
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn v1(name: &str) -> Valuation {
        let mut v = Valuation::new();
        v.insert(name.to_string());
        v
    }

    fn sat_at(f: &Formula, trace: &[Valuation], idx: usize) -> bool {
        use Formula::*;
        debug_assert!(!trace.is_empty());
        debug_assert!(idx < trace.len());

        match f {
            Const(v) => *v,
            Lit { name, positive } => {
                let mut holds = trace[idx].contains(name);
                if !*positive {
                    holds = !holds;
                }
                holds
            }
            And(items) => items.iter().all(|x| sat_at(x, trace, idx)),
            Or(items) => items.iter().any(|x| sat_at(x, trace, idx)),
            Next(inner) => {
                if idx + 1 < trace.len() {
                    sat_at(inner, trace, idx + 1)
                } else {
                    false
                }
            }
            WeakNext(inner) => {
                if idx + 1 < trace.len() {
                    sat_at(inner, trace, idx + 1)
                } else {
                    true
                }
            }
            Until { left, right } => {
                for j in idx..trace.len() {
                    if sat_at(right, trace, j) && (idx..j).all(|k| sat_at(left, trace, k)) {
                        return true;
                    }
                }
                false
            }
            Release { left, right } => {
                // Dual of until: φ R ψ ≡ ¬(¬φ U ¬ψ)
                // Direct finite-trace semantics:
                // - either ψ holds on all remaining steps, OR
                // - there exists a j where φ holds, and ψ holds on every step up to and including j.
                if (idx..trace.len()).all(|k| sat_at(right, trace, k)) {
                    return true;
                }
                for j in idx..trace.len() {
                    if sat_at(left, trace, j) && (idx..=j).all(|k| sat_at(right, trace, k)) {
                        return true;
                    }
                }
                false
            }
        }
    }

    fn sat_trace(f: &Formula, trace: &[Valuation]) -> bool {
        if trace.is_empty() {
            return false;
        }
        sat_at(f, trace, 0)
    }

    #[test]
    fn precedence_is_vacuous_when_b_never_occurs() {
        let f = Formula::precedence("verify", "execute");
        let trace = vec![v1("state"), v1("propose")];
        assert!(eval_trace(f, &trace));
    }

    #[test]
    fn precedence_fails_when_b_occurs_before_a() {
        let f = Formula::precedence("verify", "execute");
        let trace = vec![v1("execute"), v1("verify")];
        assert!(!eval_trace(f, &trace));
    }

    #[test]
    fn optional_precedence_allows_b_without_a_when_a_never_occurs() {
        let f = Formula::optional_precedence("record", "execute");
        let trace = vec![v1("verify"), v1("execute")];
        assert!(eval_trace(f, &trace));
    }

    #[test]
    fn optional_precedence_rejects_a_after_b() {
        let f = Formula::optional_precedence("record", "execute");
        let trace = vec![v1("execute"), v1("record")];
        assert!(!eval_trace(f, &trace));
    }

    #[test]
    fn bmc_finds_simple_counterexample() {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        enum S {
            Start,
            Done,
        }

        // Spec: "a precedes b"
        let spec = Formula::precedence("a", "b");

        // Model: Start -> (emit b and end).
        let ce = bmc_find_violation(spec, S::Start, 2, |s| match s {
            S::Start => vec![(v1("b"), S::Done, true)],
            S::Done => vec![],
        })
        .expect("should find violation");
        assert_eq!(ce.trace.len(), 1);
        assert!(ce.trace[0].contains("b"));
    }

    const ATOMS: [&str; 4] = ["a", "b", "c", "d"];

    fn valuation_from_mask(mask: u8) -> Valuation {
        let mut v = Valuation::new();
        for (i, name) in ATOMS.iter().enumerate() {
            if (mask & (1u8 << i)) != 0 {
                v.insert((*name).to_string());
            }
        }
        v
    }

    fn formula_strategy() -> impl Strategy<Value = Formula> {
        let leaf = prop_oneof![
            Just(Formula::Const(true)),
            Just(Formula::Const(false)),
            (0usize..ATOMS.len(), any::<bool>()).prop_map(|(i, positive)| Formula::Lit {
                name: ATOMS[i].to_string(),
                positive,
            }),
        ];

        leaf.prop_recursive(
            6,   // max depth
            128, // max nodes
            8,   // items per collection
            |inner| {
                prop_oneof![
                    inner.clone().prop_map(|f| Formula::Next(Box::new(f))),
                    inner.clone().prop_map(|f| Formula::WeakNext(Box::new(f))),
                    (inner.clone(), inner.clone()).prop_map(|(l, r)| Formula::Until {
                        left: Box::new(l),
                        right: Box::new(r),
                    }),
                    (inner.clone(), inner.clone()).prop_map(|(l, r)| Formula::Release {
                        left: Box::new(l),
                        right: Box::new(r),
                    }),
                    prop::collection::vec(inner.clone(), 2..=4).prop_map(Formula::And),
                    prop::collection::vec(inner, 2..=4).prop_map(Formula::Or),
                ]
            },
        )
    }

    proptest! {
        #[test]
        fn prop_eval_trace_matches_direct_semantics(
            f in formula_strategy(),
            masks in prop::collection::vec(0u8..16u8, 1..=6)
        ) {
            let trace: Vec<Valuation> = masks.into_iter().map(valuation_from_mask).collect();
            let got = eval_trace(f.clone(), &trace);
            let want = sat_trace(&f, &trace);
            prop_assert_eq!(got, want);
        }
    }
}
