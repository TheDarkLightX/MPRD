use crate::{hash, Hash32, MprdError, Result};

use super::{CanonicalPolicy, PolicyAtom, PolicyExpr, PolicyLimits};

use std::collections::{BTreeMap, BTreeSet};

pub const POLICY_ROBDD_HASH_DOMAIN_V1: &[u8] = b"MPRD_POLICY_ROBDD_V1";

/// Internal node id in a ROBDD.
///
/// `0` = False terminal, `1` = True terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BddId(u32);

impl BddId {
    pub const FALSE: BddId = BddId(0);
    pub const TRUE: BddId = BddId(1);

    pub fn is_terminal(self) -> bool {
        self.0 <= 1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct VarId(u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BddNode {
    var: VarId,
    low: BddId,
    high: BddId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Op {
    And,
    Or,
    Xor,
}

/// A reduced ordered binary decision diagram (ROBDD) over a fixed variable order.
#[derive(Clone, Debug)]
pub struct Robdd {
    vars: Vec<PolicyAtom>,
    nodes: Vec<BddNode>, // non-terminals only; node id = 2 + index
    root: BddId,
}

impl Robdd {
    pub fn vars(&self) -> &[PolicyAtom] {
        &self.vars
    }

    pub fn root(&self) -> BddId {
        self.root
    }

    fn node(&self, id: BddId) -> BddNode {
        debug_assert!(id.0 >= 2);
        self.nodes[(id.0 - 2) as usize]
    }

    pub fn eval(&self, mut f: impl FnMut(&PolicyAtom) -> bool) -> bool {
        let mut cur = self.root;
        loop {
            if cur == BddId::FALSE {
                return false;
            }
            if cur == BddId::TRUE {
                return true;
            }
            let n = self.node(cur);
            let var = &self.vars[n.var.0 as usize];
            cur = if f(var) { n.high } else { n.low };
        }
    }

    /// Structural hash of the ROBDD's boolean function (given its fixed variable order).
    ///
    /// This is stable across node id assignments and unique-table ordering.
    pub fn hash_v1(&self) -> Hash32 {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.vars.len() as u32).to_le_bytes());
        for v in &self.vars {
            let s = v.as_str().as_bytes();
            buf.push(u8::try_from(s.len()).unwrap_or(u8::MAX));
            buf.extend_from_slice(s);
        }
        let root_h = self.hash_node(self.root, &mut BTreeMap::new());
        buf.extend_from_slice(&root_h.0);
        hash::sha256_domain(POLICY_ROBDD_HASH_DOMAIN_V1, &buf)
    }

    fn hash_node(&self, id: BddId, memo: &mut BTreeMap<BddId, Hash32>) -> Hash32 {
        if let Some(h) = memo.get(&id) {
            return *h;
        }
        let h = if id == BddId::FALSE {
            hash::sha256_domain(b"MPRD_ROBDD_FALSE", &[])
        } else if id == BddId::TRUE {
            hash::sha256_domain(b"MPRD_ROBDD_TRUE", &[])
        } else {
            let n = self.node(id);
            let mut buf = Vec::with_capacity(2 + 32 + 32);
            buf.extend_from_slice(&n.var.0.to_le_bytes());
            buf.extend_from_slice(&self.hash_node(n.low, memo).0);
            buf.extend_from_slice(&self.hash_node(n.high, memo).0);
            hash::sha256_domain(b"MPRD_ROBDD_NODE", &buf)
        };
        memo.insert(id, h);
        h
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BddEquivResult {
    pub equivalent: bool,
    /// A concrete assignment (total over all vars) witnessing non-equivalence.
    pub counterexample: Option<BTreeMap<String, bool>>,
}

/// Compile a Policy Algebra expression into an allow/deny ROBDD (booleanizable subset).
///
/// Restrictions (fail-closed):
/// - `DenyIf` must not appear under `Not`.
/// - `Threshold(k, children)` is only supported for `k == 0` or `k == n`.
///
/// Semantics:
/// - All `DenyIf(atom)` become a top-level veto: `¬atom`.
/// - `DenyIf` nodes are removed from the "main" boolean formula.
pub fn compile_allow_robdd(expr: &PolicyExpr, limits: PolicyLimits) -> Result<Robdd> {
    limits.validate()?;
    let canon = CanonicalPolicy::new(expr.clone(), limits)?;
    validate_no_deny_if_under_not(canon.expr(), false)?;

    let vars: Vec<PolicyAtom> = canon.expr().atoms().into_iter().collect();
    let veto_atoms: Vec<PolicyAtom> = canon.expr().deny_if_atoms().into_iter().collect();

    let max_bdd_nodes = limits
        .max_nodes
        .saturating_mul(16)
        .max(limits.max_nodes)
        .min(1_000_000);

    let mut b = BddBuilder::new(vars.clone(), max_bdd_nodes)?;

    let main = strip_deny_if(canon.expr()).unwrap_or(PolicyExpr::True);
    let mut root = b.compile_expr(&main)?;

    for a in &veto_atoms {
        let v = b.var(a)?;
        let not_v = b.apply_not(v)?;
        root = b.apply(Op::And, root, not_v)?;
    }

    Ok(Robdd {
        vars,
        nodes: b.nodes,
        root,
    })
}

/// Check semantic equivalence of two Policy Algebra expressions (booleanizable subset).
///
/// Returns a counterexample assignment if not equivalent.
pub fn policy_equiv_robdd(a: &PolicyExpr, b: &PolicyExpr, limits: PolicyLimits) -> Result<BddEquivResult> {
    limits.validate()?;

    // Use a union variable order so missing atoms in one policy are still part of the comparison.
    let mut vars: BTreeSet<PolicyAtom> = BTreeSet::new();
    vars.extend(a.atoms());
    vars.extend(b.atoms());
    let vars: Vec<PolicyAtom> = vars.into_iter().collect();

    let max_bdd_nodes = limits
        .max_nodes
        .saturating_mul(16)
        .max(limits.max_nodes)
        .min(1_000_000);

    let ca = CanonicalPolicy::new(a.clone(), limits)?;
    let cb = CanonicalPolicy::new(b.clone(), limits)?;
    validate_no_deny_if_under_not(ca.expr(), false)?;
    validate_no_deny_if_under_not(cb.expr(), false)?;

    let mut ba = BddBuilder::new(vars.clone(), max_bdd_nodes)?;
    let ra = ba.compile_allow_from_canon(ca.expr())?;
    let robdd_a = Robdd {
        vars: vars.clone(),
        nodes: ba.nodes,
        root: ra,
    };

    let mut bb = BddBuilder::new(vars.clone(), max_bdd_nodes)?;
    let rb = bb.compile_allow_from_canon(cb.expr())?;
    let robdd_b = Robdd {
        vars: vars.clone(),
        nodes: bb.nodes,
        root: rb,
    };

    let mut bd = BddBuilder::new(vars.clone(), max_bdd_nodes)?;
    let da = bd.import(&robdd_a)?;
    let db = bd.import(&robdd_b)?;
    let diff = bd.apply(Op::Xor, da, db)?;
    let diff_robdd = Robdd {
        vars,
        nodes: bd.nodes,
        root: diff,
    };

    if diff == BddId::FALSE {
        return Ok(BddEquivResult {
            equivalent: true,
            counterexample: None,
        });
    }

    let assignment = sat_assignment(&diff_robdd).ok_or_else(|| {
        MprdError::ExecutionError(
            "ROBDD diff was non-false but no satisfying assignment found".into(),
        )
    })?;

    Ok(BddEquivResult {
        equivalent: false,
        counterexample: Some(assignment),
    })
}

fn sat_assignment(bdd: &Robdd) -> Option<BTreeMap<String, bool>> {
    fn go(bdd: &Robdd, id: BddId, out: &mut BTreeMap<u16, bool>) -> bool {
        if id == BddId::FALSE {
            return false;
        }
        if id == BddId::TRUE {
            return true;
        }
        let n = bdd.node(id);
        // Deterministic: try low/false first.
        out.insert(n.var.0, false);
        if go(bdd, n.low, out) {
            return true;
        }
        // Then high/true.
        out.insert(n.var.0, true);
        if go(bdd, n.high, out) {
            return true;
        }
        out.remove(&n.var.0);
        false
    }

    let mut partial: BTreeMap<u16, bool> = BTreeMap::new();
    if !go(bdd, bdd.root, &mut partial) {
        return None;
    }

    let mut full: BTreeMap<String, bool> = BTreeMap::new();
    for (i, a) in bdd.vars.iter().enumerate() {
        let v = partial.get(&(i as u16)).copied().unwrap_or(false);
        full.insert(a.as_str().to_string(), v);
    }
    Some(full)
}

fn strip_deny_if(expr: &PolicyExpr) -> Option<PolicyExpr> {
    match expr {
        PolicyExpr::DenyIf(_) => None,
        PolicyExpr::True => Some(PolicyExpr::True),
        PolicyExpr::False => Some(PolicyExpr::False),
        PolicyExpr::Atom(a) => Some(PolicyExpr::Atom(a.clone())),
        PolicyExpr::Not(p) => strip_deny_if(p).map(|c| PolicyExpr::Not(Box::new(c))),
        PolicyExpr::All(children) => Some(PolicyExpr::All(
            children.iter().filter_map(strip_deny_if).collect(),
        )),
        PolicyExpr::Any(children) => Some(PolicyExpr::Any(
            children.iter().filter_map(strip_deny_if).collect(),
        )),
        PolicyExpr::Threshold { k, children } => Some(PolicyExpr::Threshold {
            k: *k,
            children: children.iter().filter_map(strip_deny_if).collect(),
        }),
    }
}

fn validate_no_deny_if_under_not(expr: &PolicyExpr, under_not: bool) -> Result<()> {
    match expr {
        PolicyExpr::DenyIf(_) if under_not => Err(MprdError::InvalidInput(
            "compile_allow_robdd: DenyIf under Not is not supported".into(),
        )),
        PolicyExpr::Not(p) => validate_no_deny_if_under_not(p, true),
        PolicyExpr::All(children) | PolicyExpr::Any(children) => {
            for ch in children {
                validate_no_deny_if_under_not(ch, under_not)?;
            }
            Ok(())
        }
        PolicyExpr::Threshold { children, .. } => {
            for ch in children {
                validate_no_deny_if_under_not(ch, under_not)?;
            }
            Ok(())
        }
        PolicyExpr::True | PolicyExpr::False | PolicyExpr::Atom(_) | PolicyExpr::DenyIf(_) => {
            Ok(())
        }
    }
}

struct BddBuilder {
    vars: Vec<PolicyAtom>,
    var_index: BTreeMap<PolicyAtom, VarId>,
    nodes: Vec<BddNode>,
    unique: BTreeMap<(VarId, BddId, BddId), BddId>,
    cache_bin: BTreeMap<(Op, BddId, BddId), BddId>,
    cache_not: BTreeMap<BddId, BddId>,
    max_nodes: usize,
}

impl BddBuilder {
    fn new(vars: Vec<PolicyAtom>, max_nodes: usize) -> Result<Self> {
        if vars.len() > u16::MAX as usize {
            return Err(MprdError::InvalidInput(format!(
                "ROBDD var count too large: {} > {}",
                vars.len(),
                u16::MAX
            )));
        }
        let mut var_index: BTreeMap<PolicyAtom, VarId> = BTreeMap::new();
        for (i, a) in vars.iter().enumerate() {
            var_index.insert(a.clone(), VarId(i as u16));
        }
        Ok(Self {
            vars,
            var_index,
            nodes: Vec::new(),
            unique: BTreeMap::new(),
            cache_bin: BTreeMap::new(),
            cache_not: BTreeMap::new(),
            max_nodes,
        })
    }

    fn var(&mut self, a: &PolicyAtom) -> Result<BddId> {
        let Some(var) = self.var_index.get(a).copied() else {
            return Err(MprdError::InvalidInput(format!(
                "ROBDD: unknown atom '{}'",
                a.as_str()
            )));
        };
        self.mk(var, BddId::FALSE, BddId::TRUE)
    }

    fn mk(&mut self, var: VarId, low: BddId, high: BddId) -> Result<BddId> {
        if low == high {
            return Ok(low);
        }
        if let Some(id) = self.unique.get(&(var, low, high)).copied() {
            return Ok(id);
        }
        if self.nodes.len() >= self.max_nodes {
            return Err(MprdError::BoundedValueExceeded(format!(
                "ROBDD node budget exceeded (max_nodes={})",
                self.max_nodes
            )));
        }
        let id = BddId(2 + u32::try_from(self.nodes.len()).unwrap_or(u32::MAX));
        self.nodes.push(BddNode { var, low, high });
        self.unique.insert((var, low, high), id);
        Ok(id)
    }

    fn node(&self, id: BddId) -> BddNode {
        debug_assert!(id.0 >= 2);
        self.nodes[(id.0 - 2) as usize]
    }

    fn var_of(&self, id: BddId) -> Option<VarId> {
        if id.is_terminal() {
            None
        } else {
            Some(self.node(id).var)
        }
    }

    fn apply_not(&mut self, id: BddId) -> Result<BddId> {
        if let Some(v) = self.cache_not.get(&id).copied() {
            return Ok(v);
        }
        let out = if id == BddId::FALSE {
            BddId::TRUE
        } else if id == BddId::TRUE {
            BddId::FALSE
        } else {
            let n = self.node(id);
            let low = self.apply_not(n.low)?;
            let high = self.apply_not(n.high)?;
            self.mk(n.var, low, high)?
        };
        self.cache_not.insert(id, out);
        Ok(out)
    }

    fn apply(&mut self, op: Op, a: BddId, b: BddId) -> Result<BddId> {
        let key = if a <= b { (op, a, b) } else { (op, b, a) };
        if let Some(v) = self.cache_bin.get(&key).copied() {
            return Ok(v);
        }

        let out = match (a, b) {
            (BddId::FALSE, BddId::FALSE) => match op {
                Op::And => BddId::FALSE,
                Op::Or => BddId::FALSE,
                Op::Xor => BddId::FALSE,
            },
            (BddId::FALSE, BddId::TRUE) | (BddId::TRUE, BddId::FALSE) => match op {
                Op::And => BddId::FALSE,
                Op::Or => BddId::TRUE,
                Op::Xor => BddId::TRUE,
            },
            (BddId::TRUE, BddId::TRUE) => match op {
                Op::And => BddId::TRUE,
                Op::Or => BddId::TRUE,
                Op::Xor => BddId::FALSE,
            },
            _ => {
                let va = self.var_of(a);
                let vb = self.var_of(b);
                let v = match (va, vb) {
                    (Some(x), Some(y)) => if x <= y { x } else { y },
                    (Some(x), None) => x,
                    (None, Some(y)) => y,
                    (None, None) => unreachable!("terminals handled above"),
                };

                let (a_low, a_high) = if va == Some(v) {
                    let na = self.node(a);
                    (na.low, na.high)
                } else {
                    (a, a)
                };
                let (b_low, b_high) = if vb == Some(v) {
                    let nb = self.node(b);
                    (nb.low, nb.high)
                } else {
                    (b, b)
                };

                let low = self.apply(op, a_low, b_low)?;
                let high = self.apply(op, a_high, b_high)?;
                self.mk(v, low, high)?
            }
        };

        self.cache_bin.insert(key, out);
        Ok(out)
    }

    fn compile_expr(&mut self, expr: &PolicyExpr) -> Result<BddId> {
        match expr {
            PolicyExpr::True => Ok(BddId::TRUE),
            PolicyExpr::False => Ok(BddId::FALSE),
            PolicyExpr::Atom(a) => self.var(a),
            PolicyExpr::Not(p) => {
                let c = self.compile_expr(p)?;
                self.apply_not(c)
            }
            PolicyExpr::All(children) => {
                let mut acc = BddId::TRUE;
                for ch in children {
                    let c = self.compile_expr(ch)?;
                    acc = self.apply(Op::And, acc, c)?;
                }
                Ok(acc)
            }
            PolicyExpr::Any(children) => {
                let mut acc = BddId::FALSE;
                for ch in children {
                    let c = self.compile_expr(ch)?;
                    acc = self.apply(Op::Or, acc, c)?;
                }
                Ok(acc)
            }
            PolicyExpr::Threshold { k, children } => {
                if *k == 0 {
                    return Ok(BddId::TRUE);
                }
                let n = u16::try_from(children.len()).unwrap_or(u16::MAX);
                if *k == n {
                    let mut acc = BddId::TRUE;
                    for ch in children {
                        let c = self.compile_expr(ch)?;
                        acc = self.apply(Op::And, acc, c)?;
                    }
                    return Ok(acc);
                }
                Err(MprdError::InvalidInput(format!(
                    "ROBDD: Threshold(k={k}) not supported (n={})",
                    children.len()
                )))
            }
            PolicyExpr::DenyIf(_) => Err(MprdError::InvalidInput(
                "ROBDD: DenyIf must be stripped before boolean compilation".into(),
            )),
        }
    }

    fn compile_allow_from_canon(&mut self, canon: &PolicyExpr) -> Result<BddId> {
        let veto_atoms: Vec<PolicyAtom> = canon.deny_if_atoms().into_iter().collect();
        let main = strip_deny_if(canon).unwrap_or(PolicyExpr::True);
        let mut root = self.compile_expr(&main)?;
        for a in &veto_atoms {
            let v = self.var(a)?;
            let not_v = self.apply_not(v)?;
            root = self.apply(Op::And, root, not_v)?;
        }
        Ok(root)
    }

    fn import(&mut self, bdd: &Robdd) -> Result<BddId> {
        // Import by reconstructing under this builder's var order.
        // This keeps the equivalence checker simple and deterministic.
        if self.vars != bdd.vars {
            return Err(MprdError::InvalidInput(
                "ROBDD import requires identical variable order".into(),
            ));
        }

        fn go(dst: &mut BddBuilder, src: &Robdd, id: BddId, memo: &mut BTreeMap<BddId, BddId>) -> Result<BddId> {
            if let Some(v) = memo.get(&id).copied() {
                return Ok(v);
            }
            let out = if id == BddId::FALSE {
                BddId::FALSE
            } else if id == BddId::TRUE {
                BddId::TRUE
            } else {
                let n = src.node(id);
                let low = go(dst, src, n.low, memo)?;
                let high = go(dst, src, n.high, memo)?;
                dst.mk(n.var, low, high)?
            };
            memo.insert(id, out);
            Ok(out)
        }

        go(self, bdd, bdd.root, &mut BTreeMap::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim() -> PolicyLimits {
        PolicyLimits::DEFAULT
    }

    fn full_ctx(bdd: &Robdd, trues: &[&str]) -> BTreeMap<String, bool> {
        let mut m = BTreeMap::new();
        for a in bdd.vars() {
            m.insert(a.as_str().to_string(), false);
        }
        for t in trues {
            m.insert((*t).to_string(), true);
        }
        m
    }

    #[test]
    fn robdd_matches_policy_evaluate_for_total_assignments() {
        let limits = lim();
        let a = PolicyExpr::atom("a", limits).unwrap();
        let b = PolicyExpr::atom("b", limits).unwrap();
        let c = PolicyExpr::atom("c", limits).unwrap();
        let ban = PolicyExpr::deny_if("ban", limits).unwrap();

        // (a && (b || c)) with a veto guard `ban`.
        let expr = PolicyExpr::all(vec![a, PolicyExpr::any(vec![b, c, ban], limits).unwrap()], limits).unwrap();
        let canon = CanonicalPolicy::new(expr, limits).unwrap();

        let bdd = compile_allow_robdd(canon.expr(), limits).unwrap();
        assert!(bdd.vars().iter().any(|x| x.as_str() == "ban"));

        // Exhaustive over a,b,c,ban (2^4).
        for mask in 0u8..16 {
            let mut trues = Vec::new();
            for (i, name) in ["a", "b", "c", "ban"].iter().enumerate() {
                if (mask >> i) & 1 == 1 {
                    trues.push(*name);
                }
            }
            let ctx = full_ctx(&bdd, &trues);
            let allowed_eval = super::super::evaluate(canon.expr(), &ctx, limits).unwrap().allowed();
            let allowed_bdd = bdd.eval(|atom| ctx.get(atom.as_str()).copied().unwrap_or(false));
            assert_eq!(allowed_eval, allowed_bdd, "mask={mask} trues={trues:?}");
        }
    }

    #[test]
    fn equiv_detects_difference_and_returns_counterexample() {
        let limits = lim();
        let a = PolicyExpr::atom("a", limits).unwrap();
        let b = PolicyExpr::atom("b", limits).unwrap();

        let p1 = PolicyExpr::all(vec![a.clone(), b.clone()], limits).unwrap();
        let p2 = PolicyExpr::any(vec![a, b], limits).unwrap();

        let r = policy_equiv_robdd(&p1, &p2, limits).unwrap();
        assert!(!r.equivalent);
        let ce = r.counterexample.unwrap();
        assert!(ce.contains_key("a"));
        assert!(ce.contains_key("b"));

        let b1 = compile_allow_robdd(&p1, limits).unwrap();
        let b2 = compile_allow_robdd(&p2, limits).unwrap();

        let v1 = b1.eval(|atom| *ce.get(atom.as_str()).unwrap());
        let v2 = b2.eval(|atom| *ce.get(atom.as_str()).unwrap());
        assert_ne!(v1, v2);
    }

    #[test]
    fn deny_if_under_not_is_rejected() {
        let limits = lim();
        let ban = PolicyExpr::deny_if("ban", limits).unwrap();
        let expr = PolicyExpr::not(ban);
        let err = compile_allow_robdd(&expr, limits).unwrap_err();
        assert!(err.to_string().contains("DenyIf under Not"));
    }
}
