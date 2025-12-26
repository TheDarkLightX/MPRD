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
    /// A concrete assignment (total over all *signals*) witnessing non-equivalence.
    ///
    /// `None` means the signal is missing (fail-closed).
    pub counterexample: Option<BTreeMap<String, Option<bool>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DenyIfValue {
    True,
    False,
}

fn bit_present_name(a: &PolicyAtom, limits: PolicyLimits) -> Result<PolicyAtom> {
    PolicyAtom::new(format!("p_{}", a.as_str()), limits)
}

fn bit_value_name(a: &PolicyAtom, limits: PolicyLimits) -> Result<PolicyAtom> {
    PolicyAtom::new(format!("v_{}", a.as_str()), limits)
}

fn bit_var_order(signals: &BTreeSet<PolicyAtom>, limits: PolicyLimits) -> Result<Vec<PolicyAtom>> {
    let mut vars = Vec::with_capacity(signals.len().saturating_mul(2));
    for a in signals {
        vars.push(bit_present_name(a, limits)?);
        vars.push(bit_value_name(a, limits)?);
    }
    Ok(vars)
}

/// Lower a canonical Policy Algebra expression to a pure boolean expression over *presence bits*.
///
/// Each signal `a` becomes two boolean atoms:
/// - `p_a` : present bit (1 if present)
/// - `v_a` : value bit (1 if true; required to be 0 when `p_a` is 0)
///
/// The lowered expression is true iff `evaluate(expr, ctx)` returns `Allow` under the
/// veto-first, fail-closed semantics.
fn lower_to_presence_bits(expr: &PolicyExpr, limits: PolicyLimits) -> Result<PolicyExpr> {
    fn lower_main(
        expr: &PolicyExpr,
        deny_if_value: DenyIfValue,
        limits: PolicyLimits,
    ) -> Result<PolicyExpr> {
        Ok(match expr {
            PolicyExpr::True => PolicyExpr::True,
            PolicyExpr::False => PolicyExpr::False,
            PolicyExpr::Atom(a) => {
                // Allow iff present && value.
                let p = PolicyExpr::Atom(bit_present_name(a, limits)?);
                let v = PolicyExpr::Atom(bit_value_name(a, limits)?);
                PolicyExpr::all(vec![p, v], limits)?
            }
            PolicyExpr::DenyIf(_) => match deny_if_value {
                DenyIfValue::True => PolicyExpr::True,
                DenyIfValue::False => PolicyExpr::False,
            },
            PolicyExpr::Not(p) => {
                // `DenyIf` under `Not` is rejected by outer validation. Still, force False
                // semantics if it were present.
                PolicyExpr::not(lower_main(p, DenyIfValue::False, limits)?)
            }
            PolicyExpr::All(children) => {
                let mut out = Vec::with_capacity(children.len());
                for ch in children {
                    out.push(lower_main(ch, DenyIfValue::True, limits)?);
                }
                PolicyExpr::all(out, limits)?
            }
            PolicyExpr::Any(children) => {
                let mut out = Vec::with_capacity(children.len());
                for ch in children {
                    out.push(lower_main(ch, DenyIfValue::False, limits)?);
                }
                PolicyExpr::any(out, limits)?
            }
            PolicyExpr::Threshold { k, children } => {
                if *k == 0 {
                    PolicyExpr::True
                } else {
                    let n = u16::try_from(children.len()).unwrap_or(u16::MAX);
                    if *k == n {
                        let mut out = Vec::with_capacity(children.len());
                        for ch in children {
                            out.push(lower_main(ch, DenyIfValue::False, limits)?);
                        }
                        PolicyExpr::all(out, limits)?
                    } else {
                        return Err(MprdError::InvalidInput(format!(
                            "lower_to_presence_bits: Threshold(k={k}) not supported (n={})",
                            children.len()
                        )));
                    }
                }
            }
        })
    }

    // Main formula (DenyIf treated as neutral, modeled context-sensitively).
    let main = lower_main(expr, DenyIfValue::False, limits)?;

    // Veto constraints: for every DenyIf atom `a`, require `p_a && !v_a` (missing vetoes).
    let veto_atoms: Vec<PolicyAtom> = expr.deny_if_atoms().into_iter().collect();
    if veto_atoms.is_empty() {
        return Ok(main);
    }

    let mut conj = Vec::new();
    conj.push(main);
    for a in veto_atoms {
        let p = PolicyExpr::Atom(bit_present_name(&a, limits)?);
        let v = PolicyExpr::Atom(bit_value_name(&a, limits)?);
        let ok = PolicyExpr::all(vec![p, PolicyExpr::not(v)], limits)?;
        conj.push(ok);
    }

    // If we ever exceed max_children, build nested conjunctions deterministically.
    fn nested_all(mut parts: Vec<PolicyExpr>, limits: PolicyLimits) -> Result<PolicyExpr> {
        if parts.len() <= limits.max_children {
            return PolicyExpr::all(parts, limits);
        }
        // Chunk into groups of max_children and fold.
        let mut acc: Vec<PolicyExpr> = Vec::new();
        while !parts.is_empty() {
            let take = parts.len().min(limits.max_children);
            let chunk = parts.drain(0..take).collect::<Vec<_>>();
            acc.push(PolicyExpr::all(chunk, limits)?);
        }
        nested_all(acc, limits)
    }

    nested_all(conj, limits)
}

fn tristate_counterexample_from_bits(
    signals: &BTreeSet<PolicyAtom>,
    bits: &BTreeMap<String, bool>,
    limits: PolicyLimits,
) -> Result<BTreeMap<String, Option<bool>>> {
    let mut out: BTreeMap<String, Option<bool>> = BTreeMap::new();
    for a in signals {
        let p = bit_present_name(a, limits)?;
        let v = bit_value_name(a, limits)?;
        let present = bits.get(p.as_str()).copied().unwrap_or(false);
        let value = bits.get(v.as_str()).copied().unwrap_or(false);
        let tri = if present { Some(value) } else { None };
        out.insert(a.as_str().to_string(), tri);
    }
    Ok(out)
}

/// Compile a Policy Algebra expression into an allow/deny ROBDD (booleanizable subset),
/// modeling **missing signals** explicitly via presence bits.
///
/// Restrictions (fail-closed):
/// - `DenyIf` must not appear under `Not`.
/// - `Threshold(k, children)` is only supported for `k == 0` or `k == n`.
///
/// Semantics:
/// - Each signal `a` is modeled as `(p_a, v_a)` where `p_a` is presence, `v_a` is value.
/// - `Atom(a)` compiles to `p_a ∧ v_a` (missing => deny).
/// - Each `DenyIf(a)` adds a veto constraint `p_a ∧ ¬v_a` (missing => veto deny).
pub fn compile_allow_robdd(expr: &PolicyExpr, limits: PolicyLimits) -> Result<Robdd> {
    limits.validate()?;
    let canon = CanonicalPolicy::new(expr.clone(), limits)?;
    validate_no_deny_if_under_not(canon.expr(), false)?;

    let signals: BTreeSet<PolicyAtom> = canon.expr().atoms();
    let vars: Vec<PolicyAtom> = bit_var_order(&signals, limits)?;

    let max_bdd_nodes = limits
        .max_nodes
        .saturating_mul(16)
        .max(limits.max_nodes)
        .min(1_000_000);

    let lowered = lower_to_presence_bits(canon.expr(), limits)?;

    let mut b = BddBuilder::new(vars.clone(), max_bdd_nodes)?;
    let root = b.compile_expr(&lowered)?;
    Ok(Robdd {
        vars,
        nodes: b.nodes,
        root,
    })
}

/// Check semantic equivalence of two Policy Algebra expressions (booleanizable subset).
///
/// Returns a counterexample assignment if not equivalent.
pub fn policy_equiv_robdd(
    a: &PolicyExpr,
    b: &PolicyExpr,
    limits: PolicyLimits,
) -> Result<BddEquivResult> {
    limits.validate()?;

    // Union signal set, then derive a stable bit variable order.
    let mut signals: BTreeSet<PolicyAtom> = BTreeSet::new();
    signals.extend(a.atoms());
    signals.extend(b.atoms());
    let vars: Vec<PolicyAtom> = bit_var_order(&signals, limits)?;

    let max_bdd_nodes = limits
        .max_nodes
        .saturating_mul(16)
        .max(limits.max_nodes)
        .min(1_000_000);

    let ca = CanonicalPolicy::new(a.clone(), limits)?;
    let cb = CanonicalPolicy::new(b.clone(), limits)?;
    validate_no_deny_if_under_not(ca.expr(), false)?;
    validate_no_deny_if_under_not(cb.expr(), false)?;

    let la = lower_to_presence_bits(ca.expr(), limits)?;
    let mut ba = BddBuilder::new(vars.clone(), max_bdd_nodes)?;
    let ra = ba.compile_expr(&la)?;
    let robdd_a = Robdd {
        vars: vars.clone(),
        nodes: ba.nodes,
        root: ra,
    };

    let lb = lower_to_presence_bits(cb.expr(), limits)?;
    let mut bb = BddBuilder::new(vars.clone(), max_bdd_nodes)?;
    let rb = bb.compile_expr(&lb)?;
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

    let ce = tristate_counterexample_from_bits(&signals, &assignment, limits)?;
    Ok(BddEquivResult {
        equivalent: false,
        counterexample: Some(ce),
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

/// Compare a Policy Algebra expression (signal-level) to a boolean expression over presence bits.
///
/// Intended for certifying emitted Tau gates:
/// - `policy` is the Policy Algebra policy (signals are `a`, `b`, ... with missing semantics).
/// - `tau_bits` is a boolean formula over derived atoms `p_<a>` and `v_<a>`.
pub fn policy_equiv_robdd_policy_vs_tau_bits(
    policy: &PolicyExpr,
    tau_bits: &PolicyExpr,
    limits: PolicyLimits,
) -> Result<BddEquivResult> {
    limits.validate()?;

    // Signals come from the policy and from any p_/v_ atoms referenced by tau_bits.
    fn extract_signals_from_bits(
        bits_expr: &PolicyExpr,
        limits: PolicyLimits,
    ) -> Result<BTreeSet<PolicyAtom>> {
        let mut out = BTreeSet::new();
        for a in bits_expr.atoms() {
            let s = a.as_str();
            let Some(rest) = s.strip_prefix("p_").or_else(|| s.strip_prefix("v_")) else {
                return Err(MprdError::InvalidInput(format!(
                    "tau_bits contains non-bit atom '{s}' (expected prefix 'p_' or 'v_')"
                )));
            };
            if rest.is_empty() {
                return Err(MprdError::InvalidInput(
                    "tau_bits contains empty signal name after prefix".into(),
                ));
            }
            out.insert(PolicyAtom::new(rest.to_string(), limits)?);
        }
        Ok(out)
    }

    let mut signals: BTreeSet<PolicyAtom> = BTreeSet::new();
    signals.extend(policy.atoms());
    signals.extend(extract_signals_from_bits(tau_bits, limits)?);

    let vars: Vec<PolicyAtom> = bit_var_order(&signals, limits)?;

    let max_bdd_nodes = limits
        .max_nodes
        .saturating_mul(16)
        .max(limits.max_nodes)
        .min(1_000_000);

    let cp = CanonicalPolicy::new(policy.clone(), limits)?;
    validate_no_deny_if_under_not(cp.expr(), false)?;
    let lp = lower_to_presence_bits(cp.expr(), limits)?;

    let ct = CanonicalPolicy::new(tau_bits.clone(), limits)?;

    let mut bp = BddBuilder::new(vars.clone(), max_bdd_nodes)?;
    let rp = bp.compile_expr(&lp)?;
    let robdd_p = Robdd {
        vars: vars.clone(),
        nodes: bp.nodes,
        root: rp,
    };

    let mut bt = BddBuilder::new(vars.clone(), max_bdd_nodes)?;
    let rt = bt.compile_expr(ct.expr())?;
    let robdd_t = Robdd {
        vars: vars.clone(),
        nodes: bt.nodes,
        root: rt,
    };

    let mut bd = BddBuilder::new(vars.clone(), max_bdd_nodes)?;
    let dp = bd.import(&robdd_p)?;
    let dt = bd.import(&robdd_t)?;
    let diff = bd.apply(Op::Xor, dp, dt)?;
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

    let ce = tristate_counterexample_from_bits(&signals, &assignment, limits)?;
    Ok(BddEquivResult {
        equivalent: false,
        counterexample: Some(ce),
    })
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
                    (Some(x), Some(y)) => {
                        if x <= y {
                            x
                        } else {
                            y
                        }
                    }
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

    fn import(&mut self, bdd: &Robdd) -> Result<BddId> {
        // Import by reconstructing under this builder's var order.
        // This keeps the equivalence checker simple and deterministic.
        if self.vars != bdd.vars {
            return Err(MprdError::InvalidInput(
                "ROBDD import requires identical variable order".into(),
            ));
        }

        fn go(
            dst: &mut BddBuilder,
            src: &Robdd,
            id: BddId,
            memo: &mut BTreeMap<BddId, BddId>,
        ) -> Result<BddId> {
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
    use proptest::prelude::*;

    fn lim() -> PolicyLimits {
        PolicyLimits::DEFAULT
    }

    #[derive(Clone, Copy, Debug)]
    enum Tri {
        Missing,
        False,
        True,
    }

    fn ctx_from_tri(assign: &[(&str, Tri)]) -> BTreeMap<String, bool> {
        let mut m = BTreeMap::new();
        for (k, v) in assign {
            match v {
                Tri::Missing => {}
                Tri::False => {
                    m.insert((*k).to_string(), false);
                }
                Tri::True => {
                    m.insert((*k).to_string(), true);
                }
            }
        }
        m
    }

    #[test]
    fn robdd_matches_policy_evaluate_for_tristate_assignments() {
        let limits = lim();
        let a = PolicyExpr::atom("a", limits).unwrap();
        let b = PolicyExpr::atom("b", limits).unwrap();
        let c = PolicyExpr::atom("c", limits).unwrap();
        let ban = PolicyExpr::deny_if("ban", limits).unwrap();

        // (a && (b || c)) with a veto guard `ban`.
        let expr = PolicyExpr::all(
            vec![a, PolicyExpr::any(vec![b, c, ban], limits).unwrap()],
            limits,
        )
        .unwrap();
        let canon = CanonicalPolicy::new(expr, limits).unwrap();

        let bdd = compile_allow_robdd(canon.expr(), limits).unwrap();

        // Exhaustive over a,b,c,ban ∈ {missing,false,true} => 3^4 = 81.
        let domain = [Tri::Missing, Tri::False, Tri::True];
        for &ta in &domain {
            for &tb in &domain {
                for &tc in &domain {
                    for &tban in &domain {
                        let ctx = ctx_from_tri(&[("a", ta), ("b", tb), ("c", tc), ("ban", tban)]);

                        let allowed_eval = super::super::evaluate(canon.expr(), &ctx, limits)
                            .unwrap()
                            .allowed();

                        // Derive presence bits for the ROBDD.
                        let allowed_bdd = bdd.eval(|atom| {
                            let name = atom.as_str();
                            if let Some(sig) = name.strip_prefix("p_") {
                                ctx.contains_key(sig)
                            } else if let Some(sig) = name.strip_prefix("v_") {
                                *ctx.get(sig).unwrap_or(&false)
                            } else {
                                false
                            }
                        });

                        assert_eq!(
                            allowed_eval, allowed_bdd,
                            "a={ta:?} b={tb:?} c={tc:?} ban={tban:?}"
                        );
                    }
                }
            }
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
    }

    #[test]
    fn deny_if_under_not_is_rejected() {
        let limits = lim();
        let ban = PolicyExpr::deny_if("ban", limits).unwrap();
        let expr = PolicyExpr::not(ban);
        let err = compile_allow_robdd(&expr, limits).unwrap_err();
        assert!(err.to_string().contains("DenyIf under Not"));
    }

    #[test]
    fn robdd_matches_explicit_presence_bit_encoding_for_deny_if_veto() {
        let limits = lim();
        let ok = PolicyExpr::atom("ok", limits).unwrap();
        let ban = PolicyExpr::deny_if("ban", limits).unwrap();

        // Policy: ok with a deny-if veto guard `ban`.
        let with_deny_if = PolicyExpr::any(vec![ok.clone(), ban], limits).unwrap();

        // Explicit presence-bit formula:
        // (p_ok & v_ok) & (p_ban & !v_ban)
        let p_ok = PolicyExpr::atom("p_ok", limits).unwrap();
        let v_ok = PolicyExpr::atom("v_ok", limits).unwrap();
        let p_ban = PolicyExpr::atom("p_ban", limits).unwrap();
        let v_ban = PolicyExpr::atom("v_ban", limits).unwrap();
        let explicit = PolicyExpr::all(
            vec![
                PolicyExpr::all(vec![p_ok, v_ok], limits).unwrap(),
                PolicyExpr::all(vec![p_ban, PolicyExpr::not(v_ban)], limits).unwrap(),
            ],
            limits,
        )
        .unwrap();

        let lowered = lower_to_presence_bits(&with_deny_if, limits).unwrap();
        let canon_lowered = CanonicalPolicy::new(lowered, limits).unwrap();
        let canon_explicit = CanonicalPolicy::new(explicit, limits).unwrap();

        let mut signals = BTreeSet::new();
        signals.insert(PolicyAtom::new("ok".to_string(), limits).unwrap());
        signals.insert(PolicyAtom::new("ban".to_string(), limits).unwrap());
        let vars = bit_var_order(&signals, limits).unwrap();

        let max_bdd_nodes = limits
            .max_nodes
            .saturating_mul(16)
            .max(limits.max_nodes)
            .min(1_000_000);

        let mut b1 = BddBuilder::new(vars.clone(), max_bdd_nodes).unwrap();
        let r1 = b1.compile_expr(canon_lowered.expr()).unwrap();
        let robdd1 = Robdd {
            vars: vars.clone(),
            nodes: b1.nodes,
            root: r1,
        };

        let mut b2 = BddBuilder::new(vars.clone(), max_bdd_nodes).unwrap();
        let r2 = b2.compile_expr(canon_explicit.expr()).unwrap();
        let robdd2 = Robdd {
            vars: vars.clone(),
            nodes: b2.nodes,
            root: r2,
        };

        assert_eq!(robdd1.hash_v1(), robdd2.hash_v1());
    }

    fn arb_atom_name() -> impl Strategy<Value = &'static str> {
        prop_oneof![
            Just("a"),
            Just("b"),
            Just("c"),
            Just("d"),
            Just("e"),
            Just("f"),
        ]
    }

    fn arb_no_veto(limits: PolicyLimits) -> BoxedStrategy<PolicyExpr> {
        let leaf = prop_oneof![
            Just(PolicyExpr::True),
            Just(PolicyExpr::False),
            arb_atom_name().prop_map(move |n| PolicyExpr::atom(n, limits).unwrap()),
        ];

        leaf.prop_recursive(3, 48, 4, move |inner| {
            prop_oneof![
                inner.clone().prop_map(PolicyExpr::not),
                proptest::collection::vec(inner.clone(), 0..=4)
                    .prop_map(move |v| PolicyExpr::all(v, limits).unwrap()),
                proptest::collection::vec(inner.clone(), 0..=4)
                    .prop_map(move |v| PolicyExpr::any(v, limits).unwrap()),
                proptest::collection::vec(inner.clone(), 0..=4).prop_map(move |v| {
                    // Keep PBT valid under canonicalization: `k==0` remains valid even after
                    // dedup/removals in canonicalization.
                    PolicyExpr::threshold(0, v, limits).unwrap()
                }),
            ]
        })
        .boxed()
    }

    fn arb_with_veto(limits: PolicyLimits) -> BoxedStrategy<PolicyExpr> {
        let no_veto = arb_no_veto(limits);
        let veto_leaf = arb_atom_name().prop_map(move |n| PolicyExpr::deny_if(n, limits).unwrap());
        let leaf = prop_oneof![no_veto.clone(), veto_leaf];

        leaf.prop_recursive(3, 64, 4, move |inner| {
            prop_oneof![
                // Not is only allowed over deny-if-free subexpressions.
                no_veto.clone().prop_map(PolicyExpr::not),
                proptest::collection::vec(inner.clone(), 0..=4)
                    .prop_map(move |v| PolicyExpr::all(v, limits).unwrap()),
                proptest::collection::vec(inner.clone(), 0..=4)
                    .prop_map(move |v| PolicyExpr::any(v, limits).unwrap()),
                proptest::collection::vec(inner.clone(), 0..=4)
                    .prop_map(move |v| { PolicyExpr::threshold(0, v, limits).unwrap() }),
            ]
        })
        .boxed()
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            max_shrink_iters: 10_000,
            .. ProptestConfig::default()
        })]

        #[test]
        fn robdd_matches_policy_evaluate_for_random_policies_with_missing(expr in arb_with_veto(PolicyLimits::DEFAULT)) {
            let limits = lim();
            let canon = CanonicalPolicy::new(expr, limits).unwrap();
            let bdd = compile_allow_robdd(canon.expr(), limits).unwrap();

            let signals = canon.expr().atoms();
            prop_assume!(signals.len() <= 6);

            // Exhaustive tri-state over signals: 3^n (n<=6 => <=729).
            let sigs: Vec<String> = signals.iter().map(|a| a.as_str().to_string()).collect();
            let n = sigs.len();
            let max = 3u64.pow(n as u32);

            for mut code in 0..max {
                let mut ctx: BTreeMap<String, bool> = BTreeMap::new();
                for s in &sigs {
                    let digit = (code % 3) as u8;
                    code /= 3;
                    match digit {
                        0 => {} // missing
                        1 => {
                            ctx.insert(s.clone(), false);
                        }
                        2 => {
                            ctx.insert(s.clone(), true);
                        }
                        _ => unreachable!(),
                    }
                }

                let allowed_eval = super::super::evaluate(canon.expr(), &ctx, limits).unwrap().allowed();
                let allowed_bdd = bdd.eval(|atom| {
                    let name = atom.as_str();
                    if let Some(sig) = name.strip_prefix("p_") {
                        ctx.contains_key(sig)
                    } else if let Some(sig) = name.strip_prefix("v_") {
                        *ctx.get(sig).unwrap_or(&false)
                    } else {
                        false
                    }
                });
                prop_assert_eq!(allowed_eval, allowed_bdd);
            }
        }
    }
}
