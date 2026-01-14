use crate::{MprdError, Result};

use super::ast::{PolicyExpr, PolicyLimits};
use super::hash::{encode_policy_v1, policy_hash_v1};

fn has_complement_pair(flat: &[PolicyExpr]) -> bool {
    // O(n^2) but n is bounded (PolicyLimits.max_children).
    for (i, a) in flat.iter().enumerate() {
        for b in flat.iter().skip(i + 1) {
            match (a, b) {
                (PolicyExpr::Not(x), y) if **x == *y => return true,
                (x, PolicyExpr::Not(y)) if **y == *x => return true,
                _ => {}
            }
        }
    }
    false
}

fn absorb_in_any(mut flat: Vec<PolicyExpr>) -> Vec<PolicyExpr> {
    // Absorption: x ∨ (x ∧ y) = x
    // After canonicalize, nested All nodes are flattened, so we just need to drop any `All(...)`
    // child that contains some other direct child `x` as a conjunct.
    let snapshot = flat.clone();
    flat.retain(|e| {
        let PolicyExpr::All(conj) = e else { return true };
        !conj.iter().any(|c| snapshot.contains(c))
    });
    flat
}

fn absorb_in_all(mut flat: Vec<PolicyExpr>) -> Vec<PolicyExpr> {
    // Absorption: x ∧ (x ∨ y) = x
    let snapshot = flat.clone();
    flat.retain(|e| {
        let PolicyExpr::Any(disj) = e else { return true };
        !disj.iter().any(|c| snapshot.contains(c))
    });
    flat
}

/// A canonicalized policy with its stable hash commitment.
#[derive(Clone, Debug)]
pub struct CanonicalPolicy {
    expr: PolicyExpr,
    bytes_v1: Vec<u8>,
    hash_v1: crate::Hash32,
    limits: PolicyLimits,
}

impl CanonicalPolicy {
    pub fn new(expr: PolicyExpr, limits: PolicyLimits) -> Result<Self> {
        limits.validate()?;
        let expr = canonicalize(&expr, limits)?;

        let nodes = expr.node_count();
        if nodes > limits.max_nodes {
            return Err(MprdError::InvalidInput(format!(
                "CanonicalPolicy::new: policy too large (nodes={nodes} max_nodes={})",
                limits.max_nodes
            )));
        }

        let bytes_v1 = encode_policy_v1(&expr);
        let hash_v1 = policy_hash_v1(&expr);

        Ok(Self {
            expr,
            bytes_v1,
            hash_v1,
            limits,
        })
    }

    pub fn expr(&self) -> &PolicyExpr {
        &self.expr
    }

    pub fn bytes_v1(&self) -> &[u8] {
        &self.bytes_v1
    }

    pub fn hash_v1(&self) -> crate::Hash32 {
        self.hash_v1
    }

    pub fn limits(&self) -> PolicyLimits {
        self.limits
    }
}

#[derive(Clone, Debug)]
struct CanonChild {
    deny_if_rank: u8,
    bytes: Vec<u8>,
    expr: PolicyExpr,
}

fn deny_if_rank(expr: &PolicyExpr) -> u8 {
    match expr {
        PolicyExpr::DenyIf(_) => 0,
        _ => 1,
    }
}

fn canonicalize(expr: &PolicyExpr, limits: PolicyLimits) -> Result<PolicyExpr> {
    match expr {
        PolicyExpr::True | PolicyExpr::False | PolicyExpr::Atom(_) | PolicyExpr::DenyIf(_) => {
            Ok(expr.clone())
        }
        PolicyExpr::Not(child) => {
            let c = canonicalize(child, limits)?;
            match c {
                PolicyExpr::True => Ok(PolicyExpr::False),
                PolicyExpr::False => Ok(PolicyExpr::True),
                PolicyExpr::Not(inner) => Ok(*inner),
                other => Ok(PolicyExpr::Not(Box::new(other))),
            }
        }
        PolicyExpr::All(children) => {
            let mut flat: Vec<PolicyExpr> = Vec::new();
            for ch in children {
                let c = canonicalize(ch, limits)?;
                match c {
                    PolicyExpr::All(grand) => flat.extend(grand),
                    other => flat.push(other),
                }
            }
            if flat.len() > limits.max_children {
                return Err(MprdError::InvalidInput(format!(
                    "PolicyExpr::All exceeds max_children after flatten ({} > {})",
                    flat.len(),
                    limits.max_children
                )));
            }

            // Remove identity elements.
            flat.retain(|c| !matches!(c, PolicyExpr::True));
            // Constant short-circuit is only safe when there is no veto (`DenyIf`) anywhere
            // in the subtree. Otherwise we would erase veto guards, changing DenyVeto vs DenySoft.
            let has_deny_if = flat.iter().any(|c| c.contains_deny_if());
            if !has_deny_if && flat.iter().any(|c| matches!(c, PolicyExpr::False)) {
                return Ok(PolicyExpr::False);
            }
            // Boolean contradiction elimination: x ∧ ¬x = False (safe only when no DenyIf is present anywhere).
            if !has_deny_if && has_complement_pair(&flat) {
                return Ok(PolicyExpr::False);
            }
            // Boolean absorption: x ∧ (x ∨ y) = x (safe only when no DenyIf is present anywhere).
            if !has_deny_if {
                flat = absorb_in_all(flat);
            }

            if flat.is_empty() {
                return Ok(PolicyExpr::True);
            }

            let mut keyed: Vec<CanonChild> = flat
                .into_iter()
                .map(|c| CanonChild {
                    deny_if_rank: deny_if_rank(&c),
                    bytes: encode_policy_v1(&c),
                    expr: c,
                })
                .collect();

            keyed.sort_by(|a, b| {
                a.deny_if_rank
                    .cmp(&b.deny_if_rank)
                    .then_with(|| a.bytes.cmp(&b.bytes))
            });
            keyed.dedup_by(|a, b| a.bytes == b.bytes);

            if keyed.len() > limits.max_children {
                return Err(MprdError::InvalidInput(format!(
                    "PolicyExpr::All exceeds max_children after dedup ({} > {})",
                    keyed.len(),
                    limits.max_children
                )));
            }

            if keyed.len() == 1 {
                let only = keyed.pop().unwrap().expr;
                // `DenyIf` is neutral in the main formula, so `All([DenyIf(x)])` allows
                // (when veto guards are not triggered). Collapsing would change semantics.
                if matches!(only, PolicyExpr::DenyIf(_)) {
                    return Ok(PolicyExpr::All(vec![only]));
                }
                return Ok(only);
            }

            Ok(PolicyExpr::All(keyed.into_iter().map(|k| k.expr).collect()))
        }
        PolicyExpr::Any(children) => {
            let mut flat: Vec<PolicyExpr> = Vec::new();
            for ch in children {
                let c = canonicalize(ch, limits)?;
                match c {
                    PolicyExpr::Any(grand) => flat.extend(grand),
                    other => flat.push(other),
                }
            }
            if flat.len() > limits.max_children {
                return Err(MprdError::InvalidInput(format!(
                    "PolicyExpr::Any exceeds max_children after flatten ({} > {})",
                    flat.len(),
                    limits.max_children
                )));
            }

            // Remove identity elements.
            flat.retain(|c| !matches!(c, PolicyExpr::False));
            if flat.is_empty() {
                return Ok(PolicyExpr::False);
            }

            // We only short-circuit `Any(..., True, ...) -> True` when we can prove there is
            // no veto (`DenyIf`) anywhere in the subtree. Otherwise `DenyIf` must be preserved
            // as an absorbing deny guard.
            let has_deny_if = flat.iter().any(|c| c.contains_deny_if());
            if !has_deny_if && flat.iter().any(|c| matches!(c, PolicyExpr::True)) {
                return Ok(PolicyExpr::True);
            }
            // Boolean tautology elimination: x ∨ ¬x = True (safe only when no DenyIf is present anywhere).
            if !has_deny_if && has_complement_pair(&flat) {
                return Ok(PolicyExpr::True);
            }
            // Boolean absorption: x ∨ (x ∧ y) = x (safe only when no DenyIf is present anywhere).
            if !has_deny_if {
                flat = absorb_in_any(flat);
            }

            let mut keyed: Vec<CanonChild> = flat
                .into_iter()
                .map(|c| CanonChild {
                    deny_if_rank: deny_if_rank(&c),
                    bytes: encode_policy_v1(&c),
                    expr: c,
                })
                .collect();

            keyed.sort_by(|a, b| {
                a.deny_if_rank
                    .cmp(&b.deny_if_rank)
                    .then_with(|| a.bytes.cmp(&b.bytes))
            });
            keyed.dedup_by(|a, b| a.bytes == b.bytes);

            if keyed.len() > limits.max_children {
                return Err(MprdError::InvalidInput(format!(
                    "PolicyExpr::Any exceeds max_children after dedup ({} > {})",
                    keyed.len(),
                    limits.max_children
                )));
            }

            if keyed.len() == 1 {
                return Ok(keyed.pop().unwrap().expr);
            }

            Ok(PolicyExpr::Any(keyed.into_iter().map(|k| k.expr).collect()))
        }
        PolicyExpr::Threshold { k, children } => {
            let mut canon_children: Vec<PolicyExpr> = Vec::with_capacity(children.len());
            for ch in children {
                canon_children.push(canonicalize(ch, limits)?);
            }

            if canon_children.len() > limits.max_children {
                return Err(MprdError::InvalidInput(format!(
                    "PolicyExpr::Threshold exceeds max_children ({} > {})",
                    canon_children.len(),
                    limits.max_children
                )));
            }

            // Removing `False` is safe: it can never help satisfy the threshold.
            canon_children.retain(|c| !matches!(c, PolicyExpr::False));

            // `True` always contributes 1 to the allow-count, so we can remove it and decrement k.
            // This is semantics-preserving even with veto semantics, because `True` carries no `DenyIf`.
            let mut k_usize = *k as usize;
            if k_usize > 0 {
                let mut kept: Vec<PolicyExpr> = Vec::with_capacity(canon_children.len());
                for ch in canon_children.into_iter() {
                    if matches!(ch, PolicyExpr::True) {
                        k_usize = k_usize.saturating_sub(1);
                    } else {
                        kept.push(ch);
                    }
                }
                canon_children = kept;
            }

            let mut keyed: Vec<CanonChild> = canon_children
                .into_iter()
                .map(|c| CanonChild {
                    deny_if_rank: deny_if_rank(&c),
                    bytes: encode_policy_v1(&c),
                    expr: c,
                })
                .collect();

            keyed.sort_by(|a, b| {
                a.deny_if_rank
                    .cmp(&b.deny_if_rank)
                    .then_with(|| a.bytes.cmp(&b.bytes))
            });
            // IMPORTANT: do NOT deduplicate for `Threshold`.
            //
            // Unlike `All`/`Any`, `Threshold(k, children)` is sensitive to multiplicity:
            // duplicates can change the allow-count. Deduplicating would change semantics
            // (and can spuriously make `k` exceed the new child count).

            if k_usize > keyed.len() {
                return Err(MprdError::InvalidInput(format!(
                    "PolicyExpr::Threshold invalid after canonicalization: k={k} exceeds child count {}",
                    keyed.len()
                )));
            }
            let has_deny_if = keyed.iter().any(|c| c.expr.contains_deny_if());
            if k_usize == 0 {
                // Threshold(0, children) == True in the main semantics, but rewriting is only safe
                // if it would not erase any DenyIf atoms (veto set). So require no DenyIf anywhere.
                if !has_deny_if {
                    return Ok(PolicyExpr::True);
                }
            }
            if keyed.is_empty() {
                // With k>0 and no children, the threshold cannot be met.
                return Ok(PolicyExpr::False);
            }
            if k_usize == 1 {
                // Threshold(1, xs) == Any(xs) only when no child can be Neutral; otherwise Neutral
                // children contribute 0 to the count but do not deny-soft in `Any`, so the two differ.
                // A sufficient condition is: no DenyIf appears anywhere under the children.
                if !has_deny_if {
                    let xs = keyed.into_iter().map(|k| k.expr).collect();
                    return Ok(PolicyExpr::Any(xs));
                }
            }
            if k_usize == keyed.len() {
                // Threshold(n, xs) == All(xs) iff none of the children can be Neutral.
                // A sufficient condition is: no DenyIf appears anywhere under the children.
                if !has_deny_if {
                    let xs = keyed.into_iter().map(|k| k.expr).collect();
                    return Ok(PolicyExpr::All(xs));
                }
            }

            Ok(PolicyExpr::Threshold {
                k: u16::try_from(k_usize).unwrap_or(u16::MAX),
                children: keyed.into_iter().map(|k| k.expr).collect(),
            })
        }
    }
}
