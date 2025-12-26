use crate::{MprdError, Result};

use super::ast::{PolicyExpr, PolicyLimits};
use super::hash::{encode_policy_v1, policy_hash_v1};

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
            // Constant short-circuit (safe): False in All denies always.
            if flat.iter().any(|c| matches!(c, PolicyExpr::False)) {
                return Ok(PolicyExpr::False);
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
                return Ok(keyed.pop().unwrap().expr);
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
            keyed.dedup_by(|a, b| a.bytes == b.bytes);

            let k_usize = *k as usize;
            if k_usize > keyed.len() {
                return Err(MprdError::InvalidInput(format!(
                    "PolicyExpr::Threshold invalid after canonicalization: k={k} exceeds deduped child count {}",
                    keyed.len()
                )));
            }
            if keyed.is_empty() {
                return Ok(PolicyExpr::False);
            }
            if *k == 0 {
                // Threshold(0, children) allows as long as no veto triggers; we keep the structure
                // (rather than rewriting) so evaluation traces remain explicit.
            }

            Ok(PolicyExpr::Threshold {
                k: *k,
                children: keyed.into_iter().map(|k| k.expr).collect(),
            })
        }
    }
}
