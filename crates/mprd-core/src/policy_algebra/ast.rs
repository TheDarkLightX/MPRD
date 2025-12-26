use crate::{MprdError, Result};
use std::collections::BTreeSet;

/// Bounds for policy algebra objects.
///
/// These are *safety rails* (DoS and determinism), not tokenomics parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyLimits {
    pub max_children: usize,
    pub max_nodes: usize,
    pub max_trace_nodes: usize,
    pub max_atom_len: usize,
}

impl PolicyLimits {
    pub const DEFAULT: PolicyLimits = PolicyLimits {
        max_children: 64,
        max_nodes: 1024,
        max_trace_nodes: 1024,
        max_atom_len: 64,
    };

    pub fn validate(&self) -> Result<()> {
        if self.max_children == 0 {
            return Err(MprdError::InvalidInput(
                "PolicyLimits.max_children must be > 0".into(),
            ));
        }
        if self.max_nodes == 0 {
            return Err(MprdError::InvalidInput(
                "PolicyLimits.max_nodes must be > 0".into(),
            ));
        }
        if self.max_trace_nodes == 0 {
            return Err(MprdError::InvalidInput(
                "PolicyLimits.max_trace_nodes must be > 0".into(),
            ));
        }
        if self.max_atom_len == 0 {
            return Err(MprdError::InvalidInput(
                "PolicyLimits.max_atom_len must be > 0".into(),
            ));
        }
        if self.max_atom_len > u8::MAX as usize {
            return Err(MprdError::InvalidInput(format!(
                "PolicyLimits.max_atom_len must be <= {} (got {})",
                u8::MAX,
                self.max_atom_len
            )));
        }
        Ok(())
    }
}

/// Stable kind tags for canonical encoding/hashing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PolicyKind {
    True = 0,
    False = 1,
    Atom = 2,
    Not = 3,
    All = 4,
    Any = 5,
    Threshold = 6,
    DenyIf = 7,
}

/// A validated boolean “signal” name used as a leaf in the policy algebra.
///
/// This is intentionally restrictive to keep compilation targets safe (Tau identifiers, JSON keys).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyAtom(String);

impl PolicyAtom {
    /// Create a new atom name.
    ///
    /// Allowed charset: `[a-z0-9_]+` (non-empty), bounded by `limits.max_atom_len`.
    pub fn new(name: impl Into<String>, limits: PolicyLimits) -> Result<Self> {
        let name = name.into();
        if name.is_empty() {
            return Err(MprdError::InvalidInput(
                "PolicyAtom::new: name must be non-empty".into(),
            ));
        }
        if name.len() > limits.max_atom_len {
            return Err(MprdError::InvalidInput(format!(
                "PolicyAtom::new: name too long (len={} max={})",
                name.len(),
                limits.max_atom_len
            )));
        }
        for (i, c) in name.bytes().enumerate() {
            let ok = matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_');
            if !ok {
                return Err(MprdError::InvalidInput(format!(
                    "PolicyAtom::new: invalid character '{}' at byte {}",
                    c as char, i
                )));
            }
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Three-valued policy outcome used internally by the algebra.
///
/// `Neutral` is used for “veto guards” like `DenyIf`, which do not by themselves provide allow-ness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyOutcomeKind {
    Allow,
    DenySoft,
    DenyVeto,
    Neutral,
}

/// Result of evaluating a policy node (kind only; trace carries reason codes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyOutcome {
    pub kind: PolicyOutcomeKind,
}

impl PolicyOutcome {
    pub fn allow() -> Self {
        Self {
            kind: PolicyOutcomeKind::Allow,
        }
    }

    pub fn deny_soft() -> Self {
        Self {
            kind: PolicyOutcomeKind::DenySoft,
        }
    }

    pub fn deny_veto() -> Self {
        Self {
            kind: PolicyOutcomeKind::DenyVeto,
        }
    }

    pub fn neutral() -> Self {
        Self {
            kind: PolicyOutcomeKind::Neutral,
        }
    }
}

/// A bounded policy AST (boolean algebra with an absorbing “veto” node).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyExpr {
    True,
    False,
    Atom(PolicyAtom),
    Not(Box<PolicyExpr>),
    All(Vec<PolicyExpr>),
    Any(Vec<PolicyExpr>),
    Threshold {
        k: u16,
        children: Vec<PolicyExpr>,
    },
    /// Absorbing deny that does not contribute to allow count in `Any` / `Threshold`.
    DenyIf(PolicyAtom),
}

impl PolicyExpr {
    pub fn kind(&self) -> PolicyKind {
        match self {
            PolicyExpr::True => PolicyKind::True,
            PolicyExpr::False => PolicyKind::False,
            PolicyExpr::Atom(_) => PolicyKind::Atom,
            PolicyExpr::Not(_) => PolicyKind::Not,
            PolicyExpr::All(_) => PolicyKind::All,
            PolicyExpr::Any(_) => PolicyKind::Any,
            PolicyExpr::Threshold { .. } => PolicyKind::Threshold,
            PolicyExpr::DenyIf(_) => PolicyKind::DenyIf,
        }
    }

    pub fn atom(name: impl Into<String>, limits: PolicyLimits) -> Result<Self> {
        Ok(Self::Atom(PolicyAtom::new(name, limits)?))
    }

    pub fn deny_if(name: impl Into<String>, limits: PolicyLimits) -> Result<Self> {
        Ok(Self::DenyIf(PolicyAtom::new(name, limits)?))
    }

    pub fn not(child: PolicyExpr) -> Self {
        Self::Not(Box::new(child))
    }

    pub fn all(children: Vec<PolicyExpr>, limits: PolicyLimits) -> Result<Self> {
        if children.len() > limits.max_children {
            return Err(MprdError::InvalidInput(format!(
                "PolicyExpr::all: too many children ({} > max_children={})",
                children.len(),
                limits.max_children
            )));
        }
        Ok(Self::All(children))
    }

    pub fn any(children: Vec<PolicyExpr>, limits: PolicyLimits) -> Result<Self> {
        if children.len() > limits.max_children {
            return Err(MprdError::InvalidInput(format!(
                "PolicyExpr::any: too many children ({} > max_children={})",
                children.len(),
                limits.max_children
            )));
        }
        Ok(Self::Any(children))
    }

    pub fn threshold(k: u16, children: Vec<PolicyExpr>, limits: PolicyLimits) -> Result<Self> {
        if children.len() > limits.max_children {
            return Err(MprdError::InvalidInput(format!(
                "PolicyExpr::threshold: too many children ({} > max_children={})",
                children.len(),
                limits.max_children
            )));
        }
        if k as usize > children.len() {
            return Err(MprdError::InvalidInput(format!(
                "PolicyExpr::threshold: k={k} exceeds child count {}",
                children.len()
            )));
        }
        Ok(Self::Threshold { k, children })
    }

    pub fn node_count(&self) -> usize {
        match self {
            PolicyExpr::True | PolicyExpr::False | PolicyExpr::Atom(_) | PolicyExpr::DenyIf(_) => 1,
            PolicyExpr::Not(p) => 1 + p.node_count(),
            PolicyExpr::All(children) | PolicyExpr::Any(children) => {
                1 + children.iter().map(|c| c.node_count()).sum::<usize>()
            }
            PolicyExpr::Threshold { children, .. } => {
                1 + children.iter().map(|c| c.node_count()).sum::<usize>()
            }
        }
    }

    pub fn contains_deny_if(&self) -> bool {
        match self {
            PolicyExpr::DenyIf(_) => true,
            PolicyExpr::Not(p) => p.contains_deny_if(),
            PolicyExpr::All(children) | PolicyExpr::Any(children) => {
                children.iter().any(|c| c.contains_deny_if())
            }
            PolicyExpr::Threshold { children, .. } => children.iter().any(|c| c.contains_deny_if()),
            PolicyExpr::True | PolicyExpr::False | PolicyExpr::Atom(_) => false,
        }
    }

    /// Collect all atoms referenced by this policy (including `DenyIf` atoms).
    pub fn atoms(&self) -> BTreeSet<PolicyAtom> {
        let mut out = BTreeSet::new();
        self.atoms_into(&mut out);
        out
    }

    /// Collect atoms referenced by `DenyIf` nodes only.
    pub fn deny_if_atoms(&self) -> BTreeSet<PolicyAtom> {
        let mut out = BTreeSet::new();
        self.deny_if_atoms_into(&mut out);
        out
    }

    fn atoms_into(&self, out: &mut BTreeSet<PolicyAtom>) {
        match self {
            PolicyExpr::Atom(a) | PolicyExpr::DenyIf(a) => {
                out.insert(a.clone());
            }
            PolicyExpr::Not(p) => p.atoms_into(out),
            PolicyExpr::All(children) | PolicyExpr::Any(children) => {
                for ch in children {
                    ch.atoms_into(out);
                }
            }
            PolicyExpr::Threshold { children, .. } => {
                for ch in children {
                    ch.atoms_into(out);
                }
            }
            PolicyExpr::True | PolicyExpr::False => {}
        }
    }

    fn deny_if_atoms_into(&self, out: &mut BTreeSet<PolicyAtom>) {
        match self {
            PolicyExpr::DenyIf(a) => {
                out.insert(a.clone());
            }
            PolicyExpr::Not(p) => p.deny_if_atoms_into(out),
            PolicyExpr::All(children) | PolicyExpr::Any(children) => {
                for ch in children {
                    ch.deny_if_atoms_into(out);
                }
            }
            PolicyExpr::Threshold { children, .. } => {
                for ch in children {
                    ch.deny_if_atoms_into(out);
                }
            }
            PolicyExpr::True | PolicyExpr::False | PolicyExpr::Atom(_) => {}
        }
    }
}
