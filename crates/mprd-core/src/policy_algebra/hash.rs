use crate::{hash, Hash32, MprdError, Result};

use super::ast::{PolicyAtom, PolicyExpr, PolicyKind, PolicyLimits};

/// Domain tag for hashing policy algebra v1 canonical encodings.
pub const POLICY_ALGEBRA_HASH_DOMAIN_V1: &[u8] = b"MPRD_POLICY_ALGEBRA_V1";

pub fn policy_hash_v1(expr: &PolicyExpr) -> Hash32 {
    hash::sha256_domain(POLICY_ALGEBRA_HASH_DOMAIN_V1, &encode_policy_v1(expr))
}

/// Canonical v1 encoding of a `PolicyExpr`.
///
/// This is a compact, deterministic, kind-tagged, length-delimited encoding intended for
/// hash commitments and canonicalization sorting keys.
pub fn encode_policy_v1(expr: &PolicyExpr) -> Vec<u8> {
    fn enc(out: &mut Vec<u8>, expr: &PolicyExpr) {
        out.push(expr.kind() as u8);
        match expr {
            PolicyExpr::True | PolicyExpr::False => {}
            PolicyExpr::Atom(a) | PolicyExpr::DenyIf(a) => {
                let b = a.as_str().as_bytes();
                // `PolicyAtom` is already bounded by `PolicyLimits.max_atom_len`, which is <= 255.
                out.push(u8::try_from(b.len()).unwrap_or(u8::MAX));
                out.extend_from_slice(b);
            }
            PolicyExpr::Not(child) => {
                let mut buf = Vec::new();
                enc(&mut buf, child);
                out.extend_from_slice(&(buf.len() as u32).to_le_bytes());
                out.extend_from_slice(&buf);
            }
            PolicyExpr::All(children) | PolicyExpr::Any(children) => {
                let n = u16::try_from(children.len()).unwrap_or(u16::MAX);
                out.extend_from_slice(&n.to_le_bytes());
                for ch in children {
                    let mut buf = Vec::new();
                    enc(&mut buf, ch);
                    out.extend_from_slice(&(buf.len() as u32).to_le_bytes());
                    out.extend_from_slice(&buf);
                }
            }
            PolicyExpr::Threshold { k, children } => {
                let n = u16::try_from(children.len()).unwrap_or(u16::MAX);
                out.extend_from_slice(&n.to_le_bytes());
                out.extend_from_slice(&k.to_le_bytes());
                for ch in children {
                    let mut buf = Vec::new();
                    enc(&mut buf, ch);
                    out.extend_from_slice(&(buf.len() as u32).to_le_bytes());
                    out.extend_from_slice(&buf);
                }
            }
        }
    }

    let mut out = Vec::new();
    enc(&mut out, expr);
    out
}

const MAX_DECODE_DEPTH_V1: usize = 256;

/// Decode a canonical v1 encoding back into a `PolicyExpr`.
///
/// Security posture:
/// - Fail-closed on malformed encodings (unknown kinds, truncation, trailing bytes).
/// - Enforces `PolicyLimits` for DoS resistance (max_nodes, max_children, max_atom_len).
pub fn decode_policy_v1(bytes: &[u8], limits: PolicyLimits) -> Result<PolicyExpr> {
    limits.validate()?;

    let mut i: usize = 0;
    let mut nodes: usize = 0;
    let expr = dec(bytes, &mut i, &mut nodes, limits, 0)?;

    if i != bytes.len() {
        return Err(MprdError::InvalidInput(format!(
            "decode_policy_v1: trailing bytes (used={} total={})",
            i,
            bytes.len()
        )));
    }

    Ok(expr)
}

fn dec(
    bytes: &[u8],
    i: &mut usize,
    nodes: &mut usize,
    limits: PolicyLimits,
    depth: usize,
) -> Result<PolicyExpr> {
    if depth > MAX_DECODE_DEPTH_V1 {
        return Err(MprdError::InvalidInput(format!(
            "decode_policy_v1: max decode depth exceeded (depth={depth} max={MAX_DECODE_DEPTH_V1})"
        )));
    }

    let kind = take_u8(bytes, i).ok_or_else(|| {
        MprdError::InvalidInput("decode_policy_v1: unexpected EOF reading kind".into())
    })?;

    *nodes = nodes.saturating_add(1);
    if *nodes > limits.max_nodes {
        return Err(MprdError::InvalidInput(format!(
            "decode_policy_v1: policy too large (nodes={} max_nodes={})",
            *nodes, limits.max_nodes
        )));
    }

    match kind {
        k if k == PolicyKind::True as u8 => Ok(PolicyExpr::True),
        k if k == PolicyKind::False as u8 => Ok(PolicyExpr::False),
        k if k == PolicyKind::Atom as u8 || k == PolicyKind::DenyIf as u8 => {
            let n = take_u8(bytes, i).ok_or_else(|| {
                MprdError::InvalidInput("decode_policy_v1: unexpected EOF reading atom len".into())
            })? as usize;
            let b = take_bytes(bytes, i, n).ok_or_else(|| {
                MprdError::InvalidInput(
                    "decode_policy_v1: unexpected EOF reading atom bytes".into(),
                )
            })?;

            let s = std::str::from_utf8(b).map_err(|_| {
                MprdError::InvalidInput("decode_policy_v1: atom bytes are not valid UTF-8".into())
            })?;
            let atom = PolicyAtom::new(s.to_string(), limits)?;
            if kind == PolicyKind::Atom as u8 {
                Ok(PolicyExpr::Atom(atom))
            } else {
                Ok(PolicyExpr::DenyIf(atom))
            }
        }
        k if k == PolicyKind::Not as u8 => {
            let n = take_u32(bytes, i).ok_or_else(|| {
                MprdError::InvalidInput("decode_policy_v1: unexpected EOF reading not-len".into())
            })? as usize;
            let b = take_bytes(bytes, i, n).ok_or_else(|| {
                MprdError::InvalidInput(
                    "decode_policy_v1: unexpected EOF reading not payload".into(),
                )
            })?;
            let mut j: usize = 0;
            let child = dec(b, &mut j, nodes, limits, depth.saturating_add(1))?;
            if j != b.len() {
                return Err(MprdError::InvalidInput(
                    "decode_policy_v1: Not payload had trailing bytes".into(),
                ));
            }
            Ok(PolicyExpr::Not(Box::new(child)))
        }
        k if k == PolicyKind::All as u8 || k == PolicyKind::Any as u8 => {
            let n = take_u16(bytes, i).ok_or_else(|| {
                MprdError::InvalidInput("decode_policy_v1: unexpected EOF reading arity".into())
            })? as usize;
            if n > limits.max_children {
                return Err(MprdError::InvalidInput(format!(
                    "decode_policy_v1: too many children (n={n} max_children={})",
                    limits.max_children
                )));
            }

            let mut children: Vec<PolicyExpr> = Vec::with_capacity(n);
            for _ in 0..n {
                let len = take_u32(bytes, i).ok_or_else(|| {
                    MprdError::InvalidInput(
                        "decode_policy_v1: unexpected EOF reading child len".into(),
                    )
                })? as usize;
                let b = take_bytes(bytes, i, len).ok_or_else(|| {
                    MprdError::InvalidInput(
                        "decode_policy_v1: unexpected EOF reading child payload".into(),
                    )
                })?;
                let mut j: usize = 0;
                let ch = dec(b, &mut j, nodes, limits, depth.saturating_add(1))?;
                if j != b.len() {
                    return Err(MprdError::InvalidInput(
                        "decode_policy_v1: child payload had trailing bytes".into(),
                    ));
                }
                children.push(ch);
            }

            if kind == PolicyKind::All as u8 {
                PolicyExpr::all(children, limits)
            } else {
                PolicyExpr::any(children, limits)
            }
        }
        k if k == PolicyKind::Threshold as u8 => {
            let n = take_u16(bytes, i).ok_or_else(|| {
                MprdError::InvalidInput("decode_policy_v1: unexpected EOF reading arity".into())
            })? as usize;
            let k_val = take_u16(bytes, i).ok_or_else(|| {
                MprdError::InvalidInput("decode_policy_v1: unexpected EOF reading k".into())
            })?;
            if n > limits.max_children {
                return Err(MprdError::InvalidInput(format!(
                    "decode_policy_v1: too many children (n={n} max_children={})",
                    limits.max_children
                )));
            }
            if k_val as usize > n {
                return Err(MprdError::InvalidInput(format!(
                    "decode_policy_v1: threshold k={k_val} exceeds arity n={n}"
                )));
            }

            let mut children: Vec<PolicyExpr> = Vec::with_capacity(n);
            for _ in 0..n {
                let len = take_u32(bytes, i).ok_or_else(|| {
                    MprdError::InvalidInput(
                        "decode_policy_v1: unexpected EOF reading child len".into(),
                    )
                })? as usize;
                let b = take_bytes(bytes, i, len).ok_or_else(|| {
                    MprdError::InvalidInput(
                        "decode_policy_v1: unexpected EOF reading child payload".into(),
                    )
                })?;
                let mut j: usize = 0;
                let ch = dec(b, &mut j, nodes, limits, depth.saturating_add(1))?;
                if j != b.len() {
                    return Err(MprdError::InvalidInput(
                        "decode_policy_v1: child payload had trailing bytes".into(),
                    ));
                }
                children.push(ch);
            }

            PolicyExpr::threshold(k_val, children, limits)
        }
        _ => Err(MprdError::InvalidInput(format!(
            "decode_policy_v1: unknown kind tag {kind}"
        ))),
    }
}

fn take_u8(bytes: &[u8], i: &mut usize) -> Option<u8> {
    if *i >= bytes.len() {
        return None;
    }
    let b = bytes[*i];
    *i = i.saturating_add(1);
    Some(b)
}

fn take_u16(bytes: &[u8], i: &mut usize) -> Option<u16> {
    let b = take_bytes(bytes, i, 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn take_u32(bytes: &[u8], i: &mut usize) -> Option<u32> {
    let b = take_bytes(bytes, i, 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn take_bytes<'a>(bytes: &'a [u8], i: &mut usize, n: usize) -> Option<&'a [u8]> {
    let start = *i;
    let end = start.checked_add(n)?;
    if end > bytes.len() {
        return None;
    }
    *i = end;
    Some(&bytes[start..end])
}
