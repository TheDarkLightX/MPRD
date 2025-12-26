use crate::{hash, Hash32};

use super::ast::PolicyExpr;

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
