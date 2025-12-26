use crate::{MprdError, Result};

use super::{CanonicalPolicy, PolicyExpr, PolicyLimits};

/// Emit a canonical Tau gate (sbf-only) for a policy algebra expression.
///
/// This is intended as an interoperability / audit tool:
/// - host computes complex predicates as boolean inputs ("signals")
/// - Tau validates the boolean structure deterministically
///
/// Limitations (fail-closed):
/// - `Threshold(k, ..)` is only supported when `k == 0` (True) or `k == n` (All-of).
/// - `DenyIf` must not appear under `Not` (nonsensical / hard to audit).
pub fn emit_tau_gate_v1(
    expr: &PolicyExpr,
    output_name: &str,
    limits: PolicyLimits,
) -> Result<String> {
    limits.validate()?;
    let output = super::PolicyAtom::new(output_name.to_string(), limits)?;
    let canon = CanonicalPolicy::new(expr.clone(), limits)?;

    validate_no_deny_if_under_not(canon.expr(), false)?;

    let atoms = canon.expr().atoms();
    let veto_atoms = canon.expr().deny_if_atoms();

    let mut out = String::new();
    out.push_str("# ==========================================================================\n");
    out.push_str("# GENERATED: Policy Algebra → Tau gate (v1)\n");
    out.push_str("# ==========================================================================\n");
    out.push_str("# This file is generated from a canonical policy algebra expression.\n");
    out.push_str("# Policy hash is stable under canonicalization.\n");
    out.push_str("#\n");
    out.push_str(&format!(
        "# policy_hash_v1: {}\n",
        hex::encode(canon.hash_v1().0)
    ));
    out.push_str(
        "# ==========================================================================\n\n",
    );

    // Inputs
    for a in &atoms {
        out.push_str(&format!(
            "i_{name} : sbf = in file(\"inputs/{name}.in\").\n",
            name = a.as_str()
        ));
    }
    out.push('\n');

    // Output
    out.push_str(&format!(
        "o_{output} : sbf = out file(\"outputs/{output}.out\").\n\n",
        output = output.as_str()
    ));

    // Build formula
    let veto = emit_veto_conj(&veto_atoms);
    let main = emit_expr(canon.expr(), DenyIfValue::False)?;

    let full = if veto == "1:sbf" {
        main
    } else if main == "1:sbf" {
        veto
    } else {
        format!("({veto}) & ({main})")
    };

    out.push_str("defs\n");
    out.push_str("r (\n");
    out.push_str(&format!(
        "    (o_{output}[t] = {full})\n",
        output = output.as_str()
    ));
    out.push_str(")\n");
    out.push_str("n\n");
    out.push_str("q\n");

    Ok(out)
}

#[derive(Clone, Copy)]
enum DenyIfValue {
    True,
    False,
}

fn emit_veto_conj(veto_atoms: &std::collections::BTreeSet<super::PolicyAtom>) -> String {
    if veto_atoms.is_empty() {
        return "1:sbf".to_string();
    }
    let s = veto_atoms
        .iter()
        .map(|a| format!("i_{}[t]'", a.as_str()))
        .collect::<Vec<_>>()
        .join(" & ");
    if veto_atoms.len() == 1 {
        s
    } else {
        format!("({s})")
    }
}

fn emit_expr(expr: &PolicyExpr, deny_if_value: DenyIfValue) -> Result<String> {
    match expr {
        PolicyExpr::True => Ok("1:sbf".to_string()),
        PolicyExpr::False => Ok("0:sbf".to_string()),
        PolicyExpr::Atom(a) => Ok(format!("i_{}[t]", a.as_str())),
        PolicyExpr::DenyIf(_) => Ok(match deny_if_value {
            DenyIfValue::True => "1:sbf",
            DenyIfValue::False => "0:sbf",
        }
        .to_string()),
        PolicyExpr::Not(child) => {
            // NOTE: `DenyIf` under `Not` is rejected by `validate_no_deny_if_under_not`.
            Ok(format!("({})'", emit_expr(child, DenyIfValue::False)?))
        }
        PolicyExpr::All(children) => {
            if children.is_empty() {
                return Ok("1:sbf".to_string());
            }
            let mut parts = Vec::with_capacity(children.len());
            for ch in children {
                parts.push(emit_expr(ch, DenyIfValue::True)?);
            }
            let s = parts.join(" & ");
            if children.len() == 1 {
                Ok(s)
            } else {
                Ok(format!("({s})"))
            }
        }
        PolicyExpr::Any(children) => {
            if children.is_empty() {
                return Ok("0:sbf".to_string());
            }
            let mut parts = Vec::with_capacity(children.len());
            for ch in children {
                parts.push(emit_expr(ch, DenyIfValue::False)?);
            }
            let s = parts.join(" | ");
            if children.len() == 1 {
                Ok(s)
            } else {
                Ok(format!("({s})"))
            }
        }
        PolicyExpr::Threshold { k, children } => {
            // Restricted support: k==0 => True, k==n => All(children)
            if *k == 0 {
                return Ok("1:sbf".to_string());
            }
            let n = u16::try_from(children.len()).unwrap_or(u16::MAX);
            if *k == n {
                if children.is_empty() {
                    return Ok("1:sbf".to_string());
                }
                let mut parts = Vec::with_capacity(children.len());
                for ch in children {
                    parts.push(emit_expr(ch, DenyIfValue::False)?);
                }
                let s = parts.join(" & ");
                return if children.len() == 1 {
                    Ok(s)
                } else {
                    Ok(format!("({s})"))
                };
            }
            Err(MprdError::InvalidInput(format!(
                "emit_tau_gate_v1: Threshold(k={k}) not supported (n={})",
                children.len()
            )))
        }
    }
}

fn validate_no_deny_if_under_not(expr: &PolicyExpr, under_not: bool) -> Result<()> {
    match expr {
        PolicyExpr::DenyIf(_) if under_not => Err(MprdError::InvalidInput(
            "emit_tau_gate_v1: DenyIf under Not is not supported".into(),
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
