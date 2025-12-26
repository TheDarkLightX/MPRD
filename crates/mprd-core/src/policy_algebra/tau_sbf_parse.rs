use crate::{MprdError, Result};

use super::{PolicyAtom, PolicyExpr, PolicyLimits};

/// Parse an sbf-only Tau boolean expression emitted by `emit_tau_gate_v1`.
///
/// Supported (fail-closed):
/// - constants: `1:sbf`, `0:sbf`
/// - atoms: `i_<name>[t]` where `<name>` is a `PolicyAtom`
/// - operators: `&`, `|`, postfix negation `'`, parentheses
///
/// Operator precedence:
/// - postfix `'` binds tightest
/// - `&` binds tighter than `|`
pub fn parse_tau_sbf_expr_v1(expr: &str, limits: PolicyLimits) -> Result<PolicyExpr> {
    limits.validate()?;

    let mut p = Parser::new(expr, limits)?;
    let out = p.parse_expr()?;
    p.skip_ws();
    if !p.eof() {
        return Err(MprdError::InvalidInput(format!(
            "tau_sbf_parse: trailing input at byte {}",
            p.pos
        )));
    }
    Ok(out)
}

/// Extract and parse the allow expression from a Tau gate emitted by `emit_tau_gate_v1`.
///
/// This searches for the first rule line of the form:
/// `(o_<output_name>[t] = <expr>)`
pub fn parse_emitted_tau_gate_allow_expr_v1(
    tau_gate_source: &str,
    output_name: &str,
    limits: PolicyLimits,
) -> Result<PolicyExpr> {
    limits.validate()?;
    let output = PolicyAtom::new(output_name.to_string(), limits)?;

    let prefix = format!("(o_{}[t]", output.as_str());

    for (line_no, line) in tau_gate_source.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with(&prefix) {
            continue;
        }

        let eq_idx = trimmed.find('=').ok_or_else(|| {
            MprdError::InvalidInput(format!(
                "tau_sbf_parse: malformed rule line at {} (missing '=')",
                line_no + 1
            ))
        })?;

        let mut rhs = trimmed[(eq_idx + 1)..].trim();
        if !rhs.ends_with(')') {
            return Err(MprdError::InvalidInput(format!(
                "tau_sbf_parse: malformed rule line at {} (missing closing ')')",
                line_no + 1
            )));
        }

        rhs = rhs[..(rhs.len() - 1)].trim();
        if rhs.is_empty() {
            return Err(MprdError::InvalidInput(format!(
                "tau_sbf_parse: empty rhs at line {}",
                line_no + 1
            )));
        }

        return parse_tau_sbf_expr_v1(rhs, limits);
    }

    Err(MprdError::InvalidInput(format!(
        "tau_sbf_parse: did not find output rule for o_{}[t]",
        output.as_str()
    )))
}

struct Parser<'a> {
    s: &'a str,
    b: &'a [u8],
    pos: usize,
    limits: PolicyLimits,
    nodes_emitted: usize,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str, limits: PolicyLimits) -> Result<Self> {
        if s.trim().is_empty() {
            return Err(MprdError::InvalidInput(
                "tau_sbf_parse: expression cannot be empty".into(),
            ));
        }
        Ok(Self {
            s,
            b: s.as_bytes(),
            pos: 0,
            limits,
            nodes_emitted: 0,
        })
    }

    fn eof(&self) -> bool {
        self.pos >= self.b.len()
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos = self.pos.saturating_add(1);
        Some(c)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos = self.pos.saturating_add(1);
        }
    }

    fn parse_expr(&mut self) -> Result<PolicyExpr> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<PolicyExpr> {
        let mut terms = Vec::new();
        terms.push(self.parse_and()?);

        loop {
            self.skip_ws();
            if self.peek() != Some(b'|') {
                break;
            }
            self.bump();
            terms.push(self.parse_and()?);
        }

        if terms.len() == 1 {
            Ok(terms.remove(0))
        } else {
            self.emit_node()?;
            PolicyExpr::any(terms, self.limits)
        }
    }

    fn parse_and(&mut self) -> Result<PolicyExpr> {
        let mut factors = Vec::new();
        factors.push(self.parse_unary()?);

        loop {
            self.skip_ws();
            if self.peek() != Some(b'&') {
                break;
            }
            self.bump();
            factors.push(self.parse_unary()?);
        }

        if factors.len() == 1 {
            Ok(factors.remove(0))
        } else {
            self.emit_node()?;
            PolicyExpr::all(factors, self.limits)
        }
    }

    fn parse_unary(&mut self) -> Result<PolicyExpr> {
        let mut node = self.parse_primary()?;
        loop {
            self.skip_ws();
            if self.peek() != Some(b'\'') {
                break;
            }
            self.bump();
            self.emit_node()?;
            node = PolicyExpr::not(node);
        }
        Ok(node)
    }

    fn parse_primary(&mut self) -> Result<PolicyExpr> {
        self.skip_ws();
        match self.peek() {
            Some(b'(') => {
                self.bump();
                let node = self.parse_expr()?;
                self.skip_ws();
                if self.bump() != Some(b')') {
                    return Err(MprdError::InvalidInput(format!(
                        "tau_sbf_parse: expected ')' at byte {}",
                        self.pos
                    )));
                }
                Ok(node)
            }
            Some(b'0') | Some(b'1') => self.parse_const(),
            Some(b'i') => self.parse_ident(),
            Some(c) => Err(MprdError::InvalidInput(format!(
                "tau_sbf_parse: unexpected byte '{}' at {}",
                c as char, self.pos
            ))),
            None => Err(MprdError::InvalidInput(
                "tau_sbf_parse: unexpected end of input".into(),
            )),
        }
    }

    fn parse_const(&mut self) -> Result<PolicyExpr> {
        // Exact match: "0:sbf" or "1:sbf"
        let rest = &self.s[self.pos..];
        if rest.starts_with("1:sbf") {
            self.pos = self.pos.saturating_add("1:sbf".len());
            self.emit_node()?;
            return Ok(PolicyExpr::True);
        }
        if rest.starts_with("0:sbf") {
            self.pos = self.pos.saturating_add("0:sbf".len());
            self.emit_node()?;
            return Ok(PolicyExpr::False);
        }

        Err(MprdError::InvalidInput(format!(
            "tau_sbf_parse: expected sbf literal at byte {}",
            self.pos
        )))
    }

    fn parse_ident(&mut self) -> Result<PolicyExpr> {
        // Grammar: i_<name>[t]
        // Where <name> is a `PolicyAtom` (restricted charset).
        let rest = &self.s[self.pos..];
        let Some(rest) = rest.strip_prefix("i_") else {
            return Err(MprdError::InvalidInput(format!(
                "tau_sbf_parse: expected 'i_' at byte {}",
                self.pos
            )));
        };
        let name_end = rest.find("[t]").ok_or_else(|| {
            MprdError::InvalidInput(format!(
                "tau_sbf_parse: expected '[t]' after identifier at byte {}",
                self.pos
            ))
        })?;
        let name = &rest[..name_end];
        let atom = PolicyAtom::new(name.to_string(), self.limits)?;
        self.pos = self
            .pos
            .saturating_add("i_".len() + name.len() + "[t]".len());
        self.emit_node()?;
        Ok(PolicyExpr::Atom(atom))
    }

    fn emit_node(&mut self) -> Result<()> {
        self.nodes_emitted = self.nodes_emitted.saturating_add(1);
        if self.nodes_emitted > self.limits.max_nodes {
            return Err(MprdError::InvalidInput(format!(
                "tau_sbf_parse: expression too large (nodes_emitted={} max_nodes={})",
                self.nodes_emitted,
                self.limits.max_nodes
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_algebra::{emit_tau_gate_v1, policy_equiv_robdd, CanonicalPolicy, PolicyExpr};

    fn lim() -> PolicyLimits {
        PolicyLimits::DEFAULT
    }

    #[test]
    fn parse_sbf_expr_respects_precedence_and_postfix_not() {
        let limits = lim();
        // a & b | c == (a & b) | c
        let expr = parse_tau_sbf_expr_v1("i_a[t] & i_b[t] | i_c[t]", limits).unwrap();
        let canon = CanonicalPolicy::new(expr, limits).unwrap();
        let tau = emit_tau_gate_v1(canon.expr(), "allow", limits).unwrap();
        // Roundtrip the emitted gate; should parse.
        let parsed = parse_emitted_tau_gate_allow_expr_v1(&tau, "allow", limits).unwrap();
        let r = policy_equiv_robdd(canon.expr(), &parsed, limits).unwrap();
        assert!(r.equivalent);

        // Postfix not binds tightest.
        let expr = parse_tau_sbf_expr_v1("i_a[t]' | i_b[t]", limits).unwrap();
        let canon = CanonicalPolicy::new(expr, limits).unwrap();
        // Sanity: ensure hash-stable.
        assert_eq!(canon.hash_v1(), CanonicalPolicy::new(canon.expr().clone(), limits).unwrap().hash_v1());
    }

    #[test]
    fn parse_emitted_gate_matches_policy_semantics_via_robdd() {
        let limits = lim();
        let a = PolicyExpr::atom("a", limits).unwrap();
        let b = PolicyExpr::atom("b", limits).unwrap();
        let ban = PolicyExpr::deny_if("ban", limits).unwrap();
        let expr = PolicyExpr::all(vec![a, PolicyExpr::any(vec![b, ban], limits).unwrap()], limits).unwrap();
        let canon = CanonicalPolicy::new(expr, limits).unwrap();

        let tau = emit_tau_gate_v1(canon.expr(), "allow", limits).unwrap();
        let parsed = parse_emitted_tau_gate_allow_expr_v1(&tau, "allow", limits).unwrap();
        let r = policy_equiv_robdd(canon.expr(), &parsed, limits).unwrap();
        assert!(r.equivalent);
    }

    #[test]
    fn parse_emitted_gate_requires_output_line() {
        let limits = lim();
        let err = parse_emitted_tau_gate_allow_expr_v1("defs\nq\n", "allow", limits).unwrap_err();
        assert!(err.to_string().contains("did not find output rule"));
    }
}

