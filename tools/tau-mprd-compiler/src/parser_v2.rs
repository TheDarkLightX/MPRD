//! Parser for Tau-MPRD v2 with arithmetic support.
//!
//! Grammar (simplified):
//! ```text
//! spec        := temporal '(' expr ')'
//! temporal    := 'always' | '[]' | 'sometimes'
//! expr        := or_expr
//! or_expr     := and_expr ('||' and_expr)*
//! and_expr    := cmp_expr ('&&' cmp_expr)*
//! cmp_expr    := arith_expr (cmp_op arith_expr)?
//! arith_expr  := term (('+' | '-') term)*
//! term        := factor (('*' | '/') INTEGER)?
//! factor      := '!' factor | '(' expr ')' | atom | func_call
//! func_call   := ('min' | 'max') '(' expr ',' expr ')' | 'clamp' '(' expr ',' expr ',' expr ')'
//! atom        := 'state' '.' IDENT temporal_offset? | 'candidate' '.' IDENT | INTEGER | 'true' | 'false'
//! cmp_op      := '=' | '!=' | '<' | '<=' | '>' | '>='
//! temporal_offset := '[t-' INTEGER ']'
//! ```

use crate::ast_v2::*;
use crate::error::{CompileError, CompileResult};
use crate::lexer_v2::{TokenKindV2, TokenV2};

/// Parser state.
struct ParserV2<'a> {
    tokens: &'a [TokenV2],
    pos: usize,
}

impl<'a> ParserV2<'a> {
    fn new(tokens: &'a [TokenV2]) -> Self {
        Self { tokens, pos: 0 }
    }
    
    fn current(&self) -> &TokenV2 {
        &self.tokens[self.pos.min(self.tokens.len() - 1)]
    }
    
    fn peek(&self) -> &TokenKindV2 {
        &self.current().kind
    }
    
    fn line(&self) -> usize {
        self.current().line
    }
    
    fn advance(&mut self) -> TokenV2 {
        let tok = self.current().clone();
        if self.pos < self.tokens.len() - 1 {
            self.pos += 1;
        }
        tok
    }
    
    fn expect(&mut self, expected: TokenKindV2) -> CompileResult<TokenV2> {
        if std::mem::discriminant(self.peek()) == std::mem::discriminant(&expected) {
            Ok(self.advance())
        } else {
            Err(CompileError::UnexpectedToken {
                found: format!("{:?}", self.peek()),
                expected: format!("{:?}", expected),
                line: self.line(),
            })
        }
    }
    
    fn check(&self, kind: &TokenKindV2) -> bool {
        std::mem::discriminant(self.peek()) == std::mem::discriminant(kind)
    }
    
    /// Parse top-level specification.
    fn parse_spec(&mut self) -> CompileResult<TauMprdSpecV2> {
        let temporal = self.parse_temporal()?;
        self.expect(TokenKindV2::LParen)?;
        let body = self.parse_expr()?;
        self.expect(TokenKindV2::RParen)?;

        if !body.is_bool() {
            return Err(CompileError::TypeMismatch {
                expected: "bool".to_string(),
                found: body.expr_type().to_string(),
                context: "top-level policy body".to_string(),
            });
        }
        
        Ok(TauMprdSpecV2 { temporal, body })
    }
    
    fn parse_temporal(&mut self) -> CompileResult<TemporalOp> {
        match self.peek() {
            TokenKindV2::Always => {
                self.advance();
                Ok(TemporalOp::Always)
            }
            TokenKindV2::Sometimes => {
                let line = self.line();
                self.advance();
                Err(CompileError::SometimesNotSupported { line })
            }
            _ => Err(CompileError::UnexpectedToken {
                found: format!("{:?}", self.peek()),
                expected: "always or []".to_string(),
                line: self.line(),
            }),
        }
    }
    
    /// Parse expression (entry point for recursion).
    fn parse_expr(&mut self) -> CompileResult<ExprV2> {
        self.parse_or_expr()
    }
    
    /// Parse OR expression: and_expr ('||' and_expr)*
    fn parse_or_expr(&mut self) -> CompileResult<ExprV2> {
        let mut left = self.parse_and_expr()?;
        
        while self.check(&TokenKindV2::Or) {
            self.advance();
            let right = self.parse_and_expr()?;
            
            // Type check: both must be bool
            if !left.is_bool() || !right.is_bool() {
                return Err(CompileError::TypeMismatch {
                    expected: "bool".to_string(),
                    found: format!("{} || {}", left.expr_type(), right.expr_type()),
                    context: "OR expression".to_string(),
                });
            }
            
            left = ExprV2::Or(Box::new(left), Box::new(right));
        }
        
        Ok(left)
    }
    
    /// Parse AND expression: cmp_expr ('&&' cmp_expr)*
    fn parse_and_expr(&mut self) -> CompileResult<ExprV2> {
        let mut left = self.parse_cmp_expr()?;
        
        while self.check(&TokenKindV2::And) {
            self.advance();
            let right = self.parse_cmp_expr()?;
            
            // Type check: both must be bool
            if !left.is_bool() || !right.is_bool() {
                return Err(CompileError::TypeMismatch {
                    expected: "bool".to_string(),
                    found: format!("{} && {}", left.expr_type(), right.expr_type()),
                    context: "AND expression".to_string(),
                });
            }
            
            left = ExprV2::And(Box::new(left), Box::new(right));
        }
        
        Ok(left)
    }
    
    /// Parse comparison expression: arith_expr (cmp_op arith_expr)?
    fn parse_cmp_expr(&mut self) -> CompileResult<ExprV2> {
        let left = self.parse_arith_expr()?;
        
        let cmp_op = match self.peek() {
            TokenKindV2::Eq => Some(CompareOp::Eq),
            TokenKindV2::Ne => Some(CompareOp::Ne),
            TokenKindV2::Lt => Some(CompareOp::Lt),
            TokenKindV2::Le => Some(CompareOp::Le),
            TokenKindV2::Gt => Some(CompareOp::Gt),
            TokenKindV2::Ge => Some(CompareOp::Ge),
            _ => None,
        };
        
        if let Some(op) = cmp_op {
            self.advance();
            let right = self.parse_arith_expr()?;
            
            // Type check: both must be u64
            if !left.is_u64() || !right.is_u64() {
                return Err(CompileError::TypeMismatch {
                    expected: "u64".to_string(),
                    found: format!("{} {} {}", left.expr_type(), op, right.expr_type()),
                    context: "comparison".to_string(),
                });
            }
            
            Ok(ExprV2::Compare(op, Box::new(left), Box::new(right)))
        } else {
            Ok(left)
        }
    }
    
    /// Parse arithmetic expression: term (('+' | '-') term)*
    fn parse_arith_expr(&mut self) -> CompileResult<ExprV2> {
        let mut left = self.parse_term()?;
        
        loop {
            match self.peek() {
                TokenKindV2::Plus => {
                    self.advance();
                    let right = self.parse_term()?;
                    
                    // Type check: both must be u64
                    if !left.is_u64() || !right.is_u64() {
                        return Err(CompileError::TypeMismatch {
                            expected: "u64".to_string(),
                            found: format!("{} + {}", left.expr_type(), right.expr_type()),
                            context: "addition".to_string(),
                        });
                    }
                    
                    left = ExprV2::Add(Box::new(left), Box::new(right));
                }
                TokenKindV2::Minus => {
                    self.advance();
                    let right = self.parse_term()?;
                    
                    // Type check: both must be u64
                    if !left.is_u64() || !right.is_u64() {
                        return Err(CompileError::TypeMismatch {
                            expected: "u64".to_string(),
                            found: format!("{} - {}", left.expr_type(), right.expr_type()),
                            context: "subtraction".to_string(),
                        });
                    }
                    
                    left = ExprV2::Sub(Box::new(left), Box::new(right));
                }
                _ => break,
            }
        }
        
        Ok(left)
    }
    
    /// Parse term: factor (('*' | '/') INTEGER)?
    fn parse_term(&mut self) -> CompileResult<ExprV2> {
        let mut left = self.parse_factor()?;
        
        loop {
            match self.peek() {
                TokenKindV2::Star => {
                    self.advance();
                    // Must be constant multiplication
                    let const_val = self.expect_integer()?;
                    
                    if !left.is_u64() {
                        return Err(CompileError::TypeMismatch {
                            expected: "u64".to_string(),
                            found: left.expr_type().to_string(),
                            context: "multiplication".to_string(),
                        });
                    }
                    
                    left = ExprV2::MulConst(Box::new(left), const_val);
                }
                TokenKindV2::Slash => {
                    self.advance();
                    // Must be constant division
                    let const_val = self.expect_integer()?;
                    
                    if const_val == 0 {
                        return Err(CompileError::DivisionByZero { line: self.line() });
                    }
                    
                    if !left.is_u64() {
                        return Err(CompileError::TypeMismatch {
                            expected: "u64".to_string(),
                            found: left.expr_type().to_string(),
                            context: "division".to_string(),
                        });
                    }
                    
                    left = ExprV2::DivConst(Box::new(left), const_val);
                }
                _ => break,
            }
        }
        
        Ok(left)
    }
    
    fn expect_integer(&mut self) -> CompileResult<u64> {
        match self.peek().clone() {
            TokenKindV2::Integer(v) => {
                self.advance();
                Ok(v)
            }
            _ => Err(CompileError::UnexpectedToken {
                found: format!("{:?}", self.peek()),
                expected: "integer constant".to_string(),
                line: self.line(),
            }),
        }
    }
    
    /// Parse factor: '!' factor | '(' expr ')' | atom | func_call
    fn parse_factor(&mut self) -> CompileResult<ExprV2> {
        match self.peek() {
            TokenKindV2::Not => {
                self.advance();
                let inner = self.parse_factor()?;
                
                if !inner.is_bool() {
                    return Err(CompileError::TypeMismatch {
                        expected: "bool".to_string(),
                        found: inner.expr_type().to_string(),
                        context: "NOT expression".to_string(),
                    });
                }
                
                Ok(ExprV2::Not(Box::new(inner)))
            }
            TokenKindV2::LParen => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect(TokenKindV2::RParen)?;
                Ok(expr)
            }
            TokenKindV2::Min => self.parse_min_max(true),
            TokenKindV2::Max => self.parse_min_max(false),
            TokenKindV2::Clamp => self.parse_clamp(),
            _ => self.parse_atom(),
        }
    }
    
    fn parse_min_max(&mut self, is_min: bool) -> CompileResult<ExprV2> {
        self.advance(); // consume min/max
        self.expect(TokenKindV2::LParen)?;
        let a = self.parse_expr()?;
        self.expect(TokenKindV2::Comma)?;
        let b = self.parse_expr()?;
        self.expect(TokenKindV2::RParen)?;
        
        // Type check: both must be u64
        if !a.is_u64() || !b.is_u64() {
            return Err(CompileError::TypeMismatch {
                expected: "u64".to_string(),
                found: format!("{}({}, {})", if is_min { "min" } else { "max" }, a.expr_type(), b.expr_type()),
                context: if is_min { "min" } else { "max" }.to_string(),
            });
        }
        
        if is_min {
            Ok(ExprV2::Min(Box::new(a), Box::new(b)))
        } else {
            Ok(ExprV2::Max(Box::new(a), Box::new(b)))
        }
    }
    
    fn parse_clamp(&mut self) -> CompileResult<ExprV2> {
        self.advance(); // consume clamp
        self.expect(TokenKindV2::LParen)?;
        let x = self.parse_expr()?;
        self.expect(TokenKindV2::Comma)?;
        let lo = self.parse_expr()?;
        self.expect(TokenKindV2::Comma)?;
        let hi = self.parse_expr()?;
        self.expect(TokenKindV2::RParen)?;
        
        // Type check: all must be u64
        if !x.is_u64() || !lo.is_u64() || !hi.is_u64() {
            return Err(CompileError::TypeMismatch {
                expected: "u64".to_string(),
                found: format!("clamp({}, {}, {})", x.expr_type(), lo.expr_type(), hi.expr_type()),
                context: "clamp".to_string(),
            });
        }
        
        Ok(ExprV2::Clamp(Box::new(x), Box::new(lo), Box::new(hi)))
    }
    
    /// Parse atom: state.field, candidate.field, integer, bool
    fn parse_atom(&mut self) -> CompileResult<ExprV2> {
        match self.peek().clone() {
            TokenKindV2::State => {
                self.advance();
                self.expect(TokenKindV2::Dot)?;
                let name = self.expect_ident()?;
                let offset = self.parse_optional_temporal_offset()?;
                Ok(ExprV2::StateField(FieldRef::with_offset(name, offset)))
            }
            TokenKindV2::Candidate => {
                self.advance();
                self.expect(TokenKindV2::Dot)?;
                let name = self.expect_ident()?;
                // Candidate fields cannot have temporal offset
                Ok(ExprV2::CandidateField(FieldRef::new(name)))
            }
            TokenKindV2::Integer(v) => {
                self.advance();
                Ok(ExprV2::U64Lit(v))
            }
            TokenKindV2::True => {
                self.advance();
                Ok(ExprV2::BoolLit(true))
            }
            TokenKindV2::False => {
                self.advance();
                Ok(ExprV2::BoolLit(false))
            }
            _ => Err(CompileError::UnexpectedToken {
                found: format!("{:?}", self.peek()),
                expected: "state, candidate, integer, or boolean".to_string(),
                line: self.line(),
            }),
        }
    }
    
    fn expect_ident(&mut self) -> CompileResult<String> {
        match self.peek().clone() {
            TokenKindV2::Ident(s) => {
                self.advance();
                Ok(s)
            }
            _ => Err(CompileError::UnexpectedToken {
                found: format!("{:?}", self.peek()),
                expected: "identifier".to_string(),
                line: self.line(),
            }),
        }
    }
    
    fn parse_optional_temporal_offset(&mut self) -> CompileResult<usize> {
        match self.peek() {
            TokenKindV2::TemporalOffset(n) => {
                let offset = *n;
                self.advance();
                Ok(offset)
            }
            _ => Ok(0),
        }
    }
}

/// Parse Tau-MPRD v2 tokens into AST.
pub fn parse_v2(tokens: &[TokenV2]) -> CompileResult<TauMprdSpecV2> {
    let mut parser = ParserV2::new(tokens);
    parser.parse_spec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer_v2::tokenize_v2;
    
    fn parse_source(source: &str) -> CompileResult<TauMprdSpecV2> {
        let tokens = tokenize_v2(source)?;
        parse_v2(&tokens)
    }
    
    #[test]
    fn parse_simple_comparison() {
        let ast = parse_source("always (state.x >= 100)").unwrap();
        assert_eq!(ast.temporal, TemporalOp::Always);
        assert!(ast.body.is_bool());
    }
    
    #[test]
    fn parse_arithmetic() {
        let ast = parse_source("always (state.x + state.y >= 100)").unwrap();
        assert!(ast.body.is_bool());
    }
    
    #[test]
    fn parse_mul_const() {
        let ast = parse_source("always (state.weight * 2 >= state.threshold)").unwrap();
        assert!(ast.body.is_bool());
    }
    
    #[test]
    fn parse_weighted_voting() {
        let ast = parse_source(
            "always (state.w0 * 1 + state.w1 * 1 + state.w2 * 1 >= state.threshold)"
        ).unwrap();
        assert!(ast.body.is_bool());
    }
    
    #[test]
    fn parse_min_max() {
        let ast = parse_source("always (min(state.a, state.b) >= 0)").unwrap();
        assert!(ast.body.is_bool());
    }
    
    #[test]
    fn parse_clamp() {
        let ast = parse_source("always (clamp(state.x, 0, 100) >= 50)").unwrap();
        assert!(ast.body.is_bool());
    }
    
    #[test]
    fn reject_sometimes() {
        let result = parse_source("sometimes (state.x = 0)");
        assert!(matches!(result, Err(CompileError::SometimesNotSupported { .. })));
    }
    
    #[test]
    fn reject_div_by_zero() {
        let result = parse_source("always (state.x / 0 >= 0)");
        assert!(matches!(result, Err(CompileError::DivisionByZero { .. })));
    }
    
    #[test]
    fn type_check_and() {
        // Can't AND u64 values
        let result = parse_source("always (state.x && state.y)");
        assert!(matches!(result, Err(CompileError::TypeMismatch { .. })));
    }
}
