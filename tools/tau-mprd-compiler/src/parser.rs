//! Parser for Tau-MPRD.
//!
//! Converts token stream to AST with fail-closed error handling.

use crate::ast::*;
use crate::error::{CompileError, CompileResult};
use crate::lexer::{Token, TokenKind};

/// Parser state.
pub struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, pos: 0 }
    }
    
    fn current(&self) -> &Token {
        &self.tokens[self.pos.min(self.tokens.len() - 1)]
    }
    
    fn peek(&self) -> &TokenKind {
        &self.current().kind
    }
    
    fn line(&self) -> usize {
        self.current().line
    }
    
    fn advance(&mut self) -> Token {
        let tok = self.current().clone();
        if self.pos < self.tokens.len() - 1 {
            self.pos += 1;
        }
        tok
    }
    
    fn expect(&mut self, expected: TokenKind) -> CompileResult<Token> {
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
    
    fn at_end(&self) -> bool {
        matches!(self.peek(), TokenKind::Eof)
    }
    
    /// Parse a complete Tau-MPRD specification.
    fn parse_spec(&mut self) -> CompileResult<TauMprdSpec> {
        // Tau-MPRD requires explicit "always" / "[]" wrapper (fail-closed).
        let temporal = match self.peek() {
            TokenKind::Always => {
                self.advance();
                TemporalOp::Always
            }
            TokenKind::Sometimes => {
                let line = self.line();
                return Err(CompileError::SometimesNotSupported { line });
            }
            _ => {
                return Err(CompileError::UnexpectedToken {
                    found: format!("{:?}", self.peek()),
                    expected: "\"always\" or \"[]\"".to_string(),
                    line: self.line(),
                });
            }
        };
        
        let body = self.parse_local_spec()?;
        
        if !self.at_end() {
            return Err(CompileError::UnexpectedToken {
                found: format!("{:?}", self.peek()),
                expected: "end of input".to_string(),
                line: self.line(),
            });
        }
        
        Ok(TauMprdSpec { temporal, body })
    }
    
    /// Parse a local specification (logical formula).
    /// 
    /// Grammar (precedence low to high):
    /// local_spec => or_expr
    /// or_expr => and_expr ("||" and_expr)*
    /// and_expr => not_expr ("&&" not_expr)*
    /// not_expr => "!" not_expr | primary
    /// primary => comparison | "(" local_spec ")" | "T" | "F"
    fn parse_local_spec(&mut self) -> CompileResult<LocalSpec> {
        self.parse_or_expr()
    }
    
    fn parse_or_expr(&mut self) -> CompileResult<LocalSpec> {
        let mut left = self.parse_and_expr()?;
        
        while matches!(self.peek(), TokenKind::Or) {
            self.advance();
            let right = self.parse_and_expr()?;
            left = LocalSpec::or(left, right);
        }
        
        Ok(left)
    }
    
    fn parse_and_expr(&mut self) -> CompileResult<LocalSpec> {
        let mut left = self.parse_not_expr()?;
        
        while matches!(self.peek(), TokenKind::And) {
            self.advance();
            let right = self.parse_not_expr()?;
            left = LocalSpec::and(left, right);
        }
        
        Ok(left)
    }
    
    fn parse_not_expr(&mut self) -> CompileResult<LocalSpec> {
        if matches!(self.peek(), TokenKind::Not) {
            self.advance();
            let inner = self.parse_not_expr()?;
            Ok(LocalSpec::not(inner))
        } else {
            self.parse_primary()
        }
    }
    
    fn parse_primary(&mut self) -> CompileResult<LocalSpec> {
        match self.peek() {
            TokenKind::LParen => {
                self.advance();
                let inner = self.parse_local_spec()?;
                self.expect(TokenKind::RParen)?;
                Ok(inner)
            }
            TokenKind::Ident(s) if s == "T" || s == "true" => {
                self.advance();
                Ok(LocalSpec::True)
            }
            TokenKind::Ident(s) if s == "F" || s == "false" => {
                self.advance();
                Ok(LocalSpec::False)
            }
            _ => self.parse_comparison(),
        }
    }
    
    /// Parse a comparison: operand cmp_op operand
    fn parse_comparison(&mut self) -> CompileResult<LocalSpec> {
        let left = self.parse_operand()?;
        
        let op = match self.peek() {
            TokenKind::Eq => CompareOp::Eq,
            TokenKind::Ne => CompareOp::Ne,
            TokenKind::Lt => CompareOp::Lt,
            TokenKind::Le => CompareOp::Le,
            TokenKind::Gt => CompareOp::Gt,
            TokenKind::Ge => CompareOp::Ge,
            _ => {
                return Err(CompileError::UnexpectedToken {
                    found: format!("{:?}", self.peek()),
                    expected: "comparison operator (=, !=, <, <=, >, >=)".to_string(),
                    line: self.line(),
                });
            }
        };
        self.advance();
        
        let right = self.parse_operand()?;
        
        Ok(LocalSpec::compare(left, op, right))
    }
    
    /// Parse an operand: state.field, candidate.field, or constant.
    fn parse_operand(&mut self) -> CompileResult<Operand> {
        match self.peek().clone() {
            TokenKind::State => {
                self.advance();
                self.expect(TokenKind::Dot)?;
                let field = self.parse_field_ref()?;
                Ok(Operand::StateField(field))
            }
            TokenKind::Candidate => {
                self.advance();
                self.expect(TokenKind::Dot)?;
                let field = self.parse_field_ref()?;
                // Candidate fields cannot have temporal offset
                if field.temporal_offset != 0 {
                    return Err(CompileError::UnexpectedToken {
                        found: "temporal offset on candidate field".to_string(),
                        expected: "candidate fields cannot have temporal offsets".to_string(),
                        line: self.line(),
                    });
                }
                Ok(Operand::CandidateField(field))
            }
            TokenKind::Integer(n) => {
                self.advance();
                Ok(Operand::Constant(n))
            }
            _ => Err(CompileError::UnexpectedToken {
                found: format!("{:?}", self.peek()),
                expected: "operand (state.field, candidate.field, or integer)".to_string(),
                line: self.line(),
            }),
        }
    }
    
    /// Parse a field reference with optional temporal offset.
    fn parse_field_ref(&mut self) -> CompileResult<FieldRef> {
        let name = match self.peek().clone() {
            TokenKind::Ident(s) => {
                self.advance();
                s
            }
            _ => {
                return Err(CompileError::UnexpectedToken {
                    found: format!("{:?}", self.peek()),
                    expected: "field name".to_string(),
                    line: self.line(),
                });
            }
        };
        
        // Check for temporal offset: [t-k]
        let temporal_offset = if matches!(self.peek(), TokenKind::LBracket) {
            self.parse_temporal_offset()?
        } else {
            0
        };
        
        Ok(FieldRef { name, temporal_offset })
    }
    
    /// Parse temporal offset: [t-k] where k is a non-negative integer.
    fn parse_temporal_offset(&mut self) -> CompileResult<usize> {
        self.expect(TokenKind::LBracket)?;
        self.expect(TokenKind::T)?;
        
        let offset = if matches!(self.peek(), TokenKind::Minus) {
            self.advance();
            match self.peek() {
                TokenKind::Integer(n) => {
                    let n = *n;
                    self.advance();
                    n as usize
                }
                _ => {
                    return Err(CompileError::UnexpectedToken {
                        found: format!("{:?}", self.peek()),
                        expected: "integer offset".to_string(),
                        line: self.line(),
                    });
                }
            }
        } else {
            0 // [t] means current, same as no offset
        };
        
        self.expect(TokenKind::RBracket)?;
        
        Ok(offset)
    }
}

/// Parse tokens into an AST.
pub fn parse(tokens: &[Token]) -> CompileResult<TauMprdSpec> {
    let mut parser = Parser::new(tokens);
    parser.parse_spec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::tokenize;
    
    fn parse_source(source: &str) -> CompileResult<TauMprdSpec> {
        let tokens = tokenize(source)?;
        parse(&tokens)
    }
    
    #[test]
    fn parse_simple_comparison() {
        let ast = parse_source("always (state.balance >= candidate.amount)").unwrap();
        assert_eq!(ast.temporal, TemporalOp::Always);
        match ast.body {
            LocalSpec::Compare(cmp) => {
                assert_eq!(cmp.op, CompareOp::Ge);
            }
            _ => panic!("expected comparison"),
        }
    }
    
    #[test]
    fn parse_compound_and() {
        let ast = parse_source("always (state.x < 100 && state.y > 0)").unwrap();
        match ast.body {
            LocalSpec::And(_, _) => {}
            _ => panic!("expected And"),
        }
    }
    
    #[test]
    fn parse_compound_or() {
        let ast = parse_source("always (state.a = 1 || state.b = 2)").unwrap();
        match ast.body {
            LocalSpec::Or(_, _) => {}
            _ => panic!("expected Or"),
        }
    }
    
    #[test]
    fn parse_not() {
        let ast = parse_source("always !(state.x = 0)").unwrap();
        match ast.body {
            LocalSpec::Not(_) => {}
            _ => panic!("expected Not"),
        }
    }
    
    #[test]
    fn parse_temporal_offset() {
        let ast = parse_source("always (state.x[t-1] < state.x)").unwrap();
        match ast.body {
            LocalSpec::Compare(cmp) => {
                match cmp.left {
                    Operand::StateField(f) => assert_eq!(f.temporal_offset, 1),
                    _ => panic!("expected state field"),
                }
            }
            _ => panic!("expected comparison"),
        }
    }
    
    #[test]
    fn parse_box_notation() {
        let ast = parse_source("[] (state.x >= 0)").unwrap();
        assert_eq!(ast.temporal, TemporalOp::Always);
    }

    #[test]
    fn reject_missing_always() {
        let result = parse_source("(state.x >= 0)");
        assert!(result.is_err());
    }

    #[test]
    fn reject_bare_identifier_operand() {
        let result = parse_source("always (x >= 0)");
        assert!(result.is_err());
    }

    #[test]
    fn reject_sometimes() {
        let result = parse_source("sometimes (state.x = 0)");
        assert!(result.is_err());
    }
    
    #[test]
    fn parse_nested_logic() {
        let ast = parse_source("always ((state.a = 1 && state.b = 2) || !(state.c = 3))").unwrap();
        match ast.body {
            LocalSpec::Or(left, right) => {
                assert!(matches!(*left, LocalSpec::And(_, _)));
                assert!(matches!(*right, LocalSpec::Not(_)));
            }
            _ => panic!("expected Or"),
        }
    }
    
    #[test]
    fn parse_constant_comparison() {
        let ast = parse_source("always (candidate.amount <= 1000000)").unwrap();
        match ast.body {
            LocalSpec::Compare(cmp) => {
                assert!(matches!(cmp.right, Operand::Constant(1000000)));
            }
            _ => panic!("expected comparison"),
        }
    }
}
