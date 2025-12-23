//! Lexer for Tau-MPRD v2 with arithmetic support.

use crate::error::{CompileError, CompileResult};
use crate::limits::{MAX_KEY_LENGTH_V1, MAX_LOOKBACK_V1};

/// Token kinds for v2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKindV2 {
    // Keywords
    Always,
    Sometimes,
    State,
    Candidate,
    True,
    False,
    Min,
    Max,
    Clamp,
    
    // Operators - Boolean
    And,      // &&
    Or,       // ||
    Not,      // !
    
    // Operators - Comparison
    Eq,       // =
    Ne,       // !=
    Lt,       // <
    Le,       // <=
    Gt,       // >
    Ge,       // >=
    
    // Operators - Arithmetic
    Plus,     // +
    Minus,    // -
    Star,     // *
    Slash,    // /
    
    // Delimiters
    LParen,
    RParen,
    LBracket,
    RBracket,
    Dot,
    Comma,
    
    // Literals
    Integer(u64),
    Ident(String),
    
    // Special
    TemporalOffset(usize),  // [t-N]
    Eof,
}

/// Token with position info.
#[derive(Debug, Clone)]
pub struct TokenV2 {
    pub kind: TokenKindV2,
    pub line: usize,
    pub col: usize,
}

impl TokenV2 {
    pub fn new(kind: TokenKindV2, line: usize, col: usize) -> Self {
        Self { kind, line, col }
    }
}

/// Lexer state.
struct LexerV2<'a> {
    #[allow(dead_code)]
    input: &'a str,
    chars: std::iter::Peekable<std::str::CharIndices<'a>>,
    line: usize,
    col: usize,
    last_newline_pos: usize,
}

impl<'a> LexerV2<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            chars: input.char_indices().peekable(),
            line: 1,
            col: 1,
            last_newline_pos: 0,
        }
    }
    
    fn peek_char(&mut self) -> Option<char> {
        self.chars.peek().map(|&(_, c)| c)
    }
    
    fn next_char(&mut self) -> Option<(usize, char)> {
        let result = self.chars.next();
        if let Some((pos, c)) = result {
            if c == '\n' {
                self.line += 1;
                self.last_newline_pos = pos;
                self.col = 1;
            } else {
                self.col = pos - self.last_newline_pos + 1;
            }
        }
        result
    }
    
    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek_char() {
            if c.is_whitespace() {
                self.next_char();
            } else if c == '/' {
                // Check for comment
                let mut chars_clone = self.chars.clone();
                chars_clone.next();
                if chars_clone.peek().map(|&(_, c)| c) == Some('/') {
                    // Line comment
                    while let Some(c) = self.peek_char() {
                        if c == '\n' {
                            break;
                        }
                        self.next_char();
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }
    
    fn read_number(&mut self, first_digit: char) -> CompileResult<u64> {
        let mut s = String::new();
        s.push(first_digit);
        
        while let Some(c) = self.peek_char() {
            if c.is_ascii_digit() || c == '_' {
                if c != '_' {
                    s.push(c);
                }
                self.next_char();
            } else {
                break;
            }
        }
        
        s.parse::<u64>().map_err(|_| CompileError::InvalidInteger {
            value: s,
            line: self.line,
        })
    }
    
    fn read_identifier(&mut self, first_char: char) -> String {
        let mut s = String::new();
        s.push(first_char);
        
        while let Some(c) = self.peek_char() {
            if c.is_alphanumeric() || c == '_' {
                s.push(c);
                self.next_char();
            } else {
                break;
            }
        }
        
        s
    }

    fn validate_key_name(&self, name: &str, line: usize) -> CompileResult<()> {
        if name.len() > MAX_KEY_LENGTH_V1 {
            return Err(CompileError::KeyTooLong {
                key: name.to_string(),
                max: MAX_KEY_LENGTH_V1,
            });
        }

        // Enforce a stable key subset so hashing and canonical preimages don't drift:
        // keys are lowercase snake_case ([a-z][a-z0-9_]*).
        let mut chars = name.chars();
        let Some(first) = chars.next() else {
            return Err(CompileError::InvalidKeyName {
                key: name.to_string(),
                line,
            });
        };
        if !first.is_ascii_lowercase() {
            return Err(CompileError::InvalidKeyName {
                key: name.to_string(),
                line,
            });
        }
        for c in chars {
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
                return Err(CompileError::InvalidKeyName {
                    key: name.to_string(),
                    line,
                });
            }
        }

        // Reserve the temporal suffix namespace: lookbacks are represented as `<name>_t_<k>`.
        if let Some((_, suffix)) = name.rsplit_once("_t_") {
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                return Err(CompileError::ReservedTemporalSuffix {
                    key: name.to_string(),
                    line,
                });
            }
        }

        Ok(())
    }
    
    fn read_temporal_offset(&mut self) -> CompileResult<usize> {
        // Already consumed '[', expect 't-N]'
        self.skip_whitespace();
        
        // Expect 't'
        match self.next_char() {
            Some((_, 't')) => {}
            _ => return Err(CompileError::InvalidTemporalOffset { line: self.line }),
        }
        
        self.skip_whitespace();
        
        // Expect '-'
        match self.next_char() {
            Some((_, '-')) => {}
            _ => return Err(CompileError::InvalidTemporalOffset { line: self.line }),
        }
        
        self.skip_whitespace();
        
        // Expect number
        let offset = match self.next_char() {
            Some((_, c)) if c.is_ascii_digit() => self.read_number(c)? as usize,
            _ => return Err(CompileError::InvalidTemporalOffset { line: self.line }),
        };

        if offset == 0 {
            return Err(CompileError::InvalidTemporalOffset { line: self.line });
        }
        if offset > MAX_LOOKBACK_V1 {
            return Err(CompileError::LookbackExceeded {
                lookback: offset,
                max: MAX_LOOKBACK_V1,
            });
        }
        
        self.skip_whitespace();
        
        // Expect ']'
        match self.next_char() {
            Some((_, ']')) => {}
            _ => return Err(CompileError::InvalidTemporalOffset { line: self.line }),
        }
        
        Ok(offset)
    }
    
    fn next_token(&mut self) -> CompileResult<TokenV2> {
        self.skip_whitespace();
        
        let line = self.line;
        let col = self.col;
        
        let Some((_, c)) = self.next_char() else {
            return Ok(TokenV2::new(TokenKindV2::Eof, line, col));
        };
        
        let kind = match c {
            '(' => TokenKindV2::LParen,
            ')' => TokenKindV2::RParen,
            '.' => TokenKindV2::Dot,
            ',' => TokenKindV2::Comma,
            '+' => TokenKindV2::Plus,
            '-' => TokenKindV2::Minus,
            '*' => TokenKindV2::Star,
            '/' => TokenKindV2::Slash,
            
            '[' => {
                // Check if temporal offset [t-N] or box notation
                if self.peek_char() == Some(']') {
                    self.next_char();
                    TokenKindV2::Always // [] = always
                } else {
                    let offset = self.read_temporal_offset()?;
                    TokenKindV2::TemporalOffset(offset)
                }
            }
            
            '&' => {
                if self.peek_char() == Some('&') {
                    self.next_char();
                    TokenKindV2::And
                } else {
                    return Err(CompileError::UnexpectedCharacter { ch: c, line });
                }
            }
            
            '|' => {
                if self.peek_char() == Some('|') {
                    self.next_char();
                    TokenKindV2::Or
                } else {
                    return Err(CompileError::UnexpectedCharacter { ch: c, line });
                }
            }
            
            '!' => {
                if self.peek_char() == Some('=') {
                    self.next_char();
                    TokenKindV2::Ne
                } else {
                    TokenKindV2::Not
                }
            }
            
            '=' => TokenKindV2::Eq,
            
            '<' => {
                if self.peek_char() == Some('=') {
                    self.next_char();
                    TokenKindV2::Le
                } else {
                    TokenKindV2::Lt
                }
            }
            
            '>' => {
                if self.peek_char() == Some('=') {
                    self.next_char();
                    TokenKindV2::Ge
                } else {
                    TokenKindV2::Gt
                }
            }
            
            c if c.is_ascii_digit() => {
                let value = self.read_number(c)?;
                TokenKindV2::Integer(value)
            }
            
            c if c.is_alphabetic() || c == '_' => {
                let ident = self.read_identifier(c);
                match ident.as_str() {
                    "always" => TokenKindV2::Always,
                    "sometimes" => TokenKindV2::Sometimes,
                    "state" => TokenKindV2::State,
                    "candidate" => TokenKindV2::Candidate,
                    "true" => TokenKindV2::True,
                    "false" => TokenKindV2::False,
                    "min" => TokenKindV2::Min,
                    "max" => TokenKindV2::Max,
                    "clamp" => TokenKindV2::Clamp,
                    _ => {
                        self.validate_key_name(&ident, line)?;
                        TokenKindV2::Ident(ident)
                    }
                }
            }
            
            _ => return Err(CompileError::UnexpectedCharacter { ch: c, line }),
        };
        
        Ok(TokenV2::new(kind, line, col))
    }
}

/// Tokenize Tau-MPRD v2 source.
pub fn tokenize_v2(source: &str) -> CompileResult<Vec<TokenV2>> {
    let mut lexer = LexerV2::new(source);
    let mut tokens = Vec::new();
    
    loop {
        let token = lexer.next_token()?;
        let is_eof = token.kind == TokenKindV2::Eof;
        tokens.push(token);
        if is_eof {
            break;
        }
    }
    
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CompileError;
    
    #[test]
    fn tokenize_arithmetic() {
        let tokens = tokenize_v2("state.x + state.y * 2").unwrap();
        assert!(matches!(tokens[0].kind, TokenKindV2::State));
        assert!(matches!(tokens[2].kind, TokenKindV2::Ident(ref s) if s == "x"));
        assert!(matches!(tokens[3].kind, TokenKindV2::Plus));
        assert!(matches!(tokens[7].kind, TokenKindV2::Star));
        assert!(matches!(tokens[8].kind, TokenKindV2::Integer(2)));
    }
    
    #[test]
    fn tokenize_min_max() {
        let tokens = tokenize_v2("min(state.a, state.b)").unwrap();
        assert!(matches!(tokens[0].kind, TokenKindV2::Min));
        assert!(matches!(tokens[1].kind, TokenKindV2::LParen));
    }
    
    #[test]
    fn tokenize_weighted_voting() {
        let tokens = tokenize_v2(
            "always (state.w0 * candidate.v0 + state.w1 * candidate.v1 >= state.threshold)"
        ).unwrap();
        assert!(matches!(tokens[0].kind, TokenKindV2::Always));
    }

    #[test]
    fn rejects_invalid_key_name_uppercase() {
        let err = tokenize_v2("always (state.X >= 1)").unwrap_err();
        assert!(matches!(err, CompileError::InvalidKeyName { .. }));
    }

    #[test]
    fn rejects_reserved_temporal_suffix_in_key_name() {
        let err = tokenize_v2("always (state.x_t_1 >= 1)").unwrap_err();
        assert!(matches!(err, CompileError::ReservedTemporalSuffix { .. }));
    }

    #[test]
    fn rejects_temporal_offset_zero() {
        let err = tokenize_v2("always (state.x[t-0] >= 1)").unwrap_err();
        assert!(matches!(err, CompileError::InvalidTemporalOffset { .. }));
    }

    #[test]
    fn rejects_temporal_offset_too_large() {
        let err = tokenize_v2("always (state.x[t-9] >= 1)").unwrap_err();
        assert!(matches!(err, CompileError::LookbackExceeded { .. }));
    }
}
