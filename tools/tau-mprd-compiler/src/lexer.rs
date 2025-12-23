//! Lexical analyzer for Tau-MPRD.
//!
//! Tokenizes input into a stream of tokens for the parser.

use crate::error::{CompileError, CompileResult};

/// Token types for Tau-MPRD subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    // Keywords
    Always,      // "always" or "[]"
    Sometimes,   // "sometimes" or "<>" (rejected in parser)
    
    // Logical operators
    And,         // "&&"
    Or,          // "||"
    Not,         // "!"
    
    // Comparison operators
    Eq,          // "="
    Ne,          // "!="
    Lt,          // "<"
    Le,          // "<="
    Gt,          // ">"
    Ge,          // ">="
    
    // Delimiters
    LParen,      // "("
    RParen,      // ")"
    LBracket,    // "["
    RBracket,    // "]"
    Dot,         // "."
    Minus,       // "-" (for temporal offset)
    
    // Literals and identifiers
    Integer(u64),
    Ident(String),
    
    // Special keywords for operand sources
    State,       // "state"
    Candidate,   // "candidate"
    
    // Temporal variable
    T,           // "t"
    
    // End of input
    Eof,
}

/// Token with source location.
#[derive(Debug, Clone)]
pub struct Token {
    pub kind: TokenKind,
    pub line: usize,
    pub col: usize,
}

impl Token {
    pub fn new(kind: TokenKind, line: usize, col: usize) -> Self {
        Self { kind, line, col }
    }
}

/// Lexer state.
struct Lexer<'a> {
    #[allow(dead_code)]
    input: &'a str,
    chars: std::iter::Peekable<std::str::CharIndices<'a>>,
    line: usize,
    col: usize,
    last_newline_pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            chars: input.char_indices().peekable(),
            line: 1,
            col: 1,
            last_newline_pos: 0,
        }
    }
    
    fn peek(&mut self) -> Option<char> {
        self.chars.peek().map(|(_, c)| *c)
    }
    
    fn advance(&mut self) -> Option<(usize, char)> {
        let result = self.chars.next();
        if let Some((pos, ch)) = result {
            if ch == '\n' {
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
        while let Some(ch) = self.peek() {
            if ch.is_whitespace() {
                self.advance();
            } else if ch == '/' {
                // Check for comments
                let mut chars_copy = self.chars.clone();
                chars_copy.next();
                if let Some((_, '/')) = chars_copy.next() {
                    // Line comment - skip to end of line
                    self.advance(); // consume first '/'
                    self.advance(); // consume second '/'
                    while let Some(ch) = self.peek() {
                        if ch == '\n' {
                            break;
                        }
                        self.advance();
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }
    
    fn read_integer(&mut self, first_digit: char, start_line: usize) -> CompileResult<Token> {
        let start_col = self.col;
        let mut literal = String::new();
        literal.push(first_digit);
        
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                literal.push(ch);
                self.advance();
            } else {
                break;
            }
        }
        
        let value: u64 = literal.parse().map_err(|_| {
            if literal.len() > 20 {
                CompileError::IntegerOverflow { literal: literal.clone(), line: start_line }
            } else {
                CompileError::InvalidInteger { value: literal.clone(), line: start_line }
            }
        })?;
        
        Ok(Token::new(TokenKind::Integer(value), start_line, start_col))
    }
    
    fn read_ident(&mut self, first_char: char) -> Token {
        let start_line = self.line;
        let start_col = self.col;
        let mut ident = String::new();
        ident.push(first_char);
        
        while let Some(ch) = self.peek() {
            if ch.is_alphanumeric() || ch == '_' {
                ident.push(ch);
                self.advance();
            } else {
                break;
            }
        }
        
        // Check for keywords
        let kind = match ident.as_str() {
            "always" => TokenKind::Always,
            "sometimes" => TokenKind::Sometimes,
            "state" => TokenKind::State,
            "candidate" => TokenKind::Candidate,
            "t" => TokenKind::T,
            _ => TokenKind::Ident(ident),
        };
        
        Token::new(kind, start_line, start_col)
    }
    
    fn next_token(&mut self) -> CompileResult<Token> {
        self.skip_whitespace();
        
        let line = self.line;
        let col = self.col;
        
        let Some((_, ch)) = self.advance() else {
            return Ok(Token::new(TokenKind::Eof, line, col));
        };
        
        match ch {
            '(' => Ok(Token::new(TokenKind::LParen, line, col)),
            ')' => Ok(Token::new(TokenKind::RParen, line, col)),
            '[' => {
                // Check for "[]" (always)
                if self.peek() == Some(']') {
                    self.advance();
                    Ok(Token::new(TokenKind::Always, line, col))
                } else {
                    Ok(Token::new(TokenKind::LBracket, line, col))
                }
            }
            ']' => Ok(Token::new(TokenKind::RBracket, line, col)),
            '.' => Ok(Token::new(TokenKind::Dot, line, col)),
            '-' => Ok(Token::new(TokenKind::Minus, line, col)),
            
            '&' => {
                if self.peek() == Some('&') {
                    self.advance();
                    Ok(Token::new(TokenKind::And, line, col))
                } else {
                    Err(CompileError::UnexpectedChar { ch: '&', line, col })
                }
            }
            
            '|' => {
                if self.peek() == Some('|') {
                    self.advance();
                    Ok(Token::new(TokenKind::Or, line, col))
                } else {
                    Err(CompileError::UnexpectedChar { ch: '|', line, col })
                }
            }
            
            '!' => {
                if self.peek() == Some('=') {
                    self.advance();
                    Ok(Token::new(TokenKind::Ne, line, col))
                } else {
                    Ok(Token::new(TokenKind::Not, line, col))
                }
            }
            
            '=' => Ok(Token::new(TokenKind::Eq, line, col)),
            
            '<' => {
                match self.peek() {
                    Some('=') => {
                        self.advance();
                        Ok(Token::new(TokenKind::Le, line, col))
                    }
                    Some('>') => {
                        // "<>" = sometimes
                        self.advance();
                        Ok(Token::new(TokenKind::Sometimes, line, col))
                    }
                    _ => Ok(Token::new(TokenKind::Lt, line, col)),
                }
            }
            
            '>' => {
                if self.peek() == Some('=') {
                    self.advance();
                    Ok(Token::new(TokenKind::Ge, line, col))
                } else {
                    Ok(Token::new(TokenKind::Gt, line, col))
                }
            }
            
            _ if ch.is_ascii_digit() => self.read_integer(ch, line),
            _ if ch.is_alphabetic() || ch == '_' => Ok(self.read_ident(ch)),
            
            _ => Err(CompileError::UnexpectedChar { ch, line, col }),
        }
    }
}

/// Tokenize input source into a vector of tokens.
pub fn tokenize(source: &str) -> CompileResult<Vec<Token>> {
    let mut lexer = Lexer::new(source);
    let mut tokens = Vec::new();
    
    loop {
        let token = lexer.next_token()?;
        let is_eof = token.kind == TokenKind::Eof;
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
    
    #[test]
    fn tokenize_simple_comparison() {
        let tokens = tokenize("state.x >= 100").unwrap();
        assert_eq!(tokens.len(), 6); // state, ., x, >=, 100, EOF
        assert_eq!(tokens[0].kind, TokenKind::State);
        assert_eq!(tokens[1].kind, TokenKind::Dot);
        assert!(matches!(tokens[2].kind, TokenKind::Ident(ref s) if s == "x"));
        assert_eq!(tokens[3].kind, TokenKind::Ge);
        assert_eq!(tokens[4].kind, TokenKind::Integer(100));
        assert_eq!(tokens[5].kind, TokenKind::Eof);
    }
    
    #[test]
    fn tokenize_always_policy() {
        let tokens = tokenize("always (state.balance >= candidate.amount)").unwrap();
        assert_eq!(tokens[0].kind, TokenKind::Always);
    }
    
    #[test]
    fn tokenize_box_notation() {
        let tokens = tokenize("[] (state.x = 0)").unwrap();
        assert_eq!(tokens[0].kind, TokenKind::Always);
    }
    
    #[test]
    fn tokenize_temporal_offset() {
        let tokens = tokenize("state.x[t-1]").unwrap();
        assert_eq!(tokens[0].kind, TokenKind::State);
        assert_eq!(tokens[3].kind, TokenKind::LBracket);
        assert_eq!(tokens[4].kind, TokenKind::T);
        assert_eq!(tokens[5].kind, TokenKind::Minus);
        assert_eq!(tokens[6].kind, TokenKind::Integer(1));
    }
    
    #[test]
    fn tokenize_logical_operators() {
        let tokens = tokenize("!a && b || c").unwrap();
        assert_eq!(tokens[0].kind, TokenKind::Not);
        assert_eq!(tokens[2].kind, TokenKind::And);
        assert_eq!(tokens[4].kind, TokenKind::Or);
    }
    
    #[test]
    fn tokenize_comments() {
        let tokens = tokenize("state.x // this is a comment\n >= 0").unwrap();
        assert_eq!(tokens[0].kind, TokenKind::State);
        assert_eq!(tokens[1].kind, TokenKind::Dot);
        assert!(matches!(tokens[2].kind, TokenKind::Ident(ref s) if s == "x"));
        assert_eq!(tokens[3].kind, TokenKind::Ge);
        assert_eq!(tokens[4].kind, TokenKind::Integer(0));
    }
    
    #[test]
    fn reject_invalid_char() {
        let result = tokenize("state.x @ 0");
        assert!(result.is_err());
    }
}
