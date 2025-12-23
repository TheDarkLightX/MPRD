//! Error types for KRR Layer 2.

use thiserror::Error;

/// Main error type for KRR operations.
#[derive(Debug, Error)]
pub enum KrrError {
    /// TML execution error.
    #[error("TML error: {0}")]
    TmlError(String),
    
    /// Justification extraction error.
    #[error("Justification extraction failed: {0}")]
    ExtractionError(String),
    
    /// Invalid trust score.
    #[error("Invalid trust score: {0}")]
    InvalidTrust(String),
    
    /// Parse error.
    #[error("Parse error: {0}")]
    ParseError(String),
    
    /// Compilation error.
    #[error("Compilation error: {0}")]
    CompileError(String),
    
    /// IO error.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
