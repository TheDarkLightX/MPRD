//! Compiler error types (fail-closed semantics).
//!
//! All errors are terminal - the compiler does not attempt recovery.

use thiserror::Error;

/// Result type for compilation operations.
pub type CompileResult<T> = Result<T, CompileError>;

/// Compilation error with source location and detailed message.
#[derive(Debug, Error)]
pub enum CompileError {
    // =========================================================================
    // Lexer errors
    // =========================================================================
    
    #[error("unexpected character '{ch}' at line {line}, column {col}")]
    UnexpectedChar { ch: char, line: usize, col: usize },
    
    #[error("unexpected character '{ch}' at line {line}")]
    UnexpectedCharacter { ch: char, line: usize },
    
    #[error("invalid integer '{value}' at line {line}")]
    InvalidInteger { value: String, line: usize },
    
    #[error("invalid temporal offset at line {line}")]
    InvalidTemporalOffset { line: usize },
    
    #[error("unterminated string literal at line {line}")]
    UnterminatedString { line: usize },
    
    #[error("invalid integer literal '{literal}' at line {line}")]
    InvalidIntegerLiteral { literal: String, line: usize },
    
    #[error("integer literal '{literal}' exceeds u64::MAX at line {line}")]
    IntegerOverflow { literal: String, line: usize },
    
    // =========================================================================
    // Parser errors
    // =========================================================================
    
    #[error("unexpected token '{found}' at line {line}, expected {expected}")]
    UnexpectedToken { found: String, expected: String, line: usize },
    
    #[error("unexpected end of input, expected {expected}")]
    UnexpectedEof { expected: String },
    
    #[error("missing 'always' temporal operator - Tau-MPRD requires explicit 'always' wrapper")]
    MissingAlways,
    
    #[error("'sometimes' is not supported in Tau-MPRD (non-deterministic)")]
    SometimesNotSupported { line: usize },
    
    #[error("quantifier '{quantifier}' is not supported in Tau-MPRD")]
    QuantifierNotSupported { quantifier: String, line: usize },
    
    #[error("bitvector arithmetic '{op}' is not supported in Tau-MPRD")]
    BitvectorArithmeticNotSupported { op: String, line: usize },
    
    #[error("stream I/O '{stream}' is not supported in Tau-MPRD - use state/candidate references")]
    StreamNotSupported { stream: String, line: usize },
    
    #[error("recurrence relation with unbounded index is not supported")]
    UnboundedRecurrence { line: usize },
    
    // =========================================================================
    // Semantic errors
    // =========================================================================
    
    #[error("unknown field '{field}' in {context} - must be declared in schema")]
    UnknownField { field: String, context: String },
    
    #[error("type mismatch: expected {expected}, found {found} for '{context}'")]
    TypeMismatch { expected: String, found: String, context: String },
    
    #[error("temporal lookback {lookback} exceeds MAX_LOOKBACK ({max})")]
    LookbackExceeded { lookback: usize, max: usize },
    
    #[error("predicate count {count} exceeds MAX_PREDICATES ({max})")]
    PredicateCountExceeded { count: usize, max: usize },
    
    #[error("gate count {count} exceeds MAX_GATES ({max})")]
    GateCountExceeded { count: usize, max: usize },
    
    #[error("node count {count} exceeds MAX_NODES ({max})")]
    NodeCountExceeded { count: usize, max: usize },
    
    #[error("division by zero constant at line {line}")]
    DivisionByZero { line: usize },
    
    #[error("temporal field count {count} exceeds MAX_TEMPORAL_FIELDS ({max})")]
    TemporalFieldCountExceeded { count: usize, max: usize },
    
    #[error("wire index {index} exceeds MAX_WIRES ({max})")]
    WireIndexExceeded { index: usize, max: usize },
    
    #[error("comparison operands have incompatible types: {left} vs {right}")]
    IncompatibleOperandTypes { left: String, right: String },
    
    #[error("constant {value} exceeds u64::MAX")]
    ConstantOverflow { value: String },
    
    // =========================================================================
    // IR errors
    // =========================================================================
    
    #[error("circular dependency detected in predicate definitions")]
    CircularDependency,
    
    #[error("empty policy - at least one constraint required")]
    EmptyPolicy,
    
    #[error("unreachable wire {wire} in circuit")]
    UnreachableWire { wire: u32 },
    
    // =========================================================================
    // Code generation errors
    // =========================================================================
    
    #[error("failed to topologically sort gates - cycle detected")]
    TopologicalSortFailed,
    
    #[error("output wire {wire} not defined by any gate")]
    OutputWireUndefined { wire: u32 },
    
    // =========================================================================
    // Serialization errors
    // =========================================================================

    #[error("artifact size {size} exceeds MAX_COMPILED_POLICY_BYTES ({max})")]
    ArtifactTooLarge { size: usize, max: usize },

    #[error("unsupported compiled artifact version {version}")]
    UnsupportedArtifactVersion { version: u32 },

    #[error("trailing bytes in artifact ({remaining} bytes)")]
    TrailingBytes { remaining: usize },

    #[error("duplicate out_wire {wire} in circuit")]
    DuplicateWire { wire: u32 },

    #[error("key '{key}' exceeds MAX_KEY_LENGTH ({max})")]
    KeyTooLong { key: String, max: usize },

    #[error("invalid key name '{key}' at line {line} (expected [a-z][a-z0-9_]* )")]
    InvalidKeyName { key: String, line: usize },

    #[error("key name '{key}' uses reserved temporal suffix pattern '_t_<n>' at line {line}")]
    ReservedTemporalSuffix { key: String, line: usize },
    
    // =========================================================================
    // Internal errors (should not occur in correct implementation)
    // =========================================================================
    
    #[error("internal compiler error: {message}")]
    Internal { message: String },
}

impl CompileError {
    /// Create an internal error (indicates compiler bug).
    pub fn internal(message: impl Into<String>) -> Self {
        CompileError::Internal { message: message.into() }
    }
}
