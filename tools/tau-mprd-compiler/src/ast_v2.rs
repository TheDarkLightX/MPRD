//! AST definitions for Tau-MPRD v2 with arithmetic support.
//!
//! V2 extends v1 with:
//! - Arithmetic expressions (+, -, * const, / const)
//! - Typed expressions (u64 vs bool)
//! - Expression-level operations (min, max, clamp)

use std::fmt;

/// Top-level Tau-MPRD v2 specification.
#[derive(Debug, Clone)]
pub struct TauMprdSpecV2 {
    /// Temporal operator (must be Always for Tau-MPRD)
    pub temporal: TemporalOp,
    /// Body expression (must evaluate to bool)
    pub body: ExprV2,
}

/// Temporal operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalOp {
    Always,
    Sometimes, // Rejected by semantic analysis
}

/// Expression type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExprType {
    Bool,
    U64,
}

impl fmt::Display for ExprType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExprType::Bool => write!(f, "bool"),
            ExprType::U64 => write!(f, "u64"),
        }
    }
}

/// V2 Expression - typed expression tree.
#[derive(Debug, Clone)]
pub enum ExprV2 {
    // === Boolean expressions ===
    
    /// Logical AND
    And(Box<ExprV2>, Box<ExprV2>),
    
    /// Logical OR
    Or(Box<ExprV2>, Box<ExprV2>),
    
    /// Logical NOT
    Not(Box<ExprV2>),
    
    /// Comparison (produces bool from u64 operands)
    Compare(CompareOp, Box<ExprV2>, Box<ExprV2>),
    
    /// Boolean literal
    BoolLit(bool),
    
    // === Arithmetic expressions (u64) ===
    
    /// Addition (checked, fails on overflow)
    Add(Box<ExprV2>, Box<ExprV2>),
    
    /// Subtraction (checked, fails on underflow)
    Sub(Box<ExprV2>, Box<ExprV2>),
    
    /// Multiply by constant (checked)
    MulConst(Box<ExprV2>, u64),
    
    /// Divide by constant (checked, const != 0)
    DivConst(Box<ExprV2>, u64),
    
    /// Minimum of two values
    Min(Box<ExprV2>, Box<ExprV2>),
    
    /// Maximum of two values
    Max(Box<ExprV2>, Box<ExprV2>),
    
    /// Clamp value to range [lo, hi]
    Clamp(Box<ExprV2>, Box<ExprV2>, Box<ExprV2>),
    
    /// U64 literal constant
    U64Lit(u64),
    
    // === References ===
    
    /// State field reference
    StateField(FieldRef),
    
    /// Candidate field reference
    CandidateField(FieldRef),
}

impl ExprV2 {
    /// Get the type of this expression.
    pub fn expr_type(&self) -> ExprType {
        match self {
            // Boolean expressions
            ExprV2::And(_, _) => ExprType::Bool,
            ExprV2::Or(_, _) => ExprType::Bool,
            ExprV2::Not(_) => ExprType::Bool,
            ExprV2::Compare(_, _, _) => ExprType::Bool,
            ExprV2::BoolLit(_) => ExprType::Bool,
            
            // Arithmetic expressions
            ExprV2::Add(_, _) => ExprType::U64,
            ExprV2::Sub(_, _) => ExprType::U64,
            ExprV2::MulConst(_, _) => ExprType::U64,
            ExprV2::DivConst(_, _) => ExprType::U64,
            ExprV2::Min(_, _) => ExprType::U64,
            ExprV2::Max(_, _) => ExprType::U64,
            ExprV2::Clamp(_, _, _) => ExprType::U64,
            ExprV2::U64Lit(_) => ExprType::U64,
            
            // References (always u64 in v2)
            ExprV2::StateField(_) => ExprType::U64,
            ExprV2::CandidateField(_) => ExprType::U64,
        }
    }
    
    /// Check if this is a boolean expression.
    pub fn is_bool(&self) -> bool {
        self.expr_type() == ExprType::Bool
    }
    
    /// Check if this is a u64 expression.
    pub fn is_u64(&self) -> bool {
        self.expr_type() == ExprType::U64
    }
}

/// Comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,  // =
    Ne,  // !=
    Lt,  // <
    Le,  // <=
    Gt,  // >
    Ge,  // >=
}

impl fmt::Display for CompareOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompareOp::Eq => write!(f, "="),
            CompareOp::Ne => write!(f, "!="),
            CompareOp::Lt => write!(f, "<"),
            CompareOp::Le => write!(f, "<="),
            CompareOp::Gt => write!(f, ">"),
            CompareOp::Ge => write!(f, ">="),
        }
    }
}

/// Field reference with optional temporal offset.
#[derive(Debug, Clone)]
pub struct FieldRef {
    /// Field name
    pub name: String,
    /// Temporal offset (0 = current, 1 = t-1, etc.)
    pub temporal_offset: usize,
}

impl FieldRef {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            temporal_offset: 0,
        }
    }
    
    pub fn with_offset(name: impl Into<String>, offset: usize) -> Self {
        Self {
            name: name.into(),
            temporal_offset: offset,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn expr_types() {
        let add = ExprV2::Add(
            Box::new(ExprV2::U64Lit(1)),
            Box::new(ExprV2::U64Lit(2)),
        );
        assert_eq!(add.expr_type(), ExprType::U64);
        
        let cmp = ExprV2::Compare(
            CompareOp::Ge,
            Box::new(add),
            Box::new(ExprV2::U64Lit(0)),
        );
        assert_eq!(cmp.expr_type(), ExprType::Bool);
    }
    
    #[test]
    fn weighted_voting_ast() {
        // (state.w0 * candidate.v0 + state.w1 * candidate.v1) >= state.threshold
        let w0_v0 = ExprV2::MulConst(
            Box::new(ExprV2::StateField(FieldRef::new("w0"))),
            1, // placeholder - actual impl would parse candidate value
        );
        let sum = ExprV2::Add(
            Box::new(w0_v0),
            Box::new(ExprV2::U64Lit(0)),
        );
        let cmp = ExprV2::Compare(
            CompareOp::Ge,
            Box::new(sum),
            Box::new(ExprV2::StateField(FieldRef::new("threshold"))),
        );
        assert!(cmp.is_bool());
    }
}
