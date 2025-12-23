//! Abstract Syntax Tree for Tau-MPRD.
//!
//! Represents the parsed structure of a Tau-MPRD policy specification.

use std::fmt;

/// A complete Tau-MPRD specification.
#[derive(Debug, Clone)]
pub struct TauMprdSpec {
    /// The temporal wrapper (must be Always for Tau-MPRD).
    pub temporal: TemporalOp,
    /// The local specification (constraint formula).
    pub body: LocalSpec,
}

/// Temporal operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalOp {
    /// Universal temporal quantification (always / []).
    Always,
    /// Existential temporal quantification (sometimes / <>).
    /// NOTE: Not supported in Tau-MPRD, but parsed for error reporting.
    Sometimes,
}

/// Local specification (formula at a fixed time point).
#[derive(Debug, Clone)]
pub enum LocalSpec {
    /// Logical AND: spec1 && spec2
    And(Box<LocalSpec>, Box<LocalSpec>),
    /// Logical OR: spec1 || spec2
    Or(Box<LocalSpec>, Box<LocalSpec>),
    /// Logical NOT: !spec
    Not(Box<LocalSpec>),
    /// Comparison predicate: term cmp term
    Compare(Comparison),
    /// Boolean literal true
    True,
    /// Boolean literal false
    False,
}

/// Comparison expression.
#[derive(Debug, Clone)]
pub struct Comparison {
    pub left: Operand,
    pub op: CompareOp,
    pub right: Operand,
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

/// Operand in a comparison.
#[derive(Debug, Clone)]
pub enum Operand {
    /// Reference to a state field: state.field_name or state.field_name[t-k]
    StateField(FieldRef),
    /// Reference to a candidate parameter: candidate.param_name
    CandidateField(FieldRef),
    /// Integer constant
    Constant(u64),
}

/// Field reference with optional temporal offset.
#[derive(Debug, Clone)]
pub struct FieldRef {
    /// Field name (e.g., "balance", "amount")
    pub name: String,
    /// Temporal offset (0 = current, 1 = t-1, etc.)
    pub temporal_offset: usize,
}

impl FieldRef {
    pub fn current(name: impl Into<String>) -> Self {
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

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::StateField(field) => {
                if field.temporal_offset == 0 {
                    write!(f, "state.{}", field.name)
                } else {
                    write!(f, "state.{}[t-{}]", field.name, field.temporal_offset)
                }
            }
            Operand::CandidateField(field) => {
                write!(f, "candidate.{}", field.name)
            }
            Operand::Constant(v) => write!(f, "{}", v),
        }
    }
}

impl LocalSpec {
    /// Create an AND node.
    pub fn and(left: LocalSpec, right: LocalSpec) -> Self {
        LocalSpec::And(Box::new(left), Box::new(right))
    }
    
    /// Create an OR node.
    pub fn or(left: LocalSpec, right: LocalSpec) -> Self {
        LocalSpec::Or(Box::new(left), Box::new(right))
    }
    
    /// Create a NOT node.
    pub fn not(inner: LocalSpec) -> Self {
        LocalSpec::Not(Box::new(inner))
    }
    
    /// Create a comparison node.
    pub fn compare(left: Operand, op: CompareOp, right: Operand) -> Self {
        LocalSpec::Compare(Comparison { left, op, right })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn build_simple_ast() {
        let spec = TauMprdSpec {
            temporal: TemporalOp::Always,
            body: LocalSpec::compare(
                Operand::StateField(FieldRef::current("balance")),
                CompareOp::Ge,
                Operand::CandidateField(FieldRef::current("amount")),
            ),
        };
        
        assert_eq!(spec.temporal, TemporalOp::Always);
    }
    
    #[test]
    fn build_compound_ast() {
        let spec = LocalSpec::and(
            LocalSpec::compare(
                Operand::StateField(FieldRef::current("x")),
                CompareOp::Lt,
                Operand::Constant(100),
            ),
            LocalSpec::not(
                LocalSpec::compare(
                    Operand::CandidateField(FieldRef::current("y")),
                    CompareOp::Eq,
                    Operand::Constant(0),
                ),
            ),
        );
        
        match spec {
            LocalSpec::And(_, _) => {}
            _ => panic!("expected And"),
        }
    }
}
