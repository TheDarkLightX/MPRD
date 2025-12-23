//! Semantic analysis for Tau-MPRD.
//!
//! Validates AST, enforces bounds, and collects field references.

use crate::ast::*;
use crate::error::{CompileError, CompileResult};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::limits::{MAX_KEY_LENGTH_V1, MAX_LOOKBACK_V1, MAX_PREDICATES_V1};

/// Maximum temporal lookback depth (Tau-MPRD v1).
pub const MAX_LOOKBACK: usize = MAX_LOOKBACK_V1;

/// Maximum number of predicates (Tau-MPRD v1).
pub const MAX_PREDICATES: usize = MAX_PREDICATES_V1;

/// Maximum key length for field names (Tau-MPRD v1).
pub const MAX_KEY_LENGTH: usize = MAX_KEY_LENGTH_V1;

/// Semantically analyzed specification with collected metadata.
#[derive(Debug, Clone)]
pub struct CheckedSpec {
    /// The original AST (validated).
    pub spec: TauMprdSpec,
    /// State fields referenced (with max temporal offset per field).
    pub state_fields: BTreeMap<String, usize>,
    /// Candidate fields referenced.
    pub candidate_fields: BTreeSet<String>,
    /// Number of comparison predicates.
    pub predicate_count: usize,
}

/// Semantic analyzer state.
struct Analyzer {
    state_fields: HashMap<String, usize>,
    candidate_fields: HashSet<String>,
    predicate_count: usize,
}

impl Analyzer {
    fn new() -> Self {
        Self {
            state_fields: HashMap::new(),
            candidate_fields: HashSet::new(),
            predicate_count: 0,
        }
    }
    
    fn check_field_name(&self, name: &str) -> CompileResult<()> {
        if name.len() > MAX_KEY_LENGTH {
            return Err(CompileError::KeyTooLong {
                key: name.to_string(),
                max: MAX_KEY_LENGTH,
            });
        }
        
        // Validate field name characters (alphanumeric + underscore)
        if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(CompileError::UnknownField {
                field: name.to_string(),
                context: "invalid characters in field name".to_string(),
            });
        }
        
        Ok(())
    }
    
    fn analyze_operand(&mut self, operand: &Operand) -> CompileResult<()> {
        match operand {
            Operand::StateField(field) => {
                self.check_field_name(&field.name)?;
                
                if field.temporal_offset > MAX_LOOKBACK {
                    return Err(CompileError::LookbackExceeded {
                        lookback: field.temporal_offset,
                        max: MAX_LOOKBACK,
                    });
                }
                
                // Track maximum temporal offset for this field
                let entry = self.state_fields.entry(field.name.clone()).or_insert(0);
                *entry = (*entry).max(field.temporal_offset);
            }
            Operand::CandidateField(field) => {
                self.check_field_name(&field.name)?;
                
                if field.temporal_offset != 0 {
                    return Err(CompileError::LookbackExceeded {
                        lookback: field.temporal_offset,
                        max: 0, // Candidate fields cannot have temporal offset
                    });
                }
                
                self.candidate_fields.insert(field.name.clone());
            }
            Operand::Constant(_) => {
                // Constants are always valid (already parsed as u64)
            }
        }
        Ok(())
    }
    
    fn analyze_comparison(&mut self, cmp: &Comparison) -> CompileResult<()> {
        self.analyze_operand(&cmp.left)?;
        self.analyze_operand(&cmp.right)?;
        
        self.predicate_count += 1;
        if self.predicate_count > MAX_PREDICATES {
            return Err(CompileError::PredicateCountExceeded {
                count: self.predicate_count,
                max: MAX_PREDICATES,
            });
        }
        
        Ok(())
    }
    
    fn analyze_local_spec(&mut self, spec: &LocalSpec) -> CompileResult<()> {
        match spec {
            LocalSpec::And(left, right) => {
                self.analyze_local_spec(left)?;
                self.analyze_local_spec(right)?;
            }
            LocalSpec::Or(left, right) => {
                self.analyze_local_spec(left)?;
                self.analyze_local_spec(right)?;
            }
            LocalSpec::Not(inner) => {
                self.analyze_local_spec(inner)?;
            }
            LocalSpec::Compare(cmp) => {
                self.analyze_comparison(cmp)?;
            }
            LocalSpec::True | LocalSpec::False => {
                // Boolean literals are always valid
            }
        }
        Ok(())
    }
    
    fn analyze(&mut self, spec: &TauMprdSpec) -> CompileResult<()> {
        // Tau-MPRD requires Always temporal operator
        if spec.temporal != TemporalOp::Always {
            return Err(CompileError::SometimesNotSupported { line: 0 });
        }
        
        self.analyze_local_spec(&spec.body)?;
        
        // Must have at least one constraint
        if self.predicate_count == 0 {
            // Check if it's just True or False
            match &spec.body {
                LocalSpec::True | LocalSpec::False => {
                    // Allow trivial policies
                }
                _ => {
                    return Err(CompileError::EmptyPolicy);
                }
            }
        }
        
        Ok(())
    }
}

/// Perform semantic analysis on the AST.
pub fn analyze(spec: &TauMprdSpec) -> CompileResult<CheckedSpec> {
    let mut analyzer = Analyzer::new();
    analyzer.analyze(spec)?;
    
    Ok(CheckedSpec {
        spec: spec.clone(),
        state_fields: analyzer.state_fields.into_iter().collect(),
        candidate_fields: analyzer.candidate_fields.into_iter().collect(),
        predicate_count: analyzer.predicate_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::tokenize;
    use crate::parser::parse;
    
    fn analyze_source(source: &str) -> CompileResult<CheckedSpec> {
        let tokens = tokenize(source)?;
        let ast = parse(&tokens)?;
        analyze(&ast)
    }
    
    #[test]
    fn analyze_simple_policy() {
        let checked = analyze_source("always (state.balance >= candidate.amount)").unwrap();
        assert!(checked.state_fields.contains_key("balance"));
        assert!(checked.candidate_fields.contains("amount"));
        assert_eq!(checked.predicate_count, 1);
    }
    
    #[test]
    fn analyze_temporal_offset() {
        let checked = analyze_source("always (state.x[t-3] < state.x)").unwrap();
        assert_eq!(*checked.state_fields.get("x").unwrap(), 3);
    }
    
    #[test]
    fn reject_excessive_lookback() {
        let result = analyze_source("always (state.x[t-100] < 0)");
        assert!(matches!(result, Err(CompileError::LookbackExceeded { .. })));
    }
    
    #[test]
    fn collect_multiple_fields() {
        let checked = analyze_source(
            "always (state.a < state.b && candidate.x != candidate.y)"
        ).unwrap();
        assert_eq!(checked.state_fields.len(), 2);
        assert_eq!(checked.candidate_fields.len(), 2);
        assert_eq!(checked.predicate_count, 2);
    }
    
    #[test]
    fn analyze_complex_policy() {
        let checked = analyze_source(
            "always ((state.balance >= candidate.amount) && \
                    (state.rate_limit[t-1] > 0 || state.is_admin = 1))"
        ).unwrap();
        assert_eq!(checked.predicate_count, 3);
        assert_eq!(*checked.state_fields.get("rate_limit").unwrap(), 1);
    }
}
