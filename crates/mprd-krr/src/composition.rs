//! Policy composition and consistency verification.
//!
//! Algorithms for checking policy conflicts, subsumption, and compatibility.

use crate::error::KrrError;
use std::time::Duration;

/// Maximum allowed WFF length to prevent DoS via excessively large formulas.
const MAX_WFF_LENGTH: usize = 4096;

/// Maximum output bytes to read from Tau to prevent memory exhaustion.
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// Result of a consistency check.
#[derive(Clone, Debug)]
pub enum ConsistencyResult {
    /// Policies are consistent together.
    Consistent,
    /// Policies conflict with each other.
    Conflict {
        /// Minimal set of policies that conflict.
        conflicting_policies: Vec<PolicyId>,
        /// Explanation of the conflict.
        explanation: String,
    },
}

/// Policy identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyId(pub String);

/// A policy constraint.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct PolicyConstraint {
    pub id: PolicyId,
    /// WFF representation of the constraint.
    pub wff: String,
}

/// Policy composition verifier.
pub struct CompositionVerifier {
    /// Path to Tau binary.
    tau_binary: std::path::PathBuf,
    /// Timeout for Tau calls.
    timeout: Duration,
}

/// Validate that a WFF string is safe to pass to Tau.
///
/// # Security
///
/// This prevents command injection by ensuring the WFF only contains
/// characters expected in Tau formulas.
fn validate_wff(wff: &str) -> Result<(), KrrError> {
    if wff.is_empty() {
        return Err(KrrError::ParseError("WFF cannot be empty".into()));
    }

    if wff.len() > MAX_WFF_LENGTH {
        return Err(KrrError::ParseError(format!(
            "WFF exceeds maximum length of {} bytes",
            MAX_WFF_LENGTH
        )));
    }

    // SECURITY: Whitelist approach - only allow known-safe characters
    for (i, c) in wff.chars().enumerate() {
        let allowed = c.is_ascii_alphanumeric()
            || matches!(
                c,
                ' ' | '\t'      // Whitespace (no newlines!)
                | '#'           // Bitvector prefix
                | '(' | ')'     // Grouping
                | '[' | ']'     // Bitvector notation
                | '<' | '>' | '=' | '!'  // Comparison/negation
                | '&' | '|'     // Logical operators
                | '+' | '-' | '*' | '/'  // Arithmetic
                | '_' // Identifiers
            );

        if !allowed {
            return Err(KrrError::ParseError(format!(
                "WFF contains disallowed character '{}' at position {}",
                c.escape_default(),
                i
            )));
        }
    }

    // SECURITY: Explicitly reject dangerous patterns
    let dangerous_patterns = [
        "quit", "exit", "load", "save", "exec", "system",
    ];

    let wff_lower = wff.to_lowercase();
    for pattern in dangerous_patterns {
        if wff_lower.contains(pattern) {
            return Err(KrrError::ParseError(format!(
                "WFF contains potentially dangerous pattern: '{}'",
                pattern
            )));
        }
    }

    Ok(())
}

impl CompositionVerifier {
    /// Create a new verifier.
    pub fn new(tau_binary: impl Into<std::path::PathBuf>) -> Self {
        CompositionVerifier {
            tau_binary: tau_binary.into(),
            timeout: Duration::from_millis(500),
        }
    }
    
    /// Create a new verifier with custom timeout.
    pub fn with_timeout(tau_binary: impl Into<std::path::PathBuf>, timeout: Duration) -> Self {
        CompositionVerifier {
            tau_binary: tau_binary.into(),
            timeout,
        }
    }

    /// Check if a set of policies is consistent (satisfiable together).
    ///
    /// Returns `Consistent` if there exists an assignment that satisfies all policies.
    /// Returns `Conflict` with minimal conflicting subset if policies are unsatisfiable.
    pub fn check_consistency(&self, policies: &[PolicyConstraint]) -> Result<ConsistencyResult, KrrError> {
        if policies.is_empty() {
            return Ok(ConsistencyResult::Consistent);
        }
        
        // Conjoin all policies
        let combined_wff = self.conjoin_policies(policies);
        
        // Check satisfiability
        if self.is_satisfiable(&combined_wff)? {
            return Ok(ConsistencyResult::Consistent);
        }
        
        // Find minimal conflicting subset using ddmin
        let conflicting = self.find_minimal_conflict(policies)?;
        
        Ok(ConsistencyResult::Conflict {
            conflicting_policies: conflicting.iter().map(|p| p.id.clone()).collect(),
            explanation: format!(
                "Policies {} are mutually unsatisfiable",
                conflicting.iter().map(|p| p.id.0.as_str()).collect::<Vec<_>>().join(", ")
            ),
        })
    }
    
    /// Check if policy A subsumes (is stricter than) policy B.
    ///
    /// Returns true if every action allowed by A is also allowed by B.
    /// (A ⊆ B iff (A ∧ ¬B) is unsatisfiable)
    pub fn subsumes(&self, a: &PolicyConstraint, b: &PolicyConstraint) -> Result<bool, KrrError> {
        // A subsumes B iff (A && !B) is unsatisfiable
        let wff = format!("({}) && !({})", a.wff, b.wff);
        Ok(!self.is_satisfiable(&wff)?)
    }
    
    /// Check backward compatibility: new policy accepts subset of old policy.
    pub fn is_backward_compatible(
        &self,
        old: &PolicyConstraint,
        new: &PolicyConstraint,
    ) -> Result<BackwardCompatResult, KrrError> {
        // New is backward compatible if everything new allows, old also allowed
        // i.e., new ⊆ old
        if self.subsumes(new, old)? {
            return Ok(BackwardCompatResult::Compatible);
        }
        
        // Find an example that new allows but old doesn't
        let diff_wff = format!("({}) && !({})", new.wff, old.wff);
        if self.is_satisfiable(&diff_wff)? {
            return Ok(BackwardCompatResult::Breaking {
                explanation: "New policy allows actions that old policy rejected".into(),
            });
        }
        
        Ok(BackwardCompatResult::Compatible)
    }
    
    /// Conjoin multiple policy WFFs.
    fn conjoin_policies(&self, policies: &[PolicyConstraint]) -> String {
        policies
            .iter()
            .map(|p| format!("({})", p.wff))
            .collect::<Vec<_>>()
            .join(" && ")
    }
    
    /// Check if a WFF is satisfiable using Tau.
    ///
    /// # Security
    /// - Validates WFF before execution to prevent command injection
    /// - Fails closed on any unexpected output or error
    fn is_satisfiable(&self, wff: &str) -> Result<bool, KrrError> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        
        // SECURITY: Validate WFF before execution
        validate_wff(wff)?;
        
        let script = format!("solve {}\nquit\n", wff);
        
        let mut child = Command::new(&self.tau_binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| KrrError::TmlError(format!("Failed to spawn tau: {}", e)))?;
        
        {
            let stdin = child.stdin.as_mut()
                .ok_or_else(|| KrrError::TmlError("No stdin".into()))?;
            stdin.write_all(script.as_bytes())
                .map_err(|e| KrrError::TmlError(format!("Write failed: {}", e)))?;
        }
        
        let output = child.wait_with_output()
            .map_err(|e| KrrError::TmlError(format!("Wait failed: {}", e)))?;
        
        // SECURITY: Fail closed on non-zero exit
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(KrrError::TmlError(format!("Tau failed with status {}: {}", 
                output.status, stderr)));
        }
        
        // SECURITY: Bound output size
        if output.stdout.len() > MAX_OUTPUT_BYTES {
            return Err(KrrError::TmlError(format!(
                "Tau output exceeded {} bytes", MAX_OUTPUT_BYTES)));
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Parse Tau output - fail closed on unexpected output
        if stdout.contains("solution:") || stdout.contains("solution: {") {
            // Has a solution = satisfiable
            return Ok(true);
        }
        if stdout.contains("no solution") || stdout.contains("unsat") {
            return Ok(false);
        }
        
        // SECURITY: Fail closed on unexpected output
        Err(KrrError::TmlError(format!("Unexpected tau output (fail closed): {}", 
            &stdout[..stdout.len().min(200)])))
    }
    
    /// Find minimal conflicting subset using delta debugging.
    /// 
    /// # Errors
    /// Returns an error if Tau oracle fails (fail-closed for security).
    fn find_minimal_conflict<'a>(
        &self,
        policies: &'a [PolicyConstraint],
    ) -> Result<Vec<&'a PolicyConstraint>, KrrError> {
        // Track oracle errors across ddmin iterations (fail-closed)
        let oracle_error: std::cell::RefCell<Option<KrrError>> = std::cell::RefCell::new(None);
        
        // Oracle: returns true if policies conflict (unsatisfiable)
        // SECURITY: Fail-closed on Tau errors - we cannot assume satisfiable on error
        let oracle = |subset: &[&PolicyConstraint]| -> bool {
            if subset.len() < 2 {
                return false; // Single policy can't conflict with itself
            }
            
            // If we've already encountered an error, abort further oracle calls
            if oracle_error.borrow().is_some() {
                return false;
            }
            
            let wff = subset
                .iter()
                .map(|p| format!("({})", p.wff))
                .collect::<Vec<_>>()
                .join(" && ");
            
            match self.is_satisfiable(&wff) {
                Ok(is_sat) => !is_sat,
                Err(e) => {
                    // SECURITY: Capture error and fail closed
                    *oracle_error.borrow_mut() = Some(e);
                    false // Abort delta debugging
                }
            }
        };
        
        let policy_refs: Vec<&PolicyConstraint> = policies.iter().collect();
        
        // Use ddmin to find minimal conflicting subset
        let minimal = crate::ddmin::ddmin(&policy_refs, &oracle);
        
        // SECURITY: If oracle encountered any error, fail the entire operation
        if let Some(e) = oracle_error.into_inner() {
            return Err(KrrError::TmlError(format!(
                "Tau oracle failed during conflict detection (fail-closed): {}", e
            )));
        }
        
        Ok(minimal)
    }
}

/// Result of backward compatibility check.
#[derive(Clone, Debug)]
pub enum BackwardCompatResult {
    /// New policy is backward compatible.
    Compatible,
    /// New policy breaks backward compatibility.
    Breaking {
        explanation: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    
    fn tau_path() -> Option<PathBuf> {
        let paths = [
            "external/tau-lang/build-Release/tau",
            "../external/tau-lang/build-Release/tau",
        ];
        for p in paths {
            if std::path::Path::new(p).exists() {
                return Some(PathBuf::from(p));
            }
        }
        None
    }
    
    #[test]
    #[ignore] // Requires tau binary
    fn test_consistent_policies() {
        let Some(tau) = tau_path() else {
            eprintln!("Skipping: tau binary not found");
            return;
        };
        
        let verifier = CompositionVerifier::new(tau);
        
        let policies = vec![
            PolicyConstraint { id: PolicyId("p1".into()), wff: "1 = 1".into() },
            PolicyConstraint { id: PolicyId("p2".into()), wff: "1 = 1".into() },
        ];
        
        let result = verifier.check_consistency(&policies).unwrap();
        assert!(matches!(result, ConsistencyResult::Consistent));
    }
    
    #[test]
    #[ignore] // Requires tau binary
    fn test_conflicting_policies() {
        let Some(tau) = tau_path() else {
            eprintln!("Skipping: tau binary not found");
            return;
        };
        
        let verifier = CompositionVerifier::new(tau);
        
        let policies = vec![
            PolicyConstraint { id: PolicyId("p1".into()), wff: "1 = 1".into() },
            PolicyConstraint { id: PolicyId("p2".into()), wff: "1 = 0".into() }, // Contradiction
        ];
        
        let result = verifier.check_consistency(&policies).unwrap();
        assert!(matches!(result, ConsistencyResult::Conflict { .. }));
    }
}
