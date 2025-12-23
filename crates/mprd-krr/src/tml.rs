//! TML adapter for running TML as a black box.

use crate::types::FactId;
use crate::error::KrrError;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;
use std::io::Write;

/// Trait for TML execution engines.
pub trait TmlRunner {
    /// Run a TML program and return derived facts.
    fn run(&self, program: &str) -> Result<HashSet<String>, KrrError>;
}

/// CLI-based TML runner.
///
/// Invokes the TML binary as a subprocess.
#[derive(Clone, Debug)]
pub struct TmlCli {
    /// Path to TML binary.
    pub bin_path: PathBuf,
    /// Additional arguments to pass.
    pub args: Vec<String>,
}

impl TmlCli {
    /// Create a new TML CLI runner.
    pub fn new(bin_path: impl Into<PathBuf>) -> Self {
        TmlCli {
            bin_path: bin_path.into(),
            args: Vec::new(),
        }
    }
    
    /// Add additional arguments.
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }
}

impl TmlRunner for TmlCli {
    fn run(&self, program: &str) -> Result<HashSet<String>, KrrError> {
        // Create temp file for program
        let mut temp_file = tempfile::NamedTempFile::new()
            .map_err(|e| KrrError::TmlError(format!("Failed to create temp file: {}", e)))?;
        
        temp_file.write_all(program.as_bytes())
            .map_err(|e| KrrError::TmlError(format!("Failed to write program: {}", e)))?;
        
        let temp_path = temp_file.path();
        
        // Run TML
        let output = Command::new(&self.bin_path)
            .args(&self.args)
            .arg(temp_path)
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .output()
            .map_err(|e| KrrError::TmlError(format!("Failed to run TML: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(KrrError::TmlError(format!("TML failed: {}", stderr)));
        }
        
        // Parse output
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_tml_output(&stdout)
    }
}

/// Parse TML output into fact strings.
fn parse_tml_output(output: &str) -> Result<HashSet<String>, KrrError> {
    let mut facts = HashSet::new();
    
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        
        // Parse fact format: predicate(args).
        if let Some(stripped) = line.strip_suffix('.') {
            // Basic validation: should contain parentheses
            if stripped.contains('(') && stripped.contains(')') {
                // Remove trailing dot and normalize
                let fact = stripped.trim().to_string();
                facts.insert(fact);
            }
        }
    }
    
    Ok(facts)
}

/// Build a TML program from facts and rules.
#[derive(Clone, Debug, Default)]
pub struct ProgramBuilder {
    facts: Vec<String>,
    rules: Vec<String>,
}

impl ProgramBuilder {
    pub fn new() -> Self {
        ProgramBuilder::default()
    }
    
    /// Add a fact.
    pub fn fact(mut self, fact: &str) -> Self {
        let normalized = if fact.ends_with('.') {
            fact.to_string()
        } else {
            format!("{}.", fact)
        };
        self.facts.push(normalized);
        self
    }
    
    /// Add multiple facts.
    pub fn facts(mut self, facts: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        for f in facts {
            self = self.fact(f.as_ref());
        }
        self
    }
    
    /// Add a rule.
    pub fn rule(mut self, rule: &str) -> Self {
        let normalized = if rule.ends_with('.') {
            rule.to_string()
        } else {
            format!("{}.", rule)
        };
        self.rules.push(normalized);
        self
    }
    
    /// Add multiple rules.
    pub fn rules(mut self, rules: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        for r in rules {
            self = self.rule(r.as_ref());
        }
        self
    }
    
    /// Build the program string.
    pub fn build(self) -> String {
        let mut program = String::new();
        
        if !self.facts.is_empty() {
            program.push_str("// Facts\n");
            for fact in &self.facts {
                program.push_str(fact);
                program.push('\n');
            }
            program.push('\n');
        }
        
        if !self.rules.is_empty() {
            program.push_str("// Rules\n");
            for rule in &self.rules {
                program.push_str(rule);
                program.push('\n');
            }
        }
        
        program
    }
}

/// Convert a fact string to a FactId.
pub fn fact_to_id(fact: &str) -> FactId {
    // Normalize: remove trailing dot, trim whitespace
    let normalized = fact.trim().trim_end_matches('.');
    FactId::from_canonical(normalized)
}

/// Convert fact strings to FactIds.
pub fn facts_to_ids(facts: &HashSet<String>) -> HashSet<FactId> {
    facts.iter().map(|f| fact_to_id(f)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_program_builder() {
        let program = ProgramBuilder::new()
            .fact("a(1)")
            .fact("b(1)")
            .rule("c(?x) :- a(?x), b(?x)")
            .build();
        
        assert!(program.contains("a(1)."));
        assert!(program.contains("b(1)."));
        assert!(program.contains("c(?x) :- a(?x), b(?x)."));
    }
    
    #[test]
    fn test_parse_tml_output() {
        let output = "a(1).\nb(2).\n// comment\nc(3).";
        let facts = parse_tml_output(output).unwrap();
        
        assert!(facts.contains("a(1)"));
        assert!(facts.contains("b(2)"));
        assert!(facts.contains("c(3)"));
        assert_eq!(facts.len(), 3);
    }
    
    #[test]
    fn test_fact_to_id() {
        let id1 = fact_to_id("a(1)");
        let id2 = fact_to_id("a(1).");
        let id3 = fact_to_id("  a(1).  ");
        
        assert_eq!(id1, id2);
        assert_eq!(id1, id3);
    }
}
