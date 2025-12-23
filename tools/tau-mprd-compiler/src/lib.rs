//! Tau-MPRD Compiler
//!
//! Compiles a restricted subset of Tau language ("Tau-MPRD") to TCV circuit format.
//!
//! # Architecture
//!
//! ```text
//! Source -> Lexer -> Parser -> Semantic Analysis -> IR -> CodeGen -> Serialize -> Hash
//! ```
//!
//! # Design Principles
//!
//! - **Deterministic**: Same source always produces identical output
//! - **Fail-closed**: Any ambiguity causes compilation failure
//! - **Bounded**: All constructs have compile-time bounds
//! - **License-safe**: No Tau library dependencies

pub mod lexer;
pub mod parser;
pub mod ast;
pub mod semantic;
pub mod ir;
pub mod codegen;
pub mod serialize;
pub mod error;
pub mod limits;

// V2 modules with arithmetic support
pub mod ast_v2;
pub mod lexer_v2;
pub mod parser_v2;
pub mod ir_v2;
pub mod serialize_v2;
pub mod bundle_v2;
pub mod scrambler_v2;
pub mod eval_v2;

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub use error::{CompileError, CompileResult};
pub use ast::TauMprdSpec;
pub use ir::CompiledPolicy;
pub use ast_v2::TauMprdSpecV2;
pub use ir_v2::CompiledPolicyV2;

/// Domain for hashing Tau-MPRD source bytes.
pub const SOURCE_HASH_DOMAIN: &[u8] = b"MPRD_TAU_SOURCE_V1";

/// Domain for hashing compiled policy artifact.
pub const COMPILED_HASH_DOMAIN: &[u8] = b"MPRD_TAU_COMPILED_POLICY_V1";

/// Compilation output containing both hashes and artifact.
#[derive(Debug, Clone)]
pub struct CompilationOutput {
    /// Hash of the source bytes (for registry closure mapping).
    pub policy_source_hash: [u8; 32],
    
    /// Hash of the compiled artifact (policy_hash for guest).
    pub policy_hash: [u8; 32],

    /// State fields referenced (max lookback per base field).
    ///
    /// The guest reads these from the canonical `state_preimage` key/value encoding.
    pub state_fields: BTreeMap<String, usize>,

    /// Candidate fields referenced.
    ///
    /// The guest reads these from the canonical `candidate_preimage` key/value encoding.
    pub candidate_fields: BTreeSet<String>,

    /// Required state keys, including temporal lookbacks using the convention `<field>_t_<k>`.
    ///
    /// This list includes the base field names and any derived lookback keys.
    pub required_state_keys: Vec<String>,

    /// Required candidate keys (parameter names).
    pub required_candidate_keys: Vec<String>,

    /// The compiled policy artifact.
    pub artifact: CompiledPolicy,
    
    /// Canonical artifact bytes (what policy_hash commits to).
    pub artifact_bytes: Vec<u8>,
}

/// Compile Tau-MPRD source to TCV circuit format.
///
/// # Arguments
/// * `source` - Tau-MPRD source code as UTF-8 string
///
/// # Returns
/// * `CompilationOutput` on success
/// * `CompileError` on any failure (fail-closed)
///
/// # Example
/// ```
/// use tau_mprd_compiler::compile;
///
/// let source = r#"
///     always (state.balance >= candidate.amount)
/// "#;
///
/// let output = compile(source).expect("compilation failed");
/// println!("policy_hash: {:?}", output.policy_hash);
/// ```
pub fn compile(source: &str) -> CompileResult<CompilationOutput> {
    // Phase 1: Compute source hash
    let policy_source_hash = hash_source(source.as_bytes());
    
    // Phase 2: Lexical analysis
    let tokens = lexer::tokenize(source)?;
    
    // Phase 3: Parsing
    let ast = parser::parse(&tokens)?;
    
    // Phase 4: Semantic analysis
    let checked_ast = semantic::analyze(&ast)?;
    
    // Phase 5: IR construction
    let ir = ir::lower(&checked_ast)?;
    
    // Phase 6: Code generation
    let artifact = codegen::generate(&ir)?;
    
    // Phase 7: Serialization
    let artifact_bytes = serialize::to_canonical_bytes(&artifact)?;
    
    // Phase 8: Compute policy hash
    let policy_hash = hash_artifact(&artifact_bytes);
    
    let mut required_state_keys: Vec<String> = Vec::new();
    for (name, max_offset) in &checked_ast.state_fields {
        required_state_keys.push(name.clone());
        for k in 1..=*max_offset {
            required_state_keys.push(format!("{name}_t_{k}"));
        }
    }
    required_state_keys.sort();
    required_state_keys.dedup();

    let mut required_candidate_keys: Vec<String> = checked_ast.candidate_fields.iter().cloned().collect();
    required_candidate_keys.sort();
    required_candidate_keys.dedup();

    Ok(CompilationOutput {
        policy_source_hash,
        policy_hash,
        state_fields: checked_ast.state_fields.clone(),
        candidate_fields: checked_ast.candidate_fields.clone(),
        required_state_keys,
        required_candidate_keys,
        artifact,
        artifact_bytes,
    })
}

/// Hash source bytes with domain separation.
fn hash_source(source: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_HASH_DOMAIN);
    hasher.update(source);
    hasher.finalize().into()
}

/// Hash artifact bytes with domain separation.
fn hash_artifact(artifact: &[u8]) -> [u8; 32] {
    // Match the on-chain/verifier-facing commitment used by the tau_compiled guest.
    mprd_risc0_shared::tau_compiled_policy_hash_v1(artifact)
}

// =============================================================================
// V2 Compiler (with arithmetic support)
// =============================================================================

/// Domain for hashing v2 compiled policy artifact.
pub const COMPILED_HASH_DOMAIN_V2: &[u8] = b"MPRD_TAU_COMPILED_POLICY_V2";

/// V2 compilation output with arithmetic support.
#[derive(Debug, Clone)]
pub struct CompilationOutputV2 {
    /// Hash of the source bytes.
    pub policy_source_hash: [u8; 32],
    
    /// Hash of the compiled artifact.
    pub policy_hash: [u8; 32],
    
    /// The compiled policy artifact (v2 DAG format).
    pub artifact: CompiledPolicyV2,
    
    /// Canonical artifact bytes.
    pub artifact_bytes: Vec<u8>,
    
    /// State keys referenced (name → hash).
    pub state_keys: std::collections::BTreeMap<String, [u8; 32]>,
    
    /// Candidate keys referenced (name → hash).
    pub candidate_keys: std::collections::BTreeMap<String, [u8; 32]>,
}

/// Compile Tau-MPRD v2 source with arithmetic support.
///
/// # Example
/// ```
/// use tau_mprd_compiler::compile_v2;
///
/// let source = r#"
///     always (state.w0 * 2 + state.w1 * 3 >= state.threshold)
/// "#;
///
/// let output = compile_v2(source).expect("compilation failed");
/// println!("policy_hash: {:?}", output.policy_hash);
/// ```
pub fn compile_v2(source: &str) -> CompileResult<CompilationOutputV2> {
    // Phase 1: Compute source hash
    let policy_source_hash = hash_source(source.as_bytes());
    
    // Phase 2: Lexical analysis
    let tokens = lexer_v2::tokenize_v2(source)?;
    
    // Phase 3: Parsing
    let ast = parser_v2::parse_v2(&tokens)?;
    
    // Phase 4: IR construction (includes type checking)
    let artifact = ir_v2::lower_v2(&ast)?;
    
    // Phase 5: Serialization
    let artifact_bytes = serialize_v2::to_canonical_bytes_v2(&artifact)?;
    
    // Phase 6: Compute policy hash (v2 domain)
    let policy_hash = hash_artifact_v2(&artifact_bytes);
    
    Ok(CompilationOutputV2 {
        policy_source_hash,
        policy_hash,
        artifact: artifact.clone(),
        artifact_bytes,
        state_keys: artifact.state_keys,
        candidate_keys: artifact.candidate_keys,
    })
}

/// Hash v2 artifact bytes with domain separation.
fn hash_artifact_v2(artifact: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COMPILED_HASH_DOMAIN_V2);
    hasher.update(artifact);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn compile_simple_policy() {
        let source = "always (state.balance >= candidate.amount)";
        let result = compile(source);
        assert!(result.is_ok(), "compilation failed: {:?}", result.err());
    }

    #[test]
    fn compile_includes_required_keys() {
        let source = "always (state.x[t-2] < state.x && candidate.amount >= 1)";
        let out = compile(source).expect("compile");
        assert!(out.required_state_keys.iter().any(|k| k == "x"));
        assert!(out.required_state_keys.iter().any(|k| k == "x_t_1"));
        assert!(out.required_state_keys.iter().any(|k| k == "x_t_2"));
        assert!(out.required_candidate_keys.iter().any(|k| k == "amount"));
    }

    #[test]
    fn compile_deterministic() {
        let source = "always (state.x < 100 && candidate.y != 0)";
        let out1 = compile(source).unwrap();
        let out2 = compile(source).unwrap();
        assert_eq!(out1.policy_hash, out2.policy_hash);
        assert_eq!(out1.artifact_bytes, out2.artifact_bytes);
    }
    
    #[test]
    fn reject_unsupported_sometimes() {
        let source = "sometimes (state.x = 0)";
        let result = compile(source);
        assert!(result.is_err());
    }
    
    // V2 tests
    #[test]
    fn compile_v2_arithmetic() {
        let source = "always (state.a + state.b >= state.threshold)";
        let result = compile_v2(source);
        assert!(result.is_ok(), "v2 compilation failed: {:?}", result.err());
    }
    
    #[test]
    fn compile_v2_weighted_voting() {
        let source = "always (state.w0 * 2 + state.w1 * 3 + state.w2 * 1 >= state.threshold)";
        let result = compile_v2(source);
        assert!(result.is_ok(), "v2 compilation failed: {:?}", result.err());
    }
    
    #[test]
    fn compile_v2_min_max() {
        let source = "always (min(state.a, state.b) >= 0 && max(state.c, state.d) <= 100)";
        let result = compile_v2(source);
        assert!(result.is_ok(), "v2 compilation failed: {:?}", result.err());
    }
    
    #[test]
    fn compile_v2_deterministic() {
        let source = "always (state.w0 * 2 + state.w1 * 3 >= state.threshold)";
        let out1 = compile_v2(source).unwrap();
        let out2 = compile_v2(source).unwrap();
        assert_eq!(out1.policy_hash, out2.policy_hash);
        assert_eq!(out1.artifact_bytes, out2.artifact_bytes);
    }
}
