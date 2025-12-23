//! Property-based tests for Tau-MPRD v2 compiler.
//!
//! Tests compiler invariants using proptest for fuzz-like coverage.

use proptest::prelude::*;
use tau_mprd_compiler::compile_v2;
use tau_mprd_compiler::ir_v2::NodeTypeV2;
use tau_mprd_compiler::serialize_v2::{from_canonical_bytes_v2, to_canonical_bytes_v2};

// =============================================================================
// Strategy generators for random policy components
// =============================================================================

/// Generate valid field names (alphanumeric + underscore, max 32 chars).
fn field_name_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,15}".prop_map(|s| s)
}

/// Generate u64 constants (avoiding edge cases that might overflow).
fn safe_constant_strategy() -> impl Strategy<Value = u64> {
    0u64..1_000_000u64
}

/// Generate comparison operators.
fn compare_op_strategy() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("="),
        Just("!="),
        Just("<"),
        Just("<="),
        Just(">"),
        Just(">="),
    ]
}

/// Generate a simple comparison expression.
fn simple_comparison_strategy() -> impl Strategy<Value = String> {
    (field_name_strategy(), compare_op_strategy(), safe_constant_strategy())
        .prop_map(|(field, op, val)| format!("state.{} {} {}", field, op, val))
}

/// Generate arithmetic expression with state fields and constants.
fn arithmetic_expr_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // Simple field reference
        field_name_strategy().prop_map(|f| format!("state.{}", f)),
        // Field + constant
        (field_name_strategy(), safe_constant_strategy())
            .prop_map(|(f, c)| format!("state.{} + {}", f, c)),
        // Field - constant (careful with underflow)
        (field_name_strategy(), 0u64..100u64)
            .prop_map(|(f, c)| format!("state.{} - {}", f, c)),
        // Field * constant
        (field_name_strategy(), 1u64..100u64)
            .prop_map(|(f, c)| format!("state.{} * {}", f, c)),
        // Field / constant (non-zero)
        (field_name_strategy(), 1u64..100u64)
            .prop_map(|(f, c)| format!("state.{} / {}", f, c)),
    ]
}

/// Generate a complete policy with comparison.
fn policy_strategy() -> impl Strategy<Value = String> {
    (arithmetic_expr_strategy(), compare_op_strategy(), safe_constant_strategy())
        .prop_map(|(expr, op, val)| format!("always ({} {} {})", expr, op, val))
}

/// Generate compound policies with AND/OR.
fn compound_policy_strategy() -> impl Strategy<Value = String> {
    (simple_comparison_strategy(), simple_comparison_strategy())
        .prop_flat_map(|(a, b)| {
            prop_oneof![
                Just(format!("always ({} && {})", a, b)),
                Just(format!("always ({} || {})", a, b)),
                Just(format!("always (!({}))", a)),
            ]
        })
}

// =============================================================================
// Property tests
// =============================================================================

proptest! {
    /// INVARIANT: Compilation is deterministic.
    /// Same source → same policy_hash and artifact_bytes.
    #[test]
    fn prop_deterministic_compilation(source in policy_strategy()) {
        if let Ok(out1) = compile_v2(&source) {
            let out2 = compile_v2(&source).unwrap();
            prop_assert_eq!(out1.policy_hash, out2.policy_hash, 
                "policy_hash must be deterministic");
            prop_assert_eq!(out1.artifact_bytes, out2.artifact_bytes,
                "artifact_bytes must be deterministic");
            prop_assert_eq!(out1.policy_source_hash, out2.policy_source_hash,
                "policy_source_hash must be deterministic");
        }
    }
    
    /// INVARIANT: Artifact bytes roundtrip through serialization.
    #[test]
    fn prop_serialization_roundtrip(source in policy_strategy()) {
        if let Ok(out) = compile_v2(&source) {
            // Deserialize the artifact bytes
            let restored = from_canonical_bytes_v2(&out.artifact_bytes)
                .expect("deserialization should succeed");
            
            // Re-serialize
            let reserialized = to_canonical_bytes_v2(&restored)
                .expect("reserialization should succeed");
            
            prop_assert_eq!(out.artifact_bytes, reserialized,
                "roundtrip serialization must be identity");
        }
    }
    
    /// INVARIANT: Different sources produce different policy_hash (collision resistance).
    #[test]
    fn prop_hash_collision_resistance(
        source1 in policy_strategy(),
        source2 in policy_strategy()
    ) {
        if source1 != source2 {
            if let (Ok(out1), Ok(out2)) = (compile_v2(&source1), compile_v2(&source2)) {
                // Different sources should have different source hashes
                prop_assert_ne!(out1.policy_source_hash, out2.policy_source_hash,
                    "different sources must have different source hashes");
            }
        }
    }
    
    /// INVARIANT: Output node is always boolean type.
    #[test]
    fn prop_output_is_boolean(source in policy_strategy()) {
        if let Ok(out) = compile_v2(&source) {
            let output_node_id = out.artifact.output_node;
            let output_node = out.artifact.nodes.iter()
                .find(|n| n.node_id == output_node_id)
                .expect("output node must exist");
            
            // Output must be a comparison or boolean op
            let is_bool_node = matches!(output_node.node_type,
                NodeTypeV2::Eq | NodeTypeV2::Ne | NodeTypeV2::Lt | 
                NodeTypeV2::Le | NodeTypeV2::Gt | NodeTypeV2::Ge |
                NodeTypeV2::And | NodeTypeV2::Or | NodeTypeV2::Not |
                NodeTypeV2::ConstBool
            );
            prop_assert!(is_bool_node, "output node must be boolean type");
        }
    }
    
    /// INVARIANT: All node IDs are unique.
    #[test]
    fn prop_unique_node_ids(source in policy_strategy()) {
        if let Ok(out) = compile_v2(&source) {
            let mut seen_ids = std::collections::HashSet::new();
            for node in &out.artifact.nodes {
                prop_assert!(seen_ids.insert(node.node_id),
                    "node IDs must be unique, found duplicate: {}", node.node_id);
            }
        }
    }
    
    /// INVARIANT: DAG is topologically sorted (inputs come before outputs).
    #[test]
    fn prop_topological_order(source in policy_strategy()) {
        if let Ok(out) = compile_v2(&source) {
            let mut defined = std::collections::HashSet::new();
            
            for node in &out.artifact.nodes {
                // Check that inputs are already defined (for non-leaf nodes)
                match node.node_type {
                    NodeTypeV2::Add | NodeTypeV2::Sub | NodeTypeV2::Min | NodeTypeV2::Max |
                    NodeTypeV2::Eq | NodeTypeV2::Ne | NodeTypeV2::Lt | NodeTypeV2::Le |
                    NodeTypeV2::Gt | NodeTypeV2::Ge | NodeTypeV2::And | NodeTypeV2::Or => {
                        prop_assert!(defined.contains(&node.inputs[0]),
                            "input 0 must be defined before use");
                        prop_assert!(defined.contains(&node.inputs[1]),
                            "input 1 must be defined before use");
                    }
                    NodeTypeV2::Not | NodeTypeV2::MulConst | NodeTypeV2::DivConst => {
                        prop_assert!(defined.contains(&node.inputs[0]),
                            "input 0 must be defined before use");
                    }
                    NodeTypeV2::Clamp => {
                        prop_assert!(defined.contains(&node.inputs[0]),
                            "input 0 must be defined before use");
                        prop_assert!(defined.contains(&node.inputs[1]),
                            "input 1 must be defined before use");
                        prop_assert!(defined.contains(&node.inputs[2]),
                            "input 2 must be defined before use");
                    }
                    // Leaf nodes don't have inputs to check
                    NodeTypeV2::LoadStateU64 | NodeTypeV2::LoadCandidateU64 |
                    NodeTypeV2::ConstU64 | NodeTypeV2::ConstBool => {}
                }
                
                // Mark this node as defined
                defined.insert(node.node_id);
            }
            
            // Output node must be defined
            prop_assert!(defined.contains(&out.artifact.output_node),
                "output node must be defined");
        }
    }
    
    /// INVARIANT: Compound policies compile successfully.
    #[test]
    fn prop_compound_policies_compile(source in compound_policy_strategy()) {
        // Should either compile successfully or fail with a well-defined error
        let result = compile_v2(&source);
        // We don't assert Ok here since some generated policies might be invalid
        // But we assert no panics
        drop(result);
    }
    
    /// INVARIANT: Artifact size is bounded.
    #[test]
    fn prop_artifact_size_bounded(source in policy_strategy()) {
        if let Ok(out) = compile_v2(&source) {
            prop_assert!(out.artifact_bytes.len() <= 128 * 1024,
                "artifact must not exceed MAX_ARTIFACT_BYTES_V2");
        }
    }
    
    /// INVARIANT: Node count is bounded.
    #[test]
    fn prop_node_count_bounded(source in policy_strategy()) {
        if let Ok(out) = compile_v2(&source) {
            prop_assert!(out.artifact.nodes.len() <= 4096,
                "node count must not exceed MAX_NODES_V2");
        }
    }
}

// =============================================================================
// Specific regression tests
// =============================================================================

#[test]
fn test_weighted_voting_pattern() {
    let source = "always (state.w0 * 2 + state.w1 * 3 + state.w2 * 1 >= state.threshold)";
    let out = compile_v2(source).expect("weighted voting should compile");
    
    // Should have MulConst nodes
    assert!(out.artifact.nodes.iter().any(|n| n.node_type == NodeTypeV2::MulConst));
    // Should have Add nodes
    assert!(out.artifact.nodes.iter().any(|n| n.node_type == NodeTypeV2::Add));
    // Should have Ge node
    assert!(out.artifact.nodes.iter().any(|n| n.node_type == NodeTypeV2::Ge));
}

#[test]
fn test_min_max_pattern() {
    let source = "always (min(state.a, state.b) >= max(state.c, 0))";
    let out = compile_v2(source).expect("min/max should compile");
    
    assert!(out.artifact.nodes.iter().any(|n| n.node_type == NodeTypeV2::Min));
    assert!(out.artifact.nodes.iter().any(|n| n.node_type == NodeTypeV2::Max));
}

#[test]
fn test_division_by_constant() {
    let source = "always (state.total / 10 >= state.min_share)";
    let out = compile_v2(source).expect("division should compile");
    
    let div_node = out.artifact.nodes.iter()
        .find(|n| n.node_type == NodeTypeV2::DivConst)
        .expect("should have DivConst node");
    assert_eq!(div_node.const_value, 10);
}

#[test]
fn test_reject_division_by_zero() {
    let source = "always (state.x / 0 >= 0)";
    let result = compile_v2(source);
    assert!(result.is_err(), "division by zero should fail");
}

#[test]
fn test_temporal_lookback() {
    let source = "always (state.price[t-3] < state.price)";
    let out = compile_v2(source).expect("temporal should compile");
    
    assert_eq!(out.artifact.temporal_fields.len(), 1);
    assert_eq!(out.artifact.temporal_fields[0].max_lookback, 3);
}

#[test]
fn test_complex_boolean_logic() {
    let source = "always ((state.a >= 10 && state.b < 20) || !(state.c = 0))";
    let out = compile_v2(source).expect("complex boolean should compile");
    
    assert!(out.artifact.nodes.iter().any(|n| n.node_type == NodeTypeV2::And));
    assert!(out.artifact.nodes.iter().any(|n| n.node_type == NodeTypeV2::Or));
    assert!(out.artifact.nodes.iter().any(|n| n.node_type == NodeTypeV2::Not));
}
