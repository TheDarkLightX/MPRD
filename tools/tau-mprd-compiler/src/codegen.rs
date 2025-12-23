//! Code generator for Tau-MPRD.
//!
//! Validates and finalizes the compiled policy artifact.

use crate::error::{CompileError, CompileResult};
use crate::ir::{CompiledPolicy, Gate, GateType};
use crate::limits::{MAX_GATES_V1, MAX_PREDICATES_V1, MAX_TEMPORAL_FIELDS_V1, MAX_WIRES_V1};
use std::collections::{BTreeSet, HashMap};

/// Maximum number of gates (Tau-MPRD v1).
pub const MAX_GATES: usize = MAX_GATES_V1;

/// Maximum number of wires (Tau-MPRD v1).
pub const MAX_WIRES: usize = MAX_WIRES_V1;

/// Maximum temporal fields (Tau-MPRD v1).
pub const MAX_TEMPORAL_FIELDS: usize = MAX_TEMPORAL_FIELDS_V1;

/// Maximum number of predicates (Tau-MPRD v1).
pub const MAX_PREDICATES: usize = MAX_PREDICATES_V1;

/// Validate and finalize the compiled policy.
pub fn generate(policy: &CompiledPolicy) -> CompileResult<CompiledPolicy> {
    // Validate bounds
    if policy.predicates.len() > MAX_PREDICATES {
        return Err(CompileError::PredicateCountExceeded {
            count: policy.predicates.len(),
            max: MAX_PREDICATES,
        });
    }

    if policy.gates.len() > MAX_GATES {
        return Err(CompileError::GateCountExceeded {
            count: policy.gates.len(),
            max: MAX_GATES,
        });
    }
    
    if policy.temporal_fields.len() > MAX_TEMPORAL_FIELDS {
        return Err(CompileError::TemporalFieldCountExceeded {
            count: policy.temporal_fields.len(),
            max: MAX_TEMPORAL_FIELDS,
        });
    }

    // Validate unique out_wires (required for deterministic evaluation and sorting).
    let mut producer_by_wire: HashMap<u32, usize> = HashMap::with_capacity(policy.gates.len());
    for (idx, g) in policy.gates.iter().enumerate() {
        if producer_by_wire.insert(g.out_wire, idx).is_some() {
            return Err(CompileError::DuplicateWire { wire: g.out_wire });
        }
    }

    // Validate wire indices (wire references are only meaningful for And/Or/Not inputs).
    let mut max_wire = policy.output_wire;
    for g in &policy.gates {
        max_wire = max_wire.max(g.out_wire);
        match g.gate_type {
            GateType::And | GateType::Or => {
                max_wire = max_wire.max(g.in1).max(g.in2);
            }
            GateType::Not => {
                max_wire = max_wire.max(g.in1);
            }
            GateType::PredicateInput => {
                if (g.in1 as usize) >= policy.predicates.len() {
                    return Err(CompileError::internal(format!(
                        "predicate_idx {} out of range ({} predicates)",
                        g.in1,
                        policy.predicates.len()
                    )));
                }
            }
            GateType::TemporalInput => {
                let field_idx = g.in1 as usize;
                if field_idx >= policy.temporal_fields.len() {
                    return Err(CompileError::internal(format!(
                        "temporal field_idx {} out of range ({} fields)",
                        field_idx,
                        policy.temporal_fields.len()
                    )));
                }
                let lookback = g.in2 as usize;
                if lookback != 0 {
                    let max_prev = policy.temporal_fields[field_idx].prev_key_hashes.len();
                    if lookback - 1 >= max_prev {
                        return Err(CompileError::internal(format!(
                            "temporal lookback {} exceeds available prev values ({})",
                            lookback,
                            max_prev
                        )));
                    }
                }
            }
            GateType::Constant => {
                if g.in1 != 0 && g.in1 != 1 {
                    return Err(CompileError::TypeMismatch {
                        expected: "0 or 1".to_string(),
                        found: g.in1.to_string(),
                        context: "Constant gate in1".to_string(),
                    });
                }
            }
        }
    }

    if (max_wire as usize) >= MAX_WIRES {
        return Err(CompileError::WireIndexExceeded {
            index: max_wire as usize,
            max: MAX_WIRES,
        });
    }

    // Validate output wire is defined
    let defined_wires: std::collections::HashSet<u32> = policy.gates.iter()
        .map(|g| g.out_wire)
        .collect();
    
    if !defined_wires.contains(&policy.output_wire) {
        return Err(CompileError::OutputWireUndefined {
            wire: policy.output_wire,
        });
    }
    
    // Return validated policy (potentially reordered for canonical form)
    Ok(topological_sort(policy)?)
}

/// Topologically sort gates for canonical ordering.
fn topological_sort(policy: &CompiledPolicy) -> CompileResult<CompiledPolicy> {
    // Build a mapping from produced wire -> gate index (must be unique; validated earlier).
    let mut producer_by_wire: HashMap<u32, usize> = HashMap::with_capacity(policy.gates.len());
    for (idx, g) in policy.gates.iter().enumerate() {
        if producer_by_wire.insert(g.out_wire, idx).is_some() {
            return Err(CompileError::DuplicateWire { wire: g.out_wire });
        }
    }

    // Build dependency graph between gates (not wires).
    let mut deps_remaining: Vec<usize> = vec![0; policy.gates.len()];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); policy.gates.len()];

    for (idx, gate) in policy.gates.iter().enumerate() {
        let mut add_dep = |wire: u32| -> CompileResult<()> {
            let Some(&producer_idx) = producer_by_wire.get(&wire) else {
                return Err(CompileError::UnreachableWire { wire });
            };
            deps_remaining[idx] += 1;
            dependents[producer_idx].push(idx);
            Ok(())
        };

        match gate.gate_type {
            GateType::And | GateType::Or => {
                add_dep(gate.in1)?;
                add_dep(gate.in2)?;
            }
            GateType::Not => {
                add_dep(gate.in1)?;
            }
            GateType::PredicateInput | GateType::TemporalInput | GateType::Constant => {}
        }
    }

    // Deterministic Kahn: always pick the smallest (rank, out_wire) available.
    let mut ready: BTreeSet<(u8, u32)> = BTreeSet::new();
    let mut idx_by_wire: HashMap<u32, usize> = HashMap::with_capacity(policy.gates.len());
    for (idx, g) in policy.gates.iter().enumerate() {
        idx_by_wire.insert(g.out_wire, idx);
        if deps_remaining[idx] == 0 {
            ready.insert((gate_rank(g), g.out_wire));
        }
    }

    let mut sorted_gates: Vec<Gate> = Vec::with_capacity(policy.gates.len());
    let mut processed = 0usize;
    while let Some(&(rank, wire)) = ready.iter().next() {
        let _ = rank;
        ready.remove(&(rank, wire));
        let idx = *idx_by_wire
            .get(&wire)
            .ok_or_else(|| CompileError::internal("ready wire missing idx".to_string()))?;
        sorted_gates.push(policy.gates[idx].clone());
        processed += 1;

        for &dep in &dependents[idx] {
            deps_remaining[dep] = deps_remaining[dep].saturating_sub(1);
            if deps_remaining[dep] == 0 {
                let g = &policy.gates[dep];
                ready.insert((gate_rank(g), g.out_wire));
            }
        }
    }

    if processed != policy.gates.len() {
        return Err(CompileError::TopologicalSortFailed);
    }
    
    Ok(CompiledPolicy {
        version: policy.version,
        predicates: policy.predicates.clone(),
        gates: sorted_gates,
        output_wire: policy.output_wire,
        temporal_fields: policy.temporal_fields.clone(),
    })
}

fn gate_rank(g: &Gate) -> u8 {
    match g.gate_type {
        GateType::PredicateInput | GateType::TemporalInput | GateType::Constant => 0,
        GateType::Not => 1,
        GateType::And | GateType::Or => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::tokenize;
    use crate::parser::parse;
    use crate::semantic::analyze;
    use crate::ir::lower;
    
    fn generate_from_source(source: &str) -> CompileResult<CompiledPolicy> {
        let tokens = tokenize(source)?;
        let ast = parse(&tokens)?;
        let checked = analyze(&ast)?;
        let ir = lower(&checked)?;
        generate(&ir)
    }
    
    #[test]
    fn generate_simple_policy() {
        let policy = generate_from_source("always (state.x >= 100)").unwrap();
        assert_eq!(policy.version, 1);
    }
    
    #[test]
    fn generate_compound_policy() {
        let policy = generate_from_source(
            "always ((state.a < 10 && state.b > 0) || state.c = 1)"
        ).unwrap();
        
        // Gates should be topologically sorted
        let mut defined_wires = std::collections::HashSet::new();
        for gate in &policy.gates {
            match gate.gate_type {
                GateType::And | GateType::Or => {
                    assert!(defined_wires.contains(&gate.in1));
                    assert!(defined_wires.contains(&gate.in2));
                }
                GateType::Not => {
                    assert!(defined_wires.contains(&gate.in1));
                }
                _ => {}
            }
            defined_wires.insert(gate.out_wire);
        }
    }
}
