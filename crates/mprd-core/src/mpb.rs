//! MPRD Policy Bytecode (MPB) — Deterministic Policy Evaluation VM
//!
//! This module provides:
//! - A reusable, `no_std` MPB VM core (re-exported from `mprd-mpb`)
//! - A `std` policy-engine wrapper that maps MPRD state/candidates into registers
//!   and applies fail-closed evaluation semantics.

use crate::{
    CandidateAction, Hash32, MprdError, PolicyEngine, PolicyHash, Result, RuleVerdict,
    StateSnapshot,
};
use std::collections::HashMap;

pub use mprd_mpb::{BytecodeBuilder, MpbVm, OpCode, VmStatus};

// =============================================================================
// POLICY ENGINE INTEGRATION (std)
// =============================================================================

/// Compiled MPB policy.
#[derive(Clone, Debug)]
pub struct MpbPolicy {
    /// Bytecode for evaluation.
    pub bytecode: Vec<u8>,

    /// Canonical variable bindings in ascending name order.
    pub variables: Vec<(String, u8)>,

    /// Policy hash (content identity for mpb-v1).
    pub policy_hash: PolicyHash,

    /// Original source (for audit/debugging).
    pub source: Option<String>,
}

impl MpbPolicy {
    /// Create a policy from bytecode and variable mapping.
    ///
    /// The resulting `policy_hash` commits to BOTH:
    /// - the bytecode, and
    /// - the canonicalized variable bindings.
    pub fn new(bytecode: Vec<u8>, variables: HashMap<String, u8>) -> Self {
        let mut bindings: Vec<(String, u8)> = variables.into_iter().collect();
        bindings.sort_by(|a, b| a.0.cmp(&b.0));

        let refs: Vec<(&[u8], u8)> = bindings
            .iter()
            .map(|(name, reg)| (name.as_bytes(), *reg))
            .collect();

        let policy_hash = Hash32(mprd_mpb::policy_hash_v1(&bytecode, &refs));

        Self {
            bytecode,
            variables: bindings,
            policy_hash,
            source: None,
        }
    }

    /// Attach original source for debugging.
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }
}

/// MPB-based policy engine.
pub struct MpbPolicyEngine {
    /// Registered policies by hash.
    policies: HashMap<Hash32, MpbPolicy>,
    /// Fuel limit per evaluation.
    fuel_limit: u32,
}

impl MpbPolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            fuel_limit: MpbVm::DEFAULT_FUEL,
        }
    }

    /// Set custom fuel limit.
    pub fn with_fuel_limit(mut self, fuel: u32) -> Self {
        self.fuel_limit = fuel;
        self
    }

    /// Register a compiled policy.
    pub fn register(&mut self, policy: MpbPolicy) -> PolicyHash {
        let hash = policy.policy_hash.clone();
        self.policies.insert(hash.clone(), policy);
        hash
    }

    /// Evaluate a policy against a candidate.
    pub fn evaluate_one(
        &self,
        policy_hash: &PolicyHash,
        state: &StateSnapshot,
        candidate: &CandidateAction,
    ) -> Result<RuleVerdict> {
        let policy = self
            .policies
            .get(policy_hash)
            .ok_or(MprdError::PolicyNotFound {
                hash: policy_hash.clone(),
            })?;

        let registers = self.build_registers(policy, state, candidate);

        let mut vm = MpbVm::with_fuel(&registers, self.fuel_limit);
        let result = vm.execute(&policy.bytecode);

        match result {
            Ok(value) => Ok(RuleVerdict {
                allowed: value != 0,
                reasons: vec![],
                limits: HashMap::new(),
            }),
            Err(status) => Ok(RuleVerdict {
                allowed: false,
                reasons: vec![format!("MPB VM error: {:?}", status)],
                limits: HashMap::new(),
            }),
        }
    }

    fn build_registers(
        &self,
        policy: &MpbPolicy,
        state: &StateSnapshot,
        candidate: &CandidateAction,
    ) -> Vec<i64> {
        let mut registers = vec![0i64; MpbVm::MAX_REGISTERS];

        for (name, reg_u8) in &policy.variables {
            let reg = *reg_u8 as usize;
            if reg >= MpbVm::MAX_REGISTERS {
                continue;
            }

            if let Some(value) = state.fields.get(name) {
                registers[reg] = value_to_i64(value);
                continue;
            }

            if let Some(value) = candidate.params.get(name) {
                registers[reg] = value_to_i64(value);
                continue;
            }

            if name.as_str() == "score" {
                registers[reg] = candidate.score.0;
            }
        }

        registers
    }
}

impl Default for MpbPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine for MpbPolicyEngine {
    fn evaluate(
        &self,
        policy_hash: &PolicyHash,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<Vec<RuleVerdict>> {
        if candidates.len() > crate::MAX_CANDIDATES {
            return Err(MprdError::BoundedValueExceeded(
                "too many candidates for MpbPolicyEngine".into(),
            ));
        }

        let mut out = Vec::with_capacity(candidates.len());
        for c in candidates {
            out.push(self.evaluate_one(policy_hash, state, c)?);
        }
        Ok(out)
    }
}

fn value_to_i64(value: &crate::Value) -> i64 {
    match value {
        crate::Value::Bool(b) => {
            if *b {
                1
            } else {
                0
            }
        }
        crate::Value::Int(i) => *i,
        crate::Value::UInt(u) => {
            if *u > i64::MAX as u64 {
                i64::MAX
            } else {
                *u as i64
            }
        }
        crate::Value::String(_) => 0,
        crate::Value::Bytes(_) => 0,
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Score, Value};
    use std::collections::HashMap;

    fn candidate(action_type: &str, score: i64, params: &[(&str, Value)]) -> CandidateAction {
        CandidateAction {
            action_type: action_type.into(),
            params: params
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
            score: Score(score),
            candidate_hash: Hash32([0u8; 32]),
        }
    }

    fn state(fields: &[(&str, Value)]) -> StateSnapshot {
        StateSnapshot {
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
            policy_inputs: HashMap::new(),
            state_hash: Hash32([0u8; 32]),
            state_ref: crate::StateRef::unknown(),
        }
    }

    #[test]
    fn vm_simple_push_and_halt() {
        let bytecode = BytecodeBuilder::new().push_i64(42).halt().build();
        let mut vm = MpbVm::new(&[]);
        assert_eq!(vm.execute(&bytecode), Ok(42));
    }

    #[test]
    fn policy_hash_binds_variable_mapping() {
        let bytecode = BytecodeBuilder::new().load_reg(0).halt().build();
        let p1 = MpbPolicy::new(bytecode.clone(), HashMap::from([("x".into(), 0)]));
        let p2 = MpbPolicy::new(bytecode, HashMap::from([("x".into(), 1)]));
        assert_ne!(p1.policy_hash, p2.policy_hash);
    }

    #[test]
    fn engine_evaluates_one_candidate() {
        let bytecode = BytecodeBuilder::new()
            .load_reg(0) // risk
            .push_i64(100)
            .le()
            .halt()
            .build();

        let mut engine = MpbPolicyEngine::new().with_fuel_limit(1_000);
        let policy_hash = engine.register(MpbPolicy::new(
            bytecode,
            HashMap::from([("risk".into(), 0)]),
        ));

        let verdict = engine
            .evaluate_one(
                &policy_hash,
                &state(&[("risk", Value::UInt(50))]),
                &candidate("BUY", 10, &[]),
            )
            .unwrap();
        assert!(verdict.allowed);
    }

    #[test]
    fn preimage_register_mapping_matches_engine_mapping() {
        let bytecode = BytecodeBuilder::new()
            .load_reg(0) // x
            .push_i64(10)
            .ge()
            .halt()
            .build();

        let mut engine = MpbPolicyEngine::new().with_fuel_limit(1_000);
        let policy_hash = engine.register(MpbPolicy::new(
            bytecode.clone(),
            HashMap::from([("x".into(), 0), ("score".into(), 1)]),
        ));

        let state = state(&[("x", Value::Int(12))]);
        let candidate = candidate("TEST", 7, &[("x", Value::Int(1))]); // state should win

        let verdict_engine = engine
            .evaluate_one(&policy_hash, &state, &candidate)
            .unwrap();

        let state_preimage = crate::hash::state_hash_preimage(&state);
        let cand_preimage = crate::hash::candidate_hash_preimage(&candidate);
        let bindings = [("score".as_bytes(), 1u8), ("x".as_bytes(), 0u8)];

        let regs =
            mprd_mpb::registers_from_preimages_v1(&state_preimage, &cand_preimage, &bindings)
                .expect("register mapping should parse canonical preimages");
        let mut vm = mprd_mpb::MpbVm::with_fuel(&regs, 1_000);
        let allowed_direct = vm.execute(&bytecode).map(|v| v != 0).unwrap_or(false);

        assert_eq!(allowed_direct, verdict_engine.allowed);
        assert_eq!(regs[0], 12);
        assert_eq!(regs[1], 7);
    }
}
