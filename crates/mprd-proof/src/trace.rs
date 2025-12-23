//! Execution trace capture for MPB VM.
//!
//! The trace records every step of execution, enabling:
//! 1. Deterministic replay
//! 2. Merkle commitment
//! 3. Spot-check verification

use crate::{sha256, Hash256};
use serde::{Deserialize, Serialize};

/// A single step in the execution trace.
///
/// This captures all state transitions for verification.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceStep {
    /// Step number (0-indexed).
    pub step: u32,

    /// Instruction pointer before execution.
    pub ip: u32,

    /// Opcode executed.
    pub opcode: u8,

    /// Stack pointer before execution.
    pub sp_before: u8,

    /// Stack pointer after execution.
    pub sp_after: u8,

    /// First operand (if applicable).
    pub operand_a: i64,

    /// Second operand (if applicable).
    pub operand_b: i64,

    /// Result pushed to stack (if applicable).
    pub result: i64,

    /// Register index accessed (if LOAD_REG).
    pub reg_index: Option<u8>,

    /// Fuel remaining after this step.
    pub fuel_remaining: u32,
}

impl TraceStep {
    /// Compute a deterministic hash of this trace step.
    pub fn hash(&self) -> Hash256 {
        let bytes = self.to_bytes();
        sha256(&bytes)
    }

    /// Serialize to bytes for hashing.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);

        bytes.extend_from_slice(&self.step.to_le_bytes());
        bytes.extend_from_slice(&self.ip.to_le_bytes());
        bytes.push(self.opcode);
        bytes.push(self.sp_before);
        bytes.push(self.sp_after);
        bytes.extend_from_slice(&self.operand_a.to_le_bytes());
        bytes.extend_from_slice(&self.operand_b.to_le_bytes());
        bytes.extend_from_slice(&self.result.to_le_bytes());
        bytes.push(self.reg_index.unwrap_or(0xFF));
        bytes.extend_from_slice(&self.fuel_remaining.to_le_bytes());

        bytes
    }
}

/// Complete execution trace of an MPB program.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionTrace {
    /// All execution steps.
    pub steps: Vec<TraceStep>,

    /// Final result (top of stack at HALT).
    pub final_result: i64,

    /// Hash of the bytecode executed.
    pub bytecode_hash: Hash256,

    /// Hash of input registers.
    pub input_hash: Hash256,

    /// External context hash bound into the proof statement (Fiat-Shamir).
    ///
    /// This is used to bind non-VM context (e.g., `nonce_or_tx_hash`) to the proof so it cannot
    /// be replayed across distinct decisions with identical bytecode/registers.
    pub context_hash: Hash256,

    /// Total fuel consumed.
    pub fuel_consumed: u32,
}

impl ExecutionTrace {
    /// Create a new empty trace.
    pub fn new(bytecode_hash: Hash256, input_hash: Hash256) -> Self {
        Self {
            steps: Vec::new(),
            final_result: 0,
            bytecode_hash,
            input_hash,
            context_hash: [0u8; 32],
            fuel_consumed: 0,
        }
    }

    /// Create a new empty trace with an explicit context hash.
    pub fn new_with_context(
        bytecode_hash: Hash256,
        input_hash: Hash256,
        context_hash: Hash256,
    ) -> Self {
        Self {
            context_hash,
            ..Self::new(bytecode_hash, input_hash)
        }
    }

    /// Add a step to the trace.
    pub fn push(&mut self, step: TraceStep) {
        self.fuel_consumed += 1;
        self.steps.push(step);
    }

    /// Finalize the trace with the result.
    pub fn finalize(&mut self, result: i64) {
        self.final_result = result;
    }

    /// Get the number of steps.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Check if trace is empty.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Compute hash of the entire trace (expensive, use Merkle for proofs).
    pub fn full_hash(&self) -> Hash256 {
        let mut data = Vec::new();
        data.extend_from_slice(&self.bytecode_hash);
        data.extend_from_slice(&self.input_hash);
        data.extend_from_slice(&self.final_result.to_le_bytes());
        data.extend_from_slice(&self.fuel_consumed.to_le_bytes());

        for step in &self.steps {
            data.extend_from_slice(&step.hash());
        }

        sha256(&data)
    }

    /// Verify that a trace step is internally consistent.
    pub fn verify_step_consistency(&self, index: usize) -> bool {
        if index >= self.steps.len() {
            return false;
        }

        let step = &self.steps[index];

        // Verify step number
        if step.step != index as u32 {
            return false;
        }

        // Verify stack pointer changes are valid for opcode
        let sp_delta = step.sp_after as i16 - step.sp_before as i16;

        match step.opcode {
            0x01 => sp_delta == 1,         // PUSH: +1
            0x02 => sp_delta == -1,        // POP: -1
            0x03 => sp_delta == 1,         // DUP: +1
            0x04 => sp_delta == 0,         // SWAP: 0
            0x10 => sp_delta == 1,         // LOAD_REG: +1
            0x20..=0x24 => sp_delta == -1, // Binary arithmetic: -1
            0x25 | 0x26 => sp_delta == 0,  // Unary arithmetic: 0
            0x30..=0x35 => sp_delta == -1, // Comparison: -1
            0x40 | 0x41 => sp_delta == -1, // Binary logic: -1
            0x42 => sp_delta == 0,         // NOT: 0
            0x50..=0x52 => sp_delta == -1, // Binary bitvector: -1
            0x53 => sp_delta == 0,         // BIT_NOT: 0
            0x54 | 0x55 => sp_delta == -1, // Shift: -1
            0xFF => sp_delta == -1,        // HALT: -1
            _ => false,
        }
    }

    /// Verify arithmetic correctness of a step.
    pub fn verify_step_arithmetic(&self, index: usize) -> bool {
        if index >= self.steps.len() {
            return false;
        }

        let step = &self.steps[index];
        let a = step.operand_a;
        let b = step.operand_b;
        let r = step.result;

        match step.opcode {
            0x20 => r == a.saturating_add(b),                  // ADD
            0x21 => r == a.saturating_sub(b),                  // SUB
            0x22 => r == a.saturating_mul(b),                  // MUL
            0x23 => b != 0 && r == a / b,                      // DIV
            0x24 => b != 0 && r == a % b,                      // MOD
            0x25 => r == a.saturating_neg(),                   // NEG
            0x26 => r == a.saturating_abs(),                   // ABS
            0x30 => r == if a == b { 1 } else { 0 },           // EQ
            0x31 => r == if a != b { 1 } else { 0 },           // NE
            0x32 => r == if a < b { 1 } else { 0 },            // LT
            0x33 => r == if a <= b { 1 } else { 0 },           // LE
            0x34 => r == if a > b { 1 } else { 0 },            // GT
            0x35 => r == if a >= b { 1 } else { 0 },           // GE
            0x40 => r == if a != 0 && b != 0 { 1 } else { 0 }, // AND
            0x41 => r == if a != 0 || b != 0 { 1 } else { 0 }, // OR
            0x42 => r == if a == 0 { 1 } else { 0 },           // NOT
            0x50 => r == (a & b),                              // BIT_AND
            0x51 => r == (a | b),                              // BIT_OR
            0x52 => r == (a ^ b),                              // BIT_XOR
            0x53 => r == !a,                                   // BIT_NOT
            0x54 => {
                let shift = (b as u32).min(63);
                r == a.wrapping_shl(shift)
            } // SHL
            0x55 => {
                let shift = (b as u32).min(63);
                r == a.wrapping_shr(shift)
            } // SHR
            // Other opcodes don't have arithmetic to verify
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_step(step: u32, opcode: u8, sp_before: u8, sp_after: u8) -> TraceStep {
        TraceStep {
            step,
            ip: step,
            opcode,
            sp_before,
            sp_after,
            operand_a: 0,
            operand_b: 0,
            result: 0,
            reg_index: None,
            fuel_remaining: 1000 - step,
        }
    }

    #[test]
    fn trace_step_hash_deterministic() {
        let step = dummy_step(0, 0x20, 2, 1);
        let h1 = step.hash();
        let h2 = step.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn trace_step_different_data_different_hash() {
        let step1 = dummy_step(0, 0x20, 2, 1);
        let step2 = dummy_step(1, 0x20, 2, 1);
        assert_ne!(step1.hash(), step2.hash());
    }

    #[test]
    fn verify_add_arithmetic() {
        let mut trace = ExecutionTrace::new([0; 32], [0; 32]);
        trace.push(TraceStep {
            step: 0,
            ip: 0,
            opcode: 0x20, // ADD
            sp_before: 2,
            sp_after: 1,
            operand_a: 10,
            operand_b: 20,
            result: 30,
            reg_index: None,
            fuel_remaining: 999,
        });

        assert!(trace.verify_step_consistency(0));
        assert!(trace.verify_step_arithmetic(0));
    }

    #[test]
    fn verify_add_wrong_result() {
        let mut trace = ExecutionTrace::new([0; 32], [0; 32]);
        trace.push(TraceStep {
            step: 0,
            ip: 0,
            opcode: 0x20, // ADD
            sp_before: 2,
            sp_after: 1,
            operand_a: 10,
            operand_b: 20,
            result: 999, // WRONG!
            reg_index: None,
            fuel_remaining: 999,
        });

        assert!(trace.verify_step_consistency(0));
        assert!(!trace.verify_step_arithmetic(0)); // Should fail
    }
}
