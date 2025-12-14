//! MPRD Policy Bytecode (MPB) — Deterministic Policy Evaluation VM
//!
//! # Overview
//!
//! MPB is an independent, clean-room implementation of a stack-based bytecode
//! virtual machine designed for deterministic policy evaluation. It is NOT
//! derived from Tau-lang source code.
//!
//! # Purpose
//!
//! - **Deterministic execution**: Same inputs always produce same outputs
//! - **Bounded execution**: Fuel-limited, guaranteed termination
//! - **ZK-compatible**: No heap allocation, fixed-size stack, Risc0 friendly
//! - **Fail-closed**: Any error (division by zero, overflow) → DENY
//!
//! # Relationship to Tau
//!
//! MPB is designed to work alongside Tau Network integration:
//! - Tau specs are the **source of truth** (stored on Tau Network)
//! - MPB provides **deterministic re-execution** in Risc0 ZK circuits
//! - A compiler (offline) translates Tau policy expressions → MPB bytecode
//!
//! # Legal Notice
//!
//! This implementation is original work, not derived from IDNI AG's Tau-lang
//! source code. MPRD integrates with Tau Network under the permitted use case:
//! "development and use solely for the purpose of integrating with the Tau Net
//! blockchain" as specified in the Tau Language Framework license.
//!
//! Copyright (c) 2024 MPRD Contributors. MIT License.

use crate::{CandidateAction, Hash32, MprdError, PolicyHash, Result, RuleVerdict, StateSnapshot};
use std::collections::HashMap;

// =============================================================================
// INSTRUCTION SET
// =============================================================================

/// MPB Opcode definitions.
///
/// Design principles:
/// - Single-byte opcodes (cache friendly)
/// - No backward jumps (bounded execution by construction)
/// - All arithmetic is checked/saturating (no UB)
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpCode {
    // Stack manipulation
    Push = 0x01, // Push immediate i64 (followed by 8 bytes LE)
    Pop = 0x02,  // Pop and discard top
    Dup = 0x03,  // Duplicate top of stack
    Swap = 0x04, // Swap top two elements

    // Load from registers (inputs)
    LoadReg = 0x10, // Push register[arg] onto stack

    // Arithmetic (checked, saturating on overflow)
    Add = 0x20,
    Sub = 0x21,
    Mul = 0x22,
    Div = 0x23, // Division by zero → error (fail-closed)
    Mod = 0x24, // Modulo by zero → error
    Neg = 0x25, // Negate (saturating)
    Abs = 0x26, // Absolute value

    // Comparison (push 1 for true, 0 for false)
    Eq = 0x30,
    Ne = 0x31,
    Lt = 0x32,
    Le = 0x33,
    Gt = 0x34,
    Ge = 0x35,

    // Logic (0 = false, nonzero = true)
    And = 0x40,
    Or = 0x41,
    Not = 0x42,

    // Bitvector operations
    BitAnd = 0x50,
    BitOr = 0x51,
    BitXor = 0x52,
    BitNot = 0x53,
    Shl = 0x54, // Shift left (capped at 63)
    Shr = 0x55, // Shift right (capped at 63)

    // Termination
    Halt = 0xFF, // Stop execution, return top of stack
}

// =============================================================================
// VIRTUAL MACHINE
// =============================================================================

/// Execution status of the VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmStatus {
    /// VM is still running.
    Running,
    /// VM halted successfully with a result.
    Halted { result: i64 },
    /// VM ran out of fuel (bounded execution).
    OutOfFuel,
    /// Stack overflow (pushed too many values).
    StackOverflow,
    /// Stack underflow (popped from empty stack).
    StackUnderflow,
    /// Division or modulo by zero.
    DivisionByZero,
    /// Invalid opcode encountered.
    InvalidOpcode { opcode: u8 },
    /// Bytecode ended unexpectedly.
    UnexpectedEnd,
}

/// MPB Virtual Machine.
///
/// Invariants:
/// - `stack_ptr <= MAX_STACK`
/// - `fuel` decrements monotonically
/// - No heap allocation during execution
#[derive(Clone, Debug)]
pub struct MpbVm {
    /// Operand stack (fixed size, no allocation).
    stack: [i64; Self::MAX_STACK],
    /// Stack pointer (points to next free slot).
    stack_ptr: usize,
    /// Input registers (loaded from state/candidate).
    registers: [i64; Self::MAX_REGISTERS],
    /// Fuel remaining (bounded execution guarantee).
    fuel: u32,
    /// Current execution status.
    status: VmStatus,
}

impl MpbVm {
    /// Maximum stack depth.
    pub const MAX_STACK: usize = 64;
    /// Maximum number of input registers.
    pub const MAX_REGISTERS: usize = 32;
    /// Default fuel limit.
    pub const DEFAULT_FUEL: u32 = 10_000;

    /// Create a new VM with the given input registers.
    ///
    /// # Precondition
    /// `registers.len() <= MAX_REGISTERS`
    pub fn new(registers: &[i64]) -> Self {
        let mut vm = Self {
            stack: [0; Self::MAX_STACK],
            stack_ptr: 0,
            registers: [0; Self::MAX_REGISTERS],
            fuel: Self::DEFAULT_FUEL,
            status: VmStatus::Running,
        };

        let n = registers.len().min(Self::MAX_REGISTERS);
        vm.registers[..n].copy_from_slice(&registers[..n]);

        vm
    }

    /// Create a VM with custom fuel limit.
    pub fn with_fuel(registers: &[i64], fuel: u32) -> Self {
        let mut vm = Self::new(registers);
        vm.fuel = fuel;
        vm
    }

    /// Execute bytecode until halt or error.
    ///
    /// # Termination Proof
    /// The fuel counter decrements by 1 for each instruction.
    /// Since fuel is finite and never increases, execution terminates
    /// in at most `fuel` steps.
    ///
    /// # Returns
    /// - `Ok(result)` if execution halted successfully
    /// - `Err(status)` if an error occurred
    pub fn execute(&mut self, bytecode: &[u8]) -> std::result::Result<i64, VmStatus> {
        let mut ip = 0; // Instruction pointer

        while ip < bytecode.len() {
            // Fuel check — guarantees termination
            if self.fuel == 0 {
                self.status = VmStatus::OutOfFuel;
                return Err(self.status);
            }
            self.fuel -= 1;

            let opcode = bytecode[ip];
            ip += 1;

            match opcode {
                // === Stack Manipulation ===
                0x01 => {
                    // Push: read 8 bytes as i64 LE
                    if ip + 8 > bytecode.len() {
                        self.status = VmStatus::UnexpectedEnd;
                        return Err(self.status);
                    }
                    let bytes: [u8; 8] = match bytecode[ip..ip + 8].try_into() {
                        Ok(b) => b,
                        Err(_) => {
                            self.status = VmStatus::UnexpectedEnd;
                            return Err(self.status);
                        }
                    };
                    let value = i64::from_le_bytes(bytes);
                    ip += 8;
                    self.push(value)?;
                }
                0x02 => {
                    // Pop
                    self.pop()?;
                }
                0x03 => {
                    // Dup
                    let v = self.peek()?;
                    self.push(v)?;
                }
                0x04 => {
                    // Swap
                    let a = self.pop()?;
                    let b = self.pop()?;
                    self.push(a)?;
                    self.push(b)?;
                }

                // === Load Register ===
                0x10 => {
                    if ip >= bytecode.len() {
                        self.status = VmStatus::UnexpectedEnd;
                        return Err(self.status);
                    }
                    let reg = bytecode[ip] as usize;
                    ip += 1;
                    let value = self.registers.get(reg).copied().unwrap_or(0);
                    self.push(value)?;
                }

                // === Arithmetic ===
                0x20 => {
                    // Add (saturating)
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(a.saturating_add(b))?;
                }
                0x21 => {
                    // Sub (saturating)
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(a.saturating_sub(b))?;
                }
                0x22 => {
                    // Mul (saturating)
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(a.saturating_mul(b))?;
                }
                0x23 => {
                    // Div (fail on zero)
                    let b = self.pop()?;
                    let a = self.pop()?;
                    if b == 0 {
                        self.status = VmStatus::DivisionByZero;
                        return Err(self.status);
                    }
                    self.push(a / b)?;
                }
                0x24 => {
                    // Mod (fail on zero)
                    let b = self.pop()?;
                    let a = self.pop()?;
                    if b == 0 {
                        self.status = VmStatus::DivisionByZero;
                        return Err(self.status);
                    }
                    self.push(a % b)?;
                }
                0x25 => {
                    // Neg (saturating)
                    let a = self.pop()?;
                    self.push(a.saturating_neg())?;
                }
                0x26 => {
                    // Abs
                    let a = self.pop()?;
                    self.push(a.saturating_abs())?;
                }

                // === Comparison ===
                0x30 => {
                    // Eq
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(if a == b { 1 } else { 0 })?;
                }
                0x31 => {
                    // Ne
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(if a != b { 1 } else { 0 })?;
                }
                0x32 => {
                    // Lt
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(if a < b { 1 } else { 0 })?;
                }
                0x33 => {
                    // Le
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(if a <= b { 1 } else { 0 })?;
                }
                0x34 => {
                    // Gt
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(if a > b { 1 } else { 0 })?;
                }
                0x35 => {
                    // Ge
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(if a >= b { 1 } else { 0 })?;
                }

                // === Logic ===
                0x40 => {
                    // And
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(if a != 0 && b != 0 { 1 } else { 0 })?;
                }
                0x41 => {
                    // Or
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(if a != 0 || b != 0 { 1 } else { 0 })?;
                }
                0x42 => {
                    // Not
                    let a = self.pop()?;
                    self.push(if a == 0 { 1 } else { 0 })?;
                }

                // === Bitvector ===
                0x50 => {
                    // BitAnd
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(a & b)?;
                }
                0x51 => {
                    // BitOr
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(a | b)?;
                }
                0x52 => {
                    // BitXor
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(a ^ b)?;
                }
                0x53 => {
                    // BitNot
                    let a = self.pop()?;
                    self.push(!a)?;
                }
                0x54 => {
                    // Shl (capped shift)
                    let b = self.pop()?;
                    let a = self.pop()?;
                    let shift = (b as u32).min(63);
                    self.push(a.wrapping_shl(shift))?;
                }
                0x55 => {
                    // Shr (capped shift)
                    let b = self.pop()?;
                    let a = self.pop()?;
                    let shift = (b as u32).min(63);
                    self.push(a.wrapping_shr(shift))?;
                }

                // === Halt ===
                0xFF => {
                    let result = self.pop().unwrap_or(0);
                    self.status = VmStatus::Halted { result };
                    return Ok(result);
                }

                _ => {
                    self.status = VmStatus::InvalidOpcode { opcode };
                    return Err(self.status);
                }
            }
        }

        // Ran off end without explicit halt
        let result = self.pop().unwrap_or(0);
        self.status = VmStatus::Halted { result };
        Ok(result)
    }

    /// Get remaining fuel.
    pub fn remaining_fuel(&self) -> u32 {
        self.fuel
    }

    /// Get current status.
    pub fn status(&self) -> VmStatus {
        self.status
    }

    #[inline]
    fn push(&mut self, value: i64) -> std::result::Result<(), VmStatus> {
        if self.stack_ptr >= Self::MAX_STACK {
            self.status = VmStatus::StackOverflow;
            return Err(self.status);
        }
        self.stack[self.stack_ptr] = value;
        self.stack_ptr += 1;
        Ok(())
    }

    #[inline]
    fn pop(&mut self) -> std::result::Result<i64, VmStatus> {
        if self.stack_ptr == 0 {
            self.status = VmStatus::StackUnderflow;
            return Err(self.status);
        }
        self.stack_ptr -= 1;
        Ok(self.stack[self.stack_ptr])
    }

    #[inline]
    fn peek(&self) -> std::result::Result<i64, VmStatus> {
        if self.stack_ptr == 0 {
            return Err(VmStatus::StackUnderflow);
        }
        Ok(self.stack[self.stack_ptr - 1])
    }
}

// =============================================================================
// BYTECODE BUILDER
// =============================================================================

/// Helper for building MPB bytecode programmatically.
#[derive(Clone, Debug, Default)]
pub struct BytecodeBuilder {
    code: Vec<u8>,
}

impl BytecodeBuilder {
    pub fn new() -> Self {
        Self { code: Vec::new() }
    }

    /// Push an immediate i64 value.
    pub fn push_i64(&mut self, value: i64) -> &mut Self {
        self.code.push(0x01);
        self.code.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Load a register value onto the stack.
    pub fn load_reg(&mut self, reg: u8) -> &mut Self {
        self.code.push(0x10);
        self.code.push(reg);
        self
    }

    /// Emit a simple opcode (no arguments).
    pub fn op(&mut self, opcode: OpCode) -> &mut Self {
        self.code.push(opcode as u8);
        self
    }

    /// Add two values.
    pub fn add(&mut self) -> &mut Self {
        self.op(OpCode::Add)
    }

    /// Subtract.
    pub fn sub(&mut self) -> &mut Self {
        self.op(OpCode::Sub)
    }

    /// Multiply.
    pub fn mul(&mut self) -> &mut Self {
        self.op(OpCode::Mul)
    }

    /// Divide.
    pub fn div(&mut self) -> &mut Self {
        self.op(OpCode::Div)
    }

    /// Less than or equal.
    pub fn le(&mut self) -> &mut Self {
        self.op(OpCode::Le)
    }

    /// Greater than or equal.
    pub fn ge(&mut self) -> &mut Self {
        self.op(OpCode::Ge)
    }

    /// Equal.
    pub fn eq(&mut self) -> &mut Self {
        self.op(OpCode::Eq)
    }

    /// Logical AND.
    pub fn and(&mut self) -> &mut Self {
        self.op(OpCode::And)
    }

    /// Logical OR.
    pub fn or(&mut self) -> &mut Self {
        self.op(OpCode::Or)
    }

    /// Logical NOT.
    pub fn not(&mut self) -> &mut Self {
        self.op(OpCode::Not)
    }

    /// Halt execution.
    pub fn halt(&mut self) -> &mut Self {
        self.op(OpCode::Halt)
    }

    /// Build and return the bytecode.
    pub fn build(&self) -> Vec<u8> {
        let mut code = self.code.clone();
        // Ensure bytecode ends with halt
        if code.last() != Some(&0xFF) {
            code.push(0xFF);
        }
        code
    }
}

// =============================================================================
// POLICY ENGINE INTEGRATION
// =============================================================================

/// Compiled MPB policy.
#[derive(Clone, Debug)]
pub struct MpbPolicy {
    /// Bytecode for evaluation.
    pub bytecode: Vec<u8>,
    /// Variable name → register index mapping.
    pub variables: HashMap<String, u8>,
    /// Policy hash (for verification).
    pub policy_hash: PolicyHash,
    /// Original source (for audit/debugging).
    pub source: Option<String>,
}

impl MpbPolicy {
    /// Create a policy from bytecode and variable mapping.
    pub fn new(bytecode: Vec<u8>, variables: HashMap<String, u8>) -> Self {
        use crate::hash::sha256;
        let policy_hash = sha256(&bytecode);
        Self {
            bytecode,
            variables,
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

        // Build register values from state and candidate
        let registers = self.build_registers(policy, state, candidate);

        // Execute bytecode
        let mut vm = MpbVm::with_fuel(&registers, self.fuel_limit);
        let result = vm.execute(&policy.bytecode);

        match result {
            Ok(value) => Ok(RuleVerdict {
                allowed: value != 0,
                reasons: vec![],
                limits: HashMap::new(),
            }),
            Err(status) => {
                // Fail closed: any VM error → DENY
                Ok(RuleVerdict {
                    allowed: false,
                    reasons: vec![format!("MPB VM error: {:?}", status)],
                    limits: HashMap::new(),
                })
            }
        }
    }

    /// Build register array from state and candidate.
    fn build_registers(
        &self,
        policy: &MpbPolicy,
        state: &StateSnapshot,
        candidate: &CandidateAction,
    ) -> Vec<i64> {
        let mut registers = vec![0i64; MpbVm::MAX_REGISTERS];

        for (name, &reg) in &policy.variables {
            let reg = reg as usize;
            if reg >= MpbVm::MAX_REGISTERS {
                continue;
            }

            // Try state fields first
            if let Some(value) = state.fields.get(name) {
                registers[reg] = value_to_i64(value);
                continue;
            }

            // Then try candidate params
            if let Some(value) = candidate.params.get(name) {
                registers[reg] = value_to_i64(value);
                continue;
            }

            // Special fields
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

/// Convert a Value to i64 for VM registers.
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
        crate::Value::UInt(u) => *u as i64,
        crate::Value::String(_) => 0, // Strings not supported in VM
        crate::Value::Bytes(_) => 0,  // Bytes not supported in VM
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_push_and_halt() {
        let bytecode = BytecodeBuilder::new().push_i64(42).halt().build();

        let mut vm = MpbVm::new(&[]);
        let result = vm.execute(&bytecode);

        assert_eq!(result, Ok(42));
    }

    #[test]
    fn arithmetic_add() {
        let bytecode = BytecodeBuilder::new()
            .push_i64(10)
            .push_i64(32)
            .add()
            .halt()
            .build();

        let mut vm = MpbVm::new(&[]);
        assert_eq!(vm.execute(&bytecode), Ok(42));
    }

    #[test]
    fn comparison_le_true() {
        // risk=50, max_risk=100 → 50 <= 100 → 1
        let bytecode = BytecodeBuilder::new()
            .load_reg(0) // risk
            .load_reg(1) // max_risk
            .le()
            .halt()
            .build();

        let mut vm = MpbVm::new(&[50, 100]);
        assert_eq!(vm.execute(&bytecode), Ok(1));
    }

    #[test]
    fn comparison_le_false() {
        // risk=150, max_risk=100 → 150 <= 100 → 0
        let bytecode = BytecodeBuilder::new()
            .load_reg(0)
            .load_reg(1)
            .le()
            .halt()
            .build();

        let mut vm = MpbVm::new(&[150, 100]);
        assert_eq!(vm.execute(&bytecode), Ok(0));
    }

    #[test]
    fn logical_and_both_true() {
        // within_bounds=1, within_tol=1 → 1 && 1 → 1
        let bytecode = BytecodeBuilder::new()
            .load_reg(0)
            .load_reg(1)
            .and()
            .halt()
            .build();

        let mut vm = MpbVm::new(&[1, 1]);
        assert_eq!(vm.execute(&bytecode), Ok(1));
    }

    #[test]
    fn logical_and_one_false() {
        // within_bounds=1, within_tol=0 → 1 && 0 → 0
        let bytecode = BytecodeBuilder::new()
            .load_reg(0)
            .load_reg(1)
            .and()
            .halt()
            .build();

        let mut vm = MpbVm::new(&[1, 0]);
        assert_eq!(vm.execute(&bytecode), Ok(0));
    }

    #[test]
    fn division_by_zero_fails() {
        let bytecode = BytecodeBuilder::new()
            .push_i64(10)
            .push_i64(0)
            .div()
            .halt()
            .build();

        let mut vm = MpbVm::new(&[]);
        assert_eq!(vm.execute(&bytecode), Err(VmStatus::DivisionByZero));
    }

    #[test]
    fn out_of_fuel_terminates() {
        let bytecode = BytecodeBuilder::new()
            .push_i64(1)
            .push_i64(2)
            .add()
            .push_i64(3)
            .add()
            .halt()
            .build();

        let mut vm = MpbVm::with_fuel(&[], 2);
        assert_eq!(vm.execute(&bytecode), Err(VmStatus::OutOfFuel));
    }

    #[test]
    fn stack_overflow_detected() {
        let mut builder = BytecodeBuilder::new();
        for i in 0..100 {
            builder.push_i64(i);
        }
        let bytecode = builder.halt().build();

        let mut vm = MpbVm::new(&[]);
        assert_eq!(vm.execute(&bytecode), Err(VmStatus::StackOverflow));
    }

    #[test]
    fn saturating_arithmetic_no_panic() {
        let bytecode = BytecodeBuilder::new()
            .push_i64(i64::MAX)
            .push_i64(i64::MAX)
            .add()
            .halt()
            .build();

        let mut vm = MpbVm::new(&[]);
        assert_eq!(vm.execute(&bytecode), Ok(i64::MAX));
    }

    #[test]
    fn deterministic_execution() {
        let bytecode = BytecodeBuilder::new()
            .load_reg(0)
            .load_reg(1)
            .mul()
            .load_reg(2)
            .add()
            .halt()
            .build();

        let registers = [7, 8, 3];

        // Run 100 times, must be identical
        for _ in 0..100 {
            let mut vm = MpbVm::new(&registers);
            assert_eq!(vm.execute(&bytecode), Ok(59)); // 7*8+3 = 59
        }
    }

    #[test]
    fn pid_policy_bytecode() {
        // ALLOWED = within_bounds && within_tol
        // r0 = within_bounds, r1 = within_tol
        let bytecode = BytecodeBuilder::new()
            .load_reg(0)
            .load_reg(1)
            .and()
            .halt()
            .build();

        // Both true → allowed
        let mut vm = MpbVm::new(&[1, 1]);
        assert_eq!(vm.execute(&bytecode), Ok(1));

        // One false → denied
        let mut vm = MpbVm::new(&[1, 0]);
        assert_eq!(vm.execute(&bytecode), Ok(0));

        let mut vm = MpbVm::new(&[0, 1]);
        assert_eq!(vm.execute(&bytecode), Ok(0));
    }

    #[test]
    fn risk_threshold_policy() {
        // ALLOWED = (risk <= max_risk) && (cost <= max_cost)
        // r0=risk, r1=max_risk, r2=cost, r3=max_cost
        let bytecode = BytecodeBuilder::new()
            .load_reg(0) // risk
            .load_reg(1) // max_risk
            .le() // risk <= max_risk
            .load_reg(2) // cost
            .load_reg(3) // max_cost
            .le() // cost <= max_cost
            .and() // both conditions
            .halt()
            .build();

        // Both within limits → allowed
        let mut vm = MpbVm::new(&[50, 100, 30, 50]);
        assert_eq!(vm.execute(&bytecode), Ok(1));

        // Risk too high → denied
        let mut vm = MpbVm::new(&[150, 100, 30, 50]);
        assert_eq!(vm.execute(&bytecode), Ok(0));

        // Cost too high → denied
        let mut vm = MpbVm::new(&[50, 100, 60, 50]);
        assert_eq!(vm.execute(&bytecode), Ok(0));
    }
}
