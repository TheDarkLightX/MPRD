#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// Domain separator for MPB policy hashing (bytecode + variable bindings).
pub const MPB_POLICY_HASH_DOMAIN_V1: &[u8] = b"MPRD_POLICY_MPB_V1";

/// MPB Opcode definitions.
///
/// Design principles:
/// - Single-byte opcodes (cache friendly)
/// - No backward jumps (bounded execution by construction)
/// - All arithmetic uses saturating operations (no UB)
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

    // Arithmetic
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

/// Execution status of the VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmStatus {
    Running,
    Halted { result: i64 },
    OutOfFuel,
    StackOverflow,
    StackUnderflow,
    DivisionByZero,
    InvalidOpcode { opcode: u8 },
    UnexpectedEnd,
}

/// MPB Virtual Machine.
///
/// Invariants:
/// - `stack_ptr <= MAX_STACK`
/// - `fuel` decrements monotonically
#[derive(Clone, Debug)]
pub struct MpbVm {
    stack: [i64; Self::MAX_STACK],
    stack_ptr: usize,
    registers: [i64; Self::MAX_REGISTERS],
    fuel: u32,
    status: VmStatus,
}

impl MpbVm {
    pub const MAX_STACK: usize = 64;
    pub const MAX_REGISTERS: usize = 32;
    pub const DEFAULT_FUEL: u32 = 10_000;

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

    pub fn with_fuel(registers: &[i64], fuel: u32) -> Self {
        let mut vm = Self::new(registers);
        vm.fuel = fuel;
        vm
    }

    pub fn execute(&mut self, bytecode: &[u8]) -> core::result::Result<i64, VmStatus> {
        let mut ip = 0usize;

        while ip < bytecode.len() {
            if self.fuel == 0 {
                self.status = VmStatus::OutOfFuel;
                return Err(self.status);
            }
            self.fuel -= 1;

            let opcode = bytecode[ip];
            ip += 1;

            match opcode {
                // Push
                0x01 => {
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
                // Pop
                0x02 => {
                    self.pop()?;
                }
                // Dup
                0x03 => {
                    let v = self.peek()?;
                    self.push(v)?;
                }
                // Swap
                0x04 => {
                    let a = self.pop()?;
                    let b = self.pop()?;
                    self.push(a)?;
                    self.push(b)?;
                }
                // LoadReg
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

                // Arithmetic
                0x20 => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(a.saturating_add(b))?;
                }
                0x21 => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(a.saturating_sub(b))?;
                }
                0x22 => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(a.saturating_mul(b))?;
                }
                0x23 => {
                    let b = self.pop()?;
                    if b == 0 {
                        self.status = VmStatus::DivisionByZero;
                        return Err(self.status);
                    }
                    let a = self.pop()?;
                    self.push(a / b)?;
                }
                0x24 => {
                    let b = self.pop()?;
                    if b == 0 {
                        self.status = VmStatus::DivisionByZero;
                        return Err(self.status);
                    }
                    let a = self.pop()?;
                    self.push(a % b)?;
                }
                0x25 => {
                    let a = self.pop()?;
                    self.push(a.saturating_neg())?;
                }
                0x26 => {
                    let a = self.pop()?;
                    self.push(a.saturating_abs())?;
                }

                // Comparison
                0x30 => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push((a == b) as i64)?;
                }
                0x31 => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push((a != b) as i64)?;
                }
                0x32 => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push((a < b) as i64)?;
                }
                0x33 => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push((a <= b) as i64)?;
                }
                0x34 => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push((a > b) as i64)?;
                }
                0x35 => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push((a >= b) as i64)?;
                }

                // Logic
                0x40 => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(((a != 0) && (b != 0)) as i64)?;
                }
                0x41 => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(((a != 0) || (b != 0)) as i64)?;
                }
                0x42 => {
                    let a = self.pop()?;
                    self.push((a == 0) as i64)?;
                }

                // Bitwise
                0x50 => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(a & b)?;
                }
                0x51 => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(a | b)?;
                }
                0x52 => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(a ^ b)?;
                }
                0x53 => {
                    let a = self.pop()?;
                    self.push(!a)?;
                }
                0x54 => {
                    let shift = self.pop()?.clamp(0, 63) as u32;
                    let a = self.pop()?;
                    self.push(a << shift)?;
                }
                0x55 => {
                    let shift = self.pop()?.clamp(0, 63) as u32;
                    let a = self.pop()?;
                    self.push(a >> shift)?;
                }

                // Halt
                0xFF => {
                    let result = self.peek().unwrap_or(0);
                    self.status = VmStatus::Halted { result };
                    return Ok(result);
                }

                _ => {
                    self.status = VmStatus::InvalidOpcode { opcode };
                    return Err(self.status);
                }
            }
        }

        self.status = VmStatus::UnexpectedEnd;
        Err(self.status)
    }

    fn push(&mut self, value: i64) -> core::result::Result<(), VmStatus> {
        if self.stack_ptr >= Self::MAX_STACK {
            self.status = VmStatus::StackOverflow;
            return Err(self.status);
        }
        self.stack[self.stack_ptr] = value;
        self.stack_ptr += 1;
        Ok(())
    }

    fn pop(&mut self) -> core::result::Result<i64, VmStatus> {
        if self.stack_ptr == 0 {
            self.status = VmStatus::StackUnderflow;
            return Err(self.status);
        }
        self.stack_ptr -= 1;
        Ok(self.stack[self.stack_ptr])
    }

    fn peek(&mut self) -> core::result::Result<i64, VmStatus> {
        if self.stack_ptr == 0 {
            self.status = VmStatus::StackUnderflow;
            return Err(self.status);
        }
        Ok(self.stack[self.stack_ptr - 1])
    }
}

/// Builder for MPB bytecode.
#[derive(Clone, Debug, Default)]
pub struct BytecodeBuilder {
    code: Vec<u8>,
}

impl BytecodeBuilder {
    pub fn new() -> Self {
        Self { code: Vec::new() }
    }

    pub fn op(&mut self, opcode: OpCode) -> &mut Self {
        self.code.push(opcode as u8);
        self
    }

    pub fn push_i64(&mut self, value: i64) -> &mut Self {
        self.code.push(OpCode::Push as u8);
        self.code.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn load_reg(&mut self, reg: u8) -> &mut Self {
        self.code.push(OpCode::LoadReg as u8);
        self.code.push(reg);
        self
    }

    pub fn add(&mut self) -> &mut Self {
        self.op(OpCode::Add)
    }
    pub fn sub(&mut self) -> &mut Self {
        self.op(OpCode::Sub)
    }
    pub fn mul(&mut self) -> &mut Self {
        self.op(OpCode::Mul)
    }
    pub fn div(&mut self) -> &mut Self {
        self.op(OpCode::Div)
    }
    pub fn modu(&mut self) -> &mut Self {
        self.op(OpCode::Mod)
    }
    pub fn le(&mut self) -> &mut Self {
        self.op(OpCode::Le)
    }
    pub fn lt(&mut self) -> &mut Self {
        self.op(OpCode::Lt)
    }
    pub fn ge(&mut self) -> &mut Self {
        self.op(OpCode::Ge)
    }
    pub fn gt(&mut self) -> &mut Self {
        self.op(OpCode::Gt)
    }
    pub fn eq(&mut self) -> &mut Self {
        self.op(OpCode::Eq)
    }
    pub fn and(&mut self) -> &mut Self {
        self.op(OpCode::And)
    }
    pub fn or(&mut self) -> &mut Self {
        self.op(OpCode::Or)
    }
    pub fn not(&mut self) -> &mut Self {
        self.op(OpCode::Not)
    }
    pub fn halt(&mut self) -> &mut Self {
        self.op(OpCode::Halt)
    }

    pub fn build(&self) -> Vec<u8> {
        let mut code = self.code.clone();
        if code.last() != Some(&(OpCode::Halt as u8)) {
            code.push(OpCode::Halt as u8);
        }
        code
    }
}

/// Compute SHA-256(domain || canonical_policy_bytes).
///
/// Canonical policy bytes:
/// - `u32` bytecode_len (LE)
/// - `bytecode`
/// - `u32` binding_count (LE)
/// - for each binding (in canonical order):
///   - `u32` name_len (LE)
///   - `name` bytes (UTF-8)
///   - `u8` reg_index
pub fn policy_hash_v1(bytecode: &[u8], bindings: &[(&[u8], u8)]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MPB_POLICY_HASH_DOMAIN_V1);
    hasher.update((bytecode.len() as u32).to_le_bytes());
    hasher.update(bytecode);
    hasher.update((bindings.len() as u32).to_le_bytes());
    for (name, reg) in bindings {
        hasher.update((name.len() as u32).to_le_bytes());
        hasher.update(*name);
        hasher.update([*reg]);
    }
    hasher.finalize().into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterMappingError {
    MalformedState,
    MalformedCandidate,
    UnsupportedValueEncoding,
}

fn read_u32_le(bytes: &[u8], offset: &mut usize) -> Option<u32> {
    let b: [u8; 4] = bytes.get(*offset..*offset + 4)?.try_into().ok()?;
    *offset += 4;
    Some(u32::from_le_bytes(b))
}

fn read_i64_le(bytes: &[u8], offset: &mut usize) -> Option<i64> {
    let b: [u8; 8] = bytes.get(*offset..*offset + 8)?.try_into().ok()?;
    *offset += 8;
    Some(i64::from_le_bytes(b))
}

fn read_u64_le(bytes: &[u8], offset: &mut usize) -> Option<u64> {
    let b: [u8; 8] = bytes.get(*offset..*offset + 8)?.try_into().ok()?;
    *offset += 8;
    Some(u64::from_le_bytes(b))
}

fn read_len_prefixed_bytes<'a>(bytes: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let len = read_u32_le(bytes, offset)? as usize;
    let out = bytes.get(*offset..*offset + len)?;
    *offset += len;
    Some(out)
}

fn skip_len_prefixed_bytes(bytes: &[u8], offset: &mut usize) -> Option<()> {
    let _ = read_len_prefixed_bytes(bytes, offset)?;
    Some(())
}

fn read_value_i64(bytes: &[u8], offset: &mut usize) -> Result<i64, RegisterMappingError> {
    let tag = *bytes
        .get(*offset)
        .ok_or(RegisterMappingError::UnsupportedValueEncoding)?;
    *offset += 1;

    match tag {
        0x00 => {
            // Bool
            let b = *bytes
                .get(*offset)
                .ok_or(RegisterMappingError::UnsupportedValueEncoding)?;
            *offset += 1;
            Ok((b != 0) as i64)
        }
        0x01 => {
            // Int(i64)
            read_i64_le(bytes, offset).ok_or(RegisterMappingError::UnsupportedValueEncoding)
        }
        0x02 => {
            // UInt(u64) clamped to i64::MAX
            let v =
                read_u64_le(bytes, offset).ok_or(RegisterMappingError::UnsupportedValueEncoding)?;
            Ok(if v > i64::MAX as u64 {
                i64::MAX
            } else {
                v as i64
            })
        }
        0x03 | 0x04 => {
            // String / Bytes => 0, but still must be well-formed length-prefixed.
            skip_len_prefixed_bytes(bytes, offset)
                .ok_or(RegisterMappingError::UnsupportedValueEncoding)?;
            Ok(0)
        }
        _ => Err(RegisterMappingError::UnsupportedValueEncoding),
    }
}

/// Extract candidate score from a canonical candidate hash preimage.
pub fn candidate_score_from_preimage_v1(
    candidate_preimage: &[u8],
) -> Result<i64, RegisterMappingError> {
    let mut o = 0usize;
    // action_type (ignored)
    read_len_prefixed_bytes(candidate_preimage, &mut o)
        .ok_or(RegisterMappingError::MalformedCandidate)?;
    // score
    read_i64_le(candidate_preimage, &mut o).ok_or(RegisterMappingError::MalformedCandidate)
}

fn lookup_kv_value_i64_v1(
    preimage: &[u8],
    key_name: &[u8],
) -> Result<Option<i64>, RegisterMappingError> {
    let mut o = 0usize;
    while o < preimage.len() {
        let key = read_len_prefixed_bytes(preimage, &mut o)
            .ok_or(RegisterMappingError::MalformedState)?;
        // Try to parse as Value (state/candidate params encoding). If this fails, caller treats as malformed.
        let value = read_value_i64(preimage, &mut o)?;
        if key == key_name {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn lookup_candidate_param_i64_v1(
    candidate_preimage: &[u8],
    key_name: &[u8],
) -> Result<Option<i64>, RegisterMappingError> {
    let mut o = 0usize;
    // action_type (ignored)
    read_len_prefixed_bytes(candidate_preimage, &mut o)
        .ok_or(RegisterMappingError::MalformedCandidate)?;
    // score (ignored)
    read_i64_le(candidate_preimage, &mut o).ok_or(RegisterMappingError::MalformedCandidate)?;

    while o < candidate_preimage.len() {
        let key = read_len_prefixed_bytes(candidate_preimage, &mut o)
            .ok_or(RegisterMappingError::MalformedCandidate)?;
        let value = read_value_i64(candidate_preimage, &mut o)?;
        if key == key_name {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

/// Deterministically map canonical MPRD encodings to MPB registers (mpb register mapping v1).
///
/// - `state_preimage` must be the canonical bytes from `mprd-core::hash::state_hash_preimage`.
/// - `candidate_preimage` must be the canonical bytes from `mprd-core::hash::candidate_hash_preimage`.
/// - `bindings` must be canonical: unique and sorted by name.
pub fn registers_from_preimages_v1(
    state_preimage: &[u8],
    candidate_preimage: &[u8],
    bindings: &[(&[u8], u8)],
) -> Result<[i64; MpbVm::MAX_REGISTERS], RegisterMappingError> {
    let score = candidate_score_from_preimage_v1(candidate_preimage)?;
    let mut regs = [0i64; MpbVm::MAX_REGISTERS];

    for (name, reg) in bindings {
        let idx = *reg as usize;
        if idx >= MpbVm::MAX_REGISTERS {
            continue;
        }

        let v = if *name == b"score" {
            score
        } else if let Some(v) = lookup_kv_value_i64_v1(state_preimage, name)? {
            v
        } else {
            lookup_candidate_param_i64_v1(candidate_preimage, name)?.unwrap_or(0)
        };

        regs[idx] = v;
    }

    Ok(regs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_executes_simple_add() {
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
    fn policy_hash_changes_with_bindings() {
        let code = [0xFFu8];
        let a = policy_hash_v1(&code, &[(&b"x"[..], 0)]);
        let b = policy_hash_v1(&code, &[(&b"x"[..], 1)]);
        assert_ne!(a, b);
    }

    #[test]
    fn registers_mapping_prefers_state_over_candidate() {
        // state_preimage: key "x" => Int(7)
        let mut state = Vec::new();
        state.extend_from_slice(&(1u32).to_le_bytes());
        state.extend_from_slice(b"x");
        state.extend_from_slice(&[0x01]);
        state.extend_from_slice(&7i64.to_le_bytes());

        // candidate_preimage: action_type="A", score=0, param "x" => Int(9)
        let mut cand = Vec::new();
        cand.extend_from_slice(&(1u32).to_le_bytes());
        cand.extend_from_slice(b"A");
        cand.extend_from_slice(&0i64.to_le_bytes());
        cand.extend_from_slice(&(1u32).to_le_bytes());
        cand.extend_from_slice(b"x");
        cand.extend_from_slice(&[0x01]);
        cand.extend_from_slice(&9i64.to_le_bytes());

        let regs = registers_from_preimages_v1(&state, &cand, &[(&b"x"[..], 0)]).unwrap();
        assert_eq!(regs[0], 7);
    }

    #[test]
    fn out_of_fuel_is_fail_closed() {
        let bytecode = BytecodeBuilder::new()
            .push_i64(1)
            .push_i64(2)
            .add()
            .halt()
            .build();
        let mut vm = MpbVm::with_fuel(&[], 1);
        assert_eq!(vm.execute(&bytecode), Err(VmStatus::OutOfFuel));
    }
}
