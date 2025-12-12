//! Tracing MPB VM for proof generation.
//!
//! This wraps the MPB VM execution and captures a full trace
//! that can be used for proof generation.

use crate::{sha256, trace::{ExecutionTrace, TraceStep}};

/// A tracing wrapper for MPB VM execution.
///
/// Captures every step of execution for later proof generation.
pub struct TracingVm {
    /// Operand stack.
    stack: [i64; Self::MAX_STACK],
    /// Stack pointer.
    stack_ptr: usize,
    /// Input registers.
    registers: [i64; Self::MAX_REGISTERS],
    /// Initial fuel.
    initial_fuel: u32,
    /// Remaining fuel.
    fuel: u32,
    /// Execution trace being built.
    trace: ExecutionTrace,
    /// Current step number.
    step_num: u32,
}

/// Result of tracing execution.
#[derive(Debug)]
pub enum TracingResult {
    /// Execution completed successfully.
    Success {
        result: i64,
        trace: ExecutionTrace,
    },
    /// Execution failed.
    Error {
        status: TracingError,
        partial_trace: ExecutionTrace,
    },
}

/// Error during tracing execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TracingError {
    OutOfFuel,
    StackOverflow,
    StackUnderflow,
    DivisionByZero,
    InvalidOpcode { opcode: u8 },
    UnexpectedEnd,
}

impl TracingVm {
    pub const MAX_STACK: usize = 64;
    pub const MAX_REGISTERS: usize = 32;
    pub const DEFAULT_FUEL: u32 = 10_000;

    /// Create a new tracing VM.
    pub fn new(bytecode: &[u8], registers: &[i64]) -> Self {
        let bytecode_hash = sha256(bytecode);
        let input_hash = sha256(&registers_to_bytes(registers));
        
        let mut vm = Self {
            stack: [0; Self::MAX_STACK],
            stack_ptr: 0,
            registers: [0; Self::MAX_REGISTERS],
            initial_fuel: Self::DEFAULT_FUEL,
            fuel: Self::DEFAULT_FUEL,
            trace: ExecutionTrace::new(bytecode_hash, input_hash),
            step_num: 0,
        };

        let n = registers.len().min(Self::MAX_REGISTERS);
        vm.registers[..n].copy_from_slice(&registers[..n]);

        vm
    }

    /// Create with custom fuel.
    pub fn with_fuel(bytecode: &[u8], registers: &[i64], fuel: u32) -> Self {
        let mut vm = Self::new(bytecode, registers);
        vm.initial_fuel = fuel;
        vm.fuel = fuel;
        vm
    }

    /// Execute bytecode and capture trace.
    pub fn execute(mut self, bytecode: &[u8]) -> TracingResult {
        let mut ip: usize = 0;

        while ip < bytecode.len() {
            // Fuel check
            if self.fuel == 0 {
                return TracingResult::Error {
                    status: TracingError::OutOfFuel,
                    partial_trace: self.trace,
                };
            }

            let opcode = bytecode[ip];
            let sp_before = self.stack_ptr as u8;
            
            // Execute and capture operands/result
            let exec_result = self.execute_instruction(bytecode, &mut ip, opcode);
            
            match exec_result {
                Ok(step_info) => {
                    let step = TraceStep {
                        step: self.step_num,
                        ip: (ip - step_info.ip_advance) as u32,
                        opcode,
                        sp_before,
                        sp_after: self.stack_ptr as u8,
                        operand_a: step_info.operand_a,
                        operand_b: step_info.operand_b,
                        result: step_info.result,
                        reg_index: step_info.reg_index,
                        fuel_remaining: self.fuel,
                    };
                    
                    self.trace.push(step);
                    self.step_num += 1;
                    self.fuel -= 1;

                    // Check for HALT
                    if opcode == 0xFF {
                        self.trace.finalize(step_info.result);
                        return TracingResult::Success {
                            result: step_info.result,
                            trace: self.trace,
                        };
                    }
                }
                Err(err) => {
                    return TracingResult::Error {
                        status: err,
                        partial_trace: self.trace,
                    };
                }
            }
        }

        // Ran off end - implicit halt
        let result = if self.stack_ptr > 0 {
            self.stack[self.stack_ptr - 1]
        } else {
            0
        };
        self.trace.finalize(result);
        
        TracingResult::Success {
            result,
            trace: self.trace,
        }
    }

    /// Execute a single instruction and return step info.
    fn execute_instruction(
        &mut self,
        bytecode: &[u8],
        ip: &mut usize,
        opcode: u8,
    ) -> Result<StepInfo, TracingError> {
        *ip += 1; // Advance past opcode
        
        match opcode {
            // PUSH
            0x01 => {
                if *ip + 8 > bytecode.len() {
                    return Err(TracingError::UnexpectedEnd);
                }
                let bytes: [u8; 8] = bytecode[*ip..*ip + 8].try_into().unwrap();
                let value = i64::from_le_bytes(bytes);
                *ip += 8;
                self.push(value)?;
                Ok(StepInfo {
                    operand_a: 0,
                    operand_b: 0,
                    result: value,
                    reg_index: None,
                    ip_advance: 9,
                })
            }
            
            // POP
            0x02 => {
                let value = self.pop()?;
                Ok(StepInfo {
                    operand_a: value,
                    operand_b: 0,
                    result: 0,
                    reg_index: None,
                    ip_advance: 1,
                })
            }
            
            // DUP
            0x03 => {
                let value = self.peek()?;
                self.push(value)?;
                Ok(StepInfo {
                    operand_a: value,
                    operand_b: 0,
                    result: value,
                    reg_index: None,
                    ip_advance: 1,
                })
            }
            
            // SWAP
            0x04 => {
                let a = self.pop()?;
                let b = self.pop()?;
                self.push(a)?;
                self.push(b)?;
                Ok(StepInfo {
                    operand_a: a,
                    operand_b: b,
                    result: 0,
                    reg_index: None,
                    ip_advance: 1,
                })
            }
            
            // LOAD_REG
            0x10 => {
                if *ip >= bytecode.len() {
                    return Err(TracingError::UnexpectedEnd);
                }
                let reg = bytecode[*ip];
                *ip += 1;
                let value = self.registers.get(reg as usize).copied().unwrap_or(0);
                self.push(value)?;
                Ok(StepInfo {
                    operand_a: 0,
                    operand_b: 0,
                    result: value,
                    reg_index: Some(reg),
                    ip_advance: 2,
                })
            }
            
            // ADD
            0x20 => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = a.saturating_add(b);
                self.push(result)?;
                Ok(StepInfo {
                    operand_a: a,
                    operand_b: b,
                    result,
                    reg_index: None,
                    ip_advance: 1,
                })
            }
            
            // SUB
            0x21 => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = a.saturating_sub(b);
                self.push(result)?;
                Ok(StepInfo {
                    operand_a: a,
                    operand_b: b,
                    result,
                    reg_index: None,
                    ip_advance: 1,
                })
            }
            
            // MUL
            0x22 => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = a.saturating_mul(b);
                self.push(result)?;
                Ok(StepInfo {
                    operand_a: a,
                    operand_b: b,
                    result,
                    reg_index: None,
                    ip_advance: 1,
                })
            }
            
            // DIV
            0x23 => {
                let b = self.pop()?;
                let a = self.pop()?;
                if b == 0 {
                    return Err(TracingError::DivisionByZero);
                }
                let result = a / b;
                self.push(result)?;
                Ok(StepInfo {
                    operand_a: a,
                    operand_b: b,
                    result,
                    reg_index: None,
                    ip_advance: 1,
                })
            }
            
            // MOD
            0x24 => {
                let b = self.pop()?;
                let a = self.pop()?;
                if b == 0 {
                    return Err(TracingError::DivisionByZero);
                }
                let result = a % b;
                self.push(result)?;
                Ok(StepInfo {
                    operand_a: a,
                    operand_b: b,
                    result,
                    reg_index: None,
                    ip_advance: 1,
                })
            }
            
            // NEG
            0x25 => {
                let a = self.pop()?;
                let result = a.saturating_neg();
                self.push(result)?;
                Ok(StepInfo {
                    operand_a: a,
                    operand_b: 0,
                    result,
                    reg_index: None,
                    ip_advance: 1,
                })
            }
            
            // ABS
            0x26 => {
                let a = self.pop()?;
                let result = a.saturating_abs();
                self.push(result)?;
                Ok(StepInfo {
                    operand_a: a,
                    operand_b: 0,
                    result,
                    reg_index: None,
                    ip_advance: 1,
                })
            }
            
            // EQ
            0x30 => self.binary_cmp(|a, b| if a == b { 1 } else { 0 }),
            
            // NE
            0x31 => self.binary_cmp(|a, b| if a != b { 1 } else { 0 }),
            
            // LT
            0x32 => self.binary_cmp(|a, b| if a < b { 1 } else { 0 }),
            
            // LE
            0x33 => self.binary_cmp(|a, b| if a <= b { 1 } else { 0 }),
            
            // GT
            0x34 => self.binary_cmp(|a, b| if a > b { 1 } else { 0 }),
            
            // GE
            0x35 => self.binary_cmp(|a, b| if a >= b { 1 } else { 0 }),
            
            // AND
            0x40 => self.binary_cmp(|a, b| if a != 0 && b != 0 { 1 } else { 0 }),
            
            // OR
            0x41 => self.binary_cmp(|a, b| if a != 0 || b != 0 { 1 } else { 0 }),
            
            // NOT
            0x42 => {
                let a = self.pop()?;
                let result = if a == 0 { 1 } else { 0 };
                self.push(result)?;
                Ok(StepInfo {
                    operand_a: a,
                    operand_b: 0,
                    result,
                    reg_index: None,
                    ip_advance: 1,
                })
            }
            
            // BIT_AND
            0x50 => self.binary_cmp(|a, b| a & b),
            
            // BIT_OR
            0x51 => self.binary_cmp(|a, b| a | b),
            
            // BIT_XOR
            0x52 => self.binary_cmp(|a, b| a ^ b),
            
            // BIT_NOT
            0x53 => {
                let a = self.pop()?;
                let result = !a;
                self.push(result)?;
                Ok(StepInfo {
                    operand_a: a,
                    operand_b: 0,
                    result,
                    reg_index: None,
                    ip_advance: 1,
                })
            }
            
            // SHL
            0x54 => {
                let b = self.pop()?;
                let a = self.pop()?;
                let shift = (b as u32).min(63);
                let result = a.wrapping_shl(shift);
                self.push(result)?;
                Ok(StepInfo {
                    operand_a: a,
                    operand_b: b,
                    result,
                    reg_index: None,
                    ip_advance: 1,
                })
            }
            
            // SHR
            0x55 => {
                let b = self.pop()?;
                let a = self.pop()?;
                let shift = (b as u32).min(63);
                let result = a.wrapping_shr(shift);
                self.push(result)?;
                Ok(StepInfo {
                    operand_a: a,
                    operand_b: b,
                    result,
                    reg_index: None,
                    ip_advance: 1,
                })
            }
            
            // HALT
            0xFF => {
                let result = self.pop().unwrap_or(0);
                Ok(StepInfo {
                    operand_a: result,
                    operand_b: 0,
                    result,
                    reg_index: None,
                    ip_advance: 1,
                })
            }
            
            _ => Err(TracingError::InvalidOpcode { opcode }),
        }
    }

    fn binary_cmp<F>(&mut self, f: F) -> Result<StepInfo, TracingError>
    where
        F: FnOnce(i64, i64) -> i64,
    {
        let b = self.pop()?;
        let a = self.pop()?;
        let result = f(a, b);
        self.push(result)?;
        Ok(StepInfo {
            operand_a: a,
            operand_b: b,
            result,
            reg_index: None,
            ip_advance: 1,
        })
    }

    fn push(&mut self, value: i64) -> Result<(), TracingError> {
        if self.stack_ptr >= Self::MAX_STACK {
            return Err(TracingError::StackOverflow);
        }
        self.stack[self.stack_ptr] = value;
        self.stack_ptr += 1;
        Ok(())
    }

    fn pop(&mut self) -> Result<i64, TracingError> {
        if self.stack_ptr == 0 {
            return Err(TracingError::StackUnderflow);
        }
        self.stack_ptr -= 1;
        Ok(self.stack[self.stack_ptr])
    }

    fn peek(&self) -> Result<i64, TracingError> {
        if self.stack_ptr == 0 {
            return Err(TracingError::StackUnderflow);
        }
        Ok(self.stack[self.stack_ptr - 1])
    }
}

/// Information about a single execution step.
struct StepInfo {
    operand_a: i64,
    operand_b: i64,
    result: i64,
    reg_index: Option<u8>,
    ip_advance: usize,
}

/// Convert registers to bytes for hashing.
fn registers_to_bytes(registers: &[i64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(registers.len() * 8);
    for reg in registers {
        bytes.extend_from_slice(&reg.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_simple_add() -> Vec<u8> {
        // PUSH 10, PUSH 20, ADD, HALT
        let mut bytecode = vec![0x01];
        bytecode.extend_from_slice(&10i64.to_le_bytes());
        bytecode.push(0x01);
        bytecode.extend_from_slice(&20i64.to_le_bytes());
        bytecode.push(0x20); // ADD
        bytecode.push(0xFF); // HALT
        bytecode
    }

    #[test]
    fn trace_simple_add() {
        let bytecode = build_simple_add();
        let vm = TracingVm::new(&bytecode, &[]);
        
        match vm.execute(&bytecode) {
            TracingResult::Success { result, trace } => {
                assert_eq!(result, 30);
                assert_eq!(trace.len(), 4); // PUSH, PUSH, ADD, HALT
                assert_eq!(trace.final_result, 30);
            }
            TracingResult::Error { .. } => panic!("Should succeed"),
        }
    }

    #[test]
    fn trace_with_registers() {
        // LOAD_REG 0, LOAD_REG 1, LE, HALT
        let bytecode = vec![
            0x10, 0x00, // LOAD_REG 0
            0x10, 0x01, // LOAD_REG 1
            0x33,       // LE
            0xFF,       // HALT
        ];
        
        let registers = [50, 100]; // risk=50, max=100
        let vm = TracingVm::new(&bytecode, &registers);
        
        match vm.execute(&bytecode) {
            TracingResult::Success { result, trace } => {
                assert_eq!(result, 1); // 50 <= 100
                assert_eq!(trace.len(), 4);
                
                // Verify trace captures register loads
                assert_eq!(trace.steps[0].opcode, 0x10);
                assert_eq!(trace.steps[0].result, 50);
                assert_eq!(trace.steps[1].opcode, 0x10);
                assert_eq!(trace.steps[1].result, 100);
            }
            TracingResult::Error { .. } => panic!("Should succeed"),
        }
    }

    #[test]
    fn trace_captures_arithmetic() {
        let bytecode = build_simple_add();
        let vm = TracingVm::new(&bytecode, &[]);
        
        match vm.execute(&bytecode) {
            TracingResult::Success { trace, .. } => {
                // Find the ADD step
                let add_step = trace.steps.iter().find(|s| s.opcode == 0x20).unwrap();
                assert_eq!(add_step.operand_a, 10);
                assert_eq!(add_step.operand_b, 20);
                assert_eq!(add_step.result, 30);
            }
            TracingResult::Error { .. } => panic!("Should succeed"),
        }
    }
}
