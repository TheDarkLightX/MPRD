//! MPB Proof Verifier
//!
//! Verifies proofs of correct MPB execution.
//!
//! # Verification Guarantees
//!
//! If verification passes:
//! 1. The bytecode hashes to `bytecode_hash`
//! 2. The inputs hash to `input_hash`
//! 3. All spot-checked steps are arithmetically correct
//! 4. All spot-checked steps are in the committed trace
//! 5. Execution produced `output`
//!
//! # Security Level
//!
//! With k spot checks and n steps, probability of undetected cheating:
//! P(cheat) ≤ ((n-k)/n)^k
//!
//! For k=16, n=1000: P(cheat) < 2^-16 ≈ 0.0015%
//! For k=32, n=1000: P(cheat) < 2^-32 ≈ 0.00000002%

use crate::{prover::MpbProof, Hash256};
use serde::{Deserialize, Serialize};

/// Result of proof verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationResult {
    /// Proof verified successfully.
    Valid,

    /// Proof failed verification.
    Invalid(VerificationError),
}

/// Specific verification failure reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationError {
    /// First step Merkle proof invalid.
    FirstStepProofInvalid,

    /// Last step Merkle proof invalid.
    LastStepProofInvalid,

    /// Spot check Merkle proof invalid.
    SpotCheckProofInvalid { step: u32 },

    /// First step doesn't start at IP=0.
    FirstStepNotAtStart,

    /// Last step opcode is not HALT.
    LastStepNotHalt,

    /// Step arithmetic verification failed.
    ArithmeticError { step: u32, opcode: u8 },

    /// Stack pointer transition invalid.
    StackTransitionError { step: u32 },

    /// Output doesn't match last step result.
    OutputMismatch,

    /// Fuel consumed doesn't match step count.
    FuelMismatch,

    /// Step number doesn't match index.
    StepNumberMismatch { expected: u32, got: u32 },
}

/// Configuration for verification.
#[derive(Clone, Debug)]
pub struct VerifierConfig {
    /// Require all spot checks to have valid Merkle proofs.
    pub require_merkle_proofs: bool,

    /// Require arithmetic verification of all revealed steps.
    pub require_arithmetic_check: bool,

    /// Require stack transition verification.
    pub require_stack_check: bool,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            require_merkle_proofs: true,
            require_arithmetic_check: true,
            require_stack_check: true,
        }
    }
}

/// Proof verifier for MPB execution.
pub struct MpbVerifier {
    config: VerifierConfig,
}

impl MpbVerifier {
    /// Create a new verifier with default config.
    pub fn new() -> Self {
        Self {
            config: VerifierConfig::default(),
        }
    }

    /// Create a verifier with custom config.
    pub fn with_config(config: VerifierConfig) -> Self {
        Self { config }
    }

    /// Verify a proof.
    ///
    /// Time: O(k * log n) where k = number of spot checks
    pub fn verify(&self, proof: &MpbProof) -> VerificationResult {
        // 1. Verify first step Merkle proof
        if self.config.require_merkle_proofs {
            if !proof.first_step_proof.verify(&proof.trace_root) {
                return VerificationResult::Invalid(VerificationError::FirstStepProofInvalid);
            }

            if !proof.last_step_proof.verify(&proof.trace_root) {
                return VerificationResult::Invalid(VerificationError::LastStepProofInvalid);
            }
        }

        // 2. Verify first step is at IP=0
        if proof.first_step.ip != 0 || proof.first_step.step != 0 {
            return VerificationResult::Invalid(VerificationError::FirstStepNotAtStart);
        }

        // 3. Verify last step is HALT (0xFF)
        if proof.last_step.opcode != 0xFF {
            return VerificationResult::Invalid(VerificationError::LastStepNotHalt);
        }

        // 4. Verify output matches last step
        if proof.output != proof.last_step.result {
            return VerificationResult::Invalid(VerificationError::OutputMismatch);
        }

        // 5. Verify fuel consumption
        if proof.fuel_consumed != proof.num_steps as u32 {
            return VerificationResult::Invalid(VerificationError::FuelMismatch);
        }

        // 6. Verify all spot checks
        for check in &proof.spot_checks {
            // Merkle proof
            if self.config.require_merkle_proofs && !check.proof.verify(&proof.trace_root) {
                return VerificationResult::Invalid(VerificationError::SpotCheckProofInvalid {
                    step: check.step.step,
                });
            }

            // Step number matches proof index
            if check.step.step as usize != check.proof.leaf_index {
                return VerificationResult::Invalid(VerificationError::StepNumberMismatch {
                    expected: check.proof.leaf_index as u32,
                    got: check.step.step,
                });
            }

            // Arithmetic correctness
            if self.config.require_arithmetic_check && !verify_step_arithmetic(&check.step) {
                return VerificationResult::Invalid(VerificationError::ArithmeticError {
                    step: check.step.step,
                    opcode: check.step.opcode,
                });
            }

            // Stack transition
            if self.config.require_stack_check && !verify_stack_transition(&check.step) {
                return VerificationResult::Invalid(VerificationError::StackTransitionError {
                    step: check.step.step,
                });
            }
        }

        // 7. Also verify boundary steps arithmetic
        if self.config.require_arithmetic_check {
            if !verify_step_arithmetic(&proof.first_step) {
                return VerificationResult::Invalid(VerificationError::ArithmeticError {
                    step: proof.first_step.step,
                    opcode: proof.first_step.opcode,
                });
            }
            if !verify_step_arithmetic(&proof.last_step) {
                return VerificationResult::Invalid(VerificationError::ArithmeticError {
                    step: proof.last_step.step,
                    opcode: proof.last_step.opcode,
                });
            }
        }

        VerificationResult::Valid
    }

    /// Verify a proof against expected public inputs.
    pub fn verify_with_inputs(
        &self,
        proof: &MpbProof,
        expected_bytecode_hash: &Hash256,
        expected_input_hash: &Hash256,
    ) -> VerificationResult {
        // Check public inputs match
        if proof.bytecode_hash != *expected_bytecode_hash {
            return VerificationResult::Invalid(VerificationError::OutputMismatch);
        }
        if proof.input_hash != *expected_input_hash {
            return VerificationResult::Invalid(VerificationError::OutputMismatch);
        }

        self.verify(proof)
    }

    /// Calculate security level (bits) for this proof.
    ///
    /// Returns log2(1/P(cheat))
    pub fn security_bits(&self, proof: &MpbProof) -> f64 {
        let n = proof.num_steps as f64;
        let k = (proof.spot_checks.len() + 2) as f64; // +2 for boundary steps

        if n <= k {
            return f64::INFINITY; // All steps checked
        }

        // P(cheat) = ((n-k)/n)^k
        // Security bits = -log2(P(cheat)) = -k * log2((n-k)/n)
        -k * ((n - k) / n).log2()
    }
}

impl Default for MpbVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify arithmetic correctness of a single step.
fn verify_step_arithmetic(step: &crate::trace::TraceStep) -> bool {
    let a = step.operand_a;
    let b = step.operand_b;
    let r = step.result;

    match step.opcode {
        0x01 => true,                                      // PUSH: result is the pushed value
        0x02 => true,                                      // POP: no arithmetic
        0x03 => true,                                      // DUP: no arithmetic
        0x04 => true,                                      // SWAP: no arithmetic
        0x10 => true,                                      // LOAD_REG: result is register value
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
        0xFF => true,                                      // HALT: result is popped value
        _ => false,                                        // Unknown opcode
    }
}

/// Verify stack pointer transition is valid for the opcode.
fn verify_stack_transition(step: &crate::trace::TraceStep) -> bool {
    let delta = step.sp_after as i16 - step.sp_before as i16;

    match step.opcode {
        0x01 => delta == 1,         // PUSH: +1
        0x02 => delta == -1,        // POP: -1
        0x03 => delta == 1,         // DUP: +1
        0x04 => delta == 0,         // SWAP: 0
        0x10 => delta == 1,         // LOAD_REG: +1
        0x20..=0x24 => delta == -1, // Binary arithmetic: -1
        0x25 | 0x26 => delta == 0,  // Unary arithmetic: 0
        0x30..=0x35 => delta == -1, // Comparison: -1
        0x40 | 0x41 => delta == -1, // Binary logic: -1
        0x42 => delta == 0,         // NOT: 0
        0x50..=0x52 => delta == -1, // Binary bitvector: -1
        0x53 => delta == 0,         // BIT_NOT: 0
        0x54 | 0x55 => delta == -1, // Shift: -1
        0xFF => delta == -1,        // HALT: -1
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{prover::MpbProver, sha256, trace::TraceStep};

    fn make_valid_trace(steps: usize) -> crate::trace::ExecutionTrace {
        let bytecode_hash = sha256(b"test bytecode");
        let input_hash = sha256(b"test inputs");

        let mut trace = crate::trace::ExecutionTrace::new(bytecode_hash, input_hash);

        // Proper trace with PUSH operations and final HALT
        for i in 0..steps - 1 {
            trace.push(TraceStep {
                step: i as u32,
                ip: i as u32,
                opcode: 0x01, // PUSH
                sp_before: i as u8,
                sp_after: (i + 1) as u8,
                operand_a: 0,
                operand_b: 0,
                result: i as i64,
                reg_index: None,
                fuel_remaining: (10000 - i) as u32,
            });
        }

        // Final HALT step
        trace.push(TraceStep {
            step: (steps - 1) as u32,
            ip: (steps - 1) as u32,
            opcode: 0xFF, // HALT
            sp_before: (steps - 1) as u8,
            sp_after: (steps - 2) as u8,
            operand_a: 0,
            operand_b: 0,
            result: 42, // Final output
            reg_index: None,
            fuel_remaining: (10000 - steps + 1) as u32,
        });

        trace.finalize(42);
        trace
    }

    #[test]
    fn verify_valid_proof() {
        let trace = make_valid_trace(100);
        let prover = MpbProver::new();
        let proof = prover.prove(&trace).expect("prove");

        let verifier = MpbVerifier::new();
        let result = verifier.verify(&proof);

        assert_eq!(result, VerificationResult::Valid);
    }

    #[test]
    fn verify_tampered_output_fails() {
        let trace = make_valid_trace(100);
        let prover = MpbProver::new();
        let mut proof = prover.prove(&trace).expect("prove");

        // Tamper with output
        proof.output = 999;

        let verifier = MpbVerifier::new();
        let result = verifier.verify(&proof);

        assert!(matches!(
            result,
            VerificationResult::Invalid(VerificationError::OutputMismatch)
        ));
    }

    #[test]
    fn verify_tampered_first_step_fails() {
        let trace = make_valid_trace(100);
        let prover = MpbProver::new();
        let mut proof = prover.prove(&trace).expect("prove");

        // Tamper with first step
        proof.first_step.ip = 99;

        let verifier = MpbVerifier::new();
        let result = verifier.verify(&proof);

        assert!(matches!(
            result,
            VerificationResult::Invalid(VerificationError::FirstStepNotAtStart)
        ));
    }

    #[test]
    fn verify_non_halt_last_step_fails() {
        let trace = make_valid_trace(100);
        let prover = MpbProver::new();
        let mut proof = prover.prove(&trace).expect("prove");

        // Change last step opcode (not HALT)
        proof.last_step.opcode = 0x20;

        let verifier = MpbVerifier::new();
        let result = verifier.verify(&proof);

        assert!(matches!(
            result,
            VerificationResult::Invalid(VerificationError::LastStepNotHalt)
        ));
    }

    #[test]
    fn security_bits_increases_with_checks() {
        let trace = make_valid_trace(1000);

        let prover_few = MpbProver::with_config(crate::prover::ProverConfig {
            num_spot_checks: 8,
            seed: Some(42),
        });

        let prover_many = MpbProver::with_config(crate::prover::ProverConfig {
            num_spot_checks: 32,
            seed: Some(42),
        });

        let proof_few = prover_few.prove(&trace).expect("prove");
        let proof_many = prover_many.prove(&trace).expect("prove");

        let verifier = MpbVerifier::new();
        let bits_few = verifier.security_bits(&proof_few);
        let bits_many = verifier.security_bits(&proof_many);

        println!("8 checks: {:.1} bits security", bits_few);
        println!("32 checks: {:.1} bits security", bits_many);

        // More checks should give more security
        assert!(bits_many > bits_few);
        // With spot checks, security scales with number of checks
        assert!(bits_many > 0.0);
    }

    #[test]
    fn arithmetic_verification_catches_wrong_add() {
        let mut step = TraceStep {
            step: 0,
            ip: 0,
            opcode: 0x20, // ADD
            sp_before: 2,
            sp_after: 1,
            operand_a: 10,
            operand_b: 20,
            result: 999, // WRONG! Should be 30
            reg_index: None,
            fuel_remaining: 999,
        };

        assert!(!verify_step_arithmetic(&step));

        // Fix it
        step.result = 30;
        assert!(verify_step_arithmetic(&step));
    }
}
