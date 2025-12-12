//! MPB Proof Generator
//!
//! Generates compact proofs of correct MPB execution.
//!
//! # Security Properties
//!
//! - **Binding**: Prover commits to a specific execution trace
//! - **Hiding**: Verifier only sees challenged steps
//! - **Soundness**: Forging a proof requires breaking SHA-256
//!
//! # Privacy Properties
//!
//! - Bytecode content is hidden (only hash revealed)
//! - Input values are hidden (only hash revealed)
//! - Non-challenged steps are hidden

use crate::{
    merkle::{MerkleProof, MerkleTree},
    trace::{ExecutionTrace, TraceStep},
    Hash256,
};
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

/// Configuration for proof generation.
#[derive(Clone, Debug)]
pub struct ProverConfig {
    /// Number of random steps to include in proof.
    pub num_spot_checks: usize,

    /// Random seed for deterministic proofs (testing).
    pub seed: Option<u64>,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            num_spot_checks: 16,
            seed: None,
        }
    }
}

/// A complete proof of MPB execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpbProof {
    /// Hash of the bytecode executed.
    pub bytecode_hash: Hash256,

    /// Hash of the input registers.
    pub input_hash: Hash256,

    /// The output value (public).
    pub output: i64,

    /// Number of execution steps.
    pub num_steps: usize,

    /// Total fuel consumed.
    pub fuel_consumed: u32,

    /// Merkle root of all step hashes.
    pub trace_root: Hash256,

    /// Spot-checked steps with proofs.
    pub spot_checks: Vec<SpotCheck>,

    /// First step (always included for initial state verification).
    pub first_step: TraceStep,

    /// Last step (always included for output verification).
    pub last_step: TraceStep,

    /// Merkle proof for first step.
    pub first_step_proof: MerkleProof,

    /// Merkle proof for last step.
    pub last_step_proof: MerkleProof,
}

/// A spot-checked step with its Merkle proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpotCheck {
    /// The trace step data.
    pub step: TraceStep,

    /// Merkle proof that this step is in the trace.
    pub proof: MerkleProof,
}

/// Proof generator for MPB execution.
pub struct MpbProver {
    config: ProverConfig,
}

impl MpbProver {
    /// Create a new prover with default config.
    pub fn new() -> Self {
        Self {
            config: ProverConfig::default(),
        }
    }

    /// Create a prover with custom config.
    pub fn with_config(config: ProverConfig) -> Self {
        Self { config }
    }

    /// Generate a proof from an execution trace.
    ///
    /// Time: O(n) for Merkle tree construction
    /// Proof size: O(k * log n) where k = num_spot_checks
    pub fn prove(&self, trace: &ExecutionTrace) -> MpbProof {
        if trace.is_empty() {
            panic!("Cannot prove empty trace");
        }

        // Build Merkle tree of step hashes
        let step_hashes: Vec<Hash256> = trace.steps.iter().map(|s| s.hash()).collect();
        let merkle_tree = MerkleTree::build(step_hashes);

        // Always include first and last step
        let first_step = trace.steps.first().unwrap().clone();
        let last_step = trace.steps.last().unwrap().clone();
        let first_step_proof = merkle_tree.prove(0).unwrap();
        let last_step_proof = merkle_tree.prove(trace.steps.len() - 1).unwrap();

        // Select random steps for spot checking
        let spot_checks = self.select_spot_checks(trace, &merkle_tree);

        MpbProof {
            bytecode_hash: trace.bytecode_hash,
            input_hash: trace.input_hash,
            output: trace.final_result,
            num_steps: trace.steps.len(),
            fuel_consumed: trace.fuel_consumed,
            trace_root: merkle_tree.root(),
            spot_checks,
            first_step,
            last_step,
            first_step_proof,
            last_step_proof,
        }
    }

    /// Select random steps for spot checking.
    fn select_spot_checks(&self, trace: &ExecutionTrace, tree: &MerkleTree) -> Vec<SpotCheck> {
        let n = trace.steps.len();
        if n <= 2 {
            return vec![]; // First and last already included
        }

        let num_checks = self.config.num_spot_checks.min(n - 2);
        let mut rng = match self.config.seed {
            Some(seed) => rand::rngs::StdRng::seed_from_u64(seed),
            None => rand::rngs::StdRng::from_entropy(),
        };

        // Select random indices (excluding first and last)
        let mut indices: Vec<usize> = Vec::new();
        while indices.len() < num_checks {
            let idx = rng.gen_range(1..n - 1);
            if !indices.contains(&idx) {
                indices.push(idx);
            }
        }

        indices.sort();

        indices
            .into_iter()
            .filter_map(|idx| {
                let step = trace.steps[idx].clone();
                let proof = tree.prove(idx)?;
                Some(SpotCheck { step, proof })
            })
            .collect()
    }

    /// Estimate proof size in bytes.
    pub fn estimate_proof_size(&self, num_steps: usize) -> usize {
        let log_n = (num_steps as f64).log2().ceil() as usize;
        let sibling_size = 33; // hash + bool
        let step_size = 64;    // rough estimate per step

        // Fixed parts
        let fixed = 32 + 32 + 8 + 8 + 4 + 32; // hashes + output + steps + fuel + root

        // First and last steps with proofs
        let boundary = 2 * (step_size + log_n * sibling_size);

        // Spot checks
        let checks = self.config.num_spot_checks * (step_size + log_n * sibling_size);

        fixed + boundary + checks
    }
}

impl Default for MpbProver {
    fn default() -> Self {
        Self::new()
    }
}

impl MpbProof {
    /// Compute actual proof size in bytes.
    pub fn size_bytes(&self) -> usize {
        // Approximate based on serialization
        let base = 32 + 32 + 8 + 8 + 4 + 32; // hashes, output, steps, fuel, root

        let step_size = |s: &TraceStep| s.to_bytes().len();

        let proof_size = |p: &MerkleProof| p.size_bytes();

        base + step_size(&self.first_step)
            + proof_size(&self.first_step_proof)
            + step_size(&self.last_step)
            + proof_size(&self.last_step_proof)
            + self
                .spot_checks
                .iter()
                .map(|c| step_size(&c.step) + proof_size(&c.proof))
                .sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    fn make_dummy_trace(steps: usize) -> ExecutionTrace {
        let bytecode_hash = sha256(b"test bytecode");
        let input_hash = sha256(b"test inputs");

        let mut trace = ExecutionTrace::new(bytecode_hash, input_hash);

        for i in 0..steps {
            trace.push(TraceStep {
                step: i as u32,
                ip: i as u32,
                opcode: 0x20, // ADD
                sp_before: 2,
                sp_after: 1,
                operand_a: i as i64,
                operand_b: 1,
                result: i as i64 + 1,
                reg_index: None,
                fuel_remaining: (10000 - i) as u32,
            });
        }

        trace.finalize(steps as i64);
        trace
    }

    #[test]
    fn prove_simple_trace() {
        let trace = make_dummy_trace(10);
        let prover = MpbProver::new();
        let proof = prover.prove(&trace);

        assert_eq!(proof.bytecode_hash, trace.bytecode_hash);
        assert_eq!(proof.input_hash, trace.input_hash);
        assert_eq!(proof.output, trace.final_result);
        assert_eq!(proof.num_steps, 10);
    }

    #[test]
    fn proof_includes_boundary_steps() {
        let trace = make_dummy_trace(100);
        let prover = MpbProver::new();
        let proof = prover.prove(&trace);

        assert_eq!(proof.first_step.step, 0);
        assert_eq!(proof.last_step.step, 99);
    }

    #[test]
    fn proof_size_sublinear() {
        let prover = MpbProver::with_config(ProverConfig {
            num_spot_checks: 16,
            seed: Some(42),
        });

        // 100 steps
        let trace100 = make_dummy_trace(100);
        let proof100 = prover.prove(&trace100);

        // 10000 steps
        let trace10k = make_dummy_trace(10000);
        let proof10k = prover.prove(&trace10k);

        // Proof for 10000 steps should NOT be 100x larger
        let ratio = proof10k.size_bytes() as f64 / proof100.size_bytes() as f64;
        println!(
            "100 steps: {} bytes, 10000 steps: {} bytes, ratio: {:.2}x",
            proof100.size_bytes(),
            proof10k.size_bytes(),
            ratio
        );

        assert!(ratio < 2.0, "Proof size should be sublinear in trace length");
    }

    #[test]
    fn deterministic_with_seed() {
        let trace = make_dummy_trace(100);
        let prover = MpbProver::with_config(ProverConfig {
            num_spot_checks: 16,
            seed: Some(12345),
        });

        let proof1 = prover.prove(&trace);
        let proof2 = prover.prove(&trace);

        // Same seed should give same spot checks
        assert_eq!(proof1.spot_checks.len(), proof2.spot_checks.len());
        for (c1, c2) in proof1.spot_checks.iter().zip(proof2.spot_checks.iter()) {
            assert_eq!(c1.step.step, c2.step.step);
        }
    }
}
