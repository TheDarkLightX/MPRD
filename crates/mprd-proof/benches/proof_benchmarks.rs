//! Benchmarks comparing MPB custom proof system vs simulated Risc0-style overhead.
//!
//! Run with: cargo bench -p mprd-proof

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use mprd_proof::{
    prover::{MpbProver, ProverConfig},
    verifier::MpbVerifier,
    tracing_vm::{TracingVm, TracingResult},
};

/// Build a bytecode program with n arithmetic operations.
fn build_program(num_ops: usize) -> Vec<u8> {
    let mut bytecode = Vec::new();
    
    // Initial PUSH
    bytecode.push(0x01); // PUSH
    bytecode.extend_from_slice(&1i64.to_le_bytes());
    
    // Add num_ops ADD operations (push 1, add)
    for _ in 0..num_ops {
        bytecode.push(0x01); // PUSH
        bytecode.extend_from_slice(&1i64.to_le_bytes());
        bytecode.push(0x20); // ADD
    }
    
    bytecode.push(0xFF); // HALT
    bytecode
}

/// Simulate Risc0-style overhead (hashing + heavy computation).
fn simulate_risc0_proving(bytecode: &[u8], registers: &[i64], _steps: usize) {
    use sha2::{Sha256, Digest};
    
    // Simulate zkVM overhead:
    // 1. Hash bytecode (like image ID)
    let mut hasher = Sha256::new();
    hasher.update(bytecode);
    let _image_hash = hasher.finalize();
    
    // 2. Simulate heavy computation per step
    // Real Risc0 does ~1M constraints per RISC-V instruction
    // We simulate with heavy hashing
    let mut state = [0u8; 32];
    for reg in registers {
        let mut h = Sha256::new();
        h.update(&state);
        h.update(&reg.to_le_bytes());
        state.copy_from_slice(&h.finalize());
    }
    
    // Simulate per-step overhead (much lighter than real Risc0)
    for i in 0u32..100 { // Reduced for benchmark sanity
        let mut h = Sha256::new();
        h.update(&state);
        h.update(&i.to_le_bytes());
        state.copy_from_slice(&h.finalize());
    }
}

fn bench_proving_time(c: &mut Criterion) {
    let mut group = c.benchmark_group("proving_time");
    
    for num_ops in [10, 100, 1000].iter() {
        let bytecode = build_program(*num_ops);
        let registers: Vec<i64> = vec![1, 2, 3, 4];
        
        // Custom MPB proof
        group.bench_with_input(
            BenchmarkId::new("mpb_custom", num_ops),
            num_ops,
            |b, _| {
                b.iter(|| {
                    let vm = TracingVm::new(&bytecode, &registers);
                    let result = vm.execute(black_box(&bytecode));
                    
                    if let TracingResult::Success { trace, .. } = result {
                        let prover = MpbProver::with_config(ProverConfig {
                            num_spot_checks: 16,
                            seed: Some(42),
                        });
                        let _proof = prover.prove(&trace);
                    }
                });
            },
        );
        
        // Simulated Risc0-style
        group.bench_with_input(
            BenchmarkId::new("risc0_simulated", num_ops),
            num_ops,
            |b, _| {
                b.iter(|| {
                    simulate_risc0_proving(
                        black_box(&bytecode),
                        black_box(&registers),
                        *num_ops,
                    );
                });
            },
        );
    }
    
    group.finish();
}

fn bench_verification_time(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification_time");
    
    for num_ops in [10, 100, 1000].iter() {
        let bytecode = build_program(*num_ops);
        let registers: Vec<i64> = vec![1, 2, 3, 4];
        
        // Generate proof once
        let vm = TracingVm::new(&bytecode, &registers);
        let trace = match vm.execute(&bytecode) {
            TracingResult::Success { trace, .. } => trace,
            _ => panic!("Execution failed"),
        };
        
        let prover = MpbProver::with_config(ProverConfig {
            num_spot_checks: 16,
            seed: Some(42),
        });
        let proof = prover.prove(&trace);
        let verifier = MpbVerifier::new();
        
        group.bench_with_input(
            BenchmarkId::new("mpb_verify", num_ops),
            num_ops,
            |b, _| {
                b.iter(|| {
                    let _result = verifier.verify(black_box(&proof));
                });
            },
        );
    }
    
    group.finish();
}

fn bench_proof_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_size");
    
    // Note: 10000 ops would exceed default fuel limit of 10000
    for num_ops in [10, 100, 1000, 4000].iter() {
        let bytecode = build_program(*num_ops);
        let registers: Vec<i64> = vec![1, 2, 3, 4];
        
        let vm = TracingVm::new(&bytecode, &registers);
        let trace = match vm.execute(&bytecode) {
            TracingResult::Success { trace, .. } => trace,
            _ => panic!("Execution failed"),
        };
        
        let prover = MpbProver::with_config(ProverConfig {
            num_spot_checks: 16,
            seed: Some(42),
        });
        let proof = prover.prove(&trace);
        
        println!(
            "Steps: {}, Proof size: {} bytes",
            num_ops * 2 + 2, // pushes + adds + initial push + halt
            proof.size_bytes()
        );
        
        // Just measure that we can create proofs quickly
        group.bench_with_input(
            BenchmarkId::new("proof_generation", num_ops),
            num_ops,
            |b, _| {
                b.iter(|| {
                    let _proof = prover.prove(black_box(&trace));
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_proving_time,
    bench_verification_time,
    bench_proof_size,
);
criterion_main!(benches);
