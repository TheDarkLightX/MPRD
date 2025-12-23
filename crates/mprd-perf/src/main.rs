use mprd_generators::{decoded_mpb_v1_fixture, GenSeed};
use mprd_mpb::{MpbVm, OpCode};
use mprd_risc0_shared::compute_decision_commitment_v3;
use std::hint::black_box;
use std::time::Instant;

#[derive(Clone, Copy)]
enum OutputMode {
    Human,
    Json,
}

#[derive(Clone, Copy)]
struct Config {
    seed: u64,
    iters: usize,
    mpb_ops: usize,
    mode: OutputMode,
}

fn parse_args() -> Config {
    let mut cfg = Config {
        seed: 1,
        iters: 10_000,
        mpb_ops: 256,
        mode: OutputMode::Human,
    };

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--seed" => {
                cfg.seed = args
                    .next()
                    .unwrap_or_else(|| "1".into())
                    .parse()
                    .unwrap_or(1)
            }
            "--iters" => {
                cfg.iters = args
                    .next()
                    .unwrap_or_else(|| "10000".into())
                    .parse()
                    .unwrap_or(10_000)
            }
            "--mpb-ops" => {
                cfg.mpb_ops = args
                    .next()
                    .unwrap_or_else(|| "256".into())
                    .parse()
                    .unwrap_or(256)
            }
            "--json" => cfg.mode = OutputMode::Json,
            "--human" => cfg.mode = OutputMode::Human,
            _ => {}
        }
    }

    cfg
}

fn make_mpb_bytecode(num_ops: usize) -> Vec<u8> {
    let mut bc = Vec::with_capacity(1 + num_ops * 2 + 1);
    bc.push(OpCode::Push as u8);
    bc.extend_from_slice(&0i64.to_le_bytes());
    for i in 0..num_ops {
        bc.push(OpCode::LoadReg as u8);
        bc.push((i % MpbVm::MAX_REGISTERS) as u8);
        bc.push(OpCode::Add as u8);
    }
    bc.push(OpCode::Halt as u8);
    bc
}

fn bench_decision_commitment(iters: usize, seed: u64) -> (f64, [u8; 32]) {
    let mut journals = Vec::with_capacity(iters);
    for i in 0..iters {
        let f = decoded_mpb_v1_fixture(GenSeed::from_u64(seed.wrapping_add(i as u64)));
        journals.push(f.journal);
    }

    let start = Instant::now();
    let mut last = [0u8; 32];
    for j in &journals {
        last = black_box(compute_decision_commitment_v3(j));
    }
    let elapsed = start.elapsed().as_secs_f64();
    (elapsed, last)
}

fn bench_mpb_execute(iters: usize, seed: u64, num_ops: usize) -> (f64, i64) {
    let bc = make_mpb_bytecode(num_ops);
    let mut acc: i64 = 0;
    let start = Instant::now();

    for i in 0..iters {
        let mut registers = [0i64; MpbVm::MAX_REGISTERS];
        let f = decoded_mpb_v1_fixture(GenSeed::from_u64(seed ^ (i as u64)));
        // Derive deterministic "registers" from existing fixture hashes to avoid extra RNG deps.
        for (r, chunk) in registers
            .iter_mut()
            .zip(f.token.policy_hash.0.chunks_exact(4))
        {
            let mut b = [0u8; 4];
            b.copy_from_slice(chunk);
            *r = i32::from_le_bytes(b) as i64;
        }

        let mut vm = MpbVm::with_fuel(&registers, (num_ops as u32).saturating_add(100));
        let result = vm.execute(&bc).unwrap_or(0);
        acc = acc.wrapping_add(black_box(result));
    }

    let elapsed = start.elapsed().as_secs_f64();
    (elapsed, acc)
}

fn main() {
    let cfg = parse_args();

    let (dc_secs, dc_last) = bench_decision_commitment(cfg.iters, cfg.seed);
    let (mpb_secs, mpb_acc) = bench_mpb_execute(cfg.iters, cfg.seed, cfg.mpb_ops);

    match cfg.mode {
        OutputMode::Human => {
            println!("mprd-perf (reproducible harness)");
            println!("seed: {}", cfg.seed);
            println!("iters: {}", cfg.iters);
            println!();
            println!(
                "decision_commitment_v3: {:.6}s total ({:.1} ops/s) last={}",
                dc_secs,
                (cfg.iters as f64) / dc_secs.max(1e-12),
                hex::encode(dc_last)
            );
            println!(
                "mpb_execute: {:.6}s total ({:.1} exec/s) mpb_ops={} acc={}",
                mpb_secs,
                (cfg.iters as f64) / mpb_secs.max(1e-12),
                cfg.mpb_ops,
                mpb_acc
            );
        }
        OutputMode::Json => {
            let out = serde_json::json!({
                "seed": cfg.seed,
                "iters": cfg.iters,
                "decision_commitment_v3": {
                    "seconds_total": dc_secs,
                    "ops_per_sec": (cfg.iters as f64) / dc_secs.max(1e-12),
                    "last_hex": hex::encode(dc_last),
                },
                "mpb_execute": {
                    "seconds_total": mpb_secs,
                    "execs_per_sec": (cfg.iters as f64) / mpb_secs.max(1e-12),
                    "mpb_ops": cfg.mpb_ops,
                    "acc": mpb_acc,
                }
            });
            println!("{}", serde_json::to_string_pretty(&out).expect("json"));
        }
    }
}
