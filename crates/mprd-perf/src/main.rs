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

#[derive(Clone)]
struct Config {
    seed: u64,
    iters: usize,
    mpb_ops: usize,
    mode: OutputMode,
    bench: BenchKind,
    // simplex bench knobs (used only when bench==Simplex)
    simplex_k: usize,
    simplex_t: u32,
    simplex_h: usize,
    simplex_eval_iters: u32,
    simplex_time_ms: u64,
    simplex_budget_expanded: usize,
    simplex_progress_every: usize,
    simplex_check_small: bool,
    simplex_sweep: bool,
    simplex_k_list: Option<String>,
    simplex_t_list: Option<String>,
    simplex_h_list: Option<String>,
    simplex_eval_list: Option<String>,
    // policy bench knobs (used only when bench==Policy)
    policy_atoms: usize,
    policy_depth: u32,
    policy_children_max: usize,
    policy_env_iters: usize,
    policy_compile_each: bool,
    policy_sweep: bool,
    policy_atoms_list: Option<String>,
    policy_depth_list: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BenchKind {
    Core,
    Simplex,
    Policy,
}

fn parse_args() -> Config {
    let mut cfg = Config {
        seed: 1,
        iters: 10_000,
        mpb_ops: 256,
        mode: OutputMode::Human,
        bench: BenchKind::Core,
        simplex_k: 6,
        simplex_t: 12,
        simplex_h: 8,
        simplex_eval_iters: 0,
        // Default: never "freeze"; give a bounded, comparable run.
        simplex_time_ms: 2_000,
        simplex_budget_expanded: 200_000,
        simplex_progress_every: 25_000,
        simplex_check_small: true,
        simplex_sweep: false,
        simplex_k_list: None,
        simplex_t_list: None,
        simplex_h_list: None,
        simplex_eval_list: None,
        // policy bench knobs (used only when bench==Policy)
        policy_atoms: 10,
        policy_depth: 4,
        policy_children_max: 4,
        policy_env_iters: 50_000,
        policy_compile_each: false,
        policy_sweep: false,
        policy_atoms_list: None,
        policy_depth_list: None,
    };

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--bench" => {
                let v = args.next().unwrap_or_else(|| "core".into());
                cfg.bench = match v.as_str() {
                    "simplex" => BenchKind::Simplex,
                    "policy" => BenchKind::Policy,
                    _ => BenchKind::Core,
                };
            }
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
            "--k" => {
                cfg.simplex_k = args
                    .next()
                    .unwrap_or_else(|| "6".into())
                    .parse()
                    .unwrap_or(6)
            }
            "--t" => {
                cfg.simplex_t = args
                    .next()
                    .unwrap_or_else(|| "12".into())
                    .parse()
                    .unwrap_or(12)
            }
            "--h" => {
                cfg.simplex_h = args
                    .next()
                    .unwrap_or_else(|| "8".into())
                    .parse()
                    .unwrap_or(8)
            }
            "--eval-iters" => {
                cfg.simplex_eval_iters = args
                    .next()
                    .unwrap_or_else(|| "0".into())
                    .parse()
                    .unwrap_or(0)
            }
            "--time-ms" => {
                cfg.simplex_time_ms = args
                    .next()
                    .unwrap_or_else(|| "2000".into())
                    .parse()
                    .unwrap_or(2_000)
            }
            "--budget-expanded" => {
                cfg.simplex_budget_expanded = args
                    .next()
                    .unwrap_or_else(|| "200000".into())
                    .parse()
                    .unwrap_or(200_000)
            }
            "--progress-every" => {
                cfg.simplex_progress_every = args
                    .next()
                    .unwrap_or_else(|| "25000".into())
                    .parse()
                    .unwrap_or(25_000)
            }
            "--no-check" => cfg.simplex_check_small = false,
            "--sweep" => cfg.simplex_sweep = true,
            "--k-list" => cfg.simplex_k_list = args.next(),
            "--t-list" => cfg.simplex_t_list = args.next(),
            "--h-list" => cfg.simplex_h_list = args.next(),
            "--eval-list" => cfg.simplex_eval_list = args.next(),
            "--json" => cfg.mode = OutputMode::Json,
            "--human" => cfg.mode = OutputMode::Human,
            "--policy-atoms" => {
                cfg.policy_atoms = args
                    .next()
                    .unwrap_or_else(|| "10".into())
                    .parse()
                    .unwrap_or(10)
            }
            "--policy-depth" => {
                cfg.policy_depth = args
                    .next()
                    .unwrap_or_else(|| "4".into())
                    .parse()
                    .unwrap_or(4)
            }
            "--policy-children-max" => {
                cfg.policy_children_max = args
                    .next()
                    .unwrap_or_else(|| "4".into())
                    .parse()
                    .unwrap_or(4)
            }
            "--policy-env-iters" => {
                cfg.policy_env_iters = args
                    .next()
                    .unwrap_or_else(|| "50000".into())
                    .parse()
                    .unwrap_or(50_000)
            }
            "--policy-compile-each" => cfg.policy_compile_each = true,
            "--policy-sweep" => cfg.policy_sweep = true,
            "--policy-atoms-list" => cfg.policy_atoms_list = args.next(),
            "--policy-depth-list" => cfg.policy_depth_list = args.next(),
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

    if cfg.bench == BenchKind::Simplex {
        return simplex_bench::main_like(cfg);
    }
    if cfg.bench == BenchKind::Policy {
        return policy_bench::main_like(cfg);
    }

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

mod simplex_bench {
    use super::{Config, OutputMode};
    use mprd_core::tokenomics_v6::simplex_ceo::{self, SimplexCeoMode};
    use mprd_core::tokenomics_v6::simplex_por_oracle::{self, Transfer};
    use mprd_core::tokenomics_v6::simplex_planner;
    use mprd_core::tokenomics_v6::simplex_symmetry_key;
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
    use std::hint::black_box;
    use std::time::Instant;

    type State = Vec<u32>;
    type Action = Transfer;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CeoDecisionLite {
        score: i64,
        depth: usize,
        first_key: u64,
        state: Vec<u32>,
    }

    fn better_ceo_decision(a: &CeoDecisionLite, b: &CeoDecisionLite) -> bool {
        (a.score > b.score)
            || (a.score == b.score && a.depth < b.depth)
            || (a.score == b.score && a.depth == b.depth && a.first_key < b.first_key)
            || (a.score == b.score
                && a.depth == b.depth
                && a.first_key == b.first_key
                && a.state < b.state)
    }

    fn decision_lite_from_core(k: usize, d: &simplex_ceo::SimplexCeoDecision) -> CeoDecisionLite {
        CeoDecisionLite {
            score: d.score,
            depth: d.depth,
            first_key: d
                .first_action
                .map(|a| simplex_planner::action_key(k, a) as u64)
                .unwrap_or(0),
            state: d.target.clone(),
        }
    }

    fn all_actions(k: usize) -> Vec<Action> {
        let mut out = Vec::with_capacity(k.saturating_mul(k.saturating_sub(1)));
        for src in 0..k {
            for dst in 0..k {
                if src != dst {
                    out.push(Transfer::new(src, dst));
                }
            }
        }
        out
    }

    fn step_or_stay(x: &[u32], caps: &[u32], a: Action, out: &mut [u32]) {
        out.copy_from_slice(x);
        if !simplex_por_oracle::enabled(x, caps, a) {
            return;
        }
        out[a.src] = out[a.src].saturating_sub(1);
        out[a.dst] = out[a.dst].saturating_add(1);
    }

    fn action_key(k: usize, a: Action) -> u32 {
        simplex_planner::action_key(k, a)
    }

    /// Compact, deterministic rolling hash for an action trace.
    /// This is *not* cryptographic; it is for benchmarking storage/comparison costs.
    fn trace_key_hash(trace: &[Transfer], k: usize) -> u128 {
        simplex_planner::trace_key_hash(trace, k)
    }

    fn symmetry_key(x: &[u32], caps: &[u32], weights: &[u32]) -> Vec<Vec<u32>> {
        simplex_symmetry_key::symmetry_key(x, caps, weights).unwrap_or_else(|| vec![x.to_vec()])
    }

    fn eval_cost(x: &[u32], iters: u32) -> u64 {
        // Deterministic CPU burner to simulate expensive objective/verification.
        let mut h: u64 = 1469598103934665603u64;
        for _ in 0..iters {
            for &v in x {
                h ^= v as u64;
                h = h.wrapping_mul(1099511628211u64);
            }
        }
        black_box(h)
    }

    fn run_trace_enum(
        k: usize,
        h: usize,
        x0: &[u32],
        caps: &[u32],
        weights: &[u32],
        por: bool,
        eval_iters: u32,
        time_ms: u64,
        budget_expanded: usize,
        progress_every: usize,
    ) -> (u64, usize, usize, usize) {
        let acts = all_actions(k);
        let mut q: VecDeque<(Vec<Action>, State)> = VecDeque::new();
        q.push_back((Vec::new(), x0.to_vec()));

        // Decision-quality change: store only compact deterministic keys, not full traces.
        // HashSet is fine here: we never iterate it, only do membership checks; equality is exact.
        let mut seen_trace_keys: HashSet<u128> = HashSet::new();
        seen_trace_keys.insert(trace_key_hash(&[], k));

        let mut expanded = 0usize;
        let mut generated = 0usize;
        let mut reached: BTreeSet<State> = BTreeSet::new();
        reached.insert(x0.to_vec());

        let mut tmp = vec![0u32; k];
        let mut prefix_states: Vec<State> = Vec::new();
        let mut oracle_cache = simplex_planner::OracleCache::new();
        let mut acc: u64 = 0;
        let start = Instant::now();

        while let Some((tr, x)) = q.pop_front() {
            if start.elapsed().as_millis() as u64 >= time_ms {
                break;
            }
            if expanded >= budget_expanded {
                break;
            }
            if tr.len() >= h {
                continue;
            }
            expanded += 1;
            // Precompute post-prefix states for this trace once (used for all outgoing actions in POR mode).
            if por {
                prefix_states.clear();
                prefix_states.reserve(tr.len() + 1);
                let mut s = x0.to_vec();
                prefix_states.push(s.clone());
                for &act in &tr {
                    step_or_stay(&s, caps, act, &mut tmp);
                    s.copy_from_slice(&tmp);
                    prefix_states.push(s.clone());
                }
            }
            if progress_every > 0 && expanded % progress_every == 0 {
                eprintln!(
                    "[simplex/trace] expanded={} queue={} reached_states={} por={}",
                    expanded,
                    q.len(),
                    reached.len(),
                    por
                );
            }
            for &a in &acts {
                generated += 1;
                step_or_stay(&x, caps, a, &mut tmp);
                if por {
                    // Delegate to the core canonicalizer (keeps bench and planner semantics aligned).
                    let tr2_t = simplex_planner::canonicalize_append_insert_cached(
                        caps,
                        &prefix_states,
                        &tr,
                        a,
                        &mut oracle_cache,
                    )
                    .expect("canonicalize_append_insert");
                    let tr2: Vec<Action> = tr2_t;
                    let key = trace_key_hash(&tr2, k);
                    if !seen_trace_keys.insert(key) {
                        continue;
                    }
                    let x2 = tmp.clone();
                    reached.insert(x2.clone());
                    acc ^= eval_cost(&x2, eval_iters);
                    // also touch symmetry key (so we can see overhead if used downstream)
                    acc ^= black_box(symmetry_key(&x2, caps, weights).len() as u64);
                    q.push_back((tr2, x2));
                } else {
                    let mut tr2 = tr.clone();
                    tr2.push(a);
                    let key = trace_key_hash(&tr2, k);
                    if !seen_trace_keys.insert(key) {
                        continue;
                    }
                    let x2 = tmp.clone();
                    reached.insert(x2.clone());
                    acc ^= eval_cost(&x2, eval_iters);
                    // also touch symmetry key (so we can see overhead if used downstream)
                    acc ^= black_box(symmetry_key(&x2, caps, weights).len() as u64);
                    q.push_back((tr2, x2));
                }
            }
        }
        (acc, expanded, generated, reached.len())
    }

    fn run_state_bfs(
        k: usize,
        h: usize,
        x0: &[u32],
        caps: &[u32],
        weights: &[u32],
        symmetry: bool,
        eval_iters: u32,
        time_ms: u64,
        budget_expanded: usize,
        progress_every: usize,
    ) -> (u64, usize, usize, usize) {
        let acts = all_actions(k);
        let mut q: VecDeque<(State, usize)> = VecDeque::new();
        q.push_back((x0.to_vec(), 0));

        // key -> min depth
        let mut seen: BTreeMap<Vec<Vec<u32>>, usize> = BTreeMap::new();
        let key0 = if symmetry {
            symmetry_key(x0, caps, weights)
        } else {
            vec![x0.to_vec()]
        };
        seen.insert(key0, 0);

        let mut expanded = 0usize;
        let mut generated = 0usize;
        let mut reached: BTreeSet<State> = BTreeSet::new();
        reached.insert(x0.to_vec());

        let mut tmp = vec![0u32; k];
        let mut acc: u64 = 0;
        let start = Instant::now();

        while let Some((x, d)) = q.pop_front() {
            if start.elapsed().as_millis() as u64 >= time_ms {
                break;
            }
            if expanded >= budget_expanded {
                break;
            }
            if d >= h {
                continue;
            }
            expanded += 1;
            if progress_every > 0 && expanded % progress_every == 0 {
                eprintln!(
                    "[simplex/state] expanded={} queue={} reached_states={} symmetry={}",
                    expanded,
                    q.len(),
                    reached.len(),
                    symmetry
                );
            }
            for &a in &acts {
                generated += 1;
                step_or_stay(&x, caps, a, &mut tmp);
                let x2 = tmp.clone();
                reached.insert(x2.clone());
                let key = if symmetry {
                    symmetry_key(&x2, caps, weights)
                } else {
                    vec![x2.clone()]
                };
                let next_d = d + 1;
                if seen.get(&key).copied().is_some_and(|dd| dd <= next_d) {
                    continue;
                }
                seen.insert(key, next_d);
                acc ^= eval_cost(&x2, eval_iters);
                q.push_back((x2, next_d));
            }
        }
        (acc, expanded, generated, reached.len())
    }

    fn assert_small_correctness(k: usize, t: u32) {
        // Only run for very small sizes; this is our "certainty" mode:
        // compare reachable state sets for baseline vs POR (trace) and baseline vs symmetry (state).
        if k > 4 || t > 10 {
            return;
        }
        let h = 6usize;
        let mut x0 = vec![0u32; k];
        x0[0] = t / 2;
        x0[1] = t - x0[0];
        let caps = vec![t; k];
        let mut weights = vec![1u32; k];
        weights[0] = 7;
        weights[1] = 7;
        for i in 2..k {
            weights[i] = (i as u32) + 1;
        }

        // Full budget + long timeout so it finishes.
        let big_ms = 30_000u64;
        let big_budget = 5_000_000usize;

        let (_a0, _e0, _g0, r0) =
            run_trace_enum(k, h, &x0, &caps, &weights, false, 0, big_ms, big_budget, 0);
        let (_a1, _e1, _g1, r1) =
            run_trace_enum(k, h, &x0, &caps, &weights, true, 0, big_ms, big_budget, 0);
        // Reachable state *count* should match; for tiny sizes this is a strong sanity check.
        assert_eq!(r0, r1, "POR trace canonicalization changed reachable-state count");

        let (_b0, _s0, _sg0, rs0) =
            run_state_bfs(k, h, &x0, &caps, &weights, false, 0, big_ms, big_budget, 0);
        let (_b1, _s1, _sg1, rs1) =
            run_state_bfs(k, h, &x0, &caps, &weights, true, 0, big_ms, big_budget, 0);
        // Symmetry quotient should never increase distinct canonical keys; this is a weak but useful check.
        assert!(rs1 <= rs0, "symmetry quotient did not reduce or preserve reachable states");
    }

    fn parse_u32_list(s: Option<&String>, default: &[u32]) -> Vec<u32> {
        let Some(s) = s else { return default.to_vec(); };
        let mut out = Vec::new();
        for part in s.split(',') {
            let p = part.trim();
            if p.is_empty() {
                continue;
            }
            if let Ok(v) = p.parse::<u32>() {
                out.push(v);
            }
        }
        if out.is_empty() {
            default.to_vec()
        } else {
            out
        }
    }

    fn parse_usize_list(s: Option<&String>, default: &[usize]) -> Vec<usize> {
        let Some(s) = s else { return default.to_vec(); };
        let mut out = Vec::new();
        for part in s.split(',') {
            let p = part.trim();
            if p.is_empty() {
                continue;
            }
            if let Ok(v) = p.parse::<usize>() {
                out.push(v);
            }
        }
        if out.is_empty() {
            default.to_vec()
        } else {
            out
        }
    }

    fn run_point(cfg: &Config, k: usize, t: u32, h: usize, eval_iters: u32) -> serde_json::Value {
        let k = k.max(2);
        let mut x0 = vec![0u32; k];
        x0[0] = t / 2;
        x0[1] = t - x0[0];
        let caps = vec![t; k];
        let mut weights = vec![1u32; k];
        if k >= 2 {
            weights[0] = 7;
            weights[1] = 7;
        }
        for i in 2..k {
            weights[i] = (i as u32) + 1;
        }

        // CEO decision-quality benchmark setup (linear objective).
        // Use a deterministic weight pattern with a large symmetry class:
        // - bucket 0: high weight
        // - bucket 1: medium weight
        // - buckets 2..: low equal weight (symmetry within this class is sound)
        let mut w_lin: Vec<i64> = vec![1; k];
        w_lin[0] = 5;
        if k > 1 {
            w_lin[1] = 2;
        }
        let w_sym: Vec<u32> = w_lin.iter().map(|&wi| wi as u32).collect();

        fn brute_ceo_decision_linear(
            k: usize,
            h: usize,
            x0: &[u32],
            caps: &[u32],
            w: &[i64],
        ) -> CeoDecisionLite {
            let acts = all_actions(k);
            let mut acts_sorted = acts;
            acts_sorted.sort_by_key(|&a| simplex_planner::action_key(k, a));

            // state -> (best depth, best first_key at that depth)
            let mut seen: BTreeMap<Vec<u32>, (usize, u64)> = BTreeMap::new();
            seen.insert(x0.to_vec(), (0, 0));

            let mut q: VecDeque<(Vec<u32>, usize, u64)> = VecDeque::new();
            q.push_back((x0.to_vec(), 0, 0));

            let mut best = CeoDecisionLite {
                score: i64::MIN,
                depth: usize::MAX,
                first_key: u64::MAX,
                state: Vec::new(),
            };
            let mut tmp = vec![0u32; k];

            while let Some((x, d, fk)) = q.pop_front() {
                // evaluate at each visited node (matches simplex_ceo semantics: best over depths <= h)
                let mut s = 0i64;
                for i in 0..k {
                    s = s.saturating_add(w[i].saturating_mul(x[i] as i64));
                }
                let cand = CeoDecisionLite {
                    score: s,
                    depth: d,
                    first_key: fk,
                    state: x.clone(),
                };
                if best.state.is_empty() || better_ceo_decision(&cand, &best) {
                    best = cand;
                }

                if d >= h {
                    continue;
                }
                for &a in &acts_sorted {
                    step_or_stay(&x, caps, a, &mut tmp);
                    let x2 = tmp.clone();
                    let d2 = d + 1;
                    let fk2 = if fk != 0 {
                        fk
                    } else {
                        simplex_planner::action_key(k, a) as u64
                    };
                    let push = match seen.get(&x2) {
                        Some(&(d0, fk0)) => (d2 < d0) || (d2 == d0 && fk2 < fk0),
                        None => true,
                    };
                    if push {
                        seen.insert(x2.clone(), (d2, fk2));
                        q.push_back((x2, d2, fk2));
                    }
                }
            }
            best
        }

        let start = Instant::now();
        let ceo_base = brute_ceo_decision_linear(k, h, &x0, &caps, &w_lin);
        let ceo_t0 = start.elapsed().as_secs_f64();

        let start = Instant::now();
        let ceo_trace = simplex_ceo::plan_best_linear(
            SimplexCeoMode::TracePor,
            &x0,
            &caps,
            &w_sym,
            &w_lin,
            h,
            cfg.simplex_budget_expanded,
            Some(t),
        )
        .expect("ceo_trace_por");
        let ceo_t1 = start.elapsed().as_secs_f64();
        let ceo_trace_lite = decision_lite_from_core(k, &ceo_trace);

        let start = Instant::now();
        let ceo_sym = simplex_ceo::plan_best_linear(
            SimplexCeoMode::StateSymmetry,
            &x0,
            &caps,
            &w_sym,
            &w_lin,
            h,
            cfg.simplex_budget_expanded,
            Some(t),
        )
        .expect("ceo_state_symmetry");
        let ceo_t2 = start.elapsed().as_secs_f64();
        let ceo_sym_lite = decision_lite_from_core(k, &ceo_sym);

        let start = Instant::now();
        // Ample POR is fail-closed on budget exhaustion; for perf/sweep runs we record failure
        // instead of panicking.
        let ceo_ample_res = simplex_ceo::plan_best_linear(
            SimplexCeoMode::AmplePorDfsC2,
            &x0,
            &caps,
            &w_sym,
            &w_lin,
            h,
            cfg.simplex_budget_expanded,
            Some(t),
        );
        let ceo_t3 = start.elapsed().as_secs_f64();
        let ceo_ample_lite = ceo_ample_res.as_ref().ok().map(|d| decision_lite_from_core(k, d));

        let start = Instant::now();
        let (acc0, e0, g0, r0) = run_trace_enum(
            k,
            h,
            &x0,
            &caps,
            &weights,
            false,
            eval_iters,
            cfg.simplex_time_ms,
            cfg.simplex_budget_expanded,
            cfg.simplex_progress_every,
        );
        let t0 = start.elapsed().as_secs_f64();

        let start = Instant::now();
        let (acc1, e1, g1, r1) = run_trace_enum(
            k,
            h,
            &x0,
            &caps,
            &weights,
            true,
            eval_iters,
            cfg.simplex_time_ms,
            cfg.simplex_budget_expanded,
            cfg.simplex_progress_every,
        );
        let t1 = start.elapsed().as_secs_f64();

        let start = Instant::now();
        let (acc2, e2, g2, r2) = run_state_bfs(
            k,
            h,
            &x0,
            &caps,
            &weights,
            false,
            eval_iters,
            cfg.simplex_time_ms,
            cfg.simplex_budget_expanded,
            cfg.simplex_progress_every,
        );
        let t2 = start.elapsed().as_secs_f64();

        let start = Instant::now();
        let (acc3, e3, g3, r3) = run_state_bfs(
            k,
            h,
            &x0,
            &caps,
            &weights,
            true,
            eval_iters,
            cfg.simplex_time_ms,
            cfg.simplex_budget_expanded,
            cfg.simplex_progress_every,
        );
        let t3 = start.elapsed().as_secs_f64();

        json!({
            "k": k,
            "T": t,
            "h": h,
            "eval_iters": eval_iters,
            "time_ms_budget": cfg.simplex_time_ms,
            "expanded_budget": cfg.simplex_budget_expanded,
            "ceo_linear": {
                "weights": w_lin,
                "weights_sym": w_sym,
                "baseline": { "seconds_total": ceo_t0, "score": ceo_base.score, "depth": ceo_base.depth, "first_key": ceo_base.first_key, "state": ceo_base.state },
                "trace_por": { "seconds_total": ceo_t1, "score": ceo_trace_lite.score, "depth": ceo_trace_lite.depth, "first_key": ceo_trace_lite.first_key, "state": ceo_trace_lite.state, "agree": ceo_trace_lite == ceo_base },
                "state_symmetry": { "seconds_total": ceo_t2, "score": ceo_sym_lite.score, "depth": ceo_sym_lite.depth, "first_key": ceo_sym_lite.first_key, "state": ceo_sym_lite.state, "agree": ceo_sym_lite == ceo_base },
                "ample_por": if let Some(v) = ceo_ample_lite {
                    json!({ "seconds_total": ceo_t3, "ok": true, "score": v.score, "depth": v.depth, "first_key": v.first_key, "state": v.state, "agree": v == ceo_base })
                } else {
                    json!({ "seconds_total": ceo_t3, "ok": false })
                },
            },
            "trace_baseline": { "seconds_total": t0, "expanded": e0, "generated": g0, "reached_states": r0, "acc": acc0 },
            "trace_por":      { "seconds_total": t1, "expanded": e1, "generated": g1, "reached_states": r1, "acc": acc1 },
            "state_baseline": { "seconds_total": t2, "expanded": e2, "generated": g2, "reached_states": r2, "acc": acc2 },
            "state_symmetry": { "seconds_total": t3, "expanded": e3, "generated": g3, "reached_states": r3, "acc": acc3 },
        })
    }

    pub fn main_like(cfg: Config) {
        if cfg.simplex_sweep {
            // Defaults: small grid (kept small to be fast & stable).
            let ks = parse_usize_list(cfg.simplex_k_list.as_ref(), &[6, 8, 10]);
            let ts = parse_u32_list(cfg.simplex_t_list.as_ref(), &[12, 20, 30]);
            let hs = parse_usize_list(cfg.simplex_h_list.as_ref(), &[8, 10, 12]);
            let es = parse_u32_list(cfg.simplex_eval_list.as_ref(), &[0, 50, 200]);

            if cfg.simplex_check_small {
                // Run at most one tiny check (cheap) to validate invariants.
                assert_small_correctness(4, 10);
            }

            let mut rows = Vec::new();
            for &k in &ks {
                for &t in &ts {
                    for &h in &hs {
                        for &e in &es {
                            rows.push(run_point(&cfg, k, t, h, e));
                        }
                    }
                }
            }

            // Force JSON output in sweep mode (graph-friendly).
            let out = json!({
                "bench": "simplex_sweep",
                "time_ms_budget": cfg.simplex_time_ms,
                "expanded_budget": cfg.simplex_budget_expanded,
                "rows": rows,
            });
            println!("{}", serde_json::to_string_pretty(&out).expect("json"));
            return;
        }

        let k = cfg.simplex_k;
        let t = cfg.simplex_t;
        let h = cfg.simplex_h;
        let eval_iters = cfg.simplex_eval_iters;

        if cfg.simplex_check_small {
            assert_small_correctness(k, t);
        }

        let row = run_point(&cfg, k, t, h, eval_iters);

        match cfg.mode {
            OutputMode::Human => {
                println!("mprd-perf simplex (deterministic)");
                println!("k={} T={} h={} eval_iters={}", k.max(2), t, h, eval_iters);
                println!();
                let tb = &row["trace_baseline"];
                let tp = &row["trace_por"];
                let sb = &row["state_baseline"];
                let ss = &row["state_symmetry"];
                println!(
                    "trace_baseline: {:.6}s expanded={} generated={} reached_states={} acc={}",
                    tb["seconds_total"].as_f64().unwrap_or(0.0),
                    tb["expanded"].as_u64().unwrap_or(0),
                    tb["generated"].as_u64().unwrap_or(0),
                    tb["reached_states"].as_u64().unwrap_or(0),
                    tb["acc"].as_u64().unwrap_or(0),
                );
                println!(
                    "trace_POR:      {:.6}s expanded={} generated={} reached_states={} acc={}",
                    tp["seconds_total"].as_f64().unwrap_or(0.0),
                    tp["expanded"].as_u64().unwrap_or(0),
                    tp["generated"].as_u64().unwrap_or(0),
                    tp["reached_states"].as_u64().unwrap_or(0),
                    tp["acc"].as_u64().unwrap_or(0),
                );
                println!(
                    "state_baseline: {:.6}s expanded={} generated={} reached_states={} acc={}",
                    sb["seconds_total"].as_f64().unwrap_or(0.0),
                    sb["expanded"].as_u64().unwrap_or(0),
                    sb["generated"].as_u64().unwrap_or(0),
                    sb["reached_states"].as_u64().unwrap_or(0),
                    sb["acc"].as_u64().unwrap_or(0),
                );
                println!(
                    "state_symmetry: {:.6}s expanded={} generated={} reached_states={} acc={}",
                    ss["seconds_total"].as_f64().unwrap_or(0.0),
                    ss["expanded"].as_u64().unwrap_or(0),
                    ss["generated"].as_u64().unwrap_or(0),
                    ss["reached_states"].as_u64().unwrap_or(0),
                    ss["acc"].as_u64().unwrap_or(0),
                );
                println!();
                println!("NOTE: trace_* benchmarks POR (canonicalize+dedup traces). state_* benchmarks symmetry quotienting on visited keys.");
            }
            OutputMode::Json => {
                println!("{}", serde_json::to_string_pretty(&row).expect("json"));
            }
        }
    }
}

mod policy_bench {
    use super::{Config, OutputMode};
    use mprd_core::policy_algebra::{
        compile_allow_robdd, evaluate, policy_equiv_robdd_bool_fast, CanonicalPolicy, EvalContext,
        policy_hash_v1, PolicyAtom, PolicyExpr, PolicyLimits, Robdd,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::hint::black_box;
    use std::time::Instant;

    #[derive(Clone)]
    struct Env {
        // tri-state: None=missing, Some(false), Some(true)
        vals: Vec<Option<bool>>,
    }

    struct IndexedCtx<'a> {
        env: &'a Env,
        idx: &'a BTreeMap<PolicyAtom, usize>,
    }

    impl<'a> EvalContext for IndexedCtx<'a> {
        fn signal(&self, atom: &PolicyAtom) -> Option<bool> {
            let i = self.idx.get(atom).copied().unwrap_or(usize::MAX);
            if i >= self.env.vals.len() {
                return None;
            }
            self.env.vals[i]
        }
    }

    fn xorshift64(mut x: u64) -> u64 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    }

    fn sample_trit(x: u64) -> Option<bool> {
        match (x % 3) as u8 {
            0 => None,
            1 => Some(false),
            _ => Some(true),
        }
    }

    fn make_atoms(n: usize, limits: PolicyLimits) -> Vec<PolicyAtom> {
        (0..n)
            .map(|i| PolicyAtom::new(format!("a{i}"), limits).expect("atom"))
            .collect()
    }

    fn gen_policy(
        seed: u64,
        depth: u32,
        atoms: &[PolicyAtom],
        limits: PolicyLimits,
        children_max: usize,
        under_not: bool,
    ) -> PolicyExpr {
        // Deterministic structural generator (no RNG crate).
        if depth == 0 {
            let r = xorshift64(seed);
            let pick = (r % 4) as u8;
            return match pick {
                0 => PolicyExpr::True,
                1 => PolicyExpr::False,
                _ => {
                    let a = &atoms[(r as usize) % atoms.len()];
                    if !under_not && (pick == 3) {
                        PolicyExpr::DenyIf(a.clone())
                    } else {
                        PolicyExpr::Atom(a.clone())
                    }
                }
            };
        }

        let r = xorshift64(seed.wrapping_add(depth as u64));
        let choice = (r % 5) as u8;
        match choice {
            0 => {
                // Not (but forbid DenyIf under Not by setting under_not=true recursively)
                let sub = gen_policy(r, depth - 1, atoms, limits, children_max, true);
                PolicyExpr::not(sub)
            }
            1 => {
                // All
                let n = 2 + (r as usize % children_max.max(2).min(limits.max_children));
                let mut kids = Vec::with_capacity(n);
                for i in 0..n {
                    kids.push(gen_policy(r ^ (i as u64), depth - 1, atoms, limits, children_max, under_not));
                }
                PolicyExpr::all(kids, limits).expect("all")
            }
            2 => {
                // Any
                let n = 2 + (r as usize % children_max.max(2).min(limits.max_children));
                let mut kids = Vec::with_capacity(n);
                for i in 0..n {
                    kids.push(gen_policy(r ^ (i as u64), depth - 1, atoms, limits, children_max, under_not));
                }
                PolicyExpr::any(kids, limits).expect("any")
            }
            _ => {
                // Threshold(k, n)
                let n = 2 + (r as usize % children_max.max(2).min(limits.max_children));
                let mut kids = Vec::with_capacity(n);
                for i in 0..n {
                    kids.push(gen_policy(r ^ (i as u64), depth - 1, atoms, limits, children_max, under_not));
                }
                let k = ((r >> 8) as usize) % (n + 1);
                PolicyExpr::threshold(k as u16, kids, limits).expect("threshold")
            }
        }
    }

    fn gen_valid_policy(
        mut seed: u64,
        depth: u32,
        atoms: &[PolicyAtom],
        limits: PolicyLimits,
        children_max: usize,
    ) -> PolicyExpr {
        // Canonicalization is part of the MPRD contract; ensure we only benchmark valid policies.
        for _ in 0..64 {
            let p = gen_policy(seed, depth, atoms, limits, children_max, false);
            if let Ok(c) = CanonicalPolicy::new(p.clone(), limits) {
                // Avoid benchmarking the trivial constant policy whenever possible.
                if c.bytes_v1().len() > 1 {
                    return p;
                }
            }
            seed = xorshift64(seed.wrapping_add(0x9e3779b97f4a7c15u64));
        }
        // If we couldn't find a non-trivial valid policy quickly, fall back to a simple atom.
        if let Some(a0) = atoms.first() {
            return PolicyExpr::Atom(a0.clone());
        }
        PolicyExpr::True
    }

    fn node_count(e: &PolicyExpr) -> usize {
        match e {
            PolicyExpr::True | PolicyExpr::False | PolicyExpr::Atom(_) | PolicyExpr::DenyIf(_) => 1,
            PolicyExpr::Not(p) => 1 + node_count(p),
            PolicyExpr::All(v) | PolicyExpr::Any(v) => 1 + v.iter().map(node_count).sum::<usize>(),
            PolicyExpr::Threshold { children, .. } => 1 + children.iter().map(node_count).sum::<usize>(),
        }
    }

    fn expr_to_json(e: &PolicyExpr) -> serde_json::Value {
        match e {
            PolicyExpr::True => json!({"k":"T"}),
            PolicyExpr::False => json!({"k":"F"}),
            PolicyExpr::Atom(a) => json!({"k":"A","a":a.as_str()}),
            PolicyExpr::DenyIf(a) => json!({"k":"D","a":a.as_str()}),
            PolicyExpr::Not(p) => json!({"k":"N","p":expr_to_json(p)}),
            PolicyExpr::All(children) => json!({"k":"All","c":children.iter().map(expr_to_json).collect::<Vec<_>>() }),
            PolicyExpr::Any(children) => json!({"k":"Any","c":children.iter().map(expr_to_json).collect::<Vec<_>>() }),
            PolicyExpr::Threshold { k, children } => json!({"k":"Th","t":*k,"c":children.iter().map(expr_to_json).collect::<Vec<_>>() }),
        }
    }

    fn make_env(seed: u64, atoms: usize, out: &mut Env) {
        out.vals.clear();
        out.vals.reserve(atoms);
        let mut x = seed;
        for _ in 0..atoms {
            x = xorshift64(x);
            out.vals.push(sample_trit(x));
        }
    }

    fn env_to_json(env: &Env, atoms: &[PolicyAtom]) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        for (i, a) in atoms.iter().enumerate() {
            let v = env.vals.get(i).copied().unwrap_or(None);
            let jv = match v {
                None => serde_json::Value::Null,
                Some(false) => serde_json::Value::Bool(false),
                Some(true) => serde_json::Value::Bool(true),
            };
            m.insert(a.as_str().to_string(), jv);
        }
        serde_json::Value::Object(m)
    }

    fn bdd_eval(
        bdd: &Robdd,
        idx_str: &BTreeMap<String, usize>,
        env: &Env,
    ) -> bool {
        bdd.eval(|var| {
            let s = var.as_str();
            if let Some(rest) = s.strip_prefix("p_") {
                let i = idx_str.get(rest).copied().unwrap_or(usize::MAX);
                return i < env.vals.len() && env.vals[i].is_some();
            }
            if let Some(rest) = s.strip_prefix("v_") {
                let i = idx_str.get(rest).copied().unwrap_or(usize::MAX);
                return i < env.vals.len() && env.vals[i] == Some(true);
            }
            false
        })
    }

    fn parse_list(s: &Option<String>) -> Option<Vec<usize>> {
        let raw = s.as_ref()?;
        let mut out = Vec::new();
        for part in raw.split(',') {
            if let Ok(v) = part.trim().parse::<usize>() {
                out.push(v);
            }
        }
        if out.is_empty() { None } else { Some(out) }
    }

    pub fn main_like(cfg: Config) {
        let limits = PolicyLimits::DEFAULT;

        let atoms_list = parse_list(&cfg.policy_atoms_list).unwrap_or_else(|| vec![cfg.policy_atoms]);
        let depth_list = parse_list(&cfg.policy_depth_list).unwrap_or_else(|| vec![cfg.policy_depth as usize]);

        let mut rows = Vec::new();

        for &na in &atoms_list {
            let atoms = make_atoms(na, limits);
            let mut idx: BTreeMap<PolicyAtom, usize> = BTreeMap::new();
            let mut idx_str: BTreeMap<String, usize> = BTreeMap::new();
            for (i, a) in atoms.iter().enumerate() {
                idx.insert(a.clone(), i);
                idx_str.insert(a.as_str().to_string(), i);
            }
            for &d in &depth_list {
                let policy = gen_valid_policy(
                    cfg.seed ^ ((na as u64) << 32) ^ (d as u64),
                    d as u32,
                    &atoms,
                    limits,
                    cfg.policy_children_max,
                );

                // compile once
                let t_compile0 = Instant::now();
                let bdd0 = compile_allow_robdd(&policy, limits).expect("compile_allow_robdd");
                let compile_secs = t_compile0.elapsed().as_secs_f64();
                let policy_hash = policy_hash_v1(&policy);
                let canon = CanonicalPolicy::new(policy.clone(), limits).expect("canon");
                let policy_bytes_hex = hex::encode(canon.bytes_v1());
                let policy_json = expr_to_json(&policy);
                let policy_has_deny_if = policy.contains_deny_if();
                let policy_node_count = node_count(&policy);

                // build a second, slightly perturbed policy (for equiv bench)
                let policy2 = gen_valid_policy(
                    cfg.seed ^ 0x9e3779b97f4a7c15u64 ^ ((na as u64) << 32) ^ (d as u64),
                    d as u32,
                    &atoms,
                    limits,
                    cfg.policy_children_max,
                );

                let mut env = Env { vals: Vec::with_capacity(na) };
                let mut acc: u64 = 0;
                let mut agree = true;
                let mut mismatch: Option<serde_json::Value> = None;

                let t_eval = Instant::now();
                for i in 0..cfg.policy_env_iters {
                    make_env(cfg.seed ^ (i as u64), na, &mut env);
                    let ctx = IndexedCtx { env: &env, idx: &idx };
                    let r = evaluate(&policy, &ctx, limits).expect("evaluate");
                    acc ^= black_box(r.allowed() as u64);
                }
                let eval_secs = t_eval.elapsed().as_secs_f64();

                let t_bdd = Instant::now();
                for i in 0..cfg.policy_env_iters {
                    make_env(cfg.seed ^ (i as u64), na, &mut env);
                    let out_bdd = bdd_eval(&bdd0, &idx_str, &env);
                    acc ^= black_box(out_bdd as u64);
                    // spot-check agreement on a small prefix
                    if i < 256 {
                        let ctx = IndexedCtx { env: &env, idx: &idx };
                        let r = evaluate(&policy, &ctx, limits).expect("evaluate");
                        if r.allowed() != out_bdd {
                            agree = false;
                            if mismatch.is_none() {
                                mismatch = Some(json!({
                                    "iter": i,
                                    "env": env_to_json(&env, &atoms),
                                    "evaluate_allowed": r.allowed(),
                                    "bdd_allowed": out_bdd,
                                }));
                            }
                        }
                    }
                }
                let bdd_eval_secs = t_bdd.elapsed().as_secs_f64();

                let mut bdd_compile_eval_secs = 0.0;
                if cfg.policy_compile_each {
                    let t = Instant::now();
                    for i in 0..(cfg.policy_env_iters / 100).max(1) {
                        make_env(cfg.seed ^ (i as u64), na, &mut env);
                        let bdd = compile_allow_robdd(&policy, limits).expect("compile_allow_robdd");
                        acc ^= black_box(bdd_eval(&bdd, &idx_str, &env) as u64);
                    }
                    bdd_compile_eval_secs = t.elapsed().as_secs_f64();
                }

                let t_equiv = Instant::now();
                let equiv = policy_equiv_robdd_bool_fast(&policy, &policy2, limits).expect("equiv");
                let equiv_secs = t_equiv.elapsed().as_secs_f64();
                acc ^= black_box(equiv as u64);

                let row = json!({
                    "seed": cfg.seed,
                    "atoms": na,
                    "depth": d,
                    "children_max": cfg.policy_children_max,
                    "env_iters": cfg.policy_env_iters,
                    "policy_hash_v1_hex": hex::encode(policy_hash.0),
                    "policy_bytes_v1_hex": policy_bytes_hex,
                    "policy_has_deny_if": policy_has_deny_if,
                    "policy_node_count": policy_node_count,
                    "policy_expr": policy_json,
                    "compile_once_seconds": compile_secs,
                    "evaluate_seconds_total": eval_secs,
                    "evaluate_per_sec": (cfg.policy_env_iters as f64) / eval_secs.max(1e-12),
                    "bdd_eval_seconds_total": bdd_eval_secs,
                    "bdd_eval_per_sec": (cfg.policy_env_iters as f64) / bdd_eval_secs.max(1e-12),
                    "bdd_compile_eval_seconds_total": bdd_compile_eval_secs,
                    "equiv_bool_fast_seconds_total": equiv_secs,
                    "agree_prefix_256": agree,
                    "mismatch": mismatch,
                    "acc": acc,
                });
                rows.push(row);
            }
        }

        match cfg.mode {
            OutputMode::Human => {
                println!("mprd-perf policy bench (reproducible)");
                println!("seed: {}", cfg.seed);
                for r in &rows {
                    println!("{}", serde_json::to_string_pretty(r).expect("json"));
                }
            }
            OutputMode::Json => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "rows": rows })).expect("json")
                );
            }
        }
    }
}
