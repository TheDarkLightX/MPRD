//! Experimental (research-backed) simplex planner utilities.
//!
//! This module is the "production-adjacent" bridge from the Lean/Morph simplex POR work into
//! reusable Rust code. It is IO-free and deterministic.
//!
//! Scope:
//! - deterministic canonicalization of transfer traces using the POR oracle
//! - symmetry-class state keys (quotienting) via the certified symmetry-key utility
//!
//! NOTE: This does not yet replace the current v6 `MenuGraph` CEO (which is small and explicit).
//! It exists to make the k-way simplex mode feasible when/if we adopt it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::{MprdError, Result};

use super::simplex_por_oracle::{self, Transfer};
use super::simplex_symmetry_key;

/// Sound, deterministic cache for oracle checks.
///
/// Collision-free keying:
/// - states are interned as full vectors → unique integer IDs (deterministically assigned)
/// - oracle cache key is `(state_id, prev_key, next_key)`
#[derive(Debug, Default, Clone)]
pub struct OracleCache {
    intern: BTreeMap<Vec<u32>, u32>,
    next_id: u32,
    map: BTreeMap<(u32, u32, u32), bool>,
}

impl OracleCache {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn key_for(k: usize, a: Transfer) -> u32 {
        action_key(k, a)
    }

    fn state_id(&mut self, x: &[u32]) -> u32 {
        if let Some(&id) = self.intern.get(x) {
            return id;
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.intern.insert(x.to_vec(), id);
        id
    }

    pub fn stable_enabled_ineq(
        &mut self,
        caps: &[u32],
        x: &[u32],
        prev: Transfer,
        next: Transfer,
    ) -> bool {
        let k = x.len();
        let sid = self.state_id(x);
        let key = (sid, Self::key_for(k, prev), Self::key_for(k, next));
        if let Some(&v) = self.map.get(&key) {
            return v;
        }
        let v = simplex_por_oracle::stable_enabled_ineq(x, caps, prev, next);
        self.map.insert(key, v);
        v
    }
}

/// Deterministic key for transfers (used for canonical ordering).
#[inline]
pub fn action_key(k: usize, a: Transfer) -> u32 {
    (a.src as u32).saturating_mul(k as u32).saturating_add(a.dst as u32)
}

/// Deterministic bubble-like pass with state-dependent justified swaps.
///
/// If two adjacent transfers are provably independent under the closed-form oracle, we may swap
/// them to move toward sorted order by `action_key`.
pub fn canon_pass(caps: &[u32], x0: &[u32], trace: &[Transfer]) -> Result<Vec<Transfer>> {
    let k = x0.len();
    if k == 0 || caps.len() != k {
        return Err(MprdError::InvalidInput(
            "canon_pass: caps and x0 must be same non-zero length".into(),
        ));
    }

    let mut xs: Vec<Transfer> = trace.to_vec();
    let mut s: Vec<u32> = x0.to_vec();

    let mut i = 0usize;
    while i + 1 < xs.len() {
        let a = xs[i];
        let b = xs[i + 1];
        if action_key(k, b) < action_key(k, a) && simplex_por_oracle::stable_enabled_ineq(&s, caps, a, b)
        {
            // swap and advance one step by executing `b` (failure-as-noop)
            xs[i] = b;
            xs[i + 1] = a;
            s = simplex_por_oracle::step_or_stay(&s, caps, b);
        } else {
            s = simplex_por_oracle::step_or_stay(&s, caps, a);
            i += 1;
        }
    }

    Ok(xs)
}

/// Compute post-prefix states for a trace.
///
/// Returns `states` of length `trace.len() + 1` where:
/// - `states[0] = x0`
/// - `states[i+1] = step_or_stay(states[i], trace[i])`
pub fn prefix_states(caps: &[u32], x0: &[u32], trace: &[Transfer]) -> Result<Vec<Vec<u32>>> {
    let k = x0.len();
    if k == 0 || caps.len() != k {
        return Err(MprdError::InvalidInput(
            "prefix_states: caps and x0 must be same non-zero length".into(),
        ));
    }
    let mut out: Vec<Vec<u32>> = Vec::with_capacity(trace.len() + 1);
    let mut s = x0.to_vec();
    out.push(s.clone());
    for &a in trace {
        s = simplex_por_oracle::step_or_stay(&s, caps, a);
        out.push(s.clone());
    }
    Ok(out)
}

/// Fast incremental canonicalization when extending a trace by one action.
///
/// This performs a deterministic "insertion" step: append `a` and bubble it left as long as:
/// - it improves order by `action_key`, and
/// - the POR oracle certifies the adjacent swap at the post-prefix state.
///
/// Soundness intuition:
/// - Each swap is oracle-justified, hence a `SwapStep` in the Lean model.
/// - Therefore the result is `SwapEq`-equivalent to the original trace and run-invariant.
pub fn canonicalize_append_insert(
    caps: &[u32],
    x_prefix: &[Vec<u32>],
    trace: &[Transfer],
    a: Transfer,
) -> Result<Vec<Transfer>> {
    canonicalize_append_insert_cached(caps, x_prefix, trace, a, &mut OracleCache::new())
}

/// Cached variant of `canonicalize_append_insert`.
pub fn canonicalize_append_insert_cached(
    caps: &[u32],
    x_prefix: &[Vec<u32>],
    trace: &[Transfer],
    a: Transfer,
    cache: &mut OracleCache,
) -> Result<Vec<Transfer>> {
    if x_prefix.len() != trace.len() + 1 {
        return Err(MprdError::InvalidInput(
            "canonicalize_append_insert: x_prefix must have length trace.len()+1".into(),
        ));
    }
    let k = x_prefix
        .first()
        .ok_or_else(|| MprdError::InvalidInput("canonicalize_append_insert: empty prefix".into()))?
        .len();
    if k == 0 || caps.len() != k {
        return Err(MprdError::InvalidInput(
            "canonicalize_append_insert: caps and state width must match and be non-zero".into(),
        ));
    }

    let mut out = trace.to_vec();
    out.push(a);

    let a_key = action_key(k, a);
    let mut pos = out.len().saturating_sub(1);
    while pos > 0 {
        let prev = out[pos - 1];
        if a_key < action_key(k, prev)
            && cache.stable_enabled_ineq(caps, &x_prefix[pos - 1], prev, a)
        {
            out[pos] = prev;
            out[pos - 1] = a;
            pos -= 1;
        } else {
            break;
        }
    }
    Ok(out)
}

/// Canonicalize a transfer trace by iterating `canon_pass` to a fixed point.
///
/// Deterministic termination bound: O(len(trace)^2) passes.
pub fn canonicalize_trace(caps: &[u32], x0: &[u32], trace: &[Transfer]) -> Result<Vec<Transfer>> {
    let mut cur = trace.to_vec();
    let steps = cur.len().saturating_mul(cur.len()).max(1);
    for _ in 0..steps {
        let nxt = canon_pass(caps, x0, &cur)?;
        if nxt == cur {
            return Ok(cur);
        }
        cur = nxt;
    }
    Ok(cur)
}

/// Compact deterministic rolling hash for a transfer trace.
///
/// Not cryptographic; used for deterministic dedup in planners/benches.
pub fn trace_key_hash(trace: &[Transfer], k: usize) -> u128 {
    let mut h1: u64 = 1469598103934665603u64;
    let mut h2: u64 = 1099511628211u64;
    for &a in trace {
        let ak = action_key(k, a) as u64;
        h1 ^= ak;
        h1 = h1.wrapping_mul(1099511628211u64);
        h2 = h2.wrapping_add(ak.wrapping_mul(0x9e3779b97f4a7c15u64));
        h2 ^= h2 >> 33;
        h2 = h2.wrapping_mul(0xff51afd7ed558ccd_u64);
    }
    ((h1 as u128) << 64) | (h2 as u128)
}

/// Symmetry-class canonical key for a simplex state (fail-closed).
pub fn symmetry_key(x: &[u32], caps: &[u32], weights: &[u32]) -> Option<Vec<Vec<u32>>> {
    simplex_symmetry_key::symmetry_key(x, caps, weights)
}

/// Planner mode for enumeration: trace POR dedup vs state symmetry dedup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    TracePor,
    StateSymmetry,
}

/// Minimal, deterministic work summary for benchmarking/planner telemetry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub expanded: usize,
    pub generated: usize,
    pub reached_states: usize,
}

/// Enumerate reachable states within horizon `h` from `x0`.
///
/// - `Mode::TracePor`: deduplicate by canonical trace keys (POR-style)
/// - `Mode::StateSymmetry`: deduplicate by symmetry-class state key (quotienting)
///
/// This is a bounded-horizon explorer intended for planner benchmarking and feasibility checks.
pub fn enumerate_reachable(
    mode: Mode,
    x0: &[u32],
    caps: &[u32],
    weights: &[u32],
    h: usize,
    budget_expanded: usize,
) -> Result<Summary> {
    let k = x0.len();
    if k == 0 || caps.len() != k || weights.len() != k {
        return Err(MprdError::InvalidInput(
            "enumerate_reachable: x0/caps/weights must be same non-zero length".into(),
        ));
    }

    let mut acts: Vec<Transfer> = Vec::with_capacity(k.saturating_mul(k.saturating_sub(1)));
    for src in 0..k {
        for dst in 0..k {
            if src != dst {
                acts.push(Transfer::new(src, dst));
            }
        }
    }

    let mut expanded = 0usize;
    let mut generated = 0usize;
    let mut reached: BTreeSet<Vec<u32>> = BTreeSet::new();
    reached.insert(x0.to_vec());

    match mode {
        Mode::TracePor => {
            let mut q: VecDeque<(Vec<Transfer>, Vec<u32>)> = VecDeque::new();
            q.push_back((Vec::new(), x0.to_vec()));

            let mut seen_trace_keys: BTreeSet<u128> = BTreeSet::new();
            seen_trace_keys.insert(trace_key_hash(&[], k));
            let mut cache = OracleCache::new();

            while let Some((tr, x)) = q.pop_front() {
                if expanded >= budget_expanded {
                    break;
                }
                if tr.len() >= h {
                    continue;
                }
                expanded += 1;
                // Precompute post-prefix states once per expanded node (amortizes over all outgoing actions).
                let x_prefix = prefix_states(caps, x0, &tr)?;
                for &a in &acts {
                    generated += 1;
                    let x2 = simplex_por_oracle::step_or_stay(&x, caps, a);
                    let tr_can =
                        canonicalize_append_insert_cached(caps, &x_prefix, &tr, a, &mut cache)?;
                    let key = trace_key_hash(&tr_can, k);
                    if !seen_trace_keys.insert(key) {
                        continue;
                    }
                    reached.insert(x2.clone());
                    q.push_back((tr_can, x2));
                }
            }
        }
        Mode::StateSymmetry => {
            let mut q: VecDeque<(Vec<u32>, usize)> = VecDeque::new();
            q.push_back((x0.to_vec(), 0));

            let mut seen: BTreeMap<Vec<Vec<u32>>, usize> = BTreeMap::new();
            let k0 = symmetry_key(x0, caps, weights).unwrap_or_else(|| vec![x0.to_vec()]);
            seen.insert(k0, 0);

            while let Some((x, depth)) = q.pop_front() {
                if expanded >= budget_expanded {
                    break;
                }
                expanded += 1;
                if depth >= h {
                    continue;
                }
                for &a in &acts {
                    generated += 1;
                    let x2 = simplex_por_oracle::step_or_stay(&x, caps, a);
                    let key = symmetry_key(&x2, caps, weights).unwrap_or_else(|| vec![x2.clone()]);
                    let nd = depth + 1;
                    let insert = match seen.get(&key) {
                        None => true,
                        Some(&best) => nd < best,
                    };
                    if insert {
                        seen.insert(key, nd);
                        reached.insert(x2.clone());
                        q.push_back((x2, nd));
                    }
                }
            }
        }
    }

    Ok(Summary {
        expanded,
        generated,
        reached_states: reached.len(),
    })
}

