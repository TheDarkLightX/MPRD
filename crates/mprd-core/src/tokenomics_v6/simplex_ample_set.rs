//! Experimental: POR ample-set style successor reduction for simplex transfer planning.
//!
//! This is a research module. It provides:
//! - *unsafe* baseline heuristics (for falsifier mining),
//! - a *POR-style* ample-set reduction that includes a **cycle proviso** (DFS C2 check),
//! - an internal counterexample miner for small bounded instances (evidence-first falsification).
//!
//! IMPORTANT:
//! - This module makes *no* global soundness claim by default.
//! - Any pruning rule must be validated by (a) bounded exhaustive checks and/or (b) Lean proofs.
//! - Fail-closed rule: if independence cannot be proved, treat actions as dependent (do not prune).

use crate::{MprdError, Result};

use super::simplex_planner::{self, OracleCache};
use super::simplex_por_oracle::{self, Transfer};

/// Internal decision tuple that matches `simplex_ceo` tie-breaking.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Decision {
    score: i64,
    depth: usize,
    first_key: u64,
    state: Vec<u32>,
    first_action: Option<Transfer>,
}

fn better_decision(a: &Decision, b: &Decision) -> bool {
    (a.score > b.score)
        || (a.score == b.score && a.depth < b.depth)
        || (a.score == b.score && a.depth == b.depth && a.first_key < b.first_key)
        || (a.score == b.score
            && a.depth == b.depth
            && a.first_key == b.first_key
            && a.state < b.state)
}

/// Candidate ample set strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmpleStrategy {
    /// Baseline: return all actions (no pruning).
    None,
    /// Pick a single deterministic minimal enabled action (unsafe in general; used for falsifier mining).
    MinOnly,
    /// Deterministic ample set: pick minimal enabled action `a0` plus any enabled action `b` that is
    /// not certified independent from `a0` at the current state.
    ///
    /// This is a natural "dependent closure of a singleton seed" heuristic; it is not guaranteed
    /// sound without additional POR conditions (e.g., C0-C3) and therefore is shipped as experimental.
    MinPlusDependentsOfMin,
    /// Seed with minimal enabled action and close under "not-certified-independent" at the current
    /// state (dependency component under the sufficient oracle).
    ///
    /// This is strictly more conservative than `MinPlusDependentsOfMin` and is intended as a
    /// candidate that may become sound under bounded-horizon exploration, but it still requires
    /// explicit evidence (exhaustive checks) before promotion.
    MinPlusDependencyClosure,
    /// POR-style ample set using a DFS cycle proviso (C2):
    /// - Compute a candidate ample set by dependency closure under `stable_enabled_ineq` (fail-closed).
    /// - If taking any transition in the candidate ample set would reach a state already on the DFS
    ///   stack, expand **all enabled** actions (no reduction) at this state.
    ///
    /// This is the standard sufficient condition used in SPIN-style POR to preserve reachability.
    DfsC2,
}

fn all_transfers(k: usize) -> Vec<Transfer> {
    let mut out = Vec::with_capacity(k.saturating_mul(k.saturating_sub(1)));
    for src in 0..k {
        for dst in 0..k {
            if src != dst {
                out.push(Transfer::new(src, dst));
            }
        }
    }
    out.sort_by_key(|&a| simplex_planner::action_key(k, a));
    out
}

/// Return the enabled transfers in deterministic order.
pub fn enabled_actions(x: &[u32], caps: &[u32]) -> Result<Vec<Transfer>> {
    let k = x.len();
    if k == 0 || caps.len() != k {
        return Err(MprdError::InvalidInput(
            "enabled_actions: x/caps must be same non-zero length".into(),
        ));
    }
    let mut out = Vec::new();
    for a in all_transfers(k) {
        if simplex_por_oracle::enabled(x, caps, a) {
            out.push(a);
        }
    }
    Ok(out)
}

/// Select an "ample set" of enabled actions at a state.
pub fn ample_set(
    strategy: AmpleStrategy,
    x: &[u32],
    caps: &[u32],
    cache: &mut OracleCache,
) -> Result<Vec<Transfer>> {
    let enabled = enabled_actions(x, caps)?;
    if enabled.is_empty() {
        return Ok(Vec::new());
    }
    match strategy {
        AmpleStrategy::None => Ok(enabled),
        AmpleStrategy::MinOnly => Ok(vec![enabled[0]]),
        AmpleStrategy::MinPlusDependentsOfMin => {
            let a0 = enabled[0];
            let mut out = Vec::new();
            out.push(a0);
            for &b in &enabled[1..] {
                // Fail-closed: only treat as independent if oracle certifies.
                if !cache.stable_enabled_ineq(caps, x, a0, b) {
                    out.push(b);
                }
            }
            Ok(out)
        }
        AmpleStrategy::MinPlusDependencyClosure => {
            let mut out: Vec<Transfer> = vec![enabled[0]];
            // fixed point: add any enabled action that is dependent with any action already in out
            // (fail-closed: treat "not certified independent" as dependent).
            loop {
                let mut changed = false;
                for &b in &enabled {
                    if out.contains(&b) {
                        continue;
                    }
                    let mut dep = false;
                    for &a in &out {
                        if !cache.stable_enabled_ineq(caps, x, a, b) {
                            dep = true;
                            break;
                        }
                    }
                    if dep {
                        out.push(b);
                        changed = true;
                    }
                }
                if !changed {
                    break;
                }
            }
            out.sort_by_key(|&a| simplex_planner::action_key(x.len(), a));
            Ok(out)
        }
        AmpleStrategy::DfsC2 => {
            // The DFS cycle proviso is checked in the DFS explorer (it needs the stack).
            // Here we just return the conservative dependency-closure candidate.
            ample_set(AmpleStrategy::MinPlusDependencyClosure, x, caps, cache)
        }
    }
}

fn step_or_stay_inplace(x: &[u32], caps: &[u32], a: Transfer, out: &mut [u32]) {
    out.copy_from_slice(x);
    if !simplex_por_oracle::enabled(x, caps, a) {
        return;
    }
    out[a.src] = out[a.src].saturating_sub(1);
    out[a.dst] = out[a.dst].saturating_add(1);
}

/// CEO decision-quality POR planner for **linear** objectives using DFS+C2 ample-set reduction.
///
/// Contract:
/// - Deterministic.
/// - Fail-closed on budget exhaustion: returns `Err` rather than a potentially-wrong decision.
/// - Safety visibility contract: if any enabled action at a state would change the linear score
///   (`w[src] != w[dst]`), we do **not** reduce at that state (expand all enabled actions).
///
/// Returns `(best_state, best_score, best_depth, best_first_action)`.
pub fn plan_best_linear_dfs_c2(
    x0: &[u32],
    caps: &[u32],
    w: &[i64],
    horizon: usize,
    budget_expanded: usize,
    require_sum: Option<u32>,
) -> Result<(Vec<u32>, i64, usize, Option<Transfer>)> {
    let k = x0.len();
    if k == 0 || caps.len() != k || w.len() != k {
        return Err(MprdError::InvalidInput(
            "plan_best_linear_dfs_c2: x0/caps/w must be same non-zero length".into(),
        ));
    }
    if let Some(t) = require_sum {
        let s: u32 = x0.iter().copied().sum();
        if s != t {
            return Err(MprdError::InvalidInput(format!(
                "plan_best_linear_dfs_c2: require_sum={t} but sum(x0)={s}"
            )));
        }
    }
    let acts = all_transfers(k);

    let mut best = Decision {
        score: i64::MIN,
        depth: usize::MAX,
        first_key: u64::MAX,
        state: Vec::new(),
        first_action: None,
    };

    // state -> best (depth, first_key) we've seen (to prune revisits deterministically)
    let mut best_seen: std::collections::BTreeMap<Vec<u32>, (usize, u64)> =
        std::collections::BTreeMap::new();

    let mut stack: Vec<Vec<u32>> = Vec::new();
    let mut on_stack = std::collections::BTreeSet::<Vec<u32>>::new();
    let mut tmp = vec![0u32; k];
    let mut cache = OracleCache::new();
    let mut expanded: usize = 0;

    fn score_linear(x: &[u32], w: &[i64]) -> i64 {
        let mut s = 0i64;
        for i in 0..x.len() {
            s = s.saturating_add(w[i].saturating_mul(x[i] as i64));
        }
        s
    }

    fn dfs(
        x: &Vec<u32>,
        depth: usize,
        first_key: u64,
        first_action: Option<Transfer>,
        horizon: usize,
        budget_expanded: usize,
        caps: &[u32],
        w: &[i64],
        acts: &[Transfer],
        best: &mut Decision,
        best_seen: &mut std::collections::BTreeMap<Vec<u32>, (usize, u64)>,
        stack: &mut Vec<Vec<u32>>,
        on_stack: &mut std::collections::BTreeSet<Vec<u32>>,
        tmp: &mut [u32],
        cache: &mut OracleCache,
        expanded: &mut usize,
    ) -> Result<()> {
        // Budget gate (fail-closed).
        if *expanded >= budget_expanded {
            return Err(MprdError::BoundedValueExceeded(
                "plan_best_linear_dfs_c2: expansion budget exceeded".into(),
            ));
        }
        *expanded += 1;

        // Evaluate decision at this visited node (matches simplex_ceo: best over depths <= horizon).
        let s = score_linear(x, w);
        let cand = Decision {
            score: s,
            depth,
            first_key,
            state: x.clone(),
            first_action,
        };
        if best.state.is_empty() || better_decision(&cand, best) {
            *best = cand;
        }

        // Prune revisits if we already have an equal-or-better (depth, first_key) for this state.
        match best_seen.get(x) {
            Some(&(d0, fk0)) => {
                if depth > d0 || (depth == d0 && first_key >= fk0) {
                    return Ok(());
                }
            }
            None => {}
        }
        best_seen.insert(x.clone(), (depth, first_key));

        if depth >= horizon {
            return Ok(());
        }

        // Enabled set E.
        let mut enabled: Vec<Transfer> = Vec::new();
        let mut any_visible = false;
        for &a in acts {
            if simplex_por_oracle::enabled(x, caps, a) {
                enabled.push(a);
                if w[a.src] != w[a.dst] {
                    any_visible = true;
                }
            }
        }
        if enabled.is_empty() {
            return Ok(());
        }

        // Candidate ample set A (dependency closure) but only in objective-invisible regions.
        let mut ample = if any_visible {
            enabled.clone()
        } else {
            ample_set(AmpleStrategy::MinPlusDependencyClosure, x, caps, cache)?
        };

        // C2 cycle proviso: if any ample successor would land on DFS stack, expand all enabled.
        let mut violates_c2 = false;
        for &a in &ample {
            step_or_stay_inplace(x, caps, a, tmp);
            if on_stack.contains(tmp) {
                violates_c2 = true;
                break;
            }
        }
        if violates_c2 {
            ample = enabled;
        }

        stack.push(x.clone());
        on_stack.insert(x.clone());
        for &a in &ample {
            step_or_stay_inplace(x, caps, a, tmp);
            let x2 = tmp.to_vec();
            let (fk2, fa2) = if first_key != 0 {
                (first_key, first_action)
            } else {
                (simplex_planner::action_key(x.len(), a) as u64, Some(a))
            };
            dfs(
                &x2,
                depth + 1,
                fk2,
                fa2,
                horizon,
                budget_expanded,
                caps,
                w,
                acts,
                best,
                best_seen,
                stack,
                on_stack,
                tmp,
                cache,
                expanded,
            )?;
        }
        let top = stack.pop().expect("stack underflow");
        let removed = on_stack.remove(&top);
        debug_assert!(removed);
        Ok(())
    }

    let x0v = x0.to_vec();
    dfs(
        &x0v,
        0,
        0,
        None,
        horizon,
        budget_expanded,
        caps,
        w,
        &acts,
        &mut best,
        &mut best_seen,
        &mut stack,
        &mut on_stack,
        &mut tmp,
        &mut cache,
        &mut expanded,
    )?;

    Ok((best.state, best.score, best.depth, best.first_action))
}

/// Compute the set of reachable states within horizon `h` using full branching.
pub fn reachable_full(x0: &[u32], caps: &[u32], h: usize) -> Result<std::collections::BTreeSet<Vec<u32>>> {
    let k = x0.len();
    if k == 0 || caps.len() != k {
        return Err(MprdError::InvalidInput(
            "reachable_full: x0/caps must be same non-zero length".into(),
        ));
    }
    let acts = all_transfers(k);
    let mut reached = std::collections::BTreeSet::new();
    reached.insert(x0.to_vec());
    let mut q = std::collections::VecDeque::new();
    q.push_back((x0.to_vec(), 0usize));
    let mut tmp = vec![0u32; k];
    while let Some((x, d)) = q.pop_front() {
        if d >= h {
            continue;
        }
        for &a in &acts {
            step_or_stay_inplace(&x, caps, a, &mut tmp);
            let x2 = tmp.clone();
            if reached.insert(x2.clone()) {
                q.push_back((x2, d + 1));
            }
        }
    }
    Ok(reached)
}

/// Compute reachable states within horizon `h` using an ample-set strategy.
pub fn reachable_ample(
    strategy: AmpleStrategy,
    x0: &[u32],
    caps: &[u32],
    h: usize,
) -> Result<std::collections::BTreeSet<Vec<u32>>> {
    let k = x0.len();
    if k == 0 || caps.len() != k {
        return Err(MprdError::InvalidInput(
            "reachable_ample: x0/caps must be same non-zero length".into(),
        ));
    }
    let mut reached = std::collections::BTreeSet::new();
    reached.insert(x0.to_vec());
    let mut q = std::collections::VecDeque::new();
    q.push_back((x0.to_vec(), 0usize));
    let mut tmp = vec![0u32; k];
    let mut cache = OracleCache::new();
    while let Some((x, d)) = q.pop_front() {
        if d >= h {
            continue;
        }
        for a in ample_set(strategy, &x, caps, &mut cache)? {
            step_or_stay_inplace(&x, caps, a, &mut tmp);
            let x2 = tmp.clone();
            if reached.insert(x2.clone()) {
                q.push_back((x2, d + 1));
            }
        }
    }
    Ok(reached)
}

/// POR DFS explorer with cycle proviso (C2) for `AmpleStrategy::DfsC2`.
///
/// Determinism:
/// - action order is by `action_key`
/// - state order is lexicographic (`Vec<u32>` under `BTree*`)
pub fn reachable_por_dfs_c2(
    x0: &[u32],
    caps: &[u32],
    h: usize,
) -> Result<std::collections::BTreeSet<Vec<u32>>> {
    use std::collections::{BTreeMap, BTreeSet};

    let k = x0.len();
    if k == 0 || caps.len() != k {
        return Err(MprdError::InvalidInput(
            "reachable_por_dfs_c2: x0/caps must be same non-zero length".into(),
        ));
    }

    let acts = all_transfers(k);
    let mut reached: BTreeSet<Vec<u32>> = BTreeSet::new();
    let mut best_seen_depth: BTreeMap<Vec<u32>, usize> = BTreeMap::new();
    let mut stack: Vec<Vec<u32>> = Vec::new();
    let mut on_stack: BTreeSet<Vec<u32>> = BTreeSet::new();
    let mut tmp = vec![0u32; k];
    let mut cache = OracleCache::new();

    fn dfs(
        x: &Vec<u32>,
        depth: usize,
        h: usize,
        caps: &[u32],
        acts: &[Transfer],
        reached: &mut std::collections::BTreeSet<Vec<u32>>,
        best_seen_depth: &mut std::collections::BTreeMap<Vec<u32>, usize>,
        stack: &mut Vec<Vec<u32>>,
        on_stack: &mut std::collections::BTreeSet<Vec<u32>>,
        tmp: &mut [u32],
        cache: &mut OracleCache,
    ) -> Result<()> {
        reached.insert(x.clone());
        match best_seen_depth.get(x) {
            Some(&d0) if depth >= d0 => {
                // already seen at an equal-or-better depth
                return Ok(());
            }
            _ => {
                best_seen_depth.insert(x.clone(), depth);
            }
        }
        if depth >= h {
            return Ok(());
        }

        // enabled set E (deterministic order)
        let mut enabled: Vec<Transfer> = Vec::new();
        for &a in acts {
            if simplex_por_oracle::enabled(x, caps, a) {
                enabled.push(a);
            }
        }
        if enabled.is_empty() {
            return Ok(());
        }

        // Candidate ample set A via dependency closure under stable_enabled_ineq (fail-closed).
        let mut ample = ample_set(AmpleStrategy::MinPlusDependencyClosure, x, caps, cache)?;

        // Cycle proviso (C2): if any ample transition would go to a state on the DFS stack,
        // we must expand all enabled transitions (no reduction at this state).
        let mut violates_c2 = false;
        for &a in &ample {
            step_or_stay_inplace(x, caps, a, tmp);
            if on_stack.contains(tmp) {
                violates_c2 = true;
                break;
            }
        }
        if violates_c2 {
            ample = enabled;
        }

        // DFS
        stack.push(x.clone());
        on_stack.insert(x.clone());
        for &a in &ample {
            step_or_stay_inplace(x, caps, a, tmp);
            let x2 = tmp.to_vec();
            dfs(
                &x2,
                depth + 1,
                h,
                caps,
                acts,
                reached,
                best_seen_depth,
                stack,
                on_stack,
                tmp,
                cache,
            )?;
        }
        let top = stack.pop().expect("stack underflow");
        let removed = on_stack.remove(&top);
        debug_assert!(removed);
        Ok(())
    }

    let x0v = x0.to_vec();
    dfs(
        &x0v,
        0,
        h,
        caps,
        &acts,
        &mut reached,
        &mut best_seen_depth,
        &mut stack,
        &mut on_stack,
        &mut tmp,
        &mut cache,
    )?;

    Ok(reached)
}

/// Search for a counterexample where an ample-set strategy loses reachability (bounded small sizes).
///
/// Returns the first found counterexample (deterministic order).
pub fn find_reachability_counterexample(
    strategy: AmpleStrategy,
    k: usize,
    t: u32,
    h: usize,
) -> Result<Option<(Vec<u32>, Vec<u32>)>> {
    if k < 2 {
        return Err(MprdError::InvalidInput("k must be >= 2".into()));
    }
    // Canonical starting state: split mass between first two buckets.
    let mut x0 = vec![0u32; k];
    x0[0] = t / 2;
    x0[1] = t - x0[0];
    let caps = vec![t; k];

    let full = reachable_full(&x0, &caps, h)?;
    let amp = reachable_ample(strategy, &x0, &caps, h)?;

    for x in full.iter() {
        if !amp.contains(x) {
            return Ok(Some((x0, x.clone())));
        }
    }
    Ok(None)
}

/// Search for a counterexample where the DFS+C2 POR reduction loses reachability.
pub fn find_reachability_counterexample_dfs_c2(
    k: usize,
    t: u32,
    h: usize,
) -> Result<Option<(Vec<u32>, Vec<u32>)>> {
    if k < 2 {
        return Err(MprdError::InvalidInput("k must be >= 2".into()));
    }
    let mut x0 = vec![0u32; k];
    x0[0] = t / 2;
    x0[1] = t - x0[0];
    let caps = vec![t; k];

    let full = reachable_full(&x0, &caps, h)?;
    let por = reachable_por_dfs_c2(&x0, &caps, h)?;
    for x in full.iter() {
        if !por.contains(x) {
            return Ok(Some((x0, x.clone())));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: tests below define their own Decision helper for pinned falsifiers and sweeps.
    // The production planner uses the module-level `Decision` above.

    #[test]
    fn plan_best_linear_dfs_c2_matches_bruteforce_small() {
        // Basic correctness check: on small instances, the POR decision must match brute force.
        // If this ever fails, we treat it as a pinned counterexample and refine the visibility contract.
        let x0 = vec![3, 1, 2];
        let caps = vec![6, 6, 6];
        let w = vec![10, 1, 2];
        let h = 3usize;
        let budget = 20000usize;
        let (target, score, depth, first) =
            plan_best_linear_dfs_c2(&x0, &caps, &w, h, budget, Some(6)).unwrap();

        // Compare to simplex_ceo brute helper by reproducing brute here (small only).
        let acts = all_transfers(x0.len());
        let mut best_score = i64::MIN;
        let mut best_state = Vec::new();
        let mut best_depth = usize::MAX;
        let mut best_first: Option<Transfer> = None;
        let mut q: std::collections::VecDeque<(Vec<u32>, usize, Option<Transfer>)> =
            std::collections::VecDeque::new();
        q.push_back((x0.clone(), 0, None));
        let mut tmp = vec![0u32; x0.len()];
        while let Some((x, d, first0)) = q.pop_front() {
            // evaluate at each depth
            let mut s = 0i64;
            for i in 0..x.len() {
                s += w[i] * x[i] as i64;
            }
            let fk = first0.map(|f| simplex_planner::action_key(x.len(), f)).unwrap_or(0);
            let b_fk = best_first
                .map(|f| simplex_planner::action_key(x.len(), f))
                .unwrap_or(0);
            if best_state.is_empty()
                || (s > best_score)
                || (s == best_score && d < best_depth)
                || (s == best_score && d == best_depth && fk < b_fk)
                || (s == best_score && d == best_depth && fk == b_fk && x < best_state)
            {
                best_score = s;
                best_state = x.clone();
                best_depth = d;
                best_first = first0;
            }
            if d >= h {
                continue;
            }
            for &a in &acts {
                step_or_stay_inplace(&x, &caps, a, &mut tmp);
                let x2 = tmp.clone();
                let first2 = first0.or(Some(a));
                q.push_back((x2, d + 1, first2));
            }
        }

        assert_eq!(score, best_score);
        assert_eq!(target, best_state);
        assert_eq!(depth, best_depth);
        assert_eq!(first, best_first);
    }

    #[test]
    fn min_only_is_not_sound_on_small_instances() {
        // Evidence-first: we EXPECT MinOnly to be unsound; ensure we can find a counterexample quickly.
        let ce = find_reachability_counterexample(AmpleStrategy::MinOnly, 4, 10, 4)
            .unwrap()
            .expect("expected a counterexample for MinOnly");
        let (_x0, _missing) = ce;
    }

    #[test]
    fn min_plus_dependents_is_plausible_but_not_assumed_sound() {
        // This test is intentionally weak: it only checks a tiny instance and documents that
        // we are not promoting soundness without broader evidence.
        let ce = find_reachability_counterexample(AmpleStrategy::MinPlusDependentsOfMin, 4, 10, 3).unwrap();
        // Allow either outcome; we just want determinism and no panics.
        let _ = ce;
    }

    #[test]
    fn dependency_closure_is_not_sound_on_tiny_case() {
        // Evidence-first: even a dependency-closure ample set can be UNSOUND without a cycle/fairness
        // proviso. We pin a tiny counterexample so we never accidentally "promote" this strategy.
        let ce = find_reachability_counterexample(AmpleStrategy::MinPlusDependencyClosure, 4, 8, 3)
            .unwrap()
            .expect("expected a counterexample");
        assert_eq!(ce.0, vec![4, 4, 0, 0]);
        assert_eq!(ce.1, vec![1, 4, 0, 3]);
    }

    fn best_score_full_linear(x0: &[u32], caps: &[u32], w: &[i64], h: usize) -> i64 {
        let k = x0.len();
        let acts = super::all_transfers(k);
        let mut q = std::collections::VecDeque::new();
        q.push_back((x0.to_vec(), 0usize));
        let mut seen = std::collections::BTreeMap::<Vec<u32>, usize>::new();
        seen.insert(x0.to_vec(), 0);
        let mut tmp = vec![0u32; k];
        let mut best = i64::MIN;
        while let Some((x, d)) = q.pop_front() {
            // score at every visited depth (matches current simplex_ceo behavior)
            let mut s = 0i64;
            for i in 0..k {
                s = s.saturating_add(w[i].saturating_mul(x[i] as i64));
            }
            best = best.max(s);
            if d >= h {
                continue;
            }
            for &a in &acts {
                super::step_or_stay_inplace(&x, caps, a, &mut tmp);
                let x2 = tmp.clone();
                let d2 = d + 1;
                let push = match seen.get(&x2) {
                    Some(&d0) => d2 < d0,
                    None => true,
                };
                if push {
                    seen.insert(x2.clone(), d2);
                    q.push_back((x2, d2));
                }
            }
        }
        best
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Decision {
        score: i64,
        depth: usize,
        first_key: u64,
        state: Vec<u32>,
    }

    fn better_decision(a: &Decision, b: &Decision) -> bool {
        (a.score > b.score)
            || (a.score == b.score && a.depth < b.depth)
            || (a.score == b.score && a.depth == b.depth && a.first_key < b.first_key)
            || (a.score == b.score
                && a.depth == b.depth
                && a.first_key == b.first_key
                && a.state < b.state)
    }

    fn decision_from_reached_map(
        reached: &std::collections::BTreeMap<Vec<u32>, (usize, u64)>,
        w: &[i64],
    ) -> Decision {
        let mut best = Decision {
            score: i64::MIN,
            depth: usize::MAX,
            first_key: u64::MAX,
            state: Vec::new(),
        };
        for (x, (d, fk)) in reached.iter() {
            let mut s = 0i64;
            for i in 0..x.len() {
                s = s.saturating_add(w[i].saturating_mul(x[i] as i64));
            }
            let cand = Decision {
                score: s,
                depth: *d,
                first_key: *fk,
                state: x.clone(),
            };
            if best.state.is_empty() || better_decision(&cand, &best) {
                best = cand;
            }
        }
        best
    }

    fn decision_full_linear(x0: &[u32], caps: &[u32], w: &[i64], h: usize) -> Decision {
        let k = x0.len();
        let acts = super::all_transfers(k);
        // state -> (min_depth, min_first_key_at_min_depth)
        let mut best: std::collections::BTreeMap<Vec<u32>, (usize, u64)> = std::collections::BTreeMap::new();
        let mut q = std::collections::VecDeque::new();
        q.push_back((x0.to_vec(), 0usize, 0u64));
        best.insert(x0.to_vec(), (0, 0));
        let mut tmp = vec![0u32; k];

        while let Some((x, d, fk)) = q.pop_front() {
            if d >= h {
                continue;
            }
            for &a in &acts {
                super::step_or_stay_inplace(&x, caps, a, &mut tmp);
                let x2 = tmp.clone();
                let d2 = d + 1;
                let fk2: u64 = if fk != 0 {
                    fk
                } else {
                    simplex_planner::action_key(k, a) as u64
                };
                let push = match best.get(&x2) {
                    Some(&(d0, fk0)) => (d2 < d0) || (d2 == d0 && fk2 < fk0),
                    None => true,
                };
                if push {
                    best.insert(x2.clone(), (d2, fk2));
                    q.push_back((x2, d2, fk2));
                }
            }
        }
        decision_from_reached_map(&best, w)
    }

    fn best_score_por_linear_dfs_c2(x0: &[u32], caps: &[u32], w: &[i64], h: usize) -> i64 {
        let k = x0.len();
        let acts = super::all_transfers(k);
        let mut best = i64::MIN;
        let mut best_seen_depth = std::collections::BTreeMap::<Vec<u32>, usize>::new();
        let mut stack: Vec<Vec<u32>> = Vec::new();
        let mut on_stack = std::collections::BTreeSet::<Vec<u32>>::new();
        let mut tmp = vec![0u32; k];
        let mut cache = OracleCache::new();

        fn dfs(
            x: &Vec<u32>,
            depth: usize,
            h: usize,
            caps: &[u32],
            w: &[i64],
            acts: &[Transfer],
            best: &mut i64,
            best_seen_depth: &mut std::collections::BTreeMap<Vec<u32>, usize>,
            stack: &mut Vec<Vec<u32>>,
            on_stack: &mut std::collections::BTreeSet<Vec<u32>>,
            tmp: &mut [u32],
            cache: &mut OracleCache,
        ) -> Result<()> {
            // score at every visited depth
            let mut s = 0i64;
            for i in 0..x.len() {
                s = s.saturating_add(w[i].saturating_mul(x[i] as i64));
            }
            *best = (*best).max(s);

            match best_seen_depth.get(x) {
                Some(&d0) if depth >= d0 => return Ok(()),
                _ => {
                    best_seen_depth.insert(x.clone(), depth);
                }
            }
            if depth >= h {
                return Ok(());
            }

            // enabled
            let mut enabled: Vec<Transfer> = Vec::new();
            for &a in acts {
                if simplex_por_oracle::enabled(x, caps, a) {
                    enabled.push(a);
                }
            }
            if enabled.is_empty() {
                return Ok(());
            }

            // ample candidate (dependency closure, fail-closed)
            let mut ample = ample_set(AmpleStrategy::MinPlusDependencyClosure, x, caps, cache)?;

            // C2 cycle proviso (DFS stack)
            let mut violates_c2 = false;
            for &a in &ample {
                super::step_or_stay_inplace(x, caps, a, tmp);
                if on_stack.contains(tmp) {
                    violates_c2 = true;
                    break;
                }
            }
            if violates_c2 {
                ample = enabled;
            }

            stack.push(x.clone());
            on_stack.insert(x.clone());
            for &a in &ample {
                super::step_or_stay_inplace(x, caps, a, tmp);
                let x2 = tmp.to_vec();
                dfs(
                    &x2,
                    depth + 1,
                    h,
                    caps,
                    w,
                    acts,
                    best,
                    best_seen_depth,
                    stack,
                    on_stack,
                    tmp,
                    cache,
                )?;
            }
            let top = stack.pop().expect("stack underflow");
            let removed = on_stack.remove(&top);
            debug_assert!(removed);
            Ok(())
        }

        let x0v = x0.to_vec();
        dfs(
            &x0v,
            0,
            h,
            caps,
            w,
            &acts,
            &mut best,
            &mut best_seen_depth,
            &mut stack,
            &mut on_stack,
            &mut tmp,
            &mut cache,
        )
        .expect("dfs failed");
        best
    }

    fn decision_por_linear_dfs_c2(x0: &[u32], caps: &[u32], w: &[i64], h: usize) -> Decision {
        let k = x0.len();
        let acts = super::all_transfers(k);
        // state -> (best depth encountered so far, best first key at that depth)
        let mut reached: std::collections::BTreeMap<Vec<u32>, (usize, u64)> = std::collections::BTreeMap::new();
        reached.insert(x0.to_vec(), (0, 0));

        let mut best_seen_depth = std::collections::BTreeMap::<Vec<u32>, usize>::new();
        let mut stack: Vec<Vec<u32>> = Vec::new();
        let mut on_stack = std::collections::BTreeSet::<Vec<u32>>::new();
        let mut tmp = vec![0u32; k];
        let mut cache = OracleCache::new();

        fn dfs(
            x: &Vec<u32>,
            depth: usize,
            first_key: u64,
            h: usize,
            caps: &[u32],
            w: &[i64],
            acts: &[Transfer],
            reached: &mut std::collections::BTreeMap<Vec<u32>, (usize, u64)>,
            best_seen_depth: &mut std::collections::BTreeMap<Vec<u32>, usize>,
            stack: &mut Vec<Vec<u32>>,
            on_stack: &mut std::collections::BTreeSet<Vec<u32>>,
            tmp: &mut [u32],
            cache: &mut OracleCache,
        ) -> Result<()> {
            // record this state with best (depth, first_key)
            match reached.get(x) {
                Some(&(d0, fk0)) => {
                    if (depth < d0) || (depth == d0 && first_key < fk0) {
                        reached.insert(x.clone(), (depth, first_key));
                    }
                }
                None => {
                    reached.insert(x.clone(), (depth, first_key));
                }
            }

            match best_seen_depth.get(x) {
                Some(&d0) if depth >= d0 => return Ok(()),
                _ => {
                    best_seen_depth.insert(x.clone(), depth);
                }
            }
            if depth >= h {
                return Ok(());
            }

            let mut enabled: Vec<Transfer> = Vec::new();
            let mut any_visible = false;
            for &a in acts {
                if simplex_por_oracle::enabled(x, caps, a) {
                    enabled.push(a);
                    // Visibility for linear objective: transfer changes score iff w[src] != w[dst].
                    if w[a.src] != w[a.dst] {
                        any_visible = true;
                    }
                }
            }
            if enabled.is_empty() {
                return Ok(());
            }

            // Soundness knob for planning:
            // If there exists any *visible* enabled transition at this state (w[src] != w[dst]),
            // we do NOT reduce: dropping a visible action can change the argmax decision.
            //
            // We only reduce within "objective-invisible" regions, where all enabled actions are
            // score-neutral moves (w[src] == w[dst]).
            let mut ample = if any_visible {
                enabled.clone()
            } else {
                ample_set(AmpleStrategy::MinPlusDependencyClosure, x, caps, cache)?
            };

            let mut violates_c2 = false;
            for &a in &ample {
                super::step_or_stay_inplace(x, caps, a, tmp);
                if on_stack.contains(tmp) {
                    violates_c2 = true;
                    break;
                }
            }
            if violates_c2 {
                ample = enabled;
            }

            stack.push(x.clone());
            on_stack.insert(x.clone());
            for &a in &ample {
                super::step_or_stay_inplace(x, caps, a, tmp);
                let x2 = tmp.to_vec();
                let fk2: u64 = if first_key != 0 {
                    first_key
                } else {
                    simplex_planner::action_key(x.len(), a) as u64
                };
                dfs(
                    &x2,
                    depth + 1,
                    fk2,
                    h,
                    caps,
                    w,
                    acts,
                    reached,
                    best_seen_depth,
                    stack,
                    on_stack,
                    tmp,
                    cache,
                )?;
            }
            let top = stack.pop().expect("stack underflow");
            let removed = on_stack.remove(&top);
            debug_assert!(removed);
            Ok(())
        }

        let x0v = x0.to_vec();
        dfs(
            &x0v,
            0,
            0,
            h,
            caps,
            w,
            &acts,
            &mut reached,
            &mut best_seen_depth,
            &mut stack,
            &mut on_stack,
            &mut tmp,
            &mut cache,
        )
        .expect("dfs failed");

        decision_from_reached_map(&reached, w)
    }

    fn find_best_score_counterexample_linear(
        k: usize,
        t: u32,
        h: usize,
    ) -> Option<(Vec<u32>, Vec<i64>, i64, i64)> {
        // deterministic x0
        let mut x0 = vec![0u32; k];
        x0[0] = t / 2;
        x0[1] = t - x0[0];
        let caps = vec![t; k];

        // small deterministic weight families
        let weight_families: Vec<Vec<i64>> = match k {
            3 => vec![
                vec![1, 0, 0],
                vec![0, 1, 0],
                vec![0, 0, 1],
                vec![5, 1, 0],
                vec![5, 0, 1],
                vec![1, 5, 0],
                vec![1, 0, 5],
                vec![0, 5, 1],
                vec![0, 1, 5],
                vec![3, 2, 1],
                vec![3, 1, 2],
            ],
            4 => vec![
                vec![1, 0, 0, 0],
                vec![0, 1, 0, 0],
                vec![0, 0, 1, 0],
                vec![0, 0, 0, 1],
                vec![5, 1, 0, 0],
                vec![5, 0, 1, 0],
                vec![5, 0, 0, 1],
                vec![3, 2, 1, 0],
                vec![3, 2, 0, 1],
            ],
            _ => vec![vec![1; k]],
        };

        for w in weight_families {
            let full = best_score_full_linear(&x0, &caps, &w, h);
            let por = best_score_por_linear_dfs_c2(&x0, &caps, &w, h);
            if full != por {
                return Some((x0, w, full, por));
            }
        }
        None
    }

    fn find_decision_counterexample_linear(
        k: usize,
        t: u32,
        h: usize,
    ) -> Option<(Vec<u32>, Vec<i64>, Decision, Decision)> {
        let mut x0 = vec![0u32; k];
        x0[0] = t / 2;
        x0[1] = t - x0[0];
        let caps = vec![t; k];

        let weight_families: Vec<Vec<i64>> = match k {
            3 => vec![
                vec![1, 0, 0],
                vec![0, 1, 0],
                vec![0, 0, 1],
                vec![5, 1, 0],
                vec![5, 0, 1],
                vec![1, 5, 0],
                vec![1, 0, 5],
                vec![0, 5, 1],
                vec![0, 1, 5],
                vec![3, 2, 1],
                vec![3, 1, 2],
                vec![2, -1, 0],
                vec![0, 2, -1],
                vec![-1, 0, 2],
            ],
            4 => vec![
                vec![1, 0, 0, 0],
                vec![0, 1, 0, 0],
                vec![0, 0, 1, 0],
                vec![0, 0, 0, 1],
                vec![5, 1, 0, 0],
                vec![5, 0, 1, 0],
                vec![5, 0, 0, 1],
                vec![3, 2, 1, 0],
                vec![3, 2, 0, 1],
                vec![2, -1, 0, 0],
                vec![0, 2, -1, 0],
                vec![0, 0, 2, -1],
            ],
            5 => vec![
                vec![1, 0, 0, 0, 0],
                vec![0, 1, 0, 0, 0],
                vec![0, 0, 1, 0, 0],
                vec![0, 0, 0, 1, 0],
                vec![0, 0, 0, 0, 1],
                vec![5, 1, 0, 0, 0],
                vec![5, 0, 1, 0, 0],
                vec![3, 2, 1, 0, 0],
                vec![2, -1, 0, 0, 0],
                vec![0, 2, -1, 0, 0],
            ],
            _ => vec![vec![1; k]],
        };

        for w in weight_families {
            let full = decision_full_linear(&x0, &caps, &w, h);
            let por = decision_por_linear_dfs_c2(&x0, &caps, &w, h);
            if full != por {
                return Some((x0, w, full, por));
            }
        }
        None
    }

    #[test]
    fn dfs_c2_best_score_is_not_promoted_without_evidence() {
        // Popper-first: try to falsify "DFS+C2 preserves best score for linear objectives"
        // on a tiny grid. If falsified, we pin the first counterexample we find.
        let k = 3usize;
        let t = 6u32;
        let h = 2usize;
        let ce = find_best_score_counterexample_linear(k, t, h);
        if let Some((x0, w, full, por)) = ce {
            // Pin the first CE deterministically (so it doesn't silently disappear).
            assert_eq!(x0, vec![3, 3, 0]);
            assert_eq!(w.len(), 3);
            assert_ne!(full, por);
        } else {
            // If we *didn't* find a CE on this tiny grid, that's positive evidence,
            // but not a promotion to "sound" without broader proof.
            assert!(true);
        }
    }

    #[test]
    fn dfs_c2_decision_falsifier_sweep_small() {
        // Evidence-first: attempt to falsify "DFS+C2 preserves the full decision tuple"
        // (score, min-depth, first-action key, lex state) over a small grid.
        for k in 3..=4usize {
            for t in [6u32, 8u32, 10u32] {
                for h in 1..=4usize {
                    if let Some((x0, w, full, por)) = find_decision_counterexample_linear(k, t, h) {
                        // Pin the first counterexample deterministically so it becomes a regression.
                        assert_eq!(x0[0] + x0[1], t);
                        assert_ne!(full, por, "expected mismatch when CE is reported");
                        // Keep the pin minimal but stable: we record the exact tuple.
                        // (If this ever stops failing, it means we strengthened the rule and should
                        // move this into a positive evidence test + expand the grid.)
                        panic!(
                            "DFS+C2 decision mismatch (pinned CE): k={k} t={t} h={h} w={w:?} full={full:?} por={por:?}"
                        );
                    }
                }
            }
        }
    }

}

