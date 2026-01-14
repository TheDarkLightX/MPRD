//! Experimental (research-backed) simplex-mode CEO planner.
//!
//! This module is a **Mode B** building block from `docs/CEO_MENU_MODES.md`:
//! when/if MPRD adopts a k-way simplex split menu, explicit graph precomputation becomes infeasible.
//! We instead do bounded-horizon deterministic planning over unit-transfer actions.
//!
//! Key properties:
//! - deterministic (no RNG; stable tie-breakers)
//! - fail-closed (malformed inputs → error; disabled actions → no-op)
//! - can use:
//!   - POR trace canonicalization (via certified oracle + canonicalizer), and/or
//!   - symmetry quotienting for interchangeable buckets (via symmetry key)

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::{MprdError, Result};

use super::simplex_planner::{self, OracleCache};
use super::simplex_por_oracle::{self, Transfer};
use super::simplex_symmetry_key;

/// Planning mode / dedup strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimplexCeoMode {
    /// Deduplicate by POR-canonicalized traces (Mazurkiewicz-style quotient).
    TracePor,
    /// Deduplicate by symmetry-class state key (quotienting interchangeable buckets).
    StateSymmetry,
}

/// Configuration for simplex-mode planning.
///
/// This is intentionally explicit and fail-closed: callers must provide all parameters and
/// validate shapes at the boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimplexCeoConfig {
    pub mode: SimplexCeoMode,
    pub horizon: usize,
    pub budget_expanded: usize,
    /// If set, we reject inputs where `sum(x0) != T` (useful for constant-sum simplex menus).
    pub require_sum: Option<u32>,
}

impl SimplexCeoConfig {
    pub fn validate_shapes(&self, x0: &[u32], caps: &[u32], weights_for_symmetry: &[u32]) -> Result<()> {
        let k = x0.len();
        if k == 0 || caps.len() != k || weights_for_symmetry.len() != k {
            return Err(MprdError::InvalidInput(
                "SimplexCeoConfig: x0/caps/weights must be same non-zero length".into(),
            ));
        }
        if self.horizon == 0 {
            return Err(MprdError::InvalidInput(
                "SimplexCeoConfig: horizon must be > 0".into(),
            ));
        }
        if let Some(t) = self.require_sum {
            let s = sum_u32(x0);
            if s != t as u64 {
                return Err(MprdError::InvalidInput(format!(
                    "SimplexCeoConfig: sum(x0)={s} != required T={t}"
                )));
            }
        }
        Ok(())
    }

    pub fn plan_best(
        &self,
        x0: &[u32],
        caps: &[u32],
        weights_for_symmetry: &[u32],
        objective: impl Fn(&[u32]) -> i64,
    ) -> Result<SimplexCeoDecision> {
        plan_best(
            self.mode,
            x0,
            caps,
            weights_for_symmetry,
            self.horizon,
            self.budget_expanded,
            self.require_sum,
            objective,
        )
    }

    pub fn plan_best_linear(
        &self,
        x0: &[u32],
        caps: &[u32],
        weights_for_symmetry: &[u32],
        w: &[i64],
    ) -> Result<SimplexCeoDecision> {
        plan_best_linear(
            self.mode,
            x0,
            caps,
            weights_for_symmetry,
            w,
            self.horizon,
            self.budget_expanded,
            self.require_sum,
        )
    }
}

/// Result of a simplex planning call: choose a target (within horizon) and the first step to take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimplexCeoDecision {
    /// Best target state found (within horizon and budget).
    pub target: Vec<u32>,
    /// Objective score of the target.
    pub score: i64,
    /// Depth at which the target was first reached.
    pub depth: usize,
    /// First transfer to take from the start state to move toward the target.
    pub first_action: Option<Transfer>,
    /// Next state after applying `first_action` (or equal to start state if `first_action=None`).
    pub next: Vec<u32>,
}

fn step_or_stay_inplace(x: &[u32], caps: &[u32], a: Transfer, out: &mut [u32]) {
    out.copy_from_slice(x);
    if !simplex_por_oracle::enabled(x, caps, a) {
        return;
    }
    out[a.src] = out[a.src].saturating_sub(1);
    out[a.dst] = out[a.dst].saturating_add(1);
}

fn sum_u32(xs: &[u32]) -> u64 {
    xs.iter().map(|&v| v as u64).sum()
}

fn lex_trace_key(k: usize, tr: &[Transfer]) -> Vec<u32> {
    tr.iter().map(|&a| simplex_planner::action_key(k, a)).collect()
}

/// Deterministic bounded-horizon planner for simplex transfer menus.
///
/// - `objective` must be deterministic.
/// - If `require_sum` is `Some(T)`, we reject inputs where `sum(x0)!=T` (fail-closed).
/// - `weights_for_symmetry` partitions interchangeable buckets for symmetry quotienting:
///   the partition key is `(caps[i], weights_for_symmetry[i])`.
pub fn plan_best(
    mode: SimplexCeoMode,
    x0: &[u32],
    caps: &[u32],
    weights_for_symmetry: &[u32],
    horizon: usize,
    budget_expanded: usize,
    require_sum: Option<u32>,
    objective: impl Fn(&[u32]) -> i64,
) -> Result<SimplexCeoDecision> {
    let k = x0.len();
    if k == 0 || caps.len() != k || weights_for_symmetry.len() != k {
        return Err(MprdError::InvalidInput(
            "simplex_ceo::plan_best: x0/caps/weights must be same non-zero length".into(),
        ));
    }
    if horizon == 0 {
        return Err(MprdError::InvalidInput(
            "simplex_ceo::plan_best: horizon must be > 0".into(),
        ));
    }
    if let Some(t) = require_sum {
        let s = sum_u32(x0);
        if s != t as u64 {
            return Err(MprdError::InvalidInput(format!(
                "simplex_ceo::plan_best: sum(x0)={s} != required T={t}"
            )));
        }
    }

    // Deterministic action set, ordered by key.
    let mut acts: Vec<Transfer> = Vec::with_capacity(k.saturating_mul(k.saturating_sub(1)));
    for src in 0..k {
        for dst in 0..k {
            if src != dst {
                acts.push(Transfer::new(src, dst));
            }
        }
    }
    acts.sort_by_key(|&a| simplex_planner::action_key(k, a));

    // Best-so-far with deterministic tie-breakers.
    // (score desc, depth asc, first_action_key asc, target lex asc)
    let mut best: Option<(i64, usize, u32, Vec<u32>, Option<Transfer>, Vec<u32>)> = None;
    let base_score = objective(x0);
    best = Some((base_score, 0, 0, x0.to_vec(), None, x0.to_vec()));

    match mode {
        SimplexCeoMode::TracePor => {
            let mut q: VecDeque<(Vec<Transfer>, Vec<u32>)> = VecDeque::new();
            q.push_back((Vec::new(), x0.to_vec()));
            let mut seen: BTreeSet<u128> = BTreeSet::new();
            seen.insert(simplex_planner::trace_key_hash(&[], k));

            let mut expanded = 0usize;
            let mut tmp = vec![0u32; k];
            let mut cache = OracleCache::new();

            while let Some((tr, x)) = q.pop_front() {
                if expanded >= budget_expanded {
                    break;
                }
                if tr.len() >= horizon {
                    continue;
                }
                expanded += 1;

                let x_prefix = simplex_planner::prefix_states(caps, x0, &tr)?;

                for &a in &acts {
                    step_or_stay_inplace(&x, caps, a, &mut tmp);
                    let x2 = tmp.clone();

                    let tr2 = simplex_planner::canonicalize_append_insert_cached(
                        caps,
                        &x_prefix,
                        &tr,
                        a,
                        &mut cache,
                    )?;
                    let key = simplex_planner::trace_key_hash(&tr2, k);
                    if !seen.insert(key) {
                        continue;
                    }
                    let depth = tr2.len();
                    let score = objective(&x2);
                    let first = tr2.first().copied();
                    let first_key = first.map(|f| simplex_planner::action_key(k, f)).unwrap_or(0);
                    let candidate = (score, depth, first_key, x2.clone(), first, x2.clone());

                    match &best {
                        None => best = Some(candidate),
                        Some((b_score, b_depth, b_fk, b_target, _, _)) => {
                            if (score > *b_score)
                                || (score == *b_score && depth < *b_depth)
                                || (score == *b_score && depth == *b_depth && first_key < *b_fk)
                                || (score == *b_score
                                    && depth == *b_depth
                                    && first_key == *b_fk
                                    && x2 < *b_target)
                            {
                                best = Some(candidate);
                            }
                        }
                    }
                    q.push_back((tr2, x2));
                }
            }
        }
        SimplexCeoMode::StateSymmetry => {
            let mut q: VecDeque<(Vec<u32>, usize, Option<Transfer>)> = VecDeque::new();
            q.push_back((x0.to_vec(), 0, None));

            // key -> min depth (fail-closed: if key can't be computed, use raw state as key)
            let mut seen: BTreeMap<Vec<Vec<u32>>, usize> = BTreeMap::new();
            let k0 =
                simplex_symmetry_key::symmetry_key(x0, caps, weights_for_symmetry).unwrap_or_else(
                    || vec![x0.to_vec()],
                );
            seen.insert(k0, 0);

            let mut expanded = 0usize;
            let mut tmp = vec![0u32; k];

            while let Some((x, depth, first)) = q.pop_front() {
                if expanded >= budget_expanded {
                    break;
                }
                expanded += 1;
                if depth >= horizon {
                    continue;
                }

                for &a in &acts {
                    step_or_stay_inplace(&x, caps, a, &mut tmp);
                    let x2 = tmp.clone();
                    let nd = depth + 1;
                    let first2 = first.or(Some(a));
                    let key = simplex_symmetry_key::symmetry_key(&x2, caps, weights_for_symmetry)
                        .unwrap_or_else(|| vec![x2.clone()]);

                    let insert = match seen.get(&key) {
                        None => true,
                        Some(&best_d) => nd < best_d,
                    };
                    if insert {
                        seen.insert(key, nd);
                        let score = objective(&x2);
                        let fk = first2
                            .map(|f| simplex_planner::action_key(k, f))
                            .unwrap_or(0);
                        let candidate = (score, nd, fk, x2.clone(), first2, x2.clone());
                        match &best {
                            None => best = Some(candidate),
                            Some((b_score, b_depth, b_fk, b_target, _, _)) => {
                                if (score > *b_score)
                                    || (score == *b_score && nd < *b_depth)
                                    || (score == *b_score && nd == *b_depth && fk < *b_fk)
                                    || (score == *b_score
                                        && nd == *b_depth
                                        && fk == *b_fk
                                        && x2 < *b_target)
                                {
                                    best = Some(candidate);
                                }
                            }
                        }
                        q.push_back((x2, nd, first2));
                    }
                }
            }
        }
    }

    let Some((score, depth, _fk, target, first_action, _)) = best else {
        return Err(MprdError::ExecutionError(
            "simplex_ceo::plan_best: no candidate produced (unexpected)".into(),
        ));
    };

    let next = if let Some(a) = first_action {
        simplex_por_oracle::step_or_stay(x0, caps, a)
    } else {
        x0.to_vec()
    };

    Ok(SimplexCeoDecision {
        target,
        score,
        depth,
        first_action,
        next,
    })
}

/// Convenience: linear objective `sum_i w[i] * x[i]`.
pub fn plan_best_linear(
    mode: SimplexCeoMode,
    x0: &[u32],
    caps: &[u32],
    weights_for_symmetry: &[u32],
    w: &[i64],
    horizon: usize,
    budget_expanded: usize,
    require_sum: Option<u32>,
) -> Result<SimplexCeoDecision> {
    if w.len() != x0.len() {
        return Err(MprdError::InvalidInput(
            "simplex_ceo::plan_best_linear: weights length mismatch".into(),
        ));
    }
    plan_best(
        mode,
        x0,
        caps,
        weights_for_symmetry,
        horizon,
        budget_expanded,
        require_sum,
        |x| {
            let mut acc: i64 = 0;
            for i in 0..x.len() {
                acc = acc.saturating_add(w[i].saturating_mul(x[i] as i64));
            }
            acc
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brute_best_linear(
        x0: &[u32],
        caps: &[u32],
        w: &[i64],
        h: usize,
    ) -> (i64, Vec<u32>, Option<Transfer>) {
        let k = x0.len();
        let mut acts = Vec::new();
        for src in 0..k {
            for dst in 0..k {
                if src != dst {
                    acts.push(Transfer::new(src, dst));
                }
            }
        }
        acts.sort_by_key(|&a| simplex_planner::action_key(k, a));

        let mut best_score = {
            let mut s = 0i64;
            for i in 0..k {
                s += w[i] * x0[i] as i64;
            }
            s
        };
        let mut best_state = x0.to_vec();
        let mut best_first: Option<Transfer> = None;
        let mut best_depth = 0usize;

        let mut q: VecDeque<(Vec<u32>, usize, Option<Transfer>)> = VecDeque::new();
        q.push_back((x0.to_vec(), 0, None));
        let mut tmp = vec![0u32; k];

        while let Some((x, d, first)) = q.pop_front() {
            if d >= h {
                continue;
            }
            for &a in &acts {
                step_or_stay_inplace(&x, caps, a, &mut tmp);
                let x2 = tmp.clone();
                let d2 = d + 1;
                let first2 = first.or(Some(a));
                let mut score = 0i64;
                for i in 0..k {
                    score += w[i] * x2[i] as i64;
                }
                let fk = first2.map(|f| simplex_planner::action_key(k, f)).unwrap_or(0);
                let b_fk = best_first
                    .map(|f| simplex_planner::action_key(k, f))
                    .unwrap_or(0);
                if (score > best_score)
                    || (score == best_score && d2 < best_depth)
                    || (score == best_score && d2 == best_depth && fk < b_fk)
                    || (score == best_score && d2 == best_depth && fk == b_fk && x2 < best_state)
                {
                    best_score = score;
                    best_state = x2.clone();
                    best_first = first2;
                    best_depth = d2;
                }
                q.push_back((x2, d2, first2));
            }
        }

        (best_score, best_state, best_first)
    }

    #[test]
    fn plan_best_linear_matches_bruteforce_small() {
        let x0 = vec![3, 1, 2];
        let caps = vec![6, 6, 6];
        let w = vec![10, 1, 2];
        let w_sym = vec![7u32, 7u32, 1u32];
        let h = 3;

        let (b_score, b_state, b_first) = brute_best_linear(&x0, &caps, &w, h);

        let por = plan_best_linear(
            SimplexCeoMode::TracePor,
            &x0,
            &caps,
            &w_sym,
            &w,
            h,
            20000,
            Some(6),
        )
        .unwrap();
        assert_eq!(por.score, b_score);
        assert_eq!(por.target, b_state);
        assert_eq!(por.first_action, b_first);

        let sym = plan_best_linear(
            SimplexCeoMode::StateSymmetry,
            &x0,
            &caps,
            &w_sym,
            &w,
            h,
            20000,
            Some(6),
        )
        .unwrap();
        assert_eq!(sym.score, b_score);
        assert_eq!(sym.target, b_state);
        assert_eq!(sym.first_action, b_first);
    }

    #[test]
    fn config_wrapper_matches_functions() {
        let x0 = vec![3, 1, 2];
        let caps = vec![6, 6, 6];
        let w_sym = vec![7u32, 7u32, 1u32];
        let w = vec![10, 1, 2];
        let cfg = SimplexCeoConfig {
            mode: SimplexCeoMode::TracePor,
            horizon: 3,
            budget_expanded: 20000,
            require_sum: Some(6),
        };
        cfg.validate_shapes(&x0, &caps, &w_sym).unwrap();
        let a = cfg.plan_best_linear(&x0, &caps, &w_sym, &w).unwrap();
        let b = plan_best_linear(
            SimplexCeoMode::TracePor,
            &x0,
            &caps,
            &w_sym,
            &w,
            3,
            20000,
            Some(6),
        )
        .unwrap();
        assert_eq!(a, b);
    }
}

