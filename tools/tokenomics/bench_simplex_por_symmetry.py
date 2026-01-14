#!/usr/bin/env python3
"""
Deterministic micro-benchmark: simplex guarded transfers + POR canonical-trace dedup + symmetry-key state dedup.

This benchmark is intentionally dependency-free (stdlib only) and deterministic.

What it measures (for a bounded horizon h):
- number of trace expansions
- number of unique traces (raw vs canonicalized)
- number of unique reached states (raw vs symmetry-quotiented key)

The POR canonicalizer here mirrors the Lean artifact's spirit:
- state-dependent justified adjacent swaps guarded by stable-enabledness inequality oracle.

Usage:
  python3 tools/tokenomics/bench_simplex_por_symmetry.py
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from time import perf_counter
from typing import Iterable, List, Optional, Sequence, Tuple


State = Tuple[int, ...]
Action = Tuple[int, int]  # (src,dst)


def enabled(x: State, caps: State, a: Action) -> bool:
    src, dst = a
    if src == dst:
        return False
    if src < 0 or dst < 0 or src >= len(x) or dst >= len(x) or len(x) != len(caps):
        return False
    return x[src] > 0 and x[dst] < caps[dst]


def step_or_stay(x: State, caps: State, a: Action) -> State:
    if not enabled(x, caps, a):
        return x
    src, dst = a
    y = list(x)
    y[src] -= 1
    y[dst] += 1
    return tuple(y)


def stable_enabled_ineq(x: State, caps: State, a: Action, b: Action) -> bool:
    # Matches the Lean/Rust closed-form sufficient condition.
    if not enabled(x, caps, a) or not enabled(x, caps, b):
        return False
    a_src, a_dst = a
    b_src, b_dst = b
    if a_src == b_src and x[a_src] < 2:
        return False
    if a_dst == b_dst and x[a_dst] + 2 > caps[a_dst]:
        return False
    return True


def action_key(k: int, a: Action) -> int:
    src, dst = a
    return src * k + dst


def canon_pass(caps: State, x0: State, trace: Tuple[Action, ...]) -> Tuple[Action, ...]:
    """One deterministic bubble-like pass with state-dependent justified swaps."""
    xs = list(trace)
    state = x0
    i = 0
    k = len(x0)
    while i + 1 < len(xs):
        a, b = xs[i], xs[i + 1]
        # swap if out-of-order AND oracle says independent at current post-prefix state
        if action_key(k, b) < action_key(k, a) and stable_enabled_ineq(state, caps, a, b):
            xs[i], xs[i + 1] = b, a
            # execute b first (mirrors Lean)
            state = step_or_stay(state, caps, b)
            # after swap, keep scanning; we do not decrement i (deterministic forward pass)
        else:
            state = step_or_stay(state, caps, a)
            i += 1
    return tuple(xs)


def canonicalize_trace(caps: State, x0: State, trace: Tuple[Action, ...]) -> Tuple[Action, ...]:
    # bounded fixpoint iterate length^2 (Lean's canonicalize) is fine for benchmarking
    cur = trace
    steps = len(cur) * len(cur)
    for _ in range(steps):
        nxt = canon_pass(caps, x0, cur)
        if nxt == cur:
            return cur
        cur = nxt
    return cur


def symmetry_key(x: State, caps: State, weights: State) -> Tuple[Tuple[int, ...], ...]:
    """Deterministic symmetry quotient key: group indices by (cap,weight), sort values within each class."""
    groups: dict[Tuple[int, int], List[int]] = {}
    for i in range(len(x)):
        groups.setdefault((caps[i], weights[i]), []).append(x[i])
    out: List[Tuple[int, ...]] = []
    for key in sorted(groups.keys()):
        vals = sorted(groups[key])
        out.append(tuple(vals))
    return tuple(out)


def all_actions(k: int) -> List[Action]:
    # Deterministic ordering
    acts: List[Action] = []
    for src in range(k):
        for dst in range(k):
            if src != dst:
                acts.append((src, dst))
    return acts


@dataclass(frozen=True)
class BenchConfig:
    k: int
    T: int
    caps: State
    x0: State
    h: int
    weights: State
    use_por_trace_dedup: bool
    use_symmetry_state_dedup: bool


def bfs_bounded(cfg: BenchConfig) -> dict:
    acts = all_actions(cfg.k)

    # Frontier is (trace_key, state, depth). We *prune* based on canonical keys.
    q: deque[tuple[Tuple[Action, ...], State, int]] = deque()

    def trace_key(tr: Tuple[Action, ...]) -> Tuple[Action, ...]:
        return canonicalize_trace(cfg.caps, cfg.x0, tr) if cfg.use_por_trace_dedup else tr

    def run_trace(tr: Tuple[Action, ...]) -> State:
        x = cfg.x0
        for a in tr:
            x = step_or_stay(x, cfg.caps, a)
        return x

    def state_key(x: State) -> object:
        return symmetry_key(x, cfg.caps, cfg.weights) if cfg.use_symmetry_state_dedup else x

    # Dedup structures
    seen_traces: set[Tuple[Action, ...]] = set()
    # state_key -> minimum depth at which we've seen it (classic BFS visited)
    seen_states_depth: dict[object, int] = {}

    # seed
    t0 = trace_key(tuple())
    x0 = run_trace(t0)  # = cfg.x0
    q.append((t0, x0, 0))
    seen_traces.add(t0)
    seen_states_depth[state_key(x0)] = 0

    expanded = 0
    generated = 0

    while q:
        tr, x, d = q.popleft()
        if d >= cfg.h:
            continue
        expanded += 1

        for a in acts:
            generated += 1
            tr2 = tr + (a,)
            tk = trace_key(tr2)

            # Trace dedup (POR canonicalization quotient)
            if tk not in seen_traces:
                seen_traces.add(tk)

            # Compute the post-state for the *canonical* trace representative (sound by Lean theorem).
            x2 = run_trace(tk)
            sk = state_key(x2)

            # State dedup (symmetry quotient): only expand if first time or reached at smaller depth.
            prev = seen_states_depth.get(sk)
            if prev is not None and prev <= d + 1:
                continue
            seen_states_depth[sk] = d + 1
            q.append((tk, x2, d + 1))

    return {
        "expanded": expanded,
        "generated": generated,
        "unique_traces": len(seen_traces),
        "unique_states": len(seen_states_depth),
    }


def run_one(name: str, cfg: BenchConfig) -> None:
    t0 = perf_counter()
    r = bfs_bounded(cfg)
    dt = (perf_counter() - t0) * 1000.0
    print(f"\n== {name} ==")
    print(f"k={cfg.k} T={cfg.T} h={cfg.h}")
    print(f"POR_trace_dedup={cfg.use_por_trace_dedup} symmetry_state_dedup={cfg.use_symmetry_state_dedup}")
    print(f"expanded={r['expanded']} generated={r['generated']}")
    print(f"unique_traces={r['unique_traces']} unique_states={r['unique_states']}")
    print(f"time_ms={dt:.2f}")


def main() -> None:
    # Scenario A: two interchangeable buckets (0,1) with same caps+weights; others distinct.
    k = 4
    T = 10
    x0 = (5, 5, 0, 0)
    caps = (10, 10, 10, 10)
    weights = (7, 7, 1, 2)  # buckets 0 and 1 symmetric only
    h = 6

    base = BenchConfig(k=k, T=T, caps=caps, x0=x0, h=h, weights=weights, use_por_trace_dedup=False, use_symmetry_state_dedup=False)
    por = BenchConfig(k=k, T=T, caps=caps, x0=x0, h=h, weights=weights, use_por_trace_dedup=True, use_symmetry_state_dedup=False)
    sym = BenchConfig(k=k, T=T, caps=caps, x0=x0, h=h, weights=weights, use_por_trace_dedup=False, use_symmetry_state_dedup=True)
    both = BenchConfig(k=k, T=T, caps=caps, x0=x0, h=h, weights=weights, use_por_trace_dedup=True, use_symmetry_state_dedup=True)

    run_one("baseline", base)
    run_one("POR(trace canonicalize+dedup)", por)
    run_one("symmetry(state key)", sym)
    run_one("POR + symmetry", both)


if __name__ == "__main__":
    main()

