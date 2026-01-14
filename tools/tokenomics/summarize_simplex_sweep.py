#!/usr/bin/env python3
"""
Summarize mprd-perf simplex sweep JSON into a decision-quality crossover report.

Input: JSON produced by:
  cargo run -p mprd-perf -- --bench simplex --sweep --json ... > tmp/simplex_sweep.json

Output:
- Overall win rates / median ratios
- Per (k,h) and optionally per (k,h,T): which eval_iters bins are net faster for:
  - POR trace canonicalization (trace_por vs trace_baseline)
  - symmetry state quotienting (state_symmetry vs state_baseline)

Deterministic, stdlib only.
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Tuple


def _ratio(a: float, b: float) -> float:
    if b <= 0:
        return 1.0
    return a / b


def _stats(pairs: Iterable[Tuple[float, float]]) -> Dict[str, float]:
    pairs = list(pairs)
    if not pairs:
        return {"win_rate": 0.0, "median_ratio": 1.0, "p90_ratio": 1.0, "median_delta_ms": 0.0}
    wins = []
    ratios = []
    deltas_ms = []
    for base, alt in pairs:
        wins.append(alt <= base)
        ratios.append(_ratio(alt, base))
        deltas_ms.append((alt - base) * 1000.0)
    ratios_sorted = sorted(ratios)
    p90_idx = max(0, int(0.9 * len(ratios_sorted)) - 1)
    return {
        "win_rate": sum(wins) / len(wins),
        "median_ratio": statistics.median(ratios),
        "p90_ratio": ratios_sorted[p90_idx],
        "median_delta_ms": statistics.median(deltas_ms),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="Path to simplex sweep json (e.g., tmp/simplex_sweep.json)")
    ap.add_argument("--group-by-T", action="store_true", help="Include T in grouping keys (k,h,T) instead of (k,h)")
    args = ap.parse_args()

    obj = json.load(open(args.path, "r", encoding="utf-8"))
    rows: List[Dict[str, Any]] = obj.get("rows", [])
    if not rows:
        raise SystemExit("no rows")

    # Overall stats.
    por_pairs = [(r["trace_baseline"]["seconds_total"], r["trace_por"]["seconds_total"]) for r in rows]
    sym_pairs = [(r["state_baseline"]["seconds_total"], r["state_symmetry"]["seconds_total"]) for r in rows]

    por_s = _stats(por_pairs)
    sym_s = _stats(sym_pairs)

    print("=== Overall ===")
    print(f"rows: {len(rows)}")
    print(f"POR(trace_por<=baseline): win_rate={por_s['win_rate']:.3f} median_ratio={por_s['median_ratio']:.4f} p90_ratio={por_s['p90_ratio']:.4f} median_delta_ms={por_s['median_delta_ms']:+.3f}")
    print(f"SYM(state_symmetry<=baseline): win_rate={sym_s['win_rate']:.3f} median_ratio={sym_s['median_ratio']:.4f} p90_ratio={sym_s['p90_ratio']:.4f} median_delta_ms={sym_s['median_delta_ms']:+.3f}")

    # Grouped crossover: for each (k,h) (or k,h,T), show win rates by eval_iters.
    grouped: Dict[Tuple[int, int, int], Dict[int, List[Tuple[float, float, float, float]]]] = defaultdict(lambda: defaultdict(list))
    # value tuple: (trace_base, trace_por, state_base, state_sym)
    for r in rows:
        k = int(r["k"])
        h = int(r["h"])
        T = int(r["T"])
        e = int(r["eval_iters"])
        key = (k, h, T if args.group_by_T else -1)
        grouped[key][e].append(
            (
                float(r["trace_baseline"]["seconds_total"]),
                float(r["trace_por"]["seconds_total"]),
                float(r["state_baseline"]["seconds_total"]),
                float(r["state_symmetry"]["seconds_total"]),
            )
        )

    print("\n=== Crossover by group and eval_iters ===")
    # Sort keys deterministically.
    for key in sorted(grouped.keys()):
        k, h, T = key
        label = f"k={k} h={h}" if T == -1 else f"k={k} h={h} T={T}"
        evals = sorted(grouped[key].keys())
        print(f"\n-- {label} --")
        for e in evals:
            items = grouped[key][e]
            por_pairs_e = [(tb, tp) for (tb, tp, _sb, _ss) in items]
            sym_pairs_e = [(sb, ss) for (_tb, _tp, sb, ss) in items]
            por_e = _stats(por_pairs_e)
            sym_e = _stats(sym_pairs_e)
            print(
                f"eval_iters={e:>4} | POR win_rate={por_e['win_rate']:.2f} median_ratio={por_e['median_ratio']:.4f} "
                f"| SYM win_rate={sym_e['win_rate']:.2f} median_ratio={sym_e['median_ratio']:.4f}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

