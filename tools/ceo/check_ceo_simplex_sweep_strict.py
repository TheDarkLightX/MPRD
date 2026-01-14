#!/usr/bin/env python3
"""
Strict gate for the CEO simplex sweep JSON.

This is meant to be CI-style: fail non-zero if the benchmark evidence does not meet
the configured crossover expectations.

We intentionally gate on the eval-cost regime that models realistic expensive evaluation:
eval_iters >= 200.

Contract:
- structural (deterministic) metrics are reported elsewhere; this gate focuses on the time crossover.
- We require BOTH:
  - POR win_rate >= MIN_WIN_RATE for eval_iters>=MIN_EVAL_ITERS
  - POR median_ratio <= MAX_MEDIAN_RATIO for eval_iters>=MIN_EVAL_ITERS

Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import statistics
from json import JSONDecoder
from typing import Any, Dict, List


def _extract_last_obj_with_rows(raw: str) -> Dict[str, Any]:
    dec = JSONDecoder()
    last = None
    last_with_rows = None
    for i, ch in enumerate(raw):
        if ch != "{":
            continue
        try:
            obj, _end = dec.raw_decode(raw, i)
            if isinstance(obj, dict):
                last = obj
                if "rows" in obj:
                    last_with_rows = obj
        except Exception:
            continue
    if last_with_rows is not None:
        return last_with_rows
    if last is not None:
        return last
    raise ValueError("no JSON object found")


def _load(path: str) -> Dict[str, Any]:
    raw = open(path, "r", encoding="utf-8").read()
    return _extract_last_obj_with_rows(raw)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="Path to simplex sweep JSON")
    ap.add_argument("--min-eval-iters", type=int, default=200)
    ap.add_argument("--min-win-rate", type=float, default=0.75)
    ap.add_argument("--max-median-ratio", type=float, default=1.0)
    ap.add_argument("--min-rows", type=int, default=4)
    args = ap.parse_args()

    obj = _load(args.path)
    rows: List[Dict[str, Any]] = obj.get("rows", [])
    if not rows:
        print("FAIL: no rows in sweep json")
        return 2

    filt = [r for r in rows if int(r.get("eval_iters", 0)) >= args.min_eval_iters]
    if len(filt) < args.min_rows:
        print(
            f"FAIL: insufficient rows with eval_iters>={args.min_eval_iters}: "
            f"have {len(filt)} need {args.min_rows}"
        )
        return 2

    ratios: List[float] = []
    wins = 0
    for r in filt:
        base = float(r["trace_baseline"]["seconds_total"])
        por = float(r["trace_por"]["seconds_total"])
        den = base if base > 0 else 1e-12
        ratio = por / den
        ratios.append(ratio)
        if ratio <= 1.0:
            wins += 1

    win_rate = wins / len(ratios)
    med = statistics.median(ratios)

    ok = True
    if win_rate < args.min_win_rate:
        ok = False
    if med > args.max_median_ratio:
        ok = False

    status = "PASS" if ok else "FAIL"
    print(
        f"{status}: POR crossover gate on eval_iters>={args.min_eval_iters}: "
        f"rows={len(ratios)} win_rate={win_rate:.3f} median_ratio={med:.4f} "
        f"(thresholds: win_rate>={args.min_win_rate:.2f}, median_ratio<={args.max_median_ratio:.2f})"
    )

    return 0 if ok else 3


if __name__ == "__main__":
    raise SystemExit(main())

