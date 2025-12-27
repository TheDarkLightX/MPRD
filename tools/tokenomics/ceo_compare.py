#!/usr/bin/env python3
"""
Compare Algorithmic CEO strategies via deterministic multi-seed simulation runs.

This is an evidence tool (IDEA-ONLY): it produces *measurable* performance deltas
across strategies, and reports paired bootstrap confidence intervals vs a baseline.

Example:
  python3 tools/tokenomics/ceo_compare.py --epochs 365 --seeds 20 \\
    --baseline baseline \\
    --strategies baseline,profit_utility,opi_first,lipschitz_ucb \\
    --lipschitz-L 500 --lipschitz-horizon 6 --lipschitz-window 64 \\
    --lipschitz-gate safe_improve --lipschitz-margin 0 --lipschitz-churn-penalty 0
"""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
import subprocess
import sys
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class RunResult:
    seed: int
    strategy: str
    final_nw_total: int
    max_drawdown: float
    volatility: float
    churn_events: int


def parse_str_list(s: str) -> list[str]:
    parts = [p.strip() for p in s.split(",") if p.strip()]
    if not parts:
        raise ValueError("expected a non-empty comma-separated list")
    return parts


def run_one(
    *,
    epochs: int,
    seed: int,
    strategy: str,
    lipschitz: dict[str, Any],
) -> dict[str, Any]:
    cmd = [
        sys.executable,
        "tools/tokenomics/ceo_simulation.py",
        "--json",
        "--epochs",
        str(epochs),
        "--seed",
        str(seed),
        "--strategy",
        strategy,
    ]
    if strategy == "lipschitz_ucb":
        cmd.extend(
            [
                "--lipschitz-L",
                str(lipschitz["L"]),
                "--lipschitz-horizon",
                str(lipschitz["horizon"]),
                "--lipschitz-window",
                str(lipschitz["window"]),
                "--lipschitz-gate",
                lipschitz["gate"],
                "--lipschitz-margin",
                str(lipschitz["margin"]),
                "--lipschitz-churn-penalty",
                str(lipschitz["churn_penalty"]),
            ]
        )
    out = subprocess.check_output(cmd, text=True)
    return json.loads(out)


def summarize(xs: list[float]) -> dict[str, float]:
    if not xs:
        return {"n": 0.0}
    xs_sorted = sorted(xs)
    return {
        "n": float(len(xs)),
        "mean": float(statistics.mean(xs)),
        "stdev": float(statistics.pstdev(xs)),
        "p05": float(xs_sorted[max(0, int(math.floor(0.05 * (len(xs_sorted) - 1))))]),
        "p50": float(xs_sorted[max(0, int(math.floor(0.50 * (len(xs_sorted) - 1))))]),
        "p95": float(xs_sorted[max(0, int(math.floor(0.95 * (len(xs_sorted) - 1))))]),
    }


def paired_bootstrap_ci_mean(
    *,
    diffs: list[float],
    rng: random.Random,
    iters: int = 4000,
    alpha: float = 0.05,
) -> tuple[float, float]:
    if not diffs:
        return (0.0, 0.0)
    n = len(diffs)
    means: list[float] = []
    for _ in range(iters):
        sample = [diffs[rng.randrange(n)] for _ in range(n)]
        means.append(float(statistics.mean(sample)))
    means.sort()
    lo = means[int(math.floor((alpha / 2) * (iters - 1)))]
    hi = means[int(math.floor((1 - alpha / 2) * (iters - 1)))]
    return (lo, hi)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=365)
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--baseline", type=str, default="baseline")
    ap.add_argument(
        "--strategies",
        type=parse_str_list,
        default=["baseline", "profit_utility", "opi_first", "lipschitz_ucb"],
    )

    ap.add_argument("--lipschitz-L", type=int, default=500)
    ap.add_argument("--lipschitz-horizon", type=int, default=6)
    ap.add_argument("--lipschitz-window", type=int, default=64)
    ap.add_argument("--lipschitz-gate", type=str, default="safe_improve", choices=["none", "safe_improve"])
    ap.add_argument("--lipschitz-margin", type=int, default=0)
    ap.add_argument("--lipschitz-churn-penalty", type=int, default=0)

    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    if args.epochs <= 0:
        raise SystemExit("--epochs must be > 0")
    if args.seeds <= 0:
        raise SystemExit("--seeds must be > 0")
    if args.baseline not in args.strategies:
        raise SystemExit("--baseline must be included in --strategies")

    lipschitz = {
        "L": args.lipschitz_L,
        "horizon": args.lipschitz_horizon,
        "window": args.lipschitz_window,
        "gate": args.lipschitz_gate,
        "margin": args.lipschitz_margin,
        "churn_penalty": args.lipschitz_churn_penalty,
    }

    # Collect runs: strategy -> seed -> result.
    runs: dict[str, dict[int, RunResult]] = {s: {} for s in args.strategies}
    for seed in range(args.seeds):
        for strategy in args.strategies:
            js = run_one(epochs=args.epochs, seed=seed, strategy=strategy, lipschitz=lipschitz)
            runs[strategy][seed] = RunResult(
                seed=seed,
                strategy=strategy,
                final_nw_total=int(js["final"]["nw_total"]),
                max_drawdown=float(js["metrics"]["max_drawdown"]),
                volatility=float(js["metrics"]["volatility"]),
                churn_events=int(js["metrics"]["churn_events"]),
            )

    baseline = args.baseline
    rng = random.Random(1337)

    report: dict[str, Any] = {
        "epochs": args.epochs,
        "seeds": args.seeds,
        "baseline": baseline,
        "strategies": {},
        "paired_deltas_vs_baseline": {},
        "lipschitz_params": lipschitz,
    }

    for strategy in args.strategies:
        rr = list(runs[strategy].values())
        report["strategies"][strategy] = {
            "nw_total": summarize([float(r.final_nw_total) for r in rr]),
            "drawdown": summarize([float(r.max_drawdown) for r in rr]),
            "volatility": summarize([float(r.volatility) for r in rr]),
            "churn_events": summarize([float(r.churn_events) for r in rr]),
        }

    # Paired deltas on final NW vs baseline (same seeds).
    base_by_seed = runs[baseline]
    for strategy in args.strategies:
        if strategy == baseline:
            continue
        diffs: list[float] = []
        for seed in range(args.seeds):
            diffs.append(float(runs[strategy][seed].final_nw_total - base_by_seed[seed].final_nw_total))
        mean_diff = float(statistics.mean(diffs))
        ci = paired_bootstrap_ci_mean(diffs=diffs, rng=rng)
        report["paired_deltas_vs_baseline"][strategy] = {
            "mean_diff_nw_total": mean_diff,
            "ci95_mean_diff": [ci[0], ci[1]],
        }

    if args.json:
        print(json.dumps(report, sort_keys=True))
        return

    # Human-friendly summary.
    print("# Algorithmic CEO — Strategy Comparison (paired seeds)")
    print(f"epochs={args.epochs} seeds={args.seeds} baseline={baseline}")
    print("")
    for strategy in args.strategies:
        s = report["strategies"][strategy]
        nw = s["nw_total"]
        dd = s["drawdown"]
        vol = s["volatility"]
        churn = s["churn_events"]
        print(f"## {strategy}")
        print(f"- nw_total mean={nw['mean']:.2f} p50={nw['p50']:.2f} p05={nw['p05']:.2f} p95={nw['p95']:.2f}")
        print(f"- drawdown mean={dd['mean']:.4f} volatility mean={vol['mean']:.4f} churn_events mean={churn['mean']:.2f}")
        if strategy != baseline:
            d = report["paired_deltas_vs_baseline"][strategy]
            lo, hi = d["ci95_mean_diff"]
            print(f"- Δnw_total vs {baseline}: mean={d['mean_diff_nw_total']:.2f} 95%CI=[{lo:.2f},{hi:.2f}]")
        print("")


if __name__ == "__main__":
    main()

