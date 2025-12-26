#!/usr/bin/env python3
"""
Stability sweeps for the v6 Algorithmic CEO simulator.

Goals:
  - produce reproducible, machine-readable evidence for the "smoothing / step-size rails"
  - quantify tradeoffs: faster tracking (higher alpha) vs volatility / drawdown / churn

This tool runs `tools/tokenomics/ceo_simulation.py --json` across a parameter grid and
prints CSV to stdout.

Example:
  python3 tools/tokenomics/ceo_stability_sweep.py --epochs 365 --seeds 30 \\
    --strategy profit_utility \\
    --opi-adjust-bps 500,2000,5000,8000 \\
    --bcr-price-ema-alpha-bps 500,2000,5000,8000 \\
    --opi-shock-sigma-bps 0,150
"""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import subprocess
import sys
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GridPoint:
    opi_adjust_bps: int
    bcr_price_ema_alpha_bps: int
    opi_shock_sigma_bps: int


def parse_int_list(s: str) -> list[int]:
    parts = [p.strip() for p in s.split(",") if p.strip()]
    out: list[int] = []
    for p in parts:
        out.append(int(p.replace("_", "")))
    if not out:
        raise ValueError("expected a non-empty comma-separated list")
    return out


def run_one(*, epochs: int, seed: int, strategy: str, gp: GridPoint) -> dict:
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
        "--opi-adjust-bps",
        str(gp.opi_adjust_bps),
        "--bcr-price-ema-alpha-bps",
        str(gp.bcr_price_ema_alpha_bps),
        "--opi-shock-sigma-bps",
        str(gp.opi_shock_sigma_bps),
    ]
    out = subprocess.check_output(cmd, text=True)
    return json.loads(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=365)
    ap.add_argument("--seeds", type=int, default=20, help="number of seeds (runs) per grid point")
    ap.add_argument(
        "--strategy",
        type=str,
        default="profit_utility",
        choices=["baseline", "profit_utility", "opi_first", "random"],
    )
    ap.add_argument("--opi-adjust-bps", type=parse_int_list, default=[500, 2000, 5000, 8000])
    ap.add_argument("--bcr-price-ema-alpha-bps", type=parse_int_list, default=[500, 2000, 5000, 8000])
    ap.add_argument("--opi-shock-sigma-bps", type=parse_int_list, default=[0, 150])
    args = ap.parse_args()

    if args.epochs <= 0:
        raise SystemExit("--epochs must be > 0")
    if args.seeds <= 0:
        raise SystemExit("--seeds must be > 0")

    grid = [
        GridPoint(opi_adjust_bps=o, bcr_price_ema_alpha_bps=b, opi_shock_sigma_bps=s)
        for o, b, s in itertools.product(args.opi_adjust_bps, args.bcr_price_ema_alpha_bps, args.opi_shock_sigma_bps)
    ]

    w = csv.DictWriter(
        sys.stdout,
        fieldnames=[
            "strategy",
            "epochs",
            "seed",
            "opi_adjust_bps",
            "bcr_price_ema_alpha_bps",
            "opi_shock_sigma_bps",
            "final_nw_total",
            "final_opi_bps",
            "final_bcr_price_ema_bps",
            "drawdown",
            "volatility",
            "churn_events",
            "churn_l1_total",
            "churn_l1_avg",
        ],
    )
    w.writeheader()

    for gp in grid:
        for seed in range(args.seeds):
            js = run_one(epochs=args.epochs, seed=seed, strategy=args.strategy, gp=gp)
            w.writerow(
                {
                    "strategy": js["strategy"],
                    "epochs": js["epochs"],
                    "seed": js["seed"],
                    "opi_adjust_bps": js["params"]["opi_adjust_bps"],
                    "bcr_price_ema_alpha_bps": js["params"]["bcr_price_ema_alpha_bps"],
                    "opi_shock_sigma_bps": js["params"]["opi_shock_sigma_bps"],
                    "final_nw_total": js["final"]["nw_total"],
                    "final_opi_bps": js["final"]["opi_bps"],
                    "final_bcr_price_ema_bps": js["final"]["bcr_price_ema_bps"],
                    "drawdown": js["metrics"]["max_drawdown"],
                    "volatility": js["metrics"]["volatility"],
                    "churn_events": js["metrics"]["churn_events"],
                    "churn_l1_total": js["metrics"]["churn_l1_total"],
                    "churn_l1_avg": js["metrics"]["churn_l1_avg"],
                }
            )


if __name__ == "__main__":
    main()

