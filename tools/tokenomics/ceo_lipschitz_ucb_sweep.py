#!/usr/bin/env python3
"""
Parameter sweeps for the Lipschitz-UCB Algorithmic CEO simulator strategy.

This is an evidence tool: it runs `tools/tokenomics/ceo_simulation.py --json`
over a grid of Lipschitz parameters and prints CSV to stdout.

Example:
  python3 tools/tokenomics/ceo_lipschitz_ucb_sweep.py --epochs 365 --seeds 20 \\
    --L 100,300,500,800,1500 \\
    --horizon 3,6,9 \\
    --window 32,64,128 \\
    --gate none,safe_improve \\
    --margin 0,50
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
    L: int
    horizon: int
    window: int
    gate: str
    margin: int
    churn_penalty: int


def parse_int_list(s: str) -> list[int]:
    parts = [p.strip() for p in s.split(",") if p.strip()]
    out: list[int] = []
    for p in parts:
        out.append(int(p.replace("_", "")))
    if not out:
        raise ValueError("expected a non-empty comma-separated list")
    return out


def parse_str_list(s: str) -> list[str]:
    parts = [p.strip() for p in s.split(",") if p.strip()]
    if not parts:
        raise ValueError("expected a non-empty comma-separated list")
    return parts


def run_one(*, epochs: int, seed: int, gp: GridPoint) -> dict:
    cmd = [
        sys.executable,
        "tools/tokenomics/ceo_simulation.py",
        "--json",
        "--epochs",
        str(epochs),
        "--seed",
        str(seed),
        "--strategy",
        "lipschitz_ucb",
        "--lipschitz-L",
        str(gp.L),
        "--lipschitz-horizon",
        str(gp.horizon),
        "--lipschitz-window",
        str(gp.window),
        "--lipschitz-gate",
        gp.gate,
        "--lipschitz-margin",
        str(gp.margin),
        "--lipschitz-churn-penalty",
        str(gp.churn_penalty),
    ]
    out = subprocess.check_output(cmd, text=True)
    return json.loads(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=365)
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--L", type=parse_int_list, default=[100, 300, 500, 800, 1500])
    ap.add_argument("--horizon", type=parse_int_list, default=[3, 6, 9])
    ap.add_argument("--window", type=parse_int_list, default=[32, 64, 128])
    ap.add_argument("--gate", type=parse_str_list, default=["none", "safe_improve"])
    ap.add_argument("--margin", type=parse_int_list, default=[0])
    ap.add_argument("--churn-penalty", type=parse_int_list, default=[0])
    args = ap.parse_args()

    if args.epochs <= 0:
        raise SystemExit("--epochs must be > 0")
    if args.seeds <= 0:
        raise SystemExit("--seeds must be > 0")
    for L in args.L:
        if L < 0:
            raise SystemExit("--L values must be >= 0")
    for h in args.horizon:
        if h <= 0:
            raise SystemExit("--horizon values must be > 0")
    for w in args.window:
        if w <= 0:
            raise SystemExit("--window values must be > 0")
    for g in args.gate:
        if g not in ("none", "safe_improve"):
            raise SystemExit("--gate values must be one of: none,safe_improve")
    for m in args.margin:
        if m < 0:
            raise SystemExit("--margin values must be >= 0")
    for c in args.churn_penalty:
        if c < 0:
            raise SystemExit("--churn-penalty values must be >= 0")

    grid = [
        GridPoint(L=L, horizon=h, window=w, gate=g, margin=m, churn_penalty=c)
        for L, h, w, g, m, c in itertools.product(args.L, args.horizon, args.window, args.gate, args.margin, args.churn_penalty)
    ]

    w = csv.DictWriter(
        sys.stdout,
        fieldnames=[
            "strategy",
            "epochs",
            "seed",
            "L",
            "horizon",
            "window",
            "gate",
            "margin",
            "churn_penalty",
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
            js = run_one(epochs=args.epochs, seed=seed, gp=gp)
            w.writerow(
                {
                    "strategy": js["strategy"],
                    "epochs": js["epochs"],
                    "seed": js["seed"],
                    "L": gp.L,
                    "horizon": gp.horizon,
                    "window": gp.window,
                    "gate": gp.gate,
                    "margin": gp.margin,
                    "churn_penalty": gp.churn_penalty,
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
