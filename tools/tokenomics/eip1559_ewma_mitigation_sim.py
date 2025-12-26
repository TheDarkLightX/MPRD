#!/usr/bin/env python3
"""
EIP-1559-style "signal smoothing" experiment (deterministic, dependency-free).

Why this exists in MPRD
-----------------------
The v6 "Algorithmic CEO" (and tokenomics rails generally) depend on *measured signals*
that may be noisy or adversarially manipulated. A high-ROI mitigation is to avoid using
single-epoch signals directly, and instead use an exponentially weighted moving average
(EWMA / EMA). This matches the proposed EIP-7378 mitigation for EIP-1559 base fee
manipulation and provides a concrete, reproducible experiment that shows:

  - without smoothing, a single "empty block" shock can produce a large, immediate move
  - with EWMA smoothing, the shock's influence is discounted geometrically by `q`

We model a simplified variant of the DISC'23 simulation described in:
  "Base Fee Manipulation in Ethereum’s EIP-1559 Transaction Fee Mechanism"
  (Azouvi, Goren, Heimbach, Hicks)

Model (simplified / illustrative)
---------------------------------
We simulate a base-fee-like parameter `b` with target block size `s* = 1`.

Update:
  s_avg[t] = (1-q)*s[t] + q*s_avg[t-1]           (EWMA; q=0 is "no smoothing")
  b[t+1]   = b[t] * (1 + phi * (s_avg[t] - 1))   (linearized EIP-1559 update)

Attack trace (mirrors the paper's sim harness structure):
  - t=0: attacker X mines an empty block (s=0) to reduce base fee
  - t>=1: proposer is X with prob p_x; otherwise honest
      * X mines target-size blocks (s=1) to keep base fee from recovering too fast
      * honest miners mine full blocks (s=2), recovering base fee toward target

We stop when b >= 0.99 * b* (recovery threshold).

Profit proxy:
  On each attacker-mined block (t>=1), we add max(0, b* - b[t]) * s[t].
  This captures the intuition: lowered base fee creates a "spread" that can be captured
  (via tips/bribes/priority fees), and smoothing reduces the attainable spread.

This is not a full model of Ethereum; it is a controlled experiment to justify the
signal-smoothing design choice used in MPRD.
"""

from __future__ import annotations

import argparse
import csv
import random
import statistics
import sys
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Result:
    seed: int
    q: float
    px: float
    phi: float
    steps: int
    b_min: float
    profit: float
    x_blocks: int


def clamp(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x


def run_trial(*, seed: int, q: float, px: float, phi: float, recover_ratio: float = 0.99) -> Result:
    if not (0.0 <= q < 1.0):
        raise ValueError("q must be in [0,1)")
    if not (0.0 < px < 1.0):
        raise ValueError("px must be in (0,1)")
    if phi <= 0:
        raise ValueError("phi must be > 0")

    rng = random.Random(seed)

    b_star = 1.0
    b = b_star
    b_min = b
    s_avg = 1.0

    profit = 0.0
    x_blocks = 0

    # t=0: attacker mines an empty block (shock).
    s0 = 0.0
    s_avg = (1.0 - q) * s0 + q * s_avg
    b = b * (1.0 + phi * (s_avg - 1.0))
    b = max(0.0, b)
    b_min = min(b_min, b)

    steps = 1
    # After the shock, iterate until "recover to 99% of target"
    while b < recover_ratio * b_star and steps < 10_000:
        is_x = rng.random() < px
        if is_x:
            s = 1.0
            x_blocks += 1
            profit += max(0.0, b_star - b) * s
        else:
            s = 2.0

        s_avg = (1.0 - q) * s + q * s_avg
        b = b * (1.0 + phi * (s_avg - 1.0))
        b = max(0.0, b)
        b_min = min(b_min, b)
        steps += 1

    return Result(seed=seed, q=q, px=px, phi=phi, steps=steps, b_min=b_min, profit=profit, x_blocks=x_blocks)


def mean(xs: list[float]) -> float:
    return statistics.mean(xs) if xs else 0.0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=5000)
    ap.add_argument("--px", type=float, default=0.3, help="attacker proposer probability (0,1)")
    ap.add_argument("--phi", type=float, default=0.125, help="EIP-1559 step size (phi), e.g. 1/8=0.125")
    ap.add_argument(
        "--q-list",
        type=str,
        default="0.0,0.25,0.5,0.75",
        help="comma-separated q values in [0,1). q=0 is no smoothing",
    )
    ap.add_argument("--out", type=str, default="", help="optional CSV output path (default: stdout)")
    args = ap.parse_args()

    if args.trials <= 0:
        raise SystemExit("--trials must be > 0")

    q_list = []
    for p in [x.strip() for x in args.q_list.split(",") if x.strip()]:
        q_list.append(clamp(float(p), 0.0, 0.999999))

    out_fh = open(args.out, "w", newline="") if args.out else sys.stdout
    try:
        w = csv.DictWriter(
            out_fh,
            fieldnames=[
                "q",
                "px",
                "phi",
                "trials",
                "steps_mean",
                "b_min_mean",
                "profit_mean",
                "x_blocks_mean",
            ],
        )
        w.writeheader()

        for q in q_list:
            rows = [run_trial(seed=i, q=q, px=args.px, phi=args.phi) for i in range(args.trials)]
            w.writerow(
                {
                    "q": q,
                    "px": args.px,
                    "phi": args.phi,
                    "trials": args.trials,
                    "steps_mean": mean([r.steps for r in rows]),
                    "b_min_mean": mean([r.b_min for r in rows]),
                    "profit_mean": mean([r.profit for r in rows]),
                    "x_blocks_mean": mean([r.x_blocks for r in rows]),
                }
            )
    finally:
        if args.out:
            out_fh.close()


if __name__ == "__main__":
    main()

