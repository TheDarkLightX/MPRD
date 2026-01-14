#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Row:
    atoms: int
    depth: int
    children_max: int
    env_iters: int
    compile_once_seconds: float
    evaluate_seconds_total: float
    evaluate_per_sec: float
    bdd_eval_seconds_total: float
    bdd_eval_per_sec: float
    agree_prefix_256: bool


def _parse_rows(doc: dict[str, Any]) -> list[Row]:
    rows_raw = doc.get("rows", [])
    rows: list[Row] = []
    for r in rows_raw:
        rows.append(
            Row(
                atoms=int(r["atoms"]),
                depth=int(r["depth"]),
                children_max=int(r["children_max"]),
                env_iters=int(r["env_iters"]),
                compile_once_seconds=float(r.get("compile_once_seconds", 0.0)),
                evaluate_seconds_total=float(r.get("evaluate_seconds_total", 0.0)),
                evaluate_per_sec=float(r.get("evaluate_per_sec", 0.0)),
                bdd_eval_seconds_total=float(r.get("bdd_eval_seconds_total", 0.0)),
                bdd_eval_per_sec=float(r.get("bdd_eval_per_sec", 0.0)),
                agree_prefix_256=bool(r.get("agree_prefix_256", False)),
            )
        )
    return rows


def _breakeven_iters(compile_s: float, eval_ps: float, bdd_ps: float) -> float | None:
    """
    Solve for N where:
      compile_s + N/bdd_ps <= N/eval_ps
    => compile_s <= N * (1/eval_ps - 1/bdd_ps)
    """
    if compile_s <= 0.0:
        return 0.0
    if eval_ps <= 0.0 or bdd_ps <= 0.0:
        return None
    gap = (1.0 / eval_ps) - (1.0 / bdd_ps)
    if gap <= 0.0:
        # BDD is not faster per-eval; never break even (on this metric).
        return None
    return compile_s / gap


def main() -> int:
    ap = argparse.ArgumentParser(description="Summarize mprd-perf --bench policy --json sweep output.")
    ap.add_argument("json_path", nargs="?", default="-", help="Path to JSON file (or '-' for stdin).")
    args = ap.parse_args()

    raw = sys.stdin.read() if args.json_path == "-" else open(args.json_path, "r", encoding="utf-8").read()
    # mprd-perf output may include warnings before the final JSON. Extract the last valid JSON object.
    dec = json.JSONDecoder()
    doc = None
    last_ok = None
    last_ok_with_rows = None
    for i, ch in enumerate(raw):
        if ch != "{":
            continue
        try:
            obj, end = dec.raw_decode(raw, i)
            last_ok = obj
            if isinstance(obj, dict) and "rows" in obj:
                last_ok_with_rows = obj
        except Exception:
            continue
    if last_ok is None and last_ok_with_rows is None:
        raise ValueError("no JSON object found in input")
    doc = last_ok_with_rows if last_ok_with_rows is not None else last_ok
    rows = _parse_rows(doc)
    if not rows:
        print("no rows found")
        return 2

    bad = [r for r in rows if not r.agree_prefix_256]
    if bad:
        print("FAIL: agree_prefix_256=false on some rows (possible semantics mismatch):")
        for r in sorted(bad, key=lambda x: (x.atoms, x.depth)):
            print(f"  atoms={r.atoms} depth={r.depth} children_max={r.children_max}")
        return 3

    print("policy sweep summary (compile-once vs eval-many)")
    print("columns: atoms depth eval/s bdd_eval/s compile_s break_even_env_iters")
    for r in sorted(rows, key=lambda x: (x.atoms, x.depth)):
        be = _breakeven_iters(r.compile_once_seconds, r.evaluate_per_sec, r.bdd_eval_per_sec)
        be_str = "never" if be is None else str(int(math.ceil(be)))
        print(
            f"{r.atoms:5d} {r.depth:5d} "
            f"{r.evaluate_per_sec:10.1f} {r.bdd_eval_per_sec:10.1f} "
            f"{r.compile_once_seconds:9.6f} {be_str:>18}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

