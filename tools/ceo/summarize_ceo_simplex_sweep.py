#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from json import JSONDecoder
from typing import Any


@dataclass(frozen=True)
class Row:
    k: int
    T: int
    h: int
    eval_iters: int
    trace_base: dict[str, Any]
    trace_por: dict[str, Any]
    state_base: dict[str, Any]
    state_sym: dict[str, Any]
    ceo_linear: dict[str, Any] | None


def _extract_last_obj_with_rows(raw: str) -> dict[str, Any]:
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


def _load(path: str) -> dict[str, Any]:
    raw = sys.stdin.read() if path == "-" else open(path, "r", encoding="utf-8").read()
    return _extract_last_obj_with_rows(raw)


def _rows(doc: dict[str, Any]) -> list[Row]:
    out: list[Row] = []
    for r in doc.get("rows", []):
        out.append(
            Row(
                k=int(r["k"]),
                T=int(r["T"]),
                h=int(r["h"]),
                eval_iters=int(r["eval_iters"]),
                trace_base=r["trace_baseline"],
                trace_por=r["trace_por"],
                state_base=r["state_baseline"],
                state_sym=r["state_symmetry"],
                ceo_linear=r.get("ceo_linear"),
            )
        )
    return out


def _ratio(num: float, den: float) -> float:
    if den <= 0:
        return 1.0
    return num / den


def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic structural summary for CEO simplex sweep JSON.")
    ap.add_argument("path", nargs="?", default="-", help="Path to simplex sweep JSON (or '-' for stdin).")
    args = ap.parse_args()

    doc = _load(args.path)
    rows = _rows(doc)
    if not rows:
        print("no rows found")
        return 2

    print("=== CEO simplex sweep structural summary ===")
    print("Note: this report uses deterministic counters (expanded/generated/reached_states), not wall-clock time.")
    print()
    print("columns: k T h eval_iters | trace: reached_base reached_por ratio | state: reached_base reached_sym ratio")

    for r in sorted(rows, key=lambda x: (x.k, x.T, x.h, x.eval_iters)):
        tb = int(r.trace_base.get("reached_states", 0))
        tp = int(r.trace_por.get("reached_states", 0))
        sb = int(r.state_base.get("reached_states", 0))
        ss = int(r.state_sym.get("reached_states", 0))
        tr_ratio = _ratio(tp, tb)
        st_ratio = _ratio(ss, sb)
        print(
            f"{r.k:2d} {r.T:3d} {r.h:2d} {r.eval_iters:4d} | "
            f"trace {tb:5d} {tp:5d} {tr_ratio:6.3f} | "
            f"state {sb:5d} {ss:5d} {st_ratio:6.3f}"
        )

    # Decision-quality: CEO linear objective agreement rates (if present).
    have_ceo = any(r.ceo_linear is not None for r in rows)
    if have_ceo:
        def _agree(r: Row, key: str) -> bool:
            if r.ceo_linear is None:
                return True
            v = r.ceo_linear.get(key, {})
            # baseline has no agree field
            if "ok" in v and not v.get("ok"):
                return False
            return bool(v.get("agree", True))

        def _median_ratio(r: Row, key: str) -> float:
            if r.ceo_linear is None:
                return 1.0
            b = float(r.ceo_linear["baseline"].get("seconds_total", 0.0))
            x = float(r.ceo_linear.get(key, {}).get("seconds_total", 0.0))
            return _ratio(x, b if b > 0 else 1e-12)

        keys = ["trace_por", "state_symmetry", "ample_por"]
        print()
        print("=== CEO decision-quality (linear objective) ===")
        for key in keys:
            agrees = [1 if _agree(r, key) else 0 for r in rows if r.ceo_linear is not None]
            if not agrees:
                continue
            agree_rate = sum(agrees) / len(agrees)
            ratios = sorted(_median_ratio(r, key) for r in rows if r.ceo_linear is not None)
            med = ratios[len(ratios) // 2] if ratios else 1.0
            print(f"{key:13s}: agree_rate={agree_rate:.3f} median_time_ratio_vs_brute={med:.3f}")

    print()
    # Quick aggregate: geometric mean of reach ratios (more stable than mean for multiplicative effects)
    def geo_mean(xs: list[float]) -> float:
        xs = [x for x in xs if x > 0]
        if not xs:
            return 1.0
        return math.exp(sum(math.log(x) for x in xs) / len(xs))

    tr = [(_ratio(int(r.trace_por.get("reached_states", 0)), int(r.trace_base.get("reached_states", 0)))) for r in rows]
    st = [(_ratio(int(r.state_sym.get("reached_states", 0)), int(r.state_base.get("reached_states", 0)))) for r in rows]
    print(f"trace POR reach geo-mean ratio: {geo_mean(tr):.3f}")
    print(f"state SYM reach geo-mean ratio: {geo_mean(st):.3f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

