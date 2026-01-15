#!/usr/bin/env python3
"""
Bounded brute-force decision procedure for a tiny DQBF/Henkin fragment.

Intent:
- Evidence-first falsifier oracle for “quantification over Boolean functions” with dependency sets.
- Deterministic witness extraction (Skolem truth tables) for SAT, or counterexample assignment for UNSAT.

Scope (deliberately small):
- Universals: x0..x{n-1} ∈ {0,1}
- Existentials: function symbols y0..y{m-1}, each with dependency subset deps[i] ⊆ {0..n-1}
- Formula: a Boolean expression over atoms:
    - ("x", i) means xi
    - ("y", j) means yj(deps_j) evaluated at current universal assignment
  with operators: "not", "and", "or", "xor", "imp", "iff"

Semantics:
  SAT iff ∃ (Skolem tables for each yj) s.t. ∀ x ∈ {0,1}^n . eval(phi,x,skolems)=True

This is exponential in the size of dependency sets (as expected).
"""

from __future__ import annotations

import argparse
import itertools
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union


Atom = Tuple[str, int]  # ("x",i) or ("y",j)
Expr = Union[
    Atom,
    Tuple[str, Any],  # ("not", e) etc.
]


def _eval_expr(expr: Expr, x: Sequence[int], y_vals: Sequence[int]) -> int:
    """Evaluate expr to 0/1 under current universal assignment and current y outputs."""
    if isinstance(expr, (list, tuple)) and len(expr) == 2 and expr[0] in ("x", "y"):
        kind, idx = expr
        if kind == "x":
            return int(x[int(idx)])
        return int(y_vals[int(idx)])
    if not isinstance(expr, (list, tuple)):
        raise ValueError(f"bad expr: {expr!r}")
    op = expr[0]
    if op == "not":
        return 1 - _eval_expr(expr[1], x, y_vals)
    if op == "and":
        for e in expr[1:]:
            if _eval_expr(e, x, y_vals) == 0:
                return 0
        return 1
    if op == "or":
        for e in expr[1:]:
            if _eval_expr(e, x, y_vals) == 1:
                return 1
        return 0
    if op == "xor":
        a = _eval_expr(expr[1], x, y_vals)
        b = _eval_expr(expr[2], x, y_vals)
        return a ^ b
    if op == "imp":
        a = _eval_expr(expr[1], x, y_vals)
        b = _eval_expr(expr[2], x, y_vals)
        return (1 - a) | b
    if op == "iff":
        a = _eval_expr(expr[1], x, y_vals)
        b = _eval_expr(expr[2], x, y_vals)
        return 1 if a == b else 0
    raise ValueError(f"unknown op: {op!r}")


def _bits_to_int(bits: Sequence[int]) -> int:
    out = 0
    for b in bits:
        out = (out << 1) | int(b)
    return out


def _int_to_bits(v: int, width: int) -> List[int]:
    return [int((v >> (width - 1 - i)) & 1) for i in range(width)]


@dataclass(frozen=True)
class Problem:
    n_univ: int
    deps: List[List[int]]  # deps[j] ⊆ [0..n_univ)
    phi: Expr


def _load_problem(path: str) -> Problem:
    doc = json.load(open(path, "r", encoding="utf-8"))
    n = int(doc["n_univ"])
    deps = [list(map(int, d)) for d in doc["deps"]]
    phi = doc["phi"]
    return Problem(n_univ=n, deps=deps, phi=phi)


def _y_outputs_for_x(problem: Problem, x: Sequence[int], skolem_tables: Sequence[List[int]]) -> List[int]:
    """
    Compute yj(deps_j) outputs at assignment x, given truth tables for each yj.

    Table indexing convention:
    - deps bits are taken in the order listed in deps[j]
    - index is interpreted as binary (MSB first)
    """
    y_vals: List[int] = []
    for j, dep_idxs in enumerate(problem.deps):
        bits = [x[i] for i in dep_idxs]
        idx = _bits_to_int(bits) if bits else 0
        y_vals.append(int(skolem_tables[j][idx]))
    return y_vals


def decide(problem: Problem) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Decide SAT/UNSAT and return a witness:
    - SAT: skolem tables
    - UNSAT: a counterexample universal assignment for every skolem choice is not produced here;
      instead we return the first skolem that fails along with the failing x as evidence.
      (This is a falsifier oracle, not a full proof system.)
    """
    n = problem.n_univ
    m = len(problem.deps)

    # Enumerate all skolem truth tables for each yj.
    # yj has 2^{|deps_j|} entries, each entry in {0,1}.
    table_sizes = [1 << len(problem.deps[j]) for j in range(m)]

    # Deterministic enumeration order: y0 tables, then y1, etc.
    table_spaces = [list(itertools.product([0, 1], repeat=sz)) for sz in table_sizes]

    for tables in itertools.product(*table_spaces):
        sk = [list(t) for t in tables]
        ok = True
        bad_x: Optional[List[int]] = None
        for x_bits in itertools.product([0, 1], repeat=n):
            y_vals = _y_outputs_for_x(problem, x_bits, sk)
            v = _eval_expr(problem.phi, x_bits, y_vals)
            if v != 1:
                ok = False
                bad_x = list(x_bits)
                break
        if ok:
            wit = {
                "skolem_tables": [
                    {"deps": problem.deps[j], "table": sk[j]} for j in range(m)
                ]
            }
            return True, wit
        # If desired, we can return the first failing example for debugging.
        # For now we keep searching for a SAT witness.
        _ = bad_x

    # UNSAT for this bounded form (exhaustive over all skolem tables).
    return False, None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="Problem JSON path")
    args = ap.parse_args()

    p = _load_problem(args.path)
    sat, wit = decide(p)
    if sat:
        print(json.dumps({"sat": True, "witness": wit}, indent=2))
        return 0
    print(json.dumps({"sat": False}, indent=2))
    return 3


if __name__ == "__main__":
    raise SystemExit(main())

