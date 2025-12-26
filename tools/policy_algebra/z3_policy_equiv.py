#!/usr/bin/env python3
"""
Z3 semantic equivalence check for Policy Algebra v1 binaries.

This is an "exists counterexample" check:
  - If Z3 finds a model where policies differ, it prints a counterexample assignment.
  - If UNSAT, the policies are equivalent for all boolean assignments of their atoms.

Assumption: all policy atoms are provided as boolean signals (no "missing" case).

Run:
  python3 tools/policy_algebra/z3_policy_equiv.py --a a.pal --b b.pal
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Iterable

import z3


# PolicyKind tags (must match `mprd_core::policy_algebra::PolicyKind`).
K_TRUE = 0
K_FALSE = 1
K_ATOM = 2
K_NOT = 3
K_ALL = 4
K_ANY = 5
K_THRESHOLD = 6
K_DENY_IF = 7

MAX_NODES = 1024
MAX_DEPTH = 256


@dataclass(frozen=True)
class Expr:
    kind: int
    atom: str | None = None
    k: int | None = None
    children: tuple["Expr", ...] = ()


class DecodeError(RuntimeError):
    pass


def take_u8(buf: bytes, i: int) -> tuple[int, int]:
    if i >= len(buf):
        raise DecodeError("unexpected EOF")
    return buf[i], i + 1


def take_u16(buf: bytes, i: int) -> tuple[int, int]:
    if i + 2 > len(buf):
        raise DecodeError("unexpected EOF")
    return int.from_bytes(buf[i : i + 2], "little"), i + 2


def take_u32(buf: bytes, i: int) -> tuple[int, int]:
    if i + 4 > len(buf):
        raise DecodeError("unexpected EOF")
    return int.from_bytes(buf[i : i + 4], "little"), i + 4


def take_bytes(buf: bytes, i: int, n: int) -> tuple[bytes, int]:
    if i + n > len(buf):
        raise DecodeError("unexpected EOF")
    return buf[i : i + n], i + n


def validate_atom(name: str) -> None:
    if not name:
        raise DecodeError("empty atom")
    for c in name:
        ok = ("a" <= c <= "z") or ("0" <= c <= "9") or (c == "_")
        if not ok:
            raise DecodeError(f"invalid atom character: {c!r}")


def decode_policy_v1(buf: bytes) -> Expr:
    nodes = 0

    def dec(span: bytes, depth: int) -> Expr:
        nonlocal nodes
        if depth > MAX_DEPTH:
            raise DecodeError("max decode depth exceeded")
        i = 0
        kind, i2 = take_u8(span, i)
        i = i2
        nodes += 1
        if nodes > MAX_NODES:
            raise DecodeError("max nodes exceeded")

        if kind in (K_TRUE, K_FALSE):
            if i != len(span):
                raise DecodeError("trailing bytes in leaf")
            return Expr(kind=kind)

        if kind in (K_ATOM, K_DENY_IF):
            n, i = take_u8(span, i)
            b, i = take_bytes(span, i, n)
            if i != len(span):
                raise DecodeError("trailing bytes in atom")
            try:
                s = b.decode("utf-8")
            except Exception as e:
                raise DecodeError(f"atom not utf-8: {e}") from e
            validate_atom(s)
            return Expr(kind=kind, atom=s)

        if kind == K_NOT:
            n, i = take_u32(span, i)
            payload, i = take_bytes(span, i, n)
            if i != len(span):
                raise DecodeError("trailing bytes in not")
            child = dec(payload, depth + 1)
            return Expr(kind=kind, children=(child,))

        if kind in (K_ALL, K_ANY):
            n, i = take_u16(span, i)
            children: list[Expr] = []
            for _ in range(n):
                ln, i = take_u32(span, i)
                payload, i = take_bytes(span, i, ln)
                children.append(dec(payload, depth + 1))
            if i != len(span):
                raise DecodeError("trailing bytes in n-ary")
            return Expr(kind=kind, children=tuple(children))

        if kind == K_THRESHOLD:
            n, i = take_u16(span, i)
            k, i = take_u16(span, i)
            children = []
            for _ in range(n):
                ln, i = take_u32(span, i)
                payload, i = take_bytes(span, i, ln)
                children.append(dec(payload, depth + 1))
            if i != len(span):
                raise DecodeError("trailing bytes in threshold")
            if k > n:
                raise DecodeError(f"invalid threshold: k={k} > n={n}")
            return Expr(kind=kind, k=k, children=tuple(children))

        raise DecodeError(f"unknown kind tag {kind}")

    root = dec(buf, 0)
    return root


def atoms(expr: Expr) -> set[str]:
    out: set[str] = set()

    def go(e: Expr) -> None:
        if e.kind in (K_ATOM, K_DENY_IF) and e.atom is not None:
            out.add(e.atom)
        for ch in e.children:
            go(ch)

    go(expr)
    return out


def deny_if_atoms(expr: Expr) -> set[str]:
    out: set[str] = set()

    def go(e: Expr) -> None:
        if e.kind == K_DENY_IF and e.atom is not None:
            out.add(e.atom)
        for ch in e.children:
            go(ch)

    go(expr)
    return out


def z3_and(xs: Iterable[z3.BoolRef]) -> z3.BoolRef:
    xs = list(xs)
    if not xs:
        return z3.BoolVal(True)
    return z3.And(xs)


def z3_or(xs: Iterable[z3.BoolRef]) -> z3.BoolRef:
    xs = list(xs)
    if not xs:
        return z3.BoolVal(False)
    return z3.Or(xs)


def compile_pair(expr: Expr, vars: dict[str, z3.BoolRef]) -> tuple[z3.BoolRef, z3.BoolRef]:
    # Returns (allow, neutral) under Phase-2 semantics (veto handled separately).
    if expr.kind == K_TRUE:
        return z3.BoolVal(True), z3.BoolVal(False)
    if expr.kind == K_FALSE:
        return z3.BoolVal(False), z3.BoolVal(False)
    if expr.kind == K_ATOM:
        assert expr.atom is not None
        return vars[expr.atom], z3.BoolVal(False)
    if expr.kind == K_DENY_IF:
        # After veto phase, DenyIf is neutral regardless of atom value.
        return z3.BoolVal(False), z3.BoolVal(True)
    if expr.kind == K_NOT:
        (a, n) = compile_pair(expr.children[0], vars)
        return z3.And(z3.Not(a), z3.Not(n)), n
    if expr.kind == K_ALL:
        pairs = [compile_pair(ch, vars) for ch in expr.children]
        return z3_and(z3.Or(a, n) for (a, n) in pairs), z3.BoolVal(False)
    if expr.kind == K_ANY:
        pairs = [compile_pair(ch, vars) for ch in expr.children]
        return z3_or(a for (a, _n) in pairs), z3.BoolVal(False)
    if expr.kind == K_THRESHOLD:
        assert expr.k is not None
        pairs = [compile_pair(ch, vars) for ch in expr.children]
        allow_bits = [a for (a, _n) in pairs]
        if expr.k == 0:
            return z3.BoolVal(True), z3.BoolVal(False)
        if not allow_bits:
            return z3.BoolVal(False), z3.BoolVal(False)
        pb = z3.PbGe([(b, 1) for b in allow_bits], expr.k)
        return pb, z3.BoolVal(False)
    raise RuntimeError(f"unhandled kind {expr.kind}")


def compile_allow(expr: Expr) -> z3.BoolRef:
    all_atoms = sorted(atoms(expr))
    vars = {a: z3.Bool(a) for a in all_atoms}

    veto = z3_and(z3.Not(vars[a]) for a in sorted(deny_if_atoms(expr)))
    (allow, neutral) = compile_pair(expr, vars)
    # Root neutral is treated as "not allowed".
    return z3.And(veto, allow, z3.Not(neutral))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", required=True, help="policy algebra v1 file A (binary)")
    ap.add_argument("--b", required=True, help="policy algebra v1 file B (binary)")
    ap.add_argument("--show-all-atoms", action="store_true", help="print full atom assignment in counterexample")
    args = ap.parse_args()

    a_bytes = open(args.a, "rb").read()
    b_bytes = open(args.b, "rb").read()

    try:
        a_expr = decode_policy_v1(a_bytes)
        b_expr = decode_policy_v1(b_bytes)
    except DecodeError as e:
        print(f"[ERR] decode failed: {e}")
        return 2

    a_atoms = atoms(a_expr)
    b_atoms = atoms(b_expr)
    all_atoms = sorted(a_atoms | b_atoms)

    # Build a shared variable map so models print consistently.
    vars = {a: z3.Bool(a) for a in all_atoms}

    def allow_under(expr: Expr) -> z3.BoolRef:
        veto = z3_and(z3.Not(vars[a]) for a in sorted(deny_if_atoms(expr)))
        (allow, neutral) = compile_pair(expr, vars)
        return z3.And(veto, allow, z3.Not(neutral))

    allow_a = allow_under(a_expr)
    allow_b = allow_under(b_expr)

    s = z3.Solver()
    s.add(allow_a != allow_b)
    r = s.check()

    if r == z3.unsat:
        print("[OK] policies are equivalent (no counterexample)")
        return 0
    if r != z3.sat:
        print(f"[ERR] z3 returned {r}")
        return 2

    m = s.model()
    print("[DIFF] policies differ; counterexample assignment:")
    print(f"  allow(A) = {m.eval(allow_a, model_completion=True)}")
    print(f"  allow(B) = {m.eval(allow_b, model_completion=True)}")

    # Always show atoms involved in deny-if, plus any atoms that differ between A/B atom sets.
    focus = set(deny_if_atoms(a_expr) | deny_if_atoms(b_expr) | (a_atoms ^ b_atoms))
    focus_atoms = sorted(focus)

    if args.show_all_atoms:
        focus_atoms = all_atoms

    if focus_atoms:
        print("  atoms:")
        for a in focus_atoms:
            print(f"    {a} = {m.eval(vars[a], model_completion=True)}")

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

