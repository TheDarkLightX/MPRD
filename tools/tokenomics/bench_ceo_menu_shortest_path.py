#!/usr/bin/env python3
"""
Benchmark + sanity-check for the MPRD v6 Algorithmic CEO safe-menu navigation theorem.

We model the discrete lattice menu in *units* (not bps):
  - burn units    b ∈ [0,45]
  - auction units a ∈ [5,50]
  - drip units    d ∈ [1,20]
  - split cap: b + a ≤ 50

Edges correspond to deltas in {-1,0,1}^3 (27 actions, including NoOp) with fail-closed validity.

The proven Lean theorem (see `internal/specs/mprd_ceo_menu_shortest_path_proofs.lean`) implies:
  - A deterministic "sign-step" controller reaches any target in exactly distInf steps.
  - Shortest-path length in this graph equals distInf = max(|Δb|,|Δa|,|Δd|).

This script:
  1) Builds the valid node set (≈21,620 nodes).
  2) For a bounded sample of random pairs, checks:
      BFS_distance(start, goal) == distInf(start, goal)
     and also validates the explicit stepTowards path.
  3) Prints rough timing to illustrate O(1) vs O(|V|+|E|) behavior.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
import random
import time
from typing import Iterator


B_MAX = 45
A_MIN = 5
A_MAX = 50
D_MIN = 1
D_MAX = 20
CAP = 50

A_RANGE = A_MAX - A_MIN + 1
D_RANGE = D_MAX - D_MIN + 1
TOTAL_IDS = (B_MAX + 1) * A_RANGE * D_RANGE


@dataclass(frozen=True, slots=True)
class Node:
    b: int
    a: int
    d: int


def valid(n: Node) -> bool:
    return (
        0 <= n.b <= B_MAX
        and A_MIN <= n.a <= A_MAX
        and D_MIN <= n.d <= D_MAX
        and n.b + n.a <= CAP
    )


def abs_diff(x: int, y: int) -> int:
    return x - y if x >= y else y - x


def dist_inf(x: Node, y: Node) -> int:
    return max(abs_diff(x.b, y.b), abs_diff(x.a, y.a), abs_diff(x.d, y.d))


def step_nat(x: int, y: int) -> int:
    if x < y:
        return x + 1
    if y < x:
        return x - 1
    return x


def step_towards(cur: Node, tgt: Node) -> Node:
    return Node(
        b=step_nat(cur.b, tgt.b),
        a=step_nat(cur.a, tgt.a),
        d=step_nat(cur.d, tgt.d),
    )


_DELTAS: tuple[tuple[int, int, int], ...] = tuple(
    (db, da, dd) for db in (-1, 0, 1) for da in (-1, 0, 1) for dd in (-1, 0, 1)
)


def encode_coords(b: int, a: int, d: int) -> int:
    return ((b * A_RANGE + (a - A_MIN)) * D_RANGE) + (d - D_MIN)


def decode_coords(i: int) -> tuple[int, int, int]:
    d = (i % D_RANGE) + D_MIN
    i //= D_RANGE
    a = (i % A_RANGE) + A_MIN
    b = i // A_RANGE
    return b, a, d


def encode(n: Node) -> int:
    return encode_coords(n.b, n.a, n.d)


def neighbors(n: Node) -> Iterator[Node]:
    for db, da, dd in _DELTAS:
        nn = Node(n.b + db, n.a + da, n.d + dd)
        if valid(nn):
            yield nn


def bfs_distance(start: Node, goal: Node, is_valid: list[bool]) -> int:
    if start == goal:
        return 0
    start_id = encode(start)
    goal_id = encode(goal)
    q: deque[int] = deque([start_id])
    dist = [-1] * TOTAL_IDS
    dist[start_id] = 0
    while q:
        cur_id = q.popleft()
        cur_dist = dist[cur_id]
        nd = cur_dist + 1
        b, a, d = decode_coords(cur_id)
        for db, da, dd in _DELTAS:
            nb = b + db
            na = a + da
            nd_ = d + dd
            if nb < 0 or nb > B_MAX:
                continue
            if na < A_MIN or na > A_MAX:
                continue
            if nd_ < D_MIN or nd_ > D_MAX:
                continue
            nxt_id = encode_coords(nb, na, nd_)
            if not is_valid[nxt_id]:
                continue
            if dist[nxt_id] != -1:
                continue
            if nxt_id == goal_id:
                return nd
            dist[nxt_id] = nd
            q.append(nxt_id)
    raise RuntimeError("unreachable (should not happen for valid nodes under this adjacency)")


def iter_step_path(start: Node, goal: Node) -> list[Node]:
    steps = dist_inf(start, goal)
    cur = start
    path = [cur]
    for _ in range(steps):
        cur = step_towards(cur, goal)
        path.append(cur)
    return path


def all_valid_nodes() -> list[Node]:
    nodes: list[Node] = []
    for b in range(0, B_MAX + 1):
        a_hi = min(A_MAX, CAP - b)
        if a_hi < A_MIN:
            continue
        for a in range(A_MIN, a_hi + 1):
            for d in range(D_MIN, D_MAX + 1):
                nodes.append(Node(b=b, a=a, d=d))
    return nodes


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pairs", type=int, default=10, help="number of random (start,goal) pairs")
    ap.add_argument("--seed", type=int, default=0, help="RNG seed (deterministic)")
    args = ap.parse_args()

    if args.pairs <= 0:
        raise SystemExit("--pairs must be > 0")

    nodes = all_valid_nodes()
    assert len(nodes) == 21620, len(nodes)

    is_valid = [False] * TOTAL_IDS
    for n in nodes:
        is_valid[encode(n)] = True

    # Keep this bounded/deterministic.
    rng = random.Random(args.seed)
    samples: list[tuple[Node, Node]] = [(rng.choice(nodes), rng.choice(nodes)) for _ in range(args.pairs)]

    t0 = time.perf_counter()
    di = [dist_inf(s, t) for (s, t) in samples]
    t1 = time.perf_counter()

    t2 = time.perf_counter()
    bfs = [bfs_distance(s, t, is_valid) for (s, t) in samples]
    t3 = time.perf_counter()

    # Prove-by-computation (bounded sample): BFS == distInf, and the explicit path is valid.
    for (start, goal), d_bfs, d_inf in zip(samples, bfs, di, strict=True):
        if d_bfs != d_inf:
            raise AssertionError(f"distance mismatch: bfs={d_bfs} distInf={d_inf} start={start} goal={goal}")
        path = iter_step_path(start, goal)
        if len(path) != d_inf + 1:
            raise AssertionError(f"path length mismatch: got={len(path)} want={d_inf+1}")
        if path[-1] != goal:
            raise AssertionError(f"path does not reach goal: got={path[-1]} want={goal}")
        if any(not valid(n) for n in path):
            raise AssertionError("invalid node produced along stepTowards path")
        # adjacency check: each step is within {-1,0,1}^3
        for x, y in zip(path[:-1], path[1:], strict=True):
            if abs_diff(x.b, y.b) > 1 or abs_diff(x.a, y.a) > 1 or abs_diff(x.d, y.d) > 1:
                raise AssertionError(f"non-local step: {x} -> {y}")

    print("MPRD CEO safe-menu: shortest-path sanity-check OK")
    print(f"nodes={len(nodes)} pairs={args.pairs}")
    print(f"distInf time: {(t1 - t0) * 1000:.2f} ms total ({(t1 - t0) / args.pairs * 1e6:.1f} µs/pair)")
    print(f"BFS    time: {(t3 - t2) * 1000:.2f} ms total ({(t3 - t2) / args.pairs * 1000:.2f} ms/pair)")


if __name__ == "__main__":
    main()
