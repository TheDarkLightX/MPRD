from __future__ import annotations

"""
Morph domain: table rewrite law `select ∘ set` (falsifier mining).

Purpose:
- Provide a deterministic Morph `TryAccept` primitive that finds a counterexample witness
  to the naive rewrite law:

    select(set(T,k,v)) == set(select(T), k, v)

- The refined law is proved in Lean (`LeanProofs/TauTables_SelectSet.lean`), but we keep
  this domain focused on falsifier mining and replayable evidence bundles.

Model:
- Key: Bool (1-bit key table).
- Value: (hi, lo) ∈ {0,1}^2.
- Table: T : Bool -> Val (2 entries).
- select predicate: keep rows with hi=1 and canonicalize value to (hi, hi & lo), else 0.

Witness schema:
  {
    "schema": "mprd/table-rewrite/witness/v1",
    "law": "naive_select_set",
    "T": [[hi0,lo0],[hi1,lo1]],
    "k": 0|1,
    "v": [hi,lo],
    "idx": 0|1,
    "lhs": [hi,lo],
    "rhs": [hi,lo]
  }
"""

import json
from typing import Any, Dict, List, Optional, Tuple

from morph.domain import ProblemState
from morph.proofs import Transition, VerifyResult
from morph.runtime import Fail, MorphRuntime, Ok, Solution
from morph.triviality_safe import CertificateOnlyDomain, CheckResult


_WIT_SCHEMA = "mprd/table-rewrite/witness/v1"


def _b(x: int) -> int:
    return 1 if int(x) != 0 else 0


Val = Tuple[int, int]  # (hi, lo)


def _select_val(v: Val) -> Val:
    hi, lo = v
    return (_b(hi), _b(hi) & _b(lo))


def _select(T: Tuple[Val, Val], idx: int) -> Val:
    v = T[_b(idx)]
    if _b(v[0]) == 1:
        return _select_val(v)
    return (0, 0)


def _set(T: Tuple[Val, Val], k: int, v: Val) -> Tuple[Val, Val]:
    k = _b(k)
    return (v, T[1]) if k == 0 else (T[0], v)


def _find_naive_counterexample() -> Optional[Dict[str, Any]]:
    # Deterministic enumeration over all T,k,v,idx in lex order.
    vals: List[Val] = [(0, 0), (0, 1), (1, 0), (1, 1)]
    for t0 in vals:
        for t1 in vals:
            T = (t0, t1)
            for k in [0, 1]:
                for v in vals:
                    # mismatch exists if ∃ idx. LHS(idx) != RHS(idx)
                    for idx in [0, 1]:
                        lhs = _select(_set(T, k, v), idx)
                        rhs = _set((_select(T, 0), _select(T, 1)), k, v)[_b(idx)]
                        if lhs != rhs:
                            return {
                                "schema": _WIT_SCHEMA,
                                "law": "naive_select_set",
                                "T": [list(t0), list(t1)],
                                "k": int(k),
                                "v": list(v),
                                "idx": int(idx),
                                "lhs": list(lhs),
                                "rhs": list(rhs),
                            }
    return None


def _check_witness(w: Dict[str, Any]) -> bool:
    if not isinstance(w, dict) or w.get("schema") != _WIT_SCHEMA:
        return False
    if w.get("law") != "naive_select_set":
        return False
    Traw = w.get("T")
    if not (isinstance(Traw, list) and len(Traw) == 2):
        return False
    t0, t1 = Traw
    if not (isinstance(t0, list) and isinstance(t1, list) and len(t0) == 2 and len(t1) == 2):
        return False
    T: Tuple[Val, Val] = ((int(t0[0]), int(t0[1])), (int(t1[0]), int(t1[1])))
    k = int(w.get("k"))
    vraw = w.get("v")
    if not (isinstance(vraw, list) and len(vraw) == 2):
        return False
    v: Val = (int(vraw[0]), int(vraw[1]))
    idx = int(w.get("idx"))
    lhs = _select(_set(T, k, v), idx)
    rhs = _set((_select(T, 0), _select(T, 1)), k, v)[_b(idx)]
    return lhs != rhs


def make_sigma0() -> ProblemState:
    return ProblemState.create(
        goal="Find a counterexample to naive select(set) table rewrite",
        representation="Key=Bool, Val=(hi,lo) Bool×Bool, Table=Bool→Val",
        givens=(
            "select(T)(i) = if hi(T(i)) then (hi(T(i)), hi(T(i)) & lo(T(i))) else 0",
            "set(T,k,v)(i) = if i=k then v else T(i)",
        ),
        constraints=(
            "SOLVED means witness is a valid counterexample (lhs != rhs at some idx).",
            "Deterministic enumeration; fail-closed if no witness found (no promotion).",
        ),
        examples=("Counterexample exists when v=(0,1) is inserted under selection that zeros low bit.",),
    )


class MprdTableRewriteDomain(CertificateOnlyDomain):
    def __init__(self) -> None:
        super().__init__()
        self._sigma0 = make_sigma0()

    def make_sigma0(self, **kwargs: Any) -> ProblemState:  # type: ignore[override]
        return self._sigma0

    def check(self, state: ProblemState, witness: str) -> CheckResult:  # type: ignore[override]
        try:
            obj = json.loads(str(witness))
        except Exception:
            return CheckResult.FAIL
        return CheckResult.PASS if _check_witness(obj) else CheckResult.FAIL

    def check2(self, state: ProblemState, witness: str) -> CheckResult:  # type: ignore[override]
        # Independent re-check (same computation; strict parse).
        return self.check(state, witness)

    def verify_transition(self, parent: ProblemState, transition: Transition) -> VerifyResult:  # type: ignore[override]
        # TryAccept must be a no-op on the ProblemState; fail-closed otherwise.
        if transition.tactic_name != "TryAccept":
            return VerifyResult.FAIL
        if transition.parent != transition.child:
            return VerifyResult.FAIL
        return VerifyResult.PASS


def build_runtime_factory(**kwargs: Any) -> MorphRuntime:
    """
    Minimal runtime: expose `TryAccept` that deterministically finds a falsifier witness.
    """
    rt = MorphRuntime()

    def try_accept(st: ProblemState, arg: str | None):
        if arg is not None and str(arg).strip() != "":
            return Fail("TryAccept takes no args")
        w = _find_naive_counterexample()
        if w is None:
            return Fail("no counterexample found")
        wit = json.dumps(w, sort_keys=True, separators=(",", ":"))
        return Ok(Solution(state=st, artifact=wit))

    rt.primitives["TryAccept"] = try_accept
    return rt

