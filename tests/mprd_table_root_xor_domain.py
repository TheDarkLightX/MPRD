from __future__ import annotations

"""
Morph falsifier domain: global (non-pointwise) operator update is unsound without old cell.

Define a Bool-key table T : {0,1} -> {0,1}.
Define a global "root" as XOR of all entries:
  root(T) = T(0) XOR T(1)

Naive (UNSOUND) rewrite under update set(T,k,v):
  root(set(T,k,v)) == root(T) XOR v

Correct (needs old cell):
  root(set(T,k,v)) == root(T) XOR T(k) XOR v

This domain mines a counterexample to the naive rewrite.
"""

import json
from typing import Any, Dict, List, Optional, Tuple

from morph.domain import ProblemState
from morph.proofs import Transition, VerifyResult
from morph.runtime import Fail, MorphRuntime, Ok, Solution
from morph.triviality_safe import CertificateOnlyDomain, CheckResult

_WIT_SCHEMA = "mprd/table-root-xor/witness/v1"


def _b(x: int) -> int:
    return 1 if int(x) != 0 else 0


def _xor(a: int, b: int) -> int:
    return _b(a) ^ _b(b)


def _set(T: Tuple[int, int], k: int, v: int) -> Tuple[int, int]:
    k = _b(k)
    v = _b(v)
    return (v, T[1]) if k == 0 else (T[0], v)


def _root(T: Tuple[int, int]) -> int:
    return _xor(T[0], T[1])


def _find_counterexample() -> Optional[Dict[str, Any]]:
    vals = [0, 1]
    for t0 in vals:
        for t1 in vals:
            T = (_b(t0), _b(t1))
            for k in [0, 1]:
                for v in [0, 1]:
                    lhs = _root(_set(T, k, v))
                    rhs = _xor(_root(T), v)
                    if lhs != rhs:
                        return {
                            "schema": _WIT_SCHEMA,
                            "law": "root_xor_set_naive",
                            "T": [T[0], T[1]],
                            "k": int(k),
                            "v": int(v),
                            "lhs": int(lhs),
                            "rhs": int(rhs),
                        }
    return None


def _check_witness(w: Dict[str, Any]) -> bool:
    if not isinstance(w, dict) or w.get("schema") != _WIT_SCHEMA:
        return False
    if w.get("law") != "root_xor_set_naive":
        return False
    Traw = w.get("T")
    if not (isinstance(Traw, list) and len(Traw) == 2):
        return False
    T = (_b(int(Traw[0])), _b(int(Traw[1])))
    k = _b(int(w.get("k")))
    v = _b(int(w.get("v")))
    lhs = _root(_set(T, k, v))
    rhs = _xor(_root(T), v)
    return lhs != rhs


def make_sigma0() -> ProblemState:
    return ProblemState.create(
        goal="Find a counterexample to naive rootXor(set) rewrite",
        representation="Key=Bool, Val=Bool, root(T)=T(0) XOR T(1)",
        givens=(
            "set(T,k,v)(i)=if i=k then v else T(i)",
            "root(T)=XOR over all keys",
        ),
        constraints=(
            "SOLVED means witness shows root(set(T,k,v)) != root(T) XOR v.",
            "Fail-closed if no witness found.",
        ),
        examples=("Counterexample: T=[1,0], k=0, v=1 gives lhs=1 rhs=0.",),
    )


class MprdTableRootXorDomain(CertificateOnlyDomain):
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
        return self.check(state, witness)

    def verify_transition(self, parent: ProblemState, transition: Transition) -> VerifyResult:  # type: ignore[override]
        if transition.tactic_name != "TryAccept":
            return VerifyResult.FAIL
        if transition.parent != transition.child:
            return VerifyResult.FAIL
        return VerifyResult.PASS


def build_runtime_factory(**kwargs: Any) -> MorphRuntime:
    rt = MorphRuntime()

    def try_accept(st: ProblemState, arg: str | None):
        if arg is not None and str(arg).strip() != "":
            return Fail("TryAccept takes no args")
        w = _find_counterexample()
        if w is None:
            return Fail("no counterexample found")
        wit = json.dumps(w, sort_keys=True, separators=(",", ":"))
        return Ok(Solution(state=st, artifact=wit))

    rt.primitives["TryAccept"] = try_accept
    return rt

