from __future__ import annotations

"""
Morph falsifier domain: `select` idempotence depends on the value-transformer.

Law under test:
  select(select(T)) == select(T)

We run this in two variants:
- variant="good": selectVal(v) = (hi, hi & lo)   (idempotent)  -> NO falsifier.
- variant="bad":  selectVal(v) = (hi, not lo)   (NOT idempotent) -> falsifier exists.

We use Morph only for falsifier mining. Positive truth for the "good" variant is proved
in Lean (see `proofs/lean/TauTables_SelectSet.lean`).
"""

import json
from typing import Any, Dict, List, Optional, Tuple

from morph.domain import ProblemState
from morph.proofs import Transition, VerifyResult
from morph.runtime import Fail, MorphRuntime, Ok, Solution
from morph.triviality_safe import CertificateOnlyDomain, CheckResult

_WIT_SCHEMA = "mprd/table-select-idempotence/witness/v1"

Val = Tuple[int, int]  # (hi, lo)


def _b(x: int) -> int:
    return 1 if int(x) != 0 else 0


def _notb(x: int) -> int:
    return 0 if _b(x) == 1 else 1


def _select_val_good(v: Val) -> Val:
    hi, lo = v
    return (_b(hi), _b(hi) & _b(lo))


def _select_val_bad(v: Val) -> Val:
    hi, lo = v
    return (_b(hi), _notb(lo))


def _select_val(v: Val, *, variant: str) -> Val:
    if variant == "good":
        return _select_val_good(v)
    if variant == "bad":
        return _select_val_bad(v)
    raise ValueError("unknown variant")


def _select(T: Tuple[Val, Val], idx: int, *, variant: str) -> Val:
    v = T[_b(idx)]
    if _b(v[0]) == 1:
        return _select_val(v, variant=variant)
    return (0, 0)


def _select_table(T: Tuple[Val, Val], *, variant: str) -> Tuple[Val, Val]:
    return (_select(T, 0, variant=variant), _select(T, 1, variant=variant))


def _find_counterexample(*, variant: str) -> Optional[Dict[str, Any]]:
    vals: List[Val] = [(0, 0), (0, 1), (1, 0), (1, 1)]
    for t0 in vals:
        for t1 in vals:
            T = (t0, t1)
            s1 = _select_table(T, variant=variant)
            s2 = _select_table(s1, variant=variant)
            if s2 != s1:
                return {
                    "schema": _WIT_SCHEMA,
                    "law": "select_idempotence",
                    "variant": variant,
                    "T": [list(t0), list(t1)],
                    "select_T": [list(s1[0]), list(s1[1])],
                    "select_select_T": [list(s2[0]), list(s2[1])],
                }
    return None


def _check_witness(w: Dict[str, Any]) -> bool:
    if not isinstance(w, dict) or w.get("schema") != _WIT_SCHEMA:
        return False
    if w.get("law") != "select_idempotence":
        return False
    variant = str(w.get("variant"))
    Traw = w.get("T")
    if not (isinstance(Traw, list) and len(Traw) == 2):
        return False
    t0, t1 = Traw
    if not (isinstance(t0, list) and isinstance(t1, list) and len(t0) == 2 and len(t1) == 2):
        return False
    T: Tuple[Val, Val] = ((int(t0[0]), int(t0[1])), (int(t1[0]), int(t1[1])))
    s1 = _select_table(T, variant=variant)
    s2 = _select_table(s1, variant=variant)
    return s2 != s1


def make_sigma0(*, variant: str) -> ProblemState:
    return ProblemState.create(
        goal="Find a counterexample to select(select(T)) == select(T)",
        representation=f"Key=Bool, Val=(hi,lo) in {{0,1}}^2, variant={variant}",
        givens=(
            "select(T)(i) = if hi(T(i)) then selectVal(T(i)) else 0",
            "selectVal_good(hi,lo) = (hi, hi&lo)",
            "selectVal_bad(hi,lo) = (hi, not lo)",
        ),
        constraints=(
            "SOLVED means witness demonstrates select(select(T)) != select(T).",
            "Fail-closed if no witness found (do not promote).",
        ),
        examples=("For variant=bad, T(i)=(1,0) witnesses non-idempotence.",),
    )


class MprdTableSelectIdempotenceDomain(CertificateOnlyDomain):
    def __init__(self, *, variant: str) -> None:
        super().__init__()
        self.variant = str(variant)
        self._sigma0 = make_sigma0(variant=self.variant)

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
    variant = str(kwargs.get("variant", "good"))

    def try_accept(st: ProblemState, arg: str | None):
        if arg is not None and str(arg).strip() != "":
            return Fail("TryAccept takes no args")
        w = _find_counterexample(variant=variant)
        if w is None:
            return Fail("no counterexample found")
        wit = json.dumps(w, sort_keys=True, separators=(",", ":"))
        return Ok(Solution(state=st, artifact=wit))

    rt.primitives["TryAccept"] = try_accept
    return rt
