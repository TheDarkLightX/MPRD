#!/usr/bin/env python3
"""
Z3 model checks for MPRD Tokenomics v6 epoch budget invariants.

This is a *proof search* (exists-counterexample) style check:
  - If Z3 returns UNSAT for the negation of an invariant under the declared constraints,
    the invariant holds for all values in that constraint set.

Focus: `TokenomicsV6::finalize_epoch` budget rails.

Run:
  python3 tools/tokenomics/z3_tokenomics_v6_budget_invariants.py
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

import z3


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    model: z3.ModelRef | None = None


def floor_bps(amount: z3.ArithRef, bps: z3.ArithRef, BPS: int) -> z3.ArithRef:
    # For nonnegative Ints this is a true floor division.
    return (amount * bps) / BPS


def z3_int(name: str) -> z3.IntNumRef:
    return z3.Int(name)


def check_invariant(solver: z3.Solver, name: str, inv: z3.BoolRef) -> CheckResult:
    solver.push()
    solver.add(z3.Not(inv))
    r = solver.check()
    if r == z3.unsat:
        solver.pop()
        return CheckResult(name=name, ok=True, model=None)
    if r == z3.sat:
        m = solver.model()
        solver.pop()
        return CheckResult(name=name, ok=False, model=m)
    solver.pop()
    return CheckResult(name=name, ok=False, model=None)


def main() -> int:
    BPS = 10_000

    # Inputs (nonnegative integers).
    f_base_gross = z3_int("f_base_gross")
    offset_total = z3_int("offset_total")

    ops_pay_bps = z3_int("ops_pay_bps")
    ops_floor_fixed_agrs = z3_int("ops_floor_fixed_agrs")
    overhead_bps = z3_int("overhead_bps")

    reserve_target_agrs = z3_int("reserve_target_agrs")
    burn_surplus_bps = z3_int("burn_surplus_bps")
    auction_surplus_bps = z3_int("auction_surplus_bps")

    s = z3.Solver()

    # Core domain constraints (mirror ParamsV6::new + finalize_epoch preconditions).
    s.add(f_base_gross >= 0)
    s.add(offset_total >= 0)
    s.add(offset_total <= f_base_gross)

    for bps in [
        ops_pay_bps,
        overhead_bps,
        burn_surplus_bps,
        auction_surplus_bps,
    ]:
        s.add(bps >= 0, bps <= BPS)

    s.add(ops_floor_fixed_agrs >= 0)
    s.add(reserve_target_agrs >= 0)

    s.add(burn_surplus_bps + auction_surplus_bps <= BPS)

    # Derived values (as in `finalize_epoch`).
    f_net = f_base_gross - offset_total

    ops_floor_pct = floor_bps(f_net, ops_pay_bps, BPS)
    ops_floor_epoch = z3.If(ops_floor_pct >= ops_floor_fixed_agrs, ops_floor_pct, ops_floor_fixed_agrs)
    ops_budget = z3.If(f_net <= ops_floor_epoch, f_net, ops_floor_epoch)

    ops_overhead = floor_bps(ops_budget, overhead_bps, BPS)
    ops_payroll = ops_budget - ops_overhead

    reserve_budget = z3.If((f_net - ops_budget) <= reserve_target_agrs, (f_net - ops_budget), reserve_target_agrs)
    surplus = f_net - ops_budget - reserve_budget

    burn_surplus = floor_bps(surplus, burn_surplus_bps, BPS)
    auction_new = floor_bps(surplus, auction_surplus_bps, BPS)
    unallocated = surplus - burn_surplus - auction_new

    # Invariants.
    inv_nonneg = z3.And(
        f_net >= 0,
        ops_floor_pct >= 0,
        ops_floor_epoch >= 0,
        ops_budget >= 0,
        ops_overhead >= 0,
        ops_payroll >= 0,
        reserve_budget >= 0,
        surplus >= 0,
        burn_surplus >= 0,
        auction_new >= 0,
        unallocated >= 0,
    )

    inv_conservation = (
        ops_budget + reserve_budget + burn_surplus + auction_new + unallocated == f_net
    )

    inv_ops_overhead_bounded = z3.And(
        ops_overhead <= ops_budget,
        ops_payroll + ops_overhead == ops_budget,
    )

    inv_reserve_bounded = z3.And(
        reserve_budget <= reserve_target_agrs,
        reserve_budget <= (f_net - ops_budget),
    )

    inv_surplus_bounded = z3.And(
        burn_surplus <= surplus,
        auction_new <= surplus,
        unallocated <= surplus,
    )

    checks = [
        check_invariant(s, "nonnegativity", inv_nonneg),
        check_invariant(s, "budget_conservation", inv_conservation),
        check_invariant(s, "ops_overhead_bounded", inv_ops_overhead_bounded),
        check_invariant(s, "reserve_bounded", inv_reserve_bounded),
        check_invariant(s, "surplus_components_bounded", inv_surplus_bounded),
    ]

    ok = True
    for c in checks:
        if c.ok:
            print(f"[OK]   {c.name}")
            continue
        ok = False
        print(f"[FAIL] {c.name}")
        if c.model is not None:
            print("Counterexample model:")
            for v in [
                f_base_gross,
                offset_total,
                ops_pay_bps,
                ops_floor_fixed_agrs,
                overhead_bps,
                reserve_target_agrs,
                burn_surplus_bps,
                auction_surplus_bps,
                f_net,
                ops_floor_pct,
                ops_floor_epoch,
                ops_budget,
                ops_overhead,
                ops_payroll,
                reserve_budget,
                surplus,
                burn_surplus,
                auction_new,
                unallocated,
            ]:
                try:
                    print(f"  {v} = {c.model.eval(v, model_completion=True)}")
                except Exception:
                    pass
        else:
            print("Z3 returned UNKNOWN or no model was available.")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

