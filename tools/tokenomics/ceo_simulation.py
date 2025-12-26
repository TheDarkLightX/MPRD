#!/usr/bin/env python3
"""
Algorithmic CEO economic simulation (deterministic, IDEA-ONLY).

This is a lightweight, self-contained simulator for exploring the v6 "Algorithmic CEO"
setpoints on the CBC safe-menu lattice:
  - burn_surplus_bps  (BurnPct units ∈ [0,45]  → bps ∈ [5000,9500], step 100)
  - auction_surplus_bps (AuctionPct units ∈ [5,50] → bps ∈ [500,5000], step 100)
  - drip_rate_bps     (DripStep units ∈ [1,20] → bps ∈ [5,100], step 5)
  - split cap: burn + auction <= 10_000 bps

Per-epoch order (deterministic):
  demand → fees → CEO decision → auction → rewards → update valuation/OPI

Run:
  python3 tools/tokenomics/ceo_simulation.py --epochs 100 --strategy profit_utility
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import statistics
from dataclasses import dataclass
from typing import Sequence


BPS = 10_000


def clamp_int(x: int, lo: int, hi: int) -> int:
    return lo if x < lo else hi if x > hi else x


def floor_bps(amount: int, bps: int) -> int:
    if amount <= 0 or bps <= 0:
        return 0
    return (amount * bps) // BPS


def stable_seed(*parts: object) -> int:
    """
    Deterministically derive a RNG seed from structured parts (stable across runs).
    """
    h = hashlib.sha256()
    for p in parts:
        h.update(repr(p).encode("utf-8"))
        h.update(b"\x1f")
    return int.from_bytes(h.digest()[:8], "little", signed=False)


@dataclass(frozen=True, slots=True)
class Delta:
    db: int  # burn units delta in {-1,0,1}
    da: int  # auction units delta in {-1,0,1}
    dd: int  # drip units delta in {-1,0,1}

    def __post_init__(self) -> None:
        for name, v in [("db", self.db), ("da", self.da), ("dd", self.dd)]:
            if v not in (-1, 0, 1):
                raise ValueError(f"Delta.{name} must be in {{-1,0,1}} (got {v})")


DELTAS: tuple[Delta, ...] = tuple(
    Delta(db, da, dd) for db in (-1, 0, 1) for da in (-1, 0, 1) for dd in (-1, 0, 1)
)


@dataclass(frozen=True, slots=True)
class Knobs:
    """
    CBC-safe CEO setpoints, represented in lattice units (invalid states unrepresentable).
    """

    burn_units: int   # [0,45]
    auction_units: int  # [5,50]
    drip_units: int   # [1,20]

    def __post_init__(self) -> None:
        if not (0 <= self.burn_units <= 45):
            raise ValueError("--burn-units must be in [0,45]")
        if not (5 <= self.auction_units <= 50):
            raise ValueError("--auction-units must be in [5,50]")
        if not (1 <= self.drip_units <= 20):
            raise ValueError("--drip-units must be in [1,20]")
        if self.burn_bps() + self.auction_bps() > BPS:
            raise ValueError(
                f"split cap violated: burn_bps={self.burn_bps()} + auction_bps={self.auction_bps()} > {BPS}"
            )

    def burn_bps(self) -> int:
        # BurnPct units ∈ [0,45] → bps ∈ [5000,9500], step 100
        return 5000 + 100 * self.burn_units

    def auction_bps(self) -> int:
        # AuctionPct units ∈ [5,50] → bps ∈ [500,5000], step 100
        return 100 * self.auction_units

    def drip_bps(self) -> int:
        # DripStep units ∈ [1,20] → bps ∈ [5,100], step 5
        return 5 * self.drip_units

    def key(self) -> int:
        # Encoding: (burn_units << 16) | (auction_units << 8) | drip_units
        return (self.burn_units << 16) | (self.auction_units << 8) | self.drip_units

    def l1_distance(self, other: Knobs) -> int:
        return (
            abs(self.burn_units - other.burn_units)
            + abs(self.auction_units - other.auction_units)
            + abs(self.drip_units - other.drip_units)
        )

    def try_apply(self, d: Delta) -> Knobs | None:
        burn = self.burn_units + d.db
        auction = self.auction_units + d.da
        drip = self.drip_units + d.dd
        try:
            return Knobs(burn_units=burn, auction_units=auction, drip_units=drip)
        except ValueError:
            return None


@dataclass(frozen=True, slots=True)
class DemandModel:
    base_fee_agrs_per_unit: int
    baseline_volume: int
    volume_cap: int
    price_elasticity: float
    quality_elasticity: float
    opi_ref_bps: int
    demand_noise_sigma: float
    # offsets
    max_offset_epoch_bps: int
    desire_offset_bps: int
    # tips
    tip_rate_bps: int
    tip_opi_elasticity: float
    tip_noise_sigma: float
    # fixed-point
    max_iters: int = 8
    damping: float = 0.6

    def __post_init__(self) -> None:
        if self.base_fee_agrs_per_unit <= 0:
            raise ValueError("base_fee_agrs_per_unit must be > 0")
        if self.baseline_volume <= 0:
            raise ValueError("baseline_volume must be > 0")
        if self.volume_cap < self.baseline_volume:
            raise ValueError("volume_cap must be >= baseline_volume")
        if not (0 <= self.max_offset_epoch_bps <= BPS):
            raise ValueError("max_offset_epoch_bps must be in [0,10_000]")
        if not (0 <= self.desire_offset_bps <= BPS):
            raise ValueError("desire_offset_bps must be in [0,10_000]")
        if not (0 <= self.tip_rate_bps <= BPS):
            raise ValueError("tip_rate_bps must be in [0,10_000]")
        if self.opi_ref_bps <= 0 or self.opi_ref_bps > BPS:
            raise ValueError("opi_ref_bps must be in [1,10_000]")
        if self.max_iters <= 0:
            raise ValueError("max_iters must be > 0")
        if not (0.0 < self.damping <= 1.0):
            raise ValueError("damping must be in (0,1]")

    def _offset_for_base_fees(self, base_fees_gross: int, bcr_supply: int) -> int:
        if base_fees_gross <= 0 or bcr_supply <= 0:
            return 0
        desired = floor_bps(base_fees_gross, self.desire_offset_bps)
        cap = floor_bps(base_fees_gross, self.max_offset_epoch_bps)
        return min(bcr_supply, desired, cap)

    def offset_for_base_fees(self, *, base_fees_gross: int, bcr_supply: int) -> int:
        return self._offset_for_base_fees(base_fees_gross, bcr_supply)

    def _volume_from_cost_and_opi(self, effective_cost_per_unit: float, opi_bps: int) -> float:
        # Multiplicative response: baseline * quality(opi) * price(cost).
        q = max(1e-9, float(opi_bps) / float(self.opi_ref_bps))
        quality = q ** self.quality_elasticity
        pr = max(1e-9, effective_cost_per_unit / float(self.base_fee_agrs_per_unit))
        price = pr ** (-self.price_elasticity)
        return float(self.baseline_volume) * quality * price

    def _solve_volume(self, *, opi_bps: int, bcr_supply: int, noise_mult: float) -> int:
        vol = float(self.baseline_volume)
        for _ in range(self.max_iters):
            base_fees = int(round(vol)) * self.base_fee_agrs_per_unit
            offsets = self._offset_for_base_fees(base_fees, bcr_supply)
            eff_cost = (
                float(base_fees - offsets) / float(max(1, int(round(vol))))
                if base_fees > 0
                else float(self.base_fee_agrs_per_unit)
            )
            next_vol = self._volume_from_cost_and_opi(eff_cost, opi_bps) * noise_mult
            next_vol = float(clamp_int(int(round(next_vol)), 0, self.volume_cap))
            vol = (1.0 - self.damping) * vol + self.damping * next_vol
        return clamp_int(int(round(vol)), 0, self.volume_cap)

    def sample_volume(self, *, opi_bps: int, bcr_supply: int, rng: random.Random) -> int:
        noise = math.exp(rng.normalvariate(0.0, self.demand_noise_sigma)) if self.demand_noise_sigma > 0 else 1.0
        return self._solve_volume(opi_bps=opi_bps, bcr_supply=bcr_supply, noise_mult=noise)

    def expected_volume(self, *, opi_bps: int, bcr_supply: int) -> int:
        return self._solve_volume(opi_bps=opi_bps, bcr_supply=bcr_supply, noise_mult=1.0)

    def sample_tips(self, *, base_fees_gross: int, opi_bps: int, rng: random.Random) -> int:
        if base_fees_gross <= 0 or self.tip_rate_bps == 0:
            return 0
        opi_mult = (max(0.0, min(1.0, float(opi_bps) / float(BPS)))) ** self.tip_opi_elasticity
        expected = float(floor_bps(base_fees_gross, self.tip_rate_bps)) * opi_mult
        noise = math.exp(rng.normalvariate(0.0, self.tip_noise_sigma)) if self.tip_noise_sigma > 0 else 1.0
        tips = int(math.floor(expected * noise))
        return max(0, tips)

    def expected_net_fees(self, *, opi_bps: int, bcr_supply: int) -> int:
        vol = self.expected_volume(opi_bps=opi_bps, bcr_supply=bcr_supply)
        base_fees = vol * self.base_fee_agrs_per_unit
        offsets = self._offset_for_base_fees(base_fees, bcr_supply)
        return max(0, base_fees - offsets)


@dataclass(frozen=True, slots=True)
class Bid:
    qty_bcr: int
    min_price_bps: int
    tie: int

    def __post_init__(self) -> None:
        if self.qty_bcr < 0:
            raise ValueError("Bid.qty_bcr must be >= 0")
        if not (0 <= self.min_price_bps <= BPS):
            raise ValueError("Bid.min_price_bps must be in [0,10_000]")


def payout_for(qty_bcr: int, price_bps: int) -> int:
    # AGRS payout at uniform clearing price (floor).
    if qty_bcr <= 0 or price_bps <= 0:
        return 0
    return (qty_bcr * price_bps) // BPS


@dataclass(frozen=True, slots=True)
class AuctionClear:
    clearing_price_bps: int
    bcr_burned: int
    payout_sum_agrs: int
    carry_out_agrs: int
    burn_excess_agrs: int
    winners: int


@dataclass(frozen=True, slots=True)
class AuctionModel:
    sell_fraction_bps: int
    n_bids: int
    price_spread_bps: int
    carry_cap_agrs: int
    payout_lock_epochs: int

    def __post_init__(self) -> None:
        if not (0 <= self.sell_fraction_bps <= BPS):
            raise ValueError("sell_fraction_bps must be in [0,10_000]")
        if self.n_bids <= 0:
            raise ValueError("n_bids must be > 0")
        if self.price_spread_bps < 0:
            raise ValueError("price_spread_bps must be >= 0")
        if self.carry_cap_agrs < 0:
            raise ValueError("carry_cap_agrs must be >= 0")
        if self.payout_lock_epochs <= 0:
            raise ValueError("payout_lock_epochs must be > 0")

    def generate_bids(self, *, total_bcr: int, price_center_bps: int, rng: random.Random) -> list[Bid]:
        if total_bcr <= 0 or self.sell_fraction_bps == 0:
            return []
        offer_total = floor_bps(total_bcr, self.sell_fraction_bps)
        offer_total = min(offer_total, total_bcr)
        if offer_total <= 0:
            return []

        bid_count = min(self.n_bids, offer_total)
        if bid_count <= 0:
            return []

        # Random partition of offer_total into bid_count strictly-positive quantities.
        if bid_count == 1:
            qtys = [offer_total]
        else:
            cuts = [rng.randint(1, offer_total - 1) for _ in range(bid_count - 1)]
            cuts.sort()
            prev = 0
            qtys = []
            for c in cuts:
                qtys.append(c - prev)
                prev = c
            qtys.append(offer_total - prev)

        bids: list[Bid] = []
        for i, q in enumerate(qtys):
            if q <= 0:
                continue
            mu = float(clamp_int(price_center_bps, 0, BPS))
            sig = float(self.price_spread_bps)
            mp = int(round(rng.normalvariate(mu, sig))) if sig > 0 else int(round(mu))
            mp = clamp_int(mp, 0, BPS)
            bids.append(Bid(qty_bcr=q, min_price_bps=mp, tie=i))
        return bids

    def clear(self, *, budget_agrs: int, bids: Sequence[Bid], carry_in_agrs: int) -> AuctionClear:
        avail = budget_agrs + carry_in_agrs
        if avail <= 0:
            return AuctionClear(
                clearing_price_bps=0,
                bcr_burned=0,
                payout_sum_agrs=0,
                carry_out_agrs=0,
                burn_excess_agrs=0,
                winners=0,
            )
        if not bids:
            carry_out = min(avail, self.carry_cap_agrs)
            burn_excess = avail - carry_out
            return AuctionClear(
                clearing_price_bps=0,
                bcr_burned=0,
                payout_sum_agrs=0,
                carry_out_agrs=carry_out,
                burn_excess_agrs=burn_excess,
                winners=0,
            )

        bids_sorted = sorted(bids, key=lambda b: (b.min_price_bps, b.tie))
        winners: list[Bid] = []
        q_sum = 0
        clearing_price = 0
        for b in bids_sorted:
            if b.qty_bcr <= 0:
                continue
            q_next = q_sum + b.qty_bcr
            p_next = b.min_price_bps
            cost_next = payout_for(q_next, p_next)
            if cost_next <= avail:
                winners.append(b)
                q_sum = q_next
                clearing_price = p_next
            else:
                break

        payout_sum = sum(payout_for(b.qty_bcr, clearing_price) for b in winners)
        payout_sum = min(payout_sum, avail)
        leftover = avail - payout_sum
        carry_out = min(leftover, self.carry_cap_agrs)
        burn_excess = leftover - carry_out

        return AuctionClear(
            clearing_price_bps=clearing_price,
            bcr_burned=q_sum,
            payout_sum_agrs=payout_sum,
            carry_out_agrs=carry_out,
            burn_excess_agrs=burn_excess,
            winners=len(winners),
        )


@dataclass(frozen=True, slots=True)
class ValuationModel:
    ema_alpha_bps: int
    price_min_bps: int
    price_max_bps: int
    discount_bps_per_epoch: int

    def __post_init__(self) -> None:
        if not (0 <= self.ema_alpha_bps <= BPS):
            raise ValueError("ema_alpha_bps must be in [0,10_000]")
        if not (0 <= self.price_min_bps <= self.price_max_bps <= BPS):
            raise ValueError("price_min_bps/price_max_bps must satisfy 0 <= min <= max <= 10_000")
        if not (0 <= self.discount_bps_per_epoch <= BPS):
            raise ValueError("discount_bps_per_epoch must be in [0,10_000]")

    def update_price_ema(self, *, prev_ema_bps: int, observed_price_bps: int) -> int:
        if observed_price_bps <= 0:
            return clamp_int(prev_ema_bps, self.price_min_bps, self.price_max_bps)
        obs = clamp_int(observed_price_bps, self.price_min_bps, self.price_max_bps)
        ema = clamp_int(prev_ema_bps, self.price_min_bps, self.price_max_bps)
        delta = obs - ema
        ema = ema + (delta * self.ema_alpha_bps) // BPS
        return clamp_int(ema, self.price_min_bps, self.price_max_bps)

    def discount(self, *, amount_agrs: int, epochs: int) -> int:
        if amount_agrs <= 0:
            return 0
        if epochs <= 0:
            return amount_agrs
        v = amount_agrs
        for _ in range(epochs):
            v = floor_bps(v, self.discount_bps_per_epoch)
            if v == 0:
                return 0
        return v

    def pv_locked(self, *, locked_by_unlock: dict[int, int], now_epoch: int) -> int:
        pv = 0
        for unlock_epoch, amt in locked_by_unlock.items():
            rem = unlock_epoch - now_epoch
            if rem <= 0:
                # Should have been unlocked already; fail-closed by ignoring.
                continue
            pv += self.discount(amount_agrs=amt, epochs=rem)
        return pv


@dataclass(frozen=True, slots=True)
class OpiModel:
    opi_adjust_bps: int
    base_opi_bps: int
    cashflow_scale_agrs: int
    cashflow_weight_bps: int
    drip_weight_bps: int
    liquidity_weight_bps: int
    reserve_weight_bps: int
    reserve_target_agrs: int
    shock_sigma_bps: int

    def __post_init__(self) -> None:
        if not (0 <= self.opi_adjust_bps <= BPS):
            raise ValueError("opi_adjust_bps must be in [0,10_000]")
        if not (0 <= self.base_opi_bps <= BPS):
            raise ValueError("base_opi_bps must be in [0,10_000]")
        if self.cashflow_scale_agrs <= 0:
            raise ValueError("cashflow_scale_agrs must be > 0")
        for name, bps in [
            ("cashflow_weight_bps", self.cashflow_weight_bps),
            ("drip_weight_bps", self.drip_weight_bps),
            ("liquidity_weight_bps", self.liquidity_weight_bps),
            ("reserve_weight_bps", self.reserve_weight_bps),
        ]:
            if not (0 <= bps <= BPS):
                raise ValueError(f"{name} must be in [0,10_000]")
        if self.reserve_target_agrs < 0:
            raise ValueError("reserve_target_agrs must be >= 0")
        if self.shock_sigma_bps < 0:
            raise ValueError("shock_sigma_bps must be >= 0")

    def sample_shock(self, rng: random.Random) -> int:
        if self.shock_sigma_bps == 0:
            return 0
        return int(round(rng.normalvariate(0.0, float(self.shock_sigma_bps))))

    def next_opi(
        self,
        *,
        opi_bps: int,
        operator_cashflow_agrs: int,
        drip_bps: int,
        clearing_price_bps: int,
        reserve_agrs: int,
        shock_bps: int,
    ) -> int:
        # Simple, bounded target:
        # - cashflow increases quality (log utility)
        # - drip improves incentives
        # - liquidity (clearing price) improves confidence
        # - reserve coverage improves stability
        cash = max(0.0, float(operator_cashflow_agrs))
        cash_term = math.log1p(cash / float(self.cashflow_scale_agrs))
        cash_score = floor_bps(int(round(cash_term * BPS)), self.cashflow_weight_bps)

        drip_score = floor_bps(int(round(float(drip_bps) / 100.0 * BPS)), self.drip_weight_bps)
        liq_score = floor_bps(clearing_price_bps, self.liquidity_weight_bps)

        reserve_ratio = 1.0
        if self.reserve_target_agrs > 0:
            reserve_ratio = min(1.0, max(0.0, float(reserve_agrs) / float(self.reserve_target_agrs)))
        reserve_score = floor_bps(int(round(reserve_ratio * BPS)), self.reserve_weight_bps)

        target = self.base_opi_bps + cash_score + drip_score + liq_score + reserve_score
        target = clamp_int(target, 0, BPS)

        cur = clamp_int(opi_bps, 0, BPS)
        nxt = cur + ((target - cur) * self.opi_adjust_bps) // BPS
        nxt = clamp_int(nxt + shock_bps, 0, BPS)
        return nxt


@dataclass(slots=True)
class SimState:
    epoch: int
    knobs: Knobs

    # protocol balances (AGRS)
    reserve_agrs: int
    unallocated_agrs: int
    auction_carry_agrs: int
    burned_total_agrs: int

    # market/ops state
    opi_bps: int
    bcr_supply: int
    bcr_price_ema_bps: int

    # operator balances (AGRS)
    operator_liquid_agrs: int
    locked_by_unlock: dict[int, int]


@dataclass(frozen=True, slots=True)
class EpochRecord:
    epoch: int
    knobs: Knobs
    knobs_prev: Knobs
    churn_l1: int

    volume: int
    base_fees_gross: int
    tips: int
    offsets_spent: int
    net_fees: int

    burn_surplus: int
    auction_new: int
    unallocated_new: int
    reserve_in: int
    reserve_end_agrs: int
    ops_payroll: int
    ops_overhead: int

    auction_available: int
    auction_clearing_price_bps: int
    auction_winners: int
    auction_payout: int
    auction_carry_end: int
    auction_burn_excess: int
    bcr_burned_auction: int
    bcr_minted: int

    opi_end: int
    bcr_supply_end: int
    bcr_price_ema_end_bps: int

    nw_total: int
    nw_protocol_agrs: int
    nw_operator_liquid_agrs: int
    nw_operator_locked_pv_agrs: int
    nw_bcr_mtm_agrs: int


def fmt_int(n: int) -> str:
    return f"{n:,}"


def pct(x: float) -> str:
    return f"{x * 100:.2f}%"


def quantile(sorted_vals: Sequence[int], q: float) -> float:
    if not sorted_vals:
        return 0.0
    if q <= 0:
        return float(sorted_vals[0])
    if q >= 1:
        return float(sorted_vals[-1])
    n = len(sorted_vals)
    pos = (n - 1) * q
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return float(sorted_vals[lo])
    w = pos - lo
    return float(sorted_vals[lo]) * (1.0 - w) + float(sorted_vals[hi]) * w


def compute_drawdown(series: Sequence[int]) -> float:
    if not series:
        return 0.0
    peak = float(series[0])
    max_dd = 0.0
    for v in series:
        fv = float(v)
        if fv > peak:
            peak = fv
        if peak > 0:
            dd = (fv - peak) / peak
            if dd < max_dd:
                max_dd = dd
    return max_dd


def compute_volatility(series: Sequence[int]) -> float:
    # Stddev of simple returns.
    if len(series) < 2:
        return 0.0
    rets: list[float] = []
    for a, b in zip(series[:-1], series[1:], strict=True):
        if a <= 0:
            continue
        rets.append((float(b) - float(a)) / float(a))
    return statistics.pstdev(rets) if len(rets) >= 2 else 0.0


class Controller:
    def decide(self, *, epoch: int, state: SimState, ctx: "EpochContext") -> Knobs:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class EpochContext:
    volume: int
    base_fees_gross: int
    tips: int
    offsets_spent: int
    net_fees: int
    bids: list[Bid]
    opi_shock_bps: int
    locked_pv_now_agrs: int


class BaselineController(Controller):
    def decide(self, *, epoch: int, state: SimState, ctx: EpochContext) -> Knobs:
        return state.knobs


class RandomController(Controller):
    def __init__(self, seed: int) -> None:
        self._seed = seed

    def decide(self, *, epoch: int, state: SimState, ctx: EpochContext) -> Knobs:
        rng = random.Random(stable_seed(self._seed, epoch, "strategy"))
        candidates = [k for d in DELTAS if (k := state.knobs.try_apply(d)) is not None]
        if not candidates:
            return state.knobs
        return rng.choice(candidates)


class ProfitUtilityController(Controller):
    def __init__(
        self,
        *,
        churn_penalty_agrs: int,
        reserve_floor_agrs: int,
        fixed: FixedParams,
        models: SimModels,
    ) -> None:
        self._churn_penalty = max(0, churn_penalty_agrs)
        self._reserve_floor = max(0, reserve_floor_agrs)
        self._fixed = fixed
        self._models = models

    def decide(self, *, epoch: int, state: SimState, ctx: EpochContext) -> Knobs:
        best: tuple[int, int, int, Knobs] | None = None
        for d in DELTAS:
            nxt = state.knobs.try_apply(d)
            if nxt is None:
                continue

            nw_total, reserve_end, _opi_end, _bcr_end, _price_end, _locked_pv_end, _rev_next = (
                candidate_transition(
                    epoch=epoch,
                    state=state,
                    ctx=ctx,
                    candidate=nxt,
                    fixed=self._fixed,
                    models=self._models,
                    locked_pv_now=ctx.locked_pv_now_agrs,
                )
            )
            score = nw_total
            churn = state.knobs.l1_distance(nxt)
            score -= self._churn_penalty * churn

            # Fail-closed reserve floor (protocol reserve is tracked separately from auction carry).
            if reserve_end < self._reserve_floor:
                continue

            # Deterministic tie-breakers: higher score, lower churn, lower key.
            cand = (score, -churn, -nxt.key(), nxt)
            if best is None or cand > best:
                best = cand
        return best[3] if best is not None else state.knobs


class OpiFirstController(Controller):
    def __init__(
        self,
        *,
        revenue_floor_agrs: int,
        fixed: FixedParams,
        models: SimModels,
    ) -> None:
        self._revenue_floor = max(0, revenue_floor_agrs)
        self._fixed = fixed
        self._models = models

    def decide(self, *, epoch: int, state: SimState, ctx: EpochContext) -> Knobs:
        best: tuple[int, int, int, int, Knobs] | None = None
        for d in DELTAS:
            nxt = state.knobs.try_apply(d)
            if nxt is None:
                continue

            _nw_total, _reserve_end, opi_end, _bcr_end, _price_end, _locked_pv_end, revenue_next = (
                candidate_transition(
                    epoch=epoch,
                    state=state,
                    ctx=ctx,
                    candidate=nxt,
                    fixed=self._fixed,
                    models=self._models,
                    locked_pv_now=ctx.locked_pv_now_agrs,
                )
            )
            if revenue_next < self._revenue_floor:
                continue

            churn = state.knobs.l1_distance(nxt)
            # Deterministic tie-breakers: higher OPI, higher revenue_next, lower churn, lower key.
            cand = (opi_end, revenue_next, -churn, -nxt.key(), nxt)
            if best is None or cand > best:
                best = cand
        return best[4] if best is not None else state.knobs


@dataclass(frozen=True, slots=True)
class FixedParams:
    # profit-first rails (kept fixed in this sim)
    ops_floor_agrs: int
    ops_pay_bps: int
    overhead_bps: int
    reserve_target_agrs: int

    # BCR supply
    total_staked_agrs: int


@dataclass(frozen=True, slots=True)
class SimModels:
    demand: DemandModel
    auction: AuctionModel
    valuation: ValuationModel
    opi: OpiModel


def price_center_bps(
    *,
    base_fees_gross: int,
    bcr_supply: int,
    opi_bps: int,
    ema_bps: int,
    max_offset_epoch_bps: int,
) -> int:
    # Heuristic "fundamental": BCR is more valuable when offset capacity is high relative to supply.
    offset_cap = max(1, floor_bps(base_fees_gross, max_offset_epoch_bps))
    ratio = float(bcr_supply) / float(offset_cap)
    pressure = ratio / (1.0 + ratio)  # in [0,1)
    fundamental = int(round(10_000 - 2_500 * pressure))  # 7500..10000
    fundamental = clamp_int(fundamental + (opi_bps - 8_000) // 10, 5_000, 10_000)
    # Blend with EMA to avoid extreme jumps in bid centers.
    blended = int(round(0.7 * float(ema_bps) + 0.3 * float(fundamental)))
    return clamp_int(blended, 0, 10_000)


def compute_budgets(
    *,
    net_fees: int,
    knobs: Knobs,
    fixed: FixedParams,
) -> tuple[int, int, int, int, int, int, int, int]:
    """
    Mirrors `TokenomicsV6::finalize_epoch` budget rails at a high level.

    Returns:
      (ops_budget, ops_overhead, ops_payroll, reserve_budget, burn_surplus, auction_new, unallocated, surplus)
    """
    ops_floor_pct = floor_bps(net_fees, fixed.ops_pay_bps)
    ops_floor_epoch = max(fixed.ops_floor_agrs, ops_floor_pct)
    ops_budget = min(net_fees, ops_floor_epoch)
    ops_overhead = floor_bps(ops_budget, fixed.overhead_bps)
    ops_payroll = max(0, ops_budget - ops_overhead)

    reserve_budget = min(max(0, net_fees - ops_budget), fixed.reserve_target_agrs)
    surplus = max(0, net_fees - ops_budget - reserve_budget)

    burn_surplus = floor_bps(surplus, knobs.burn_bps())
    auction_new = floor_bps(surplus, knobs.auction_bps())
    unallocated = max(0, surplus - burn_surplus - auction_new)
    return (
        ops_budget,
        ops_overhead,
        ops_payroll,
        reserve_budget,
        burn_surplus,
        auction_new,
        unallocated,
        surplus,
    )


def compute_net_worth(
    *,
    reserve_agrs: int,
    unallocated_agrs: int,
    auction_carry_agrs: int,
    operator_liquid_agrs: int,
    locked_pv_agrs: int,
    bcr_supply: int,
    bcr_price_ema_bps: int,
) -> tuple[int, int, int, int]:
    nw_protocol = reserve_agrs + unallocated_agrs + auction_carry_agrs
    nw_locked = locked_pv_agrs
    nw_bcr = payout_for(bcr_supply, bcr_price_ema_bps)
    nw = nw_protocol + operator_liquid_agrs + nw_locked + nw_bcr
    return nw, nw_protocol, nw_locked, nw_bcr


def candidate_transition(
    *,
    epoch: int,
    state: SimState,
    ctx: EpochContext,
    candidate: Knobs,
    fixed: FixedParams,
    models: SimModels,
    # PV of locked schedule after unlocking at epoch start (avoids dict cloning for scoring).
    locked_pv_now: int,
) -> tuple[int, int, int, int, int, int, int]:
    """
    Apply the candidate knobs for the remainder of this epoch and return:
      (nw_total_end, reserve_end, opi_end, bcr_supply_end, bcr_price_ema_end, locked_pv_end, revenue_next_expected)
    """
    (
        _ops_budget,
        _ops_overhead,
        ops_payroll,
        reserve_budget,
        _burn_surplus,
        auction_new,
        unallocated,
        _surplus,
    ) = compute_budgets(net_fees=ctx.net_fees, knobs=candidate, fixed=fixed)

    reserve_end = state.reserve_agrs + reserve_budget
    unallocated_end = state.unallocated_agrs + unallocated
    operator_liquid_end = state.operator_liquid_agrs + ops_payroll  # tips already credited during fees stage
    clear = models.auction.clear(budget_agrs=auction_new, bids=ctx.bids, carry_in_agrs=state.auction_carry_agrs)

    bcr_after_auction = max(0, state.bcr_supply - clear.bcr_burned)
    bcr_minted = floor_bps(fixed.total_staked_agrs, candidate.drip_bps())
    bcr_end = bcr_after_auction + bcr_minted

    bcr_price_ema_end = models.valuation.update_price_ema(
        prev_ema_bps=state.bcr_price_ema_bps,
        observed_price_bps=clear.clearing_price_bps,
    )

    # Locked PV advances by the PV of newly locked payout at (epoch + lock_epochs).
    locked_pv_end = locked_pv_now + models.valuation.discount(
        amount_agrs=clear.payout_sum_agrs,
        epochs=models.auction.payout_lock_epochs,
    )

    # OPI update (for next epoch) depends on drip + clearing price + reserve and a single exogenous shock.
    operator_cashflow = ctx.tips + ops_payroll
    opi_end = models.opi.next_opi(
        opi_bps=state.opi_bps,
        operator_cashflow_agrs=operator_cashflow,
        drip_bps=candidate.drip_bps(),
        clearing_price_bps=clear.clearing_price_bps,
        reserve_agrs=reserve_end,
        shock_bps=ctx.opi_shock_bps,
    )

    auction_carry_end = clear.carry_out_agrs

    nw_total, _nw_protocol, locked_pv_check, _nw_bcr = compute_net_worth(
        reserve_agrs=reserve_end,
        unallocated_agrs=unallocated_end,
        auction_carry_agrs=auction_carry_end,
        operator_liquid_agrs=operator_liquid_end,
        locked_pv_agrs=locked_pv_end,
        bcr_supply=bcr_end,
        bcr_price_ema_bps=bcr_price_ema_end,
    )
    # Internal sanity: should match.
    if locked_pv_check != locked_pv_end:
        raise AssertionError("locked PV mismatch (bug)")

    revenue_next = models.demand.expected_net_fees(opi_bps=opi_end, bcr_supply=bcr_end)
    return (
        nw_total,
        reserve_end,
        opi_end,
        bcr_end,
        bcr_price_ema_end,
        locked_pv_end,
        revenue_next,
    )
def run_simulation(*, seed: int, epochs: int, controller: Controller, state: SimState, fixed: FixedParams, models: SimModels) -> list[EpochRecord]:
    if epochs <= 0:
        raise ValueError("--epochs must be > 0")

    records: list[EpochRecord] = []

    for e in range(epochs):
        state.epoch = e

        # Unlock previously locked AGRS payouts (operator side).
        unlocked = state.locked_by_unlock.pop(e, 0)
        if unlocked:
            state.operator_liquid_agrs += unlocked

        # Demand stage.
        rng_demand = random.Random(stable_seed(seed, e, "demand"))
        rng_tips = random.Random(stable_seed(seed, e, "tips"))
        volume = models.demand.sample_volume(opi_bps=state.opi_bps, bcr_supply=state.bcr_supply, rng=rng_demand)

        # Fees stage (base fees + tips; offsets burn BCR, reduce net fees).
        base_fees_gross = volume * models.demand.base_fee_agrs_per_unit
        tips = models.demand.sample_tips(base_fees_gross=base_fees_gross, opi_bps=state.opi_bps, rng=rng_tips)

        offsets_spent = models.demand.offset_for_base_fees(base_fees_gross=base_fees_gross, bcr_supply=state.bcr_supply)
        offsets_spent = min(offsets_spent, state.bcr_supply)
        state.bcr_supply -= offsets_spent
        net_fees = base_fees_gross - offsets_spent

        # Tips are paid directly to operators (outside protocol budgets).
        state.operator_liquid_agrs += tips

        # Prepare bids (truthful baseline: min_price ~ private value distribution).
        rng_bids = random.Random(stable_seed(seed, e, "bids"))
        center = price_center_bps(
            base_fees_gross=base_fees_gross,
            bcr_supply=state.bcr_supply,
            opi_bps=state.opi_bps,
            ema_bps=state.bcr_price_ema_bps,
            max_offset_epoch_bps=models.demand.max_offset_epoch_bps,
        )
        bids = models.auction.generate_bids(total_bcr=state.bcr_supply, price_center_bps=center, rng=rng_bids)

        # Exogenous OPI shock (applied after rewards).
        rng_opi = random.Random(stable_seed(seed, e, "opi"))
        opi_shock = models.opi.sample_shock(rng_opi)

        locked_pv_now = models.valuation.pv_locked(locked_by_unlock=state.locked_by_unlock, now_epoch=e)

        ctx = EpochContext(
            volume=volume,
            base_fees_gross=base_fees_gross,
            tips=tips,
            offsets_spent=offsets_spent,
            net_fees=net_fees,
            bids=bids,
            opi_shock_bps=opi_shock,
            locked_pv_now_agrs=locked_pv_now,
        )

        knobs_prev = state.knobs
        knobs = controller.decide(epoch=e, state=state, ctx=ctx)
        churn = knobs_prev.l1_distance(knobs)
        state.knobs = knobs

        (
            _ops_budget,
            ops_overhead,
            ops_payroll,
            reserve_budget,
            burn_surplus,
            auction_new,
            unallocated_new,
            _surplus,
        ) = compute_budgets(net_fees=net_fees, knobs=knobs, fixed=fixed)

        # Apply budgets (protocol + operators).
        state.reserve_agrs += reserve_budget
        state.unallocated_agrs += unallocated_new
        state.burned_total_agrs += burn_surplus
        state.operator_liquid_agrs += ops_payroll

        # Auction stage.
        auction_available = auction_new + state.auction_carry_agrs
        clear = models.auction.clear(budget_agrs=auction_new, bids=bids, carry_in_agrs=state.auction_carry_agrs)
        state.auction_carry_agrs = clear.carry_out_agrs
        state.burned_total_agrs += clear.burn_excess_agrs

        bcr_burned_auction = min(clear.bcr_burned, state.bcr_supply)
        state.bcr_supply -= bcr_burned_auction

        if clear.payout_sum_agrs:
            unlock_epoch = e + models.auction.payout_lock_epochs
            state.locked_by_unlock[unlock_epoch] = state.locked_by_unlock.get(unlock_epoch, 0) + clear.payout_sum_agrs

        # Rewards stage (BCR drip).
        bcr_minted = floor_bps(fixed.total_staked_agrs, knobs.drip_bps())
        state.bcr_supply += bcr_minted

        # Valuation update.
        state.bcr_price_ema_bps = models.valuation.update_price_ema(
            prev_ema_bps=state.bcr_price_ema_bps,
            observed_price_bps=clear.clearing_price_bps,
        )

        # OPI update (for next epoch).
        operator_cashflow = tips + ops_payroll
        state.opi_bps = models.opi.next_opi(
            opi_bps=state.opi_bps,
            operator_cashflow_agrs=operator_cashflow,
            drip_bps=knobs.drip_bps(),
            clearing_price_bps=clear.clearing_price_bps,
            reserve_agrs=state.reserve_agrs,
            shock_bps=opi_shock,
        )

        locked_pv = models.valuation.pv_locked(locked_by_unlock=state.locked_by_unlock, now_epoch=e)
        nw_total, nw_protocol, nw_locked, nw_bcr = compute_net_worth(
            reserve_agrs=state.reserve_agrs,
            unallocated_agrs=state.unallocated_agrs,
            auction_carry_agrs=state.auction_carry_agrs,
            operator_liquid_agrs=state.operator_liquid_agrs,
            locked_pv_agrs=locked_pv,
            bcr_supply=state.bcr_supply,
            bcr_price_ema_bps=state.bcr_price_ema_bps,
        )

        records.append(
            EpochRecord(
                epoch=e,
                knobs=knobs,
                knobs_prev=knobs_prev,
                churn_l1=churn,
                volume=volume,
                base_fees_gross=base_fees_gross,
                tips=tips,
                offsets_spent=offsets_spent,
                net_fees=net_fees,
                burn_surplus=burn_surplus,
                auction_new=auction_new,
                unallocated_new=unallocated_new,
                reserve_in=reserve_budget,
                reserve_end_agrs=state.reserve_agrs,
                ops_payroll=ops_payroll,
                ops_overhead=ops_overhead,
                auction_available=auction_available,
                auction_clearing_price_bps=clear.clearing_price_bps,
                auction_winners=clear.winners,
                auction_payout=clear.payout_sum_agrs,
                auction_carry_end=state.auction_carry_agrs,
                auction_burn_excess=clear.burn_excess_agrs,
                bcr_burned_auction=bcr_burned_auction,
                bcr_minted=bcr_minted,
                opi_end=state.opi_bps,
                bcr_supply_end=state.bcr_supply,
                bcr_price_ema_end_bps=state.bcr_price_ema_bps,
                nw_total=nw_total,
                nw_protocol_agrs=nw_protocol,
                nw_operator_liquid_agrs=state.operator_liquid_agrs,
                nw_operator_locked_pv_agrs=nw_locked,
                nw_bcr_mtm_agrs=nw_bcr,
            )
        )

    return records


def build_controller(
    *,
    strategy: str,
    seed: int,
    churn_penalty_agrs: int,
    reserve_floor_agrs: int,
    revenue_floor_agrs: int,
    fixed: FixedParams,
    models: SimModels,
) -> Controller:
    if strategy == "baseline":
        return BaselineController()
    if strategy == "random":
        return RandomController(seed)
    if strategy == "profit_utility":
        return ProfitUtilityController(
            churn_penalty_agrs=churn_penalty_agrs,
            reserve_floor_agrs=reserve_floor_agrs,
            fixed=fixed,
            models=models,
        )
    if strategy == "opi_first":
        return OpiFirstController(
            revenue_floor_agrs=revenue_floor_agrs,
            fixed=fixed,
            models=models,
        )
    raise ValueError(f"unknown strategy: {strategy}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=365)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument(
        "--strategy",
        type=str,
        default="baseline",
        choices=["baseline", "profit_utility", "opi_first", "random"],
    )
    ap.add_argument("--burn-units", type=int, default=30, help="initial burn units (0..45)")
    ap.add_argument("--auction-units", type=int, default=10, help="initial auction units (5..50)")
    ap.add_argument("--drip-units", type=int, default=10, help="initial drip units (1..20)")
    ap.add_argument("--initial-bcr", type=int, default=200_000, help="initial outstanding BCR (>= 0)")
    ap.add_argument("--initial-opi-bps", type=int, default=8_000, help="initial OPI in bps (0..10_000)")
    ap.add_argument("--initial-bcr-price-bps", type=int, default=9_000, help="initial BCR mtm price EMA (0..10_000)")

    ap.add_argument(
        "--bcr-price-ema-alpha-bps",
        type=int,
        default=2_000,
        help="BCR price EMA alpha in bps (0..10_000); higher = faster but noisier",
    )
    ap.add_argument(
        "--opi-adjust-bps",
        type=int,
        default=2_000,
        help="OPI adjustment alpha in bps (0..10_000); higher = faster but noisier",
    )
    ap.add_argument(
        "--opi-shock-sigma-bps",
        type=int,
        default=150,
        help="OPI exogenous shock sigma (bps, >= 0); 0 disables shocks",
    )

    ap.add_argument("--churn-penalty-agrs", type=int, default=50, help="profit_utility: penalty per L1 unit moved")
    ap.add_argument("--reserve-floor-agrs", type=int, default=0, help="profit_utility: reject moves that end < floor")
    ap.add_argument("--revenue-floor-agrs", type=int, default=60_000, help="opi_first: required expected next-epoch net fees")
    ap.add_argument("--json", action="store_true", help="emit a machine-readable JSON summary only")
    args = ap.parse_args()

    if args.epochs <= 0:
        raise SystemExit("--epochs must be > 0")
    if args.churn_penalty_agrs < 0:
        raise SystemExit("--churn-penalty-agrs must be >= 0")
    if args.reserve_floor_agrs < 0:
        raise SystemExit("--reserve-floor-agrs must be >= 0")
    if args.revenue_floor_agrs < 0:
        raise SystemExit("--revenue-floor-agrs must be >= 0")
    if args.initial_bcr < 0:
        raise SystemExit("--initial-bcr must be >= 0")
    if not (0 <= args.initial_opi_bps <= BPS):
        raise SystemExit("--initial-opi-bps must be in [0,10_000]")
    if not (0 <= args.initial_bcr_price_bps <= BPS):
        raise SystemExit("--initial-bcr-price-bps must be in [0,10_000]")
    if not (0 <= args.bcr_price_ema_alpha_bps <= BPS):
        raise SystemExit("--bcr-price-ema-alpha-bps must be in [0,10_000]")
    if not (0 <= args.opi_adjust_bps <= BPS):
        raise SystemExit("--opi-adjust-bps must be in [0,10_000]")
    if args.opi_shock_sigma_bps < 0:
        raise SystemExit("--opi-shock-sigma-bps must be >= 0")

    knobs0 = Knobs(burn_units=args.burn_units, auction_units=args.auction_units, drip_units=args.drip_units)

    fixed = FixedParams(
        ops_floor_agrs=15_000,
        ops_pay_bps=1_500,
        overhead_bps=500,
        reserve_target_agrs=25_000,
        total_staked_agrs=2_000_000,
    )

    models = SimModels(
        demand=DemandModel(
            base_fee_agrs_per_unit=10,
            baseline_volume=10_000,
            volume_cap=50_000,
            price_elasticity=1.15,
            quality_elasticity=1.0,
            opi_ref_bps=8_000,
            demand_noise_sigma=0.05,
            max_offset_epoch_bps=2_000,
            desire_offset_bps=5_000,
            tip_rate_bps=500,
            tip_opi_elasticity=0.5,
            tip_noise_sigma=0.10,
        ),
        auction=AuctionModel(
            sell_fraction_bps=2_000,
            n_bids=80,
            price_spread_bps=900,
            carry_cap_agrs=5_000_000,
            payout_lock_epochs=14,
        ),
        valuation=ValuationModel(
            ema_alpha_bps=args.bcr_price_ema_alpha_bps,
            price_min_bps=2_000,
            price_max_bps=10_000,
            discount_bps_per_epoch=9_950,
        ),
        opi=OpiModel(
            opi_adjust_bps=args.opi_adjust_bps,
            base_opi_bps=6_500,
            cashflow_scale_agrs=20_000,
            cashflow_weight_bps=2_000,
            drip_weight_bps=2_000,
            liquidity_weight_bps=1_500,
            reserve_weight_bps=1_000,
            reserve_target_agrs=fixed.reserve_target_agrs,
            shock_sigma_bps=args.opi_shock_sigma_bps,
        ),
    )

    controller = build_controller(
        strategy=args.strategy,
        seed=args.seed,
        churn_penalty_agrs=args.churn_penalty_agrs,
        reserve_floor_agrs=args.reserve_floor_agrs,
        revenue_floor_agrs=args.revenue_floor_agrs,
        fixed=fixed,
        models=models,
    )

    state = SimState(
        epoch=0,
        knobs=knobs0,
        reserve_agrs=0,
        unallocated_agrs=0,
        auction_carry_agrs=0,
        burned_total_agrs=0,
        opi_bps=args.initial_opi_bps,
        bcr_supply=args.initial_bcr,
        bcr_price_ema_bps=args.initial_bcr_price_bps,
        operator_liquid_agrs=0,
        locked_by_unlock={},
    )

    records = run_simulation(
        seed=args.seed,
        epochs=args.epochs,
        controller=controller,
        state=state,
        fixed=fixed,
        models=models,
    )

    nw = [r.nw_total for r in records]
    opi = [r.opi_end for r in records]
    reserve = [r.reserve_end_agrs for r in records]
    churn = [r.churn_l1 for r in records]

    dd = compute_drawdown(nw)
    vol = compute_volatility(nw)

    opi_sorted = sorted(opi)
    reserve_sorted = sorted(reserve)
    churn_events = sum(1 for c in churn if c != 0)

    last = records[-1]
    summary = {
        "epochs": args.epochs,
        "seed": args.seed,
        "strategy": args.strategy,
        "params": {
            "bcr_price_ema_alpha_bps": args.bcr_price_ema_alpha_bps,
            "opi_adjust_bps": args.opi_adjust_bps,
            "opi_shock_sigma_bps": args.opi_shock_sigma_bps,
        },
        "initial": {
            "burn_bps": knobs0.burn_bps(),
            "auction_bps": knobs0.auction_bps(),
            "drip_bps": knobs0.drip_bps(),
            "opi_bps": args.initial_opi_bps,
            "bcr_supply": args.initial_bcr,
            "bcr_price_ema_bps": args.initial_bcr_price_bps,
        },
        "final": {
            "burn_bps": last.knobs.burn_bps(),
            "auction_bps": last.knobs.auction_bps(),
            "drip_bps": last.knobs.drip_bps(),
            "opi_bps": last.opi_end,
            "bcr_supply": last.bcr_supply_end,
            "bcr_price_ema_bps": last.bcr_price_ema_end_bps,
            "nw_total": last.nw_total,
            "nw_protocol": last.nw_protocol_agrs,
            "nw_operator_liquid": last.nw_operator_liquid_agrs,
            "nw_operator_locked_pv": last.nw_operator_locked_pv_agrs,
            "nw_bcr_mtm": last.nw_bcr_mtm_agrs,
            "reserve_end": last.reserve_end_agrs,
        },
        "metrics": {
            "max_drawdown": dd,
            "volatility": vol,
            "opi_mean": statistics.mean(opi),
            "opi_p05": quantile(opi_sorted, 0.05),
            "opi_p50": quantile(opi_sorted, 0.5),
            "opi_p95": quantile(opi_sorted, 0.95),
            "reserve_min": min(reserve),
            "reserve_p05": int(round(quantile(reserve_sorted, 0.05))),
            "churn_events": churn_events,
            "churn_l1_total": sum(churn),
            "churn_l1_avg": statistics.mean(churn),
        },
    }

    if args.json:
        print(json.dumps(summary, sort_keys=True))
        return

    print("# Algorithmic CEO — Economic Simulation (deterministic)\n")
    print(f"epochs={summary['epochs']} seed={summary['seed']} strategy={summary['strategy']}")
    print(
        "initial_knobs: "
        f"burn={summary['initial']['burn_bps']} auction={summary['initial']['auction_bps']} drip={summary['initial']['drip_bps']} (bps)"
    )
    print(
        "final_knobs:   "
        f"burn={summary['final']['burn_bps']} auction={summary['final']['auction_bps']} drip={summary['final']['drip_bps']} (bps)"
    )

    print("\n## Final balances (AGRS)\n")
    print(f"NW_total:              {fmt_int(summary['final']['nw_total'])}")
    print(f"  protocol (reserve+unalloc+carry): {fmt_int(summary['final']['nw_protocol'])}")
    print(f"  operators liquid:               {fmt_int(summary['final']['nw_operator_liquid'])}")
    print(f"  operators locked PV:            {fmt_int(summary['final']['nw_operator_locked_pv'])}")
    print(
        f"  BCR mtm (EMA):                  {fmt_int(summary['final']['nw_bcr_mtm'])} @ {summary['final']['bcr_price_ema_bps']} bps"
    )

    print("\n## Risk + behavior\n")
    print(f"max drawdown (NW):     {pct(summary['metrics']['max_drawdown'])}")
    print(f"volatility (NW):       {pct(summary['metrics']['volatility'])}")
    print(
        "OPI mean/median/p5/p95: "
        f"{summary['metrics']['opi_mean']:.1f} / {summary['metrics']['opi_p50']:.1f} / "
        f"{summary['metrics']['opi_p05']:.1f} / {summary['metrics']['opi_p95']:.1f}"
    )
    print(
        "reserve end/min/p5:    "
        f"{fmt_int(summary['final']['reserve_end'])} / {fmt_int(summary['metrics']['reserve_min'])} / {fmt_int(summary['metrics']['reserve_p05'])}"
    )
    print(
        "parameter churn:       "
        f"events={summary['metrics']['churn_events']}/{summary['epochs']} "
        f"total_L1={summary['metrics']['churn_l1_total']} avg_L1={summary['metrics']['churn_l1_avg']:.2f}"
    )


if __name__ == "__main__":
    main()
