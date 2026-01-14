# Algorithmic CEO Menu Modes (UX + Use-Case Analysis)

This note evaluates whether a **k-way simplex menu** (constant-sum allocation) is worth adopting over the current v6 “safe menu graph” for operator-setpoint control.

## Current v6 menu (what you have)

The menu node is effectively a product:

- **Split lane (2D with cap):**
  - `burn_surplus_bps ∈ [5000, 9500]` (100 bps steps)
  - `auction_surplus_bps ∈ [500, 5000]` (100 bps steps)
  - constraint: `burn + auction ≤ 10_000`
  - implicit remainder: `unallocated = 10_000 - burn - auction`
- **Drip lane (1D):**
  - `drip_rate_bps ∈ [5, 100]` (5 bps steps)

So the split is already a simplex-like object: it’s a **3-way split** (`burn`, `auction`, `unallocated`) represented with only **2 degrees of freedom**.

## What “k-way simplex” means

Represent the split as a bounded vector of allocations:

`x ∈ Nat^k,  ∑ xᵢ = 10_000`  (or a lattice-scaled version)

An action is a *unit transfer* `i→j`:
- decreases one bucket by 1 unit
- increases another bucket by 1 unit
- preserves the sum by construction

## UX / operator use-cases where simplex is better

1. **More buckets without more “cap math”**
   - Once you add buckets (reserve, buyback, insurance, grants, etc.), independent sliders with pairwise caps get confusing.
   - A simplex UI (stacked bar / pie / allocation sliders) makes “always sums to 100%” obvious.

2. **Safer interaction design**
   - The UI can enforce constant-sum automatically: no “invalid slider combination” states.
   - Mode toggles become straightforward: enabling/disabling buckets just changes which coordinates are visible/editable.

3. **Presets / profiles**
   - “Deflationary”, “Liquidity-first”, “Growth”, “Auction-heavy” become named points in the simplex.
   - The CEO can then do bounded, auditable moves between presets.

4. **Policy gating is cleaner**
   - `∑ xᵢ = 10_000` can be made CBC (unrepresentable to violate).
   - Per-step limits become “max transfer units per epoch”.

## Engineering downsides / risks

1. **State-space size explodes if you precompute the full graph**
   - With lattice sum `T` and `k` buckets, node count is `C(T+k-1, k-1)` (stars and bars).
   - This is fine for `k=3..4` at moderate granularity, but quickly becomes too large for `k≥5` unless you coarsen steps.

2. **Hashing/auditing a fully materialized graph becomes expensive**
   - The current `MenuGraph::canonical_hash()` hashes the explicit node list + edges.
   - For large simplex menus, you’ll likely want a **definition hash** (`k`, ranges, step size, allowed transfer actions) rather than enumerating all nodes.

3. **“One epoch = one step” semantics change**
   - In the current 3D lattice, one action can change up to 3 coordinates simultaneously (diagonal).
   - In simplex transfers, a single action changes exactly 2 buckets.
   - This is usually OK (and arguably more interpretable), but it can feel “slower” unless you allow multiple transfers per epoch or larger unit steps.

## Recommendation

- **Keep the current v6 menu** for the current 3-knob reality: it’s already implemented, proved (Lean), and integrates well with the safety rail.
- **Adopt simplex representation when you add a 4th+ split bucket**, because that’s where UX and policy complexity start to dominate.
- **Do it as a “mode”**:
  - `Mode A (Simple)`: the existing v6 menu (burn/auction/drip).
  - `Mode B (Split-Advanced)`: simplex split across 4 buckets (e.g., burn/auction/reserve/unallocated) × drip lattice.
  - `Mode C (Expert)`: allows the advanced controller to pick targets; safety rail still enforces one bounded step.

To support toggles cleanly, treat “mode change” as a **policy-gated action** with cooldown (so it can’t be flapped).

## Implementation status (current repo)

- **Mode A**: implemented via `MenuGraph` and controllers in `crates/mprd-core/src/tokenomics_v6/{ceo.rs,ceo_lipschitz_ucb.rs}`.
- **Mode B building blocks (simplex)**: implemented as research-backed, deterministic modules:
  - Oracle: `crates/mprd-core/src/tokenomics_v6/simplex_por_oracle.rs`
  - Canonicalization + cache: `crates/mprd-core/src/tokenomics_v6/simplex_planner.rs`
  - Bounded-horizon planner: `crates/mprd-core/src/tokenomics_v6/simplex_ceo.rs`
  - Symmetry quotient key: `crates/mprd-core/src/tokenomics_v6/simplex_symmetry_key.rs`

For a one-command reproducibility gate (tests + sweep + summaries), see:
- `bash tools/ceo/check_ceo_simplex_rail.sh`
