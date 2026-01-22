# CEO Simplex POR: Integration Obligations + Next Theorem Targets

This note bridges the **certified simplex POR artifacts** into the Algorithmic CEO planning stack.

**Formal artifact**: `proofs/lean/CEO_SimplexPOR.lean`  
**Runtime oracle**: `crates/mprd-core/src/tokenomics_v6/simplex_por_oracle.rs`

---

## 1) Model recap (what is certified)

### State space
- **State**: \(x \in \mathbb{N}^k\) (bucket balances / simplex coordinates)
- **Caps**: `caps : Vec<u32>` with `x[i] ≤ caps[i]`
- (Typical simplex menu case) **Constant-sum**: \(\sum_i x_i = T\)

### Actions (unit transfers)
- **Transfer**: `a = (src → dst)` with `src != dst`
- **Enabled**: `enabled(x, caps, a)` iff `x[src] > 0` and `x[dst] < caps[dst]`
- **Step semantics**: `step_or_stay(x, caps, a)` applies the unit transfer if enabled; otherwise it is a **no-op** (fail-closed).

### Independence oracle (closed form)
`stable_enabled_ineq(x, caps, a, b)` is a **constant-time sufficient condition** implying the dynamic POR predicate:

`enabled(a,x) ∧ enabled(b,x) ∧ enabled(b, step(a,x)) ∧ enabled(a, step(b,x))`

Intuition (tight, minimal special cases):
- **Shared source** (`a.src == b.src`) requires **two units** at that source.
- **Shared destination** (`a.dst == b.dst`) requires **two slack** at that destination.

### Certified consequences (Lean)
Under `stableEnabledIneq` (the Lean analogue of `stable_enabled_ineq`):
- **Two-step commutation**: `stepOrStay a (stepOrStay b x) = stepOrStay b (stepOrStay a x)`
- **Trace adjacent-swap**: swapping adjacent actions preserves `run` when the oracle holds at the post-prefix state.
- **Swap equivalence**: `SwapEq` (RST-closure of oracle-guarded adjacent swaps) preserves `run`.
- **Deterministic canonicalization**: `canonicalize : List Action → List Action` preserves `run` and stays in the `SwapEq` class; normal-form/idempotence lemmas are proved for fixed points.

---

## 2) Where this plugs into CEO planning

The current v6 CEO uses `MenuGraph` (explicit node enumeration) for a small 3D lattice (`burn/auction/drip`).
For a future **k-way simplex menu**, explicit graph generation becomes infeasible; planning becomes a bounded search over **transfer traces** and/or reachable simplex states.

POR/canonicalization fits at two layers:

### Layer A — successor generation (state-graph search)
When expanding a state `x` at depth `d`, there can be many enabled transfers.
POR aims to explore only a subset of enabled actions (an “ample set”) while retaining completeness for reachability / best-in-horizon queries.

- **Obligation (fail-closed)**: if the oracle cannot prove independence, treat it as **dependent** (do not prune).
- **Obligation (determinism)**: tie-breaking (action ordering) must be deterministic (e.g., lexicographic key `(src,dst)`).

### Layer B — trace canonicalization (Mazurkiewicz-style quotient)
Even if you do **not** do POR at successor-generation time, you can quotient the trace space:
normalize each candidate trace to a **deterministic normal form** under oracle-justified adjacent swaps.

- **Why this helps**: if many interleavings are oracle-commutative, they collapse to the same canonical trace.
- **How to use**: when exploring bounded-depth traces, maintain a `HashSet` of canonical traces (or their hashes) and only expand a trace if its canonical form is new.

**Obligation (state-dependent swaps)**: the swap permission depends on the **post-prefix state**.
So canonicalization is not “sort by key once”; it is a deterministic, stateful normalization where each prospective adjacent swap must be justified by `stable_enabled_ineq` evaluated at the state reached by the prefix.

---

## 3) Practical integration contract (what must match the proof)

### Semantics contract (kernel)
- **Failure-as-no-op**: disabled actions MUST stutter (leave state unchanged).
- **Fail-closed**: any `UNKNOWN/TIMEOUT/parse_error` at the oracle boundary is treated as **“not independent”**.
- **Determinism**: action ordering and all tie-breakers MUST be deterministic (no RNG).

### Oracle contract (runtime ↔ Lean)
The Rust predicate `stable_enabled_ineq` must be kept in lockstep with the Lean `stableEnabledIneq`:
- Same notion of `enabled`
- Same shared-source/shared-destination margin rules
- Same early-reject behavior on malformed actions (`src==dst`, out-of-range indices, length mismatch)

### Data-structure contract (for planning)
- **State key**: canonical representation of `x` (and any other planner-relevant components).
- **Trace key (optional)**: canonicalized action list under the certified swap rules.
- **Cache**: memoize oracle calls by `(x_hash, a, b)` to keep cost \(O(1)\) amortized.

---

## 4) Mapping to the simplex geometry (A_{k-1})

For constant-sum menus, the state space is the integer simplex:
\[
  \Delta(T,k) = \{x \in \mathbb{N}^k \mid \sum_i x_i = T\}.
\]

Each transfer is the lattice move \(e_{dst} - e_{src}\), i.e., the root lattice generator of \(A_{k-1}\).
Guards (caps and nonnegativity) carve out a bounded feasible region.

This viewpoint is useful operationally:
- **Distance heuristics**: L1 distance corresponds to minimum number of unit transfers ignoring guards.
- **Symmetry quotient**: if some buckets are equivalent (same caps, same objective weights), then permuting those coordinates yields isomorphic dynamics; quotienting by that permutation group can reduce planning cost.

---

## 5) Next Lean theorem targets (draft statements)

These are the missing “complete POR story” pieces for bounded-horizon CEO planning on simplex menus.
They should be proved **fail-closed** (only prune when justified).

## 6) (1) POR completeness up to horizon via canonical trace quotient (implemented)

If your planner is “bounded-horizon” (depth ≤ h), you can get a **sound, deterministic reduction**
without needing an ample-set POR rule:

- Enumerate traces as usual (BFS/DFS/beam)
- Replace each candidate trace `xs` with `canonicalize xs` (state-dependent, oracle-justified swaps)
- Deduplicate traces by the canonical form (or its hash)

**Lean guarantee** (reachability completeness):
- `reachableWithin_via_canonicalize` proves that the set of reachable states within depth `h`
  is unchanged by canonicalizing traces (and `length_canonicalize` shows horizon is preserved).

This is an immediately usable POR story: it removes redundant interleavings whenever the oracle
permits adjacent swaps, and it is fail-closed (only swaps when justified).

## 7) (2) Symmetry quotient (state-space) (implemented)

The trace quotient above reduces redundant interleavings; symmetry quotient reduces redundant
**states** when buckets are interchangeable.

Lean now proves transposition equivariance:
- `stepOrStay_swapIJ` and `run_swapIJ` (any transposition `swap(i,j)`)

Planner contract (fail-closed):
- Only treat indices as interchangeable if their **caps and objective weights** are identical
  (and any other observables/gates treat them identically).
- Canonicalize states by sorting values inside each identical class; canonicalize actions by
  renaming indices accordingly.

Runtime helper (Rust, deterministic):
- `crates/mprd-core/src/tokenomics_v6/simplex_symmetry_key.rs` provides `symmetry_key(x,caps,weights)`,
  which groups indices by `(cap, weight)` and sorts values within each class to produce a canonical key.
  This is safe **only** when the semantics are invariant under permuting indices in each class.

## 8) Simplex-mode CEO planner (Mode B building block)

If/when we adopt a k-way simplex split menu (Mode B), the core building block is now implemented as:

- `crates/mprd-core/src/tokenomics_v6/simplex_ceo.rs`
  - `plan_best(...)`: deterministic bounded-horizon planner over unit transfers
  - Modes:
    - `TracePor`: POR canonical trace dedup (uses `simplex_planner` + `stable_enabled_ineq` oracle cache)
    - `StateSymmetry`: symmetry-class state-key dedup (uses `simplex_symmetry_key`)
    - `AmplePorDfsC2`: DFS ample-set POR with a cycle proviso (C2) and a **decision-safety visibility contract**
      for linear objectives: if any enabled move would change the linear score (`w[src] != w[dst]`), the
      planner expands all enabled actions at that state (no reduction). Reduction only occurs in
      “objective-invisible” regions where enabled moves are score-neutral.

This module is **not yet wired into** the production v6 `MenuGraph` CEO; it exists to make Mode B feasible
without precomputing an exponential menu graph.

## 8) Rail gate (one command)

To keep the simplex POR + symmetry plumbing reproducible and prevent regressions, run:

```bash
cd /home/trevormoc/Downloads/MPRD
bash tools/ceo/check_ceo_simplex_rail.sh
```

This runs core unit tests for the oracle/key and executes a bounded `mprd-perf` sweep, printing a
crossover summary via:
- `tools/ceo/summarize_ceo_simplex_sweep.py` (structural, deterministic counters)
- `tools/tokenomics/summarize_simplex_sweep.py` (time-based, informational)

### Decision-quality benchmark gate (crossover)

The rail also enforces a strict crossover gate:

- For the “expensive evaluation” regime (`eval_iters >= 200`), **symmetry quotienting must be a net win** on the sweep:
  - win_rate ≥ 0.75
  - median_ratio ≤ 1.0

This gate is implemented by:
- `tools/ceo/check_ceo_simplex_sweep_strict.py --gate sym`

### (T0) Symmetry quotient correctness (swap of interchangeable buckets)
If two buckets are observationally indistinguishable (same caps and same role in objective/gates),
then swapping them is a bisimulation/equivariance of the transition system.

- **Certified (Lean)**: `proofs/lean/CEO_SimplexPOR.lean` now contains swap-01 equivariance lemmas:
  - enabledness equivariance (`enabled_swap01_iff`)
  - guarded-step equivariance (`stepOrStay_swap01`)

**Generalization (recommended)**:
- Any finite permutation is generated by transpositions. The Lean file also includes **general transposition** lemmas:
  - `enabled_swapIJ_iff`
  - `stepOrStay_swapIJ`

This is the core building block for quotienting by *any* symmetry group on “identical bucket classes”.

**Planner use** (sound quotient):
- If `caps` is invariant under swap (in practice, `caps[0] == caps[1]` and the objective treats them identically),
  you can canonicalize states by sorting those coordinates (or applying `swap01` to enforce `x0 ≤ x1`) and deduplicate.
  This is *independent* of POR commutation; it composes with it.

### (T1) Canonicalization reaches a normal form (fixed point)
Goal: show `canonicalize xs` is a fixed point of the pass operator (or equivalent).

- **Statement sketch**:
  - `normalForm (canonicalize xs)`

### (T2) Depth-h reachability completeness under canonical trace quotient
Let `Traces(h)` be all length-≤h traces; let `CanonTraces(h) = { canonicalize xs | xs ∈ Traces(h) }`.

- **Statement sketch**:
  - For all `xs` with `length xs ≤ h`, there exists `ys` with `ys = canonicalize xs` and `run ys s = run xs s`.
  - Therefore the set of reachable states within depth `h` is unchanged by restricting to canonical traces.

### (T3) Sound ample-set POR rule derived from the oracle
Define an ample-set selection rule (e.g., pick a deterministically-minimal enabled action plus dependent closure).

- **Statement sketch**:
  - The reduced search explores a subset of traces but reaches the same set of states up to depth `h`
  - (Optional) preserves max-score objective within horizon.

### (T4) Symmetry quotient correctness (if we exploit bucket equivalence)
If two buckets are observationally indistinguishable (same caps and same role in objective/gates),
permuting them is a bisimulation.

- **Statement sketch**:
  - `run xs s` and `run (permute xs) (permute s)` correspond, and canonical representative selection is well-defined.
