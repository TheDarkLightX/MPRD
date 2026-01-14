# Policy Certification (ROBDD rail)

MPRD’s **Policy Algebra** is designed to be “safe to change”: canonical, bounded, deterministic, fail‑closed.

This doc describes an additional rail: compiling a policy to a **canonical ROBDD** (reduced ordered binary decision diagram)
and using that to:
- compute a **semantic hash** (hash of the boolean function, not just the syntax bytes)
- perform **semantic diffs** with concrete counterexamples

This is a developer/tooling rail intended to reduce “silent policy regressions” during refactors and upgrades.

## Why ROBDD?

Given a fixed variable order, a reduced ordered BDD is a canonical representation of a boolean function.
This makes semantic comparison cheap:
- `equivalent(p, q)` becomes “are their ROBDDs identical?” (or, in our implementation, “does `p XOR q` reduce to False?”).

## What is certified / what is not

This rail is intentionally scoped to the **booleanizable subset** of Policy Algebra:
- `True`, `False`, `Atom`, `Not`, `All`, `Any`
- `DenyIf(atom)` supported **only** as a *global veto* (must not appear under `Not`)
- `Threshold(k, children)` supported for all `0 <= k <= n` (compiled via a deterministic DP)

It **does** model “missing signals” (fail‑closed behavior) by lowering each signal `a` into two boolean bits:
- `p_a`: presence bit (1 if present)
- `v_a`: value bit (1 if true; required to be 0 when missing)

Under this lowering:
- `Atom(a)` becomes `p_a ∧ v_a` (missing denies)
- each `DenyIf(a)` adds a veto constraint `p_a ∧ ¬v_a` (missing vetoes)

## CLI usage

### Semantic hash

Compute a stable semantic hash for a policy:

```bash
mprd policy algebra-bdd-hash --policy path/to/policy.pal
```

This outputs:
- `robdd_hash_v1`: a domain‑separated hash over the canonical variable order + the ROBDD function structure.

### Semantic diff + counterexample

Compare two policies:

```bash
mprd policy algebra-diff --a old.pal --b new.pal
```

If not equivalent, it prints a concrete assignment (a counterexample) showing how they differ.
Counterexamples are shown over **signals** as `missing|true|false`.

### Certify an emitted Tau gate

To ensure the emitted sbf-only Tau gate matches the Policy Algebra semantics (for the booleanizable subset),
you can certify equivalence via ROBDD:

```bash
mprd policy algebra-certify-tau --policy path/to/policy.pal --tau path/to/gate.tau --output-name allow
```

The emitted v2 gate uses presence bits, so it expects inputs:
- `inputs/p_<signal>.in` (presence)
- `inputs/v_<signal>.in` (value)

If not equivalent, it prints a concrete counterexample assignment over the policy’s signals.

## API usage (Rust)

`mprd_core::policy_algebra` exports:
- `compile_allow_robdd(expr, limits) -> Robdd`
- `policy_equiv_robdd(a, b, limits) -> BddEquivResult`
 - `parse_emitted_tau_gate_allow_expr_v1(tau_source, output_name, limits) -> PolicyExpr`
 - `policy_equiv_robdd_policy_vs_tau_bits(policy, tau_bits, limits) -> BddEquivResult`

## Next steps (if we want stronger certification)

The current rail is “semantic hashing + counterexample diff”. If we want *proof-carrying* certification, the next steps are:
- emit SAT proofs (e.g., DRAT) for equivalence checks and verify them with a small checker, or
- run compilation inside a zkVM and bind the artifact to a receipt.

## Machine-checked semantics artifact (Lean)

We also maintain a mathlib-backed Lean formalization of the **veto-first** semantics and the
core booleanization lemma (“veto passes and main-allow holds iff evaluation returns Allow”):

- `internal/MPRD_PolicyAlgebra.lean`

This is currently an internal proof artifact that is useful for auditing and for keeping the
compiler and evaluator semantics aligned over time.

## Decision-quality benchmark (eval vs ROBDD)

To quantify when the ROBDD rail is worth it (compile-once vs eval-many), use the reproducible
benchmark harness:

```bash
cd /home/trevormoc/Downloads/MPRD
cargo run -q -p mprd-perf -- --bench policy --policy-atoms 12 --policy-depth 4 --policy-env-iters 20000 --json
```

To run a small sweep and print break-even points:

```bash
cd /home/trevormoc/Downloads/MPRD
cargo run -q -p mprd-perf -- --bench policy --policy-atoms-list 6,8,10,12 --policy-depth-list 2,3,4,5 --policy-env-iters 5000 --json > /tmp/policy_sweep.json
python3 tools/policy/summarize_policy_sweep.py /tmp/policy_sweep.json
```

The summarizer **fails non-zero** if any row has `agree_prefix_256=false` (a semantics mismatch),
so it can be used as a strict CI-style gate.

### One-command gate

For a single, fail-closed command that runs the key property tests plus the sweep gate:

```bash
cd /home/trevormoc/Downloads/MPRD
bash tools/policy/check_policy_rail.sh
```
