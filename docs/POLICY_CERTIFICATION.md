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
- `Threshold(k, children)` supported only for `k==0` or `k==n` (otherwise rejected)

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
