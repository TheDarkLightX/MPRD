# Policy Algebra (Core)

This repo uses “Policy Algebra” as the **universal gating layer**: every state transition on a trust boundary must be authorized by an explicit, deterministic, fail-closed predicate (e.g., `Allowed(policy, state, action)` / `Allowed_op`).

The Rust kernel for this lives at `crates/mprd-core/src/policy_algebra/`.

## Goals

- **CBC-first:** make invalid policy states hard to represent (bounded arity, validated atoms).
- **Deterministic:** canonicalization + evaluation order are stable (hashes and traces are reproducible).
- **Fail-closed:** missing/unknown inputs deny.
- **Bounded:** max nodes, max children, max trace entries.

## What it is (today)

`mprd_core::policy_algebra` is a small, IO-free boolean policy core:

- `PolicyExpr`: a bounded policy AST over boolean “signals”
  - `All`, `Any`, `Not`, `Threshold`, leaf `Atom`
  - special leaf `DenyIf(atom)` which acts as an **absorbing veto guard**
- `CanonicalPolicy`: canonicalizes a `PolicyExpr` (flatten/dedup/sort/bounds) and computes a stable hash.
- `evaluate`: deterministic evaluation with a bounded `PolicyTrace`.

## `DenyIf` semantics (important)

Evaluation is **veto-first**:

1. Collect all `DenyIf(atom)` occurrences in the policy (anywhere in the tree).
2. Evaluate those signals first:
   - if any is `true` → `DenyVeto`
   - if any is missing → `DenyVeto` (fail-closed)
3. Evaluate the rest of the policy with `DenyIf(_)` treated as `Neutral`.

This prevents “short-circuit allow” from bypassing a veto.

## Example

Express “allow if `link_ok` and (`is_admin` or `is_self`) and NOT blacklisted”:

```rust
use mprd_core::policy_algebra::*;

let lim = PolicyLimits::DEFAULT;
let p = PolicyExpr::all(
    vec![
        PolicyExpr::atom("link_ok", lim)?,
        PolicyExpr::any(
            vec![
                PolicyExpr::atom("is_admin", lim)?,
                PolicyExpr::atom("is_self", lim)?,
            ],
            lim,
        )?,
        PolicyExpr::deny_if("is_blacklisted", lim)?,
    ],
    lim,
)?;

let canon = CanonicalPolicy::new(p, lim)?;
let policy_hash = canon.hash_v1();
```

## Integration patterns

- **Tokenomics v6:** the state machine is pure (`TokenomicsV6::apply`) and is gated via `PolicyGateV6`.
  Tau specs in `policies/tokenomics/canonical/` are the intended production “Allowed_op” artifacts today.
  The policy algebra core is a building block for:
  - generating canonical gate structure,
  - semantic diffing and property checking,
  - future compilation targets.

- **Main MPRD pipeline:** the core `PolicyEngine` trait evaluates candidate actions under an authorized `policy_hash`.

