# Policy Algebra

The **Policy Algebra** is MPRD's universal gating layer. Every state transition on a trust boundary must be authorized by an explicit, deterministic, fail-closed predicate.

> **Key insight:** Policy is the safety rail, not an operator privilege.

## Mental Model

| Role | Relationship to Policy |
|------|------------------------|
| **Tau Net** | **Owns** the policy (authors, reviews, deploys) |
| **Operators** | **Run** the policy (don't pick or override) |
| **Proposers/CEO** | **Subject to** the policy (actions gated) |
| **Auditors** | **Verify** the policy (reproduce decisions) |

Operators are untrusted for authorization. Tau Net owns `p`. This is fundamentally different from "operators choose their rules" — operators choose their **objective** (profit vs OPI), but the **safety rails** are not negotiable.

---

## Design Goals

- **CBC-first:** Invalid policy states are hard to represent (bounded arity, validated atoms)
- **Deterministic:** Canonicalization + evaluation order are stable (hashes and traces reproducible)
- **Fail-closed:** Missing/unknown inputs deny
- **Bounded:** Max nodes, max children, max trace entries (DoS protection)

---

## Core Components

| Component | Purpose |
|-----------|---------|
| `PolicyExpr` | Bounded policy AST (`All`, `Any`, `Not`, `Threshold`, `Atom`, `DenyIf`) |
| `CanonicalPolicy` | Canonicalizes + computes stable hash |
| `evaluate` | Deterministic evaluation with bounded trace |

---

## `DenyIf` Semantics (Veto-First)

`DenyIf` is an **absorbing veto guard** that cannot be bypassed:

1. Collect all `DenyIf(atom)` occurrences in the policy tree
2. Evaluate those signals first:
   - If any is `true` → `DenyVeto`
   - If any is missing → `DenyVeto` (fail-closed)
3. Evaluate the rest with `DenyIf(_)` treated as `Neutral`

This prevents "short-circuit allow" from bypassing a veto.

---

## Use Cases by Role

### Tau Net Policy Author / Reviewer

You use Policy Algebra to **author and audit** rule logic:

```rust
// "Allow if link_ok AND (is_admin OR is_self) AND NOT blacklisted"
let policy = PolicyExpr::all(vec![
    PolicyExpr::atom("link_ok", lim)?,
    PolicyExpr::any(vec![
        PolicyExpr::atom("is_admin", lim)?,
        PolicyExpr::atom("is_self", lim)?,
    ], lim)?,
    PolicyExpr::deny_if("is_blacklisted", lim)?,
], lim)?;

let canon = CanonicalPolicy::new(policy, lim)?;
let policy_hash = canon.hash_v1();  // Stable, anchor for review
```

- **Compose** small checks into gates (`All`, `Any`, `Threshold`)
- **Mark vetoes** with `DenyIf` (can't be bypassed)
- **Canonicalize** for stable hashing (reordering doesn't change meaning)
- **Trace** to debug: "which guard blocked this?"

### MPRD Implementer (Rust)

You use Policy Algebra to **make the rail explicit and testable**:

1. Convert state/evidence → boolean signals (`sig_ok`, `cooldown_ok`, `delta_ok`)
2. Evaluate policy over those signals
3. If deny → return bounded trace for debugging
4. If allow → apply the state transition

**Key invariant:** Missing signals = deny (fail-closed). `DenyIf` vetoes can't be bypassed by short-circuiting.

### Operator / Infra Runner

You use Policy Algebra to **run policies, not pick them**:

1. **Fetch** the Tau Net policy by `policy_hash`
2. **Evaluate** the gate when actions are proposed (by proposer or CEO)
3. **Receive** a trace for audit/debug
4. **Cannot override** allow/deny without violating the rail

### External Auditor / Verifier

You use Policy Algebra to **reproduce decisions**:

1. **Recompute** `policy_hash` from the canonical form
2. **Re-run** evaluation on the same inputs
3. **Confirm** the same deny/allow + trace (deterministic, bounded)

---

## Example: CEO Setpoint Gating

Before the Algorithmic CEO can change tokenomics parameters:

```rust
let ceo_gate = PolicyExpr::all(vec![
    PolicyExpr::atom("opi_healthy_ok", lim)?,      // OPI ≥ 9000 bps
    PolicyExpr::atom("reserve_runway_ok", lim)?,   // Reserve sufficient
    PolicyExpr::atom("cooldown_elapsed_ok", lim)?, // Cooldown period
    PolicyExpr::deny_if("emergency_freeze", lim)?, // Hard stop
], lim)?;
```

If `emergency_freeze` is ever true, the action is denied regardless of other conditions.

---

## Example: Multi-Sig Authorization

```rust
// "Allow if at least 2 of 3 keyholders approve"
let multisig = PolicyExpr::threshold(2, vec![
    PolicyExpr::atom("alice_signed", lim)?,
    PolicyExpr::atom("bob_signed", lim)?,
    PolicyExpr::atom("carol_signed", lim)?,
], lim)?;
```

---

## Integration Patterns

- **Tokenomics v6:** The state machine is pure (`TokenomicsV6::apply`) and gated via `PolicyGateV6`. Tau specs in `policies/tokenomics/canonical/` are the production `Allowed_op` artifacts.

- **Main MPRD pipeline:** The `PolicyEngine` trait evaluates candidate actions under an authorized `policy_hash`.

---

## API Reference

```rust
use mprd_core::policy_algebra::*;
use std::collections::HashMap;

// Limits (DoS protection)
let lim = PolicyLimits::DEFAULT;  // max_children=64, max_nodes=1024

// Build expressions
PolicyExpr::atom("name", lim)?        // Boolean signal
PolicyExpr::deny_if("name", lim)?     // Absorbing veto
PolicyExpr::all(children, lim)?       // AND
PolicyExpr::any(children, lim)?       // OR
PolicyExpr::not(child)                // NOT
PolicyExpr::threshold(k, children, lim)?  // k-of-n

// Canonicalize and hash
let canon = CanonicalPolicy::new(expr, lim)?;
let hash = canon.hash_v1();

// Evaluate
let signals: HashMap<String, bool> = ...;
let result = evaluate(canon.expr(), &signals, lim)?;
let allowed = result.allowed();
let trace = result.trace;
```

---

## File Locations

| File | Purpose |
|------|---------|
| `crates/mprd-core/src/policy_algebra/ast.rs` | PolicyExpr AST |
| `crates/mprd-core/src/policy_algebra/canon.rs` | Canonicalization + hash |
| `crates/mprd-core/src/policy_algebra/eval.rs` | Veto-first evaluation |
| `policies/tokenomics/canonical/` | Production Tau specs |
