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

## Why “Boolean algebra” laws can fail

Policy Algebra is **not** plain 2-valued Boolean logic once `DenyIf` exists.

- Inputs are **3-valued** (`missing|false|true`), and the evaluator has **4 outcomes**
  (`Allow|DenySoft|DenyVeto|Neutral`).
- `DenyIf(a)` is special: it contributes to a **global veto phase** and otherwise evaluates as `Neutral`.

That means many familiar Boolean identities can fail. For example, let `x = DenyIf(a)`:

- If `a=false`, then `x = Neutral` but `Any(x, x) = DenySoft` → idempotence fails (`x ∨ x ≠ x`).
- If `a=false`, then `Any(x, Not(x)) = DenySoft` → excluded middle can fail (`x ∨ ¬x ≠ True`).
- If `a=false`, then `All(x, Not(x)) = Allow` → non-contradiction can fail (`x ∧ ¬x ≠ False`).

**Implication:** don’t apply ad-hoc boolean rewrites to policies. Use:
- canonicalization + hashing (syntax stability),
- the ROBDD rail for the **booleanizable subset** (`docs/POLICY_CERTIFICATION.md`),
- counterexample mining to discover which laws hold only under explicit preconditions.

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

## Policy Menu (templates → Tau)

MPRD ships a small curated **Policy Algebra menu**: templates intended to be **suggestions** you can audit, emit to Tau,
and then certify like any other gate.

List available entries:

```bash
mprd policy algebra-menu-list
```

Machine-friendly output (includes required `atoms` / `deny_if_atoms`):

```bash
mprd policy algebra-menu-list --format json
```

Emit a canonical Tau gate (v2, presence bits) for a menu entry:

```bash
mprd policy algebra-menu-emit-tau --id tokenomics_v6_action_gate_fast --out ./gate.tau
```

Write canonical Policy Algebra v1 bytes for a menu entry (for hashing/certification workflows):

```bash
mprd policy algebra-menu-write --id tokenomics_v6_action_gate_fast --out ./policy.bin
```

Note: menu entries are intentionally built to be fail-closed and Tau-emittable (avoid `Not(DenyIf(..))` and other
hard-to-audit constructs).

The shipped menu family also has a tracked RC1 semantic-equivalence receipt:

```bash
python3 tools/policy/replay_menu_tau_equivalence_rc1.py \
  --output docs/receipts/rc1_policy_menu_tau_equivalence_20260326.json
```

That receipt proves the built-in curated menu entries round-trip through `algebra-menu-emit-tau`
and `algebra-certify-tau` on the current toolchain. It narrows the RC1 Tau compiler-equivalence
gap for the shipped menu family, but not for arbitrary Tau artifacts.

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
