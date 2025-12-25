# `i_link_ok` Trust Boundary Contract

This document specifies what `i_link_ok` **must bind** to ensure that Tau policy checks are sound.

## Security Architecture

> [!IMPORTANT]
> **Tau specs express policy; a verifier rail must enforce it.**

This contract is written for the **intended trust-minimized deployment** where Tau evaluation and
input binding are verified (e.g. via zkVM or an equivalent attested execution path).

If you run the gate in a purely host-trusted mode (no proof / no attestation), then `i_link_ok`
is only as strong as the component that computes it.

The Tau spec itself is pure Boolean logic over host-provided inputs. If the host could arbitrarily set inputs, no security would exist. MPRD achieves **security by architecture**:

| Layer | Role |
|-------|------|
| **Tau Spec** | Expresses authorization policy as deterministic logic |
| **Host** | Proposes action + computes inputs (untrusted in isolation) |
| **Verifier rail** | Ensures inputs/decision are bound to `(policy,state,action)` and cannot be forged |

In a trust-minimized deployment, the host cannot lie about `i_link_ok` because the verifier rail:
1. binds the Tau evaluation to committed inputs (or an attested computation),
2. runs deterministically over those committed inputs, and
3. binds the authorization decision to the committed `(policy_hash, state_hash, action_hash)`.

## Purpose

`i_link_ok` is the **linkage predicate** that ties all host-computed inputs to a specific, committed context. Without it, a malicious or buggy host could:
- Set all authorization bits to `1` without verification
- Replay old input files for different proposals
- Substitute inputs from a different action/proposal

## Required Bindings

The host MUST set `i_link_ok = 1` only when ALL of the following hold:

| Binding | Description |
|---------|-------------|
| **Policy Hash** | The Tau spec being evaluated matches the expected canonical hash |
| **State Hash** | Current engine state (epoch, balances, stakes) is committed |
| **Action Hash** | The exact `ActionV6` being authorized is committed |
| **Decoded Flags** | One-hot action flags (`i_is_*`) match the committed action kind |
| **Actor/Target** | Identity performing the action and target operator |
| **Epoch/Phase** | Current epoch and phase are committed and checked |
| **Receipts/Nonces** | All anti-replay evidence is fresh and valid |

## Implementation Guidelines

```rust
fn compute_link_ok(
    policy_hash: Hash32,
    state: &TokenomicsV6,
    action: &ActionV6,
    decoded_flags: &ActionFlags,
    actor: &Identity,
    receipts: &[Receipt],
) -> bool {
    // Pseudocode: the concrete bindings depend on the deployment mode.
    // 1. Policy hash matches expected canonical
    policy_hash == CANONICAL_ACTION_GATE_HASH
    // 2. Action flags match decoded action kind
    && decoded_flags.matches(action)
    // 3. All receipts are valid (not replayed)
    && receipts.iter().all(|r| r.is_fresh())
    // 4. State commitment is current
    && state.epoch() == current_epoch()
}
```

## Security Properties

If `i_link_ok` is computed correctly:
- **Soundness**: Authorization decisions are bound to real state
- **Non-replay**: Old input files cannot authorize new actions
- **Fail-closed**: Any missing binding → `i_link_ok = 0` → deny

## Changes Log

| Date | Change |
|------|--------|
| 2025-12-25 | Initial documentation |
