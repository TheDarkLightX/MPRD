# MPRD Tokenomics Policies (Tau)

This directory contains Tau specifications for **tokenomics control-plane gating**.

## Background

The v6 tokenomics kernel (`crates/mprd-core/src/tokenomics_v6/`) is a pure state machine.
It applies state transitions only through `TokenomicsV6::apply(gate, action)` where the
`gate` is a `PolicyGateV6` authorization hook.

Tau is intended to define the **single source of truth** for what tokenomics actions are
allowed (the operator-paper `Allowed_op` idea), while keeping heavy computation off-chain:

- **Host computes, Tau validates**: complicated math, signatures, receipts, and data fetching
  happen outside Tau; Tau checks bounded, deterministic predicates (mostly `sbf` flags and
  simple `bv` comparisons).
- **Fail-closed**: unknown action kinds or missing evidence must deny.

## Canonical specs (recommended)

The `canonical/` folder contains the intended production Tau specs:

| Spec | Purpose |
|------|---------|
| `mprd_tokenomics_v6_action_gate.tau` | Main gate for v6 action execution (`ActionV6`) (fast, minimal outputs) |
| `mprd_tokenomics_v6_action_gate_audit.tau` | Same decision as action gate, but with debug/audit outputs (slower) |
| `mprd_tokenomics_v6_pid_update_gate.tau` | Gate for PID-proposed parameter updates (bounds + step limits) |

The `inputs/` / `outputs/` directories are for local Tau runs and are gitignored.

## Action kinds (v6)

Tau comparisons on `bv[N]` are formulas (not terms), so the canonical gate uses **one-hot sbf inputs**
to avoid mixing bitvector comparisons into term-level logic.

The host decodes `ActionV6` into one-hot sbf flags:

- `i_is_admit_operator`
- `i_is_credit_agrs`
- `i_is_set_opi`
- `i_is_set_bounds`
- `i_is_stake_start`
- `i_is_stake_end`
- `i_is_accrue_bcr_drip`
- `i_is_apply_service_tx`
- `i_is_auction_reveal`
- `i_is_finalize_epoch`
- `i_is_settle_ops_payroll`
- `i_is_settle_auction`
- `i_is_advance_epoch`

Unknown/unsupported actions must set all flags to `0` (fail-closed).

The canonical action gate relies on an explicit host/CBC rail:
- `i_action_one_hot_ok` is **computed by the host** and must be `1` exactly when the action flags are one-hot.
- Tau additionally checks `o_action_any` (OR of all action flags) to fail-close “all zero” cases even if the host mis-sets `i_action_one_hot_ok`.

## Integration sketch

The intended wiring is:

1. A tokenomics daemon / controller proposes `ActionV6` transitions.
2. The host computes Tau inputs (including cryptographic checks as `sbf` flags).
3. Tau evaluates `o_allow`.
4. If allowed, the host calls `TokenomicsV6::apply(gate, action)`.

The gate is *the hook* that makes the MPRD pattern explicit for tokenomics.

For the trust-boundary contract of `i_link_ok`, see `canonical/link_ok_contract.md`.

## PID update gate (v6)

`mprd_tokenomics_v6_pid_update_gate.tau` is **sbf-only** by design:
- the host computes the PID proposal and the numeric safety checks (bounds, step limits, split cap)
- Tau enforces the *boolean structure* (`link_ok & auth_ok & all_checks_ok`)

This keeps Tau execution bounded and avoids brittle bitvector arithmetic in the interpreter.
