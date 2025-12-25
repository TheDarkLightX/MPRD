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
| `mprd_tokenomics_v6_action_gate.tau` | Main gate for v6 action execution (`ActionV6`) |
| `mprd_tokenomics_v6_pid_update_gate.tau` | Gate for PID-proposed parameter updates (bounds + step limits) |

The `inputs/` / `outputs/` directories are for local Tau runs and are gitignored.

## Action kinds (v6)

`mprd_tokenomics_v6_action_gate.tau` uses `i_action_kind : bv[8]`:

- `0x01` `ADMIT_OPERATOR`
- `0x02` `CREDIT_AGRS`
- `0x03` `SET_OPI`
- `0x04` `SET_BOUNDS`
- `0x10` `STAKE_START`
- `0x11` `STAKE_END`
- `0x12` `ACCRUE_BCR_DRIP`
- `0x20` `APPLY_SERVICE_TX`
- `0x30` `AUCTION_REVEAL`
- `0x40` `FINALIZE_EPOCH`
- `0x41` `SETTLE_OPS_PAYROLL`
- `0x42` `SETTLE_AUCTION`
- `0x43` `ADVANCE_EPOCH`

Unknown kinds must deny.

## Integration sketch

The intended wiring is:

1. A tokenomics daemon / controller proposes `ActionV6` transitions.
2. The host computes Tau inputs (including cryptographic checks as `sbf` flags).
3. Tau evaluates `o_allow`.
4. If allowed, the host calls `TokenomicsV6::apply(gate, action)`.

The gate is *the hook* that makes the MPRD pattern explicit for tokenomics.

