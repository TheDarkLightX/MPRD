# Fuzzing (High-ROI Security Testing)

This repo includes `cargo-fuzz` targets for the most security-sensitive byte-parsing paths.

For unit-test and property-test best practices, see `docs/TESTING.md`.

## Why fuzzing helps (and when to use it)

`cargo-fuzz` (libFuzzer) is an *evolutionary*, coverage-guided testing tool: it mutates inputs, keeps a corpus of “interesting” cases, and searches for crashes and invariant violations.

Use fuzzing when:
- you change any parsing/deserialization logic (DoS and panic risk),
- you change any fail-closed accounting logic (discounts, allocations, budget routing),
- you add a new receipt/journal/versioned byte format,
- you want hardening against “unknown unknowns” beyond hand-written unit tests.

## Stateful / model-based PBT (when fuzzing is not enough)

For “economic correctness” logic (staking discounts, voucher spend rules, allocation algorithms), a second tool is often higher signal than raw input fuzzing:

- **Stateful / model-based property-based tests (PBT)** using `proptest`:
  - generate sequences of actions (grants/spends/queries),
  - run the real implementation and an independent reference model,
  - and shrink failures to a minimal counterexample.

Use stateful PBT when:
- you modify accounting rules (voucher eligibility, expiry, allocation tie-breaks),
- you want adversarial sequencing coverage (reordering, duplicates, boundary epochs),
- you need minimal repros for subtle “no-crash but wrong outcome” bugs.

Example (ASDE):
- `cargo test -p mprd-asde` runs both deterministic procedural tests and `proptest`-backed model-based tests.
- If a `proptest` case fails, it prints a repro seed; keep the minimized counterexample (or the seed) as a permanent regression test.

## Targets

- `limits_bytes_v1`: fuzzes `mprd_core::limits::parse_limits_v1`
- `candidate_preimage_v1`: fuzzes `mprd_core::validation::decode_candidate_preimage_v1`
- `receipt_deser`: fuzzes bounded receipt deserialization (`mprd_zk::bounded_deser::deserialize_receipt`)
- `mpb_artifact_deser`: fuzzes bounded MPB artifact deserialization (`mprd_zk::bounded_deser::deserialize_mpb_artifact`)
- `asde_voucher_trace_v1`: fuzzes ASDE voucher grant/spend trace accounting against an independent reference implementation
- `asde_allocation_v1`: fuzzes ASDE capped proportional allocation invariants (sortedness, caps, budget)

## Running

From repo root:

```bash
CARGO_NET_OFFLINE=true tools/fuzz.sh run limits_bytes_v1 -- -max_total_time=60
```

Notes:
- Recommended: use `tools/fuzz.sh` (it selects the correct toolchain defaults and applies a `zerocopy` AVX-512 workaround needed by some nightly toolchains).
- Default `cargo-fuzz` runs with sanitizers and typically requires a nightly toolchain.
- If you can’t use nightly/sanitizers, you can still do coverage-guided fuzzing on stable with sanitizer disabled (lower bug-finding power):

  ```bash
  CARGO_NET_OFFLINE=true cd fuzz && cargo fuzz run -s none limits_bytes_v1 -- -max_total_time=60
  ```

- The targets rely on bounded deserialization to avoid allocation DoS during fuzzing.
- For stateful / economic logic targets (ASDE), prefer longer runs and preserve the discovered corpus as regression material.
