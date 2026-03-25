# RC1 Blockers

This file is the git-tracked RC1 board for MPRD. It separates:

- gates that are now automated and expected to stay green, from
- gaps that still block an honest "release candidate 1" claim.

Do not treat "CI green" as equivalent to "RC1 ready". RC1 requires both.

## Automated Gates

These are currently expected to pass through tracked workflows or release-gate runs on tracked branches:

- `cargo fmt --check`
- `RISC0_SKIP_BUILD=1 cargo clippy --workspace --all-targets -- -D warnings`
- `RISC0_SKIP_BUILD=1 cargo test --workspace --all-targets`
- `cargo audit` / `cargo audit --no-fetch` in the dedicated Cargo Audit workflow
- tracked fuzz smoke campaign in `.github/workflows/fuzz-smoke.yml`
- tracked network replay receipt comparison in `.github/workflows/network-replay.yml`

These gates are necessary, but not sufficient, for RC1.

## Remaining RC1 Blockers

### Tier 0: Security / Assurance Closure

- Runtime refinement still stops short of one top-level concrete execution theorem.
  - Narrowed: the shipped concrete adapters now override `execute_ready(...)` directly instead of inheriting the legacy default that fell back to raw `execute(ready.verified())`, so the witness-native path now survives into the real side-effecting adapter layer and not only through the guard wrappers.
  - Needed: constructor-gated witness chain from runtime objects into the execution boundary packet.
- Governance-to-execution closure is still incomplete.
  - Narrowed: prepared state rails in `mprd-core` and concrete `GovernanceGateInput` packets in `mprd-zk` now share one constructor-gated governance admission rule, and the live `attest_ready -> verify -> execute_ready` path now fails closed if attestors drop or drift that admitted governance metadata before execution.
  - Narrowed further: `mprd-zk` now has a concrete bridge helper that rebuilds `ExecutionReadyBundle` from a verifier-trusted registry authorization provider plus an optional concrete `GovernanceGateInput`, and it fails closed if registry attestation metadata drifts or the governance gate input disagrees with the state-prepared rails.
  - Narrowed further: the shipped concrete HTTP/webhook/file executors now emit the admitted governance fields explicitly on the `execute_ready(...)` path, so real side-effect payloads and audit trails no longer have to recover governance context only from the generic proof-metadata map.
  - Narrowed further: the append-only decision log now publishes V3 records by default, preserving a deterministic attestation-metadata hash plus explicit governance fields when present while still reopening and appending across legacy V1/V2 chains.
  - Narrowed further: verified artifact-repo production-profile commits now have a constructor-gated bridge into the shipped registry-bound attestor and verifier helpers, so `policy_ref` and the signed registry checkpoint no longer have to be re-derived from loose commit fields by convention on either side of the production pair.
  - Narrowed further: registry-bound attestors now stamp the resolved authorization tuple into proof metadata, and the direct registry-bound verifier fails closed if that tuple drifts from a fresh resolution out of the verifier-trusted registry checkpoint.
  - Needed: replayable refinement from concrete registry and governance objects into the live execution authorization packet, not just a shared admission constructor.
- Tau source to compiled artifact semantic equivalence is still open.
  - Current state: provenance and artifact witness are strong; compiler equivalence is not proved.
- Mode C is not yet full minimized trust.
  - Current state: strong private-boundary verification surface, but plaintext visibility and trust-root minimization remain open.

### Tier 0: Distributed / Network Resilience

- Network chaos is not yet release-complete.
  - Narrowed: the tracked replay-model series now has a consolidated RC1 receipt at `docs/receipts/rc1_network_replay_20260325.json`, so the remaining gap is no longer "network safety evidence is scattered".
  - Missing: replayable chaos campaigns for stale checkpoints, checkpoint withholding, quorum degradation, Tau/API outages, and related partition schedules.
- Global at-most-once execution across crash and partition scenarios is not yet a shipped end-to-end theorem.
  - Current state: strong replay barrier packet series exists, but this still needs tighter runtime and deployment closure.

### Tier 1: Operational / Policy Admission

- Owner namespace, node assignment, activation epoch, and certification-tier admission are not first-class yet.
  - Current state: authority is cryptographic and fail-closed, but not yet modeled as "which namespace this node should obey".
- Source mapping still is not universal across every runtime surface, but the shipped registry-bound production proving and verifying helpers, plus the direct registry-bound policy-authorization provider and verifier, now enforce it by default.
  - Remaining gap: non-registry-bound or explicitly relaxed surfaces can still opt out, so RC1 claims must stay scoped to the production registry-bound path.

## Release Rule

MPRD should not be described as "RC1" until:

1. all automated gates above are green on the candidate branch, and
2. every Tier 0 blocker above is either closed or explicitly downgraded out of the RC1 claim.

## Related Docs

- [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md)
- [FUZZING.md](FUZZING.md)
- [TIER0_BOUNDARY_MATRIX.md](TIER0_BOUNDARY_MATRIX.md)
- [SECURITY_HARDENING_CHECKLIST.md](SECURITY_HARDENING_CHECKLIST.md)
- [PARALLELIZATION_AND_NETWORK_RESILIENCE.md](PARALLELIZATION_AND_NETWORK_RESILIENCE.md)
