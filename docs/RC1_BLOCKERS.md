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

These gates are necessary, but not sufficient, for RC1.

## Remaining RC1 Blockers

### Tier 0: Security / Assurance Closure

- Runtime refinement still stops short of one top-level concrete execution theorem.
  - Needed: constructor-gated witness chain from runtime objects into the execution boundary packet.
- Governance-to-execution closure is still incomplete.
  - Narrowed: prepared state rails in `mprd-core` and concrete `GovernanceGateInput` packets in `mprd-zk` now share one constructor-gated governance admission rule, and the live `attest_ready -> verify -> execute_ready` path now fails closed if attestors drop or drift that admitted governance metadata before execution.
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
- Source mapping still is not universal across every runtime surface, but the shipped registry-bound production proving and verifying helpers now enforce it by default.
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
