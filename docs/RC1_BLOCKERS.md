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
  - Narrowed further: the tracked Lean bundle now includes a top-level signed-registry production `mprd serve` packet proving that reachable executed states on the shipped production path require validated registry and state anchors, explicit policy selection, production verifier binding, ready-bridge invocation, the signed-registry bridge facts, and the concrete execution guards before side effects.
  - Narrowed further: the tracked Lean bundle now also includes a top-level packet for the shipped `idempotent_http` production path, proving that successful remote execution requires the signed-registry serve-boundary facts, explicit `idempotent_http` selection, configured effect-journal binding, a pending-barrier check, and a committed local effect barrier before success.
  - Needed: constructor-gated witness chain from runtime objects into the execution boundary packet.
- Governance-to-execution closure is still incomplete.
  - Narrowed: prepared state rails in `mprd-core` and concrete `GovernanceGateInput` packets in `mprd-zk` now share one constructor-gated governance admission rule, and the live `attest_ready -> verify -> execute_ready` path now fails closed if attestors drop or drift that admitted governance metadata before execution.
  - Narrowed further: `mprd-zk` now has a concrete bridge helper that rebuilds `ExecutionReadyBundle` from a verifier-trusted registry authorization provider plus an optional concrete `GovernanceGateInput`, and a sibling helper that executes through the real `execute_ready(...)` boundary on top of that same concrete bridge. Both fail closed if registry attestation metadata drifts or the governance gate input disagrees with the state-prepared rails.
  - Narrowed further: the shipped production `mprd serve` path now injects that concrete bridge through `orchestrator::run_once_with_ready_bridge(...)`, the local executor wrappers in the CLI forward `execute_ready(...)` instead of collapsing back to raw `execute(ready.verified())`, and that serve path now fails closed if a governance witness appears before a concrete `GovernanceGateInput` packet is available.
  - Narrowed further: the shipped production `mprd serve` path now also uses the real registry-bound verifier derived from the signed checkpoint, instead of a stub local verifier, before it reaches the concrete ready bridge and side-effect boundary.
  - Narrowed further: proofs now carry a deterministic `execution_authorization_hash_v1` over the attested policy/state/governance packet, and the concrete registry/governance bridge re-derives and checks that hash fail-closed before rebuilding the live ready bundle.
  - Narrowed further: proofs built from a signed registry checkpoint now also carry a deterministic checkpoint-attestation hash, and both the signed-registry production verifier and the signed-registry ready bridge re-check that exact checkpoint binding fail-closed.
  - Narrowed further: proofs now also carry a deterministic registry-authorization resolution hash, and the concrete ready bridge preserves that exact registry resolution plus the optional checkpoint binding inside `ExecutionReadyBundle` and the shipped ready-path HTTP/webhook/file payloads instead of discarding those concrete bridge facts after local verification.
  - Narrowed further: the tracked Lean bundle now also has a signed-registry bridge-witness packet proving that reachable executed states on this path require registry-authorization hash binding and preservation of the concrete bridge witness into the rebuilt ready bundle.
  - Narrowed further: the tracked Lean bundle now has a lightweight signed-registry bridge packet proving that reachable executed states on this path require registry resolution, exact checkpoint binding, execution-authorization binding, governance alignment, and ready-bundle rebuild.
  - Narrowed further: the tracked Lean bundle now also has a joined signed-registry execution-boundary packet proving that reachable executed states on this path require those bridge facts plus the concrete execution guards (verified, allowed, replay, binding, executor).
  - Narrowed further: the shipped concrete HTTP/webhook/file executors now emit the admitted governance fields explicitly on the `execute_ready(...)` path, so real side-effect payloads and audit trails no longer have to recover governance context only from the generic proof-metadata map.
  - Narrowed further: the append-only decision log now publishes V3 records by default, preserving a deterministic attestation-metadata hash plus explicit governance fields when present while still reopening and appending across legacy V1/V2 chains.
  - Narrowed further: verified artifact-repo production-profile commits now have a constructor-gated bridge into the shipped registry-bound attestor and verifier helpers, so `policy_ref` and the signed registry checkpoint no longer have to be re-derived from loose commit fields by convention on either side of the production pair.
  - Narrowed further: registry-bound attestors now stamp the resolved authorization tuple into proof metadata, and the direct registry-bound verifier fails closed if that tuple drifts from a fresh resolution out of the verifier-trusted registry checkpoint.
  - Narrowed further: the shipped production `mprd serve` path now requires explicit signed-state trust anchors too, rejects caller-supplied request state on the production run route, and loads state through `SignedSnapshotStateProvider` instead of `SimpleStateProvider`, so the operator boundary no longer advertises a provenance-required production mode while still constructing `StateRef::unknown()`.
  - Narrowed further: the same trustless/private `mprd serve` path now fails fast at startup if the registry or signed-state trust anchors are missing, malformed, or signature-invalid, or if the production signing-key / persistent anti-replay config required by the live side-effect boundary is absent or cannot initialize, instead of only surfacing the misconfiguration after the process is already up.
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
  - Narrowed: the tracked replay-model series now includes a crash-ordering effect-finalization packet, so the safety story no longer stops at replay ownership or visibility alone. The model shows that if a durable effect-commit barrier survives crash and retry, late nonce finalization can still complete without a second external effect emission.
  - Narrowed further: the shipped HTTP, webhook, and audit executor surfaces now all emit the same deterministic `execution_idempotency_key_v1` derived from the policy/state/action/nonce tuple, so downstream services no longer have to reconstruct that tuple ad hoc to enforce retry idempotence.
  - Narrowed further: trustless/private production `mprd serve` now rejects the plain append-only `file` executor and requires the per-nonce `idempotent_file` sink for file-based side effects, so the shipped production file path no longer advertises a local side-effect mode that cannot act as a retry barrier.
  - Narrowed further: trustless/private production `mprd serve` now also rejects plain `http` and requires `execution.executor_type = "idempotent_http"` plus a local effect journal. The shipped remote-effect path now writes a fail-closed pending or committed barrier keyed by `execution_idempotency_key_v1`, blocks automatic replay while a pending barrier exists, and only short-circuits retries after a committed marker is durable.
  - Narrowed further: the tracked replay-model series now also includes `idempotent_http_effect_barrier`, a concrete adapter-facing safety packet showing that the shipped pending/committed HTTP barrier blocks duplicate remote effect emission on retry while pending is unresolved and only allows idempotent short-circuiting after commit.
  - Current state: this still needs tighter runtime and deployment closure before it becomes a shipped end-to-end theorem.

### Tier 1: Operational / Policy Admission

- Owner namespace, node assignment, activation epoch, and certification-tier admission are not first-class yet.
  - Current state: authority is cryptographic and fail-closed, but not yet modeled as "which namespace this node should obey".
- Source mapping still is not universal across every runtime surface, but the shipped registry-bound production proving and verifying helpers, plus the direct registry-bound policy-authorization provider and verifier, now enforce it by default.
  - Narrowed further: the shipped trustless/private `mprd serve` startup path now instantiates that same registry-bound production attestor/verifier pair and fails fast on missing required policy-source mapping, so this is no longer only a per-request runtime guarantee.
  - Current scope: the shipped production `mprd serve` path is still MPB-specific; it now selects the first authorized MPB policy explicitly and fails fast at startup if the configured registry bundle has no authorized `mpb-v1` policy.
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
