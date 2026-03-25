# Tier-0 Boundary Matrix

This matrix makes the RC1 boundary-value and edge-case coverage explicit for the critical
execution, parsing, replay, governance, and policy surfaces.

It is not a claim that every Tier-0 blocker is closed. It is the tracked inventory of which
boundaries already have concrete evidence, which style of evidence exists, and which gaps still
need stronger closure.

For current RC1 status, see [RC1_BLOCKERS.md](RC1_BLOCKERS.md).

## How to read this matrix

- **Boundary classes** list the exact edge families that must stay fail-closed.
- **Evidence** points to concrete unit/property/fuzz coverage already in the repo.
- **Residual gap** says what this row still does *not* prove.

## Tier-0 Matrix

| Surface | Boundary classes | Evidence | Residual gap |
| --- | --- | --- | --- |
| Execution-boundary admission (`ExecutionReadyBundle`) | missing `chosen_action_preimage`; preimage/hash mismatch; malformed limits; schema-boundary rejects must stay `InvalidInput`; admitted policy/state/governance identity plus executor-side signature, state-provenance, and replay admission must survive the live `execute_ready` path; concrete adapters must not fall back from `execute_ready(...)` to raw `execute(ready.verified())` | [lib.rs](../crates/mprd-core/src/lib.rs), [components.rs](../crates/mprd-core/src/components.rs), [orchestrator.rs](../crates/mprd-core/src/orchestrator.rs), [anti_replay.rs](../crates/mprd-core/src/anti_replay.rs), [executors.rs](../crates/mprd-adapters/src/executors.rs) | still lacks one top-level concrete refinement theorem from runtime objects into the formal execution packet |
| Limits bytes parser | empty/truncated payloads; bad version; field-width errors; min/max/off-by-one values | [limits.rs](../crates/mprd-core/src/limits.rs), [limits_bytes_v1.rs](../fuzz/fuzz_targets/limits_bytes_v1.rs) | parser is covered; broader deployment-time limits-policy semantics are separate |
| Candidate preimage decode | malformed bytes; ordering and type decode failures; random byte streams | [validation.rs](../crates/mprd-core/src/validation.rs), [candidate_preimage_v1.rs](../fuzz/fuzz_targets/candidate_preimage_v1.rs) | semantic canonicalization beyond exact preimage syntax remains open |
| Receipt and MPB artifact deserialization | oversize envelopes; kind mismatch; digest mismatch; version-family decode compatibility | [bounded_deser.rs](../crates/mprd-zk/src/bounded_deser.rs), [receipt_deser.rs](../fuzz/fuzz_targets/receipt_deser.rs), [mpb_artifact_deser.rs](../fuzz/fuzz_targets/mpb_artifact_deser.rs) | deserialization is strong; source-to-artifact semantic equivalence is still open |
| Decoded journal verifier boundary | single-field journal mutations; recomputed commitment vs field-specific checks; fail-closed journal rejection | [decoded_journal_metamorphic_v3.rs](../fuzz/fuzz_targets/decoded_journal_metamorphic_v3.rs) | concrete refinement from full runtime journal objects into the formal selector/governance slices is still open |
| Tau output attestation envelope | malformed envelope bytes; round-trip encode/decode stability; canonical hash preservation | [tau_output_attestation_envelope_v1.rs](../fuzz/fuzz_targets/tau_output_attestation_envelope_v1.rs) | this covers envelope syntax, not the larger Tau governance authority model |
| Anti-replay boundary | duplicate nonces; claimed-vs-used transitions; high-trust vs low-trust sequencing; failure must not consume nonce; replay clearance must survive the live `execute_ready` boundary instead of staying wrapper-local; shipped HTTP/webhook/audit adapters should expose one deterministic idempotency key for the concrete (`policy_hash`, `state_hash`, `action_hash`, `nonce_or_tx_hash`) tuple; trustless/private production serve should not allow the plain append-only `file` executor as a file-backed side-effect sink; trustless/private production serve should not allow plain `http` without a local pending/committed effect barrier keyed by that same idempotency tuple; missing `effect_journal_dir` must fail closed for `idempotent_http`; the tracked replay series should include one concrete adapter-facing pending/committed HTTP barrier model in addition to the abstract crash-ordering packet | [anti_replay.rs](../crates/mprd-core/src/anti_replay.rs), [components.rs](../crates/mprd-core/src/components.rs), [e2e_pipeline.rs](../crates/mprd-core/tests/e2e_pipeline.rs), [anti_replay_state_machine.rs](../fuzz/fuzz_targets/anti_replay_state_machine.rs), [executors.rs](../crates/mprd-adapters/src/executors.rs), [serve.rs](../crates/mprd-cli/src/commands/serve.rs), [PARALLELIZATION_AND_NETWORK_RESILIENCE.md](PARALLELIZATION_AND_NETWORK_RESILIENCE.md), [rc1_network_replay_20260325.json](receipts/rc1_network_replay_20260325.json) | global at-most-once execution across crash/partition scenarios still needs tighter runtime/deployment closure |
| Governance admission witness | zero-hot lane; non-one-hot lane; whitespace-padded booleans; malformed prepared governance packet; concrete `GovernanceGateInput` must admit or reject identically to the core state-rail constructor; admitted governance metadata must survive the live `attest_ready -> verify -> execute_ready` path without omission or drift; proofs should carry a deterministic execution-authorization hash over the attested policy/state/governance packet and the concrete bridge must re-check it; proofs built from a signed registry checkpoint should also carry a deterministic checkpoint-attestation hash and both the signed-registry production verifier and signed-registry bridge must re-check that exact anchor fail-closed; proofs should also carry a deterministic registry-authorization resolution hash and the concrete bridge must preserve that exact registry resolution plus optional checkpoint binding into the live `ExecutionReadyBundle`; concrete registry authorization plus optional concrete governance gate input must rebuild the same live `ExecutionReadyBundle` authorization packet or fail closed; the same concrete bridge must also be able to drive the real `execute_ready(...)` boundary without dropping authorization; production `mprd serve` wiring must not silently bypass that bridge or collapse wrapper-local `execute_ready(...)` calls back to raw `execute(ready.verified())`; if the serve path lacks a concrete governance gate packet, any non-`None` governance witness must be rejected fail-closed; concrete `execute_ready(...)` effect surfaces should expose the admitted governance fields explicitly instead of only burying them in the generic proof-metadata map | [lib.rs](../crates/mprd-core/src/lib.rs), [orchestrator.rs](../crates/mprd-core/src/orchestrator.rs), [serve.rs](../crates/mprd-cli/src/commands/serve.rs), [executors.rs](../crates/mprd-adapters/src/executors.rs), [modes.rs](../crates/mprd-zk/src/modes.rs), [modes_v2.rs](../crates/mprd-zk/src/modes_v2.rs), [registry_bound_attestor.rs](../crates/mprd-zk/src/registry_bound_attestor.rs), [registry_state.rs](../crates/mprd-zk/src/registry_state.rs), [decentralization.rs](../crates/mprd-zk/src/decentralization.rs), [governance_admission_witness_v1.rs](../fuzz/fuzz_targets/governance_admission_witness_v1.rs) | one top-level execution/refinement theorem is still open even though the concrete bridge helper now exists |
| Policy authority witness | `policy_hash` drift; `policy_ref` drift between selected decision and tokenized authority surface; missing `policy_source_*` mapping on the registry-bound authorization path must fail closed by default; registry-bound proofs should carry the resolved authorization tuple and verifier-side re-resolution should reject any metadata drift; trustless/private `mprd serve` startup should fail closed if the same shipped registry-bound attestor/verifier pair cannot be instantiated from the configured bundle; the shipped MPB-specific serve path must not silently select a non-MPB policy out of a mixed registry bundle | [lib.rs](../crates/mprd-core/src/lib.rs), [orchestrator.rs](../crates/mprd-core/src/orchestrator.rs), [registry_bound_attestor.rs](../crates/mprd-zk/src/registry_bound_attestor.rs), [registry_state.rs](../crates/mprd-zk/src/registry_state.rs), [serve.rs](../crates/mprd-cli/src/commands/serve.rs) | owner namespace / node assignment / activation-tier admission are still not first-class |
| State provenance and state binding | missing state refs; unallowlisted state sources; `state_hash` drift; `state_ref` drift; duplicate attestors and freshness edges; production `mprd serve` must not accept caller-supplied state or silently fall back to `SimpleStateProvider` when production validation requires signed provenance; trustless/private serve startup must fail closed if the signed-state anchors or the production signing-key / persistent anti-replay config required by the live execution boundary are missing or cannot initialize | [state_provenance.rs](../crates/mprd-core/src/state_provenance.rs), [state_provenance.txt](../crates/mprd-core/proptest-regressions/state_provenance.txt), [serve.rs](../crates/mprd-cli/src/commands/serve.rs) | provenance admission is stronger on the shipped operator path now, but full deployment-time freshness and trust-root closure remain open |
| Signature admission | valid vs invalid signatures; ready-path and raw execute-path symmetry | [crypto.rs](../crates/mprd-core/src/crypto.rs), [components.rs](../crates/mprd-core/src/components.rs) | signature validity alone is not the full authority model |
| Decision log publication | legacy V1/V2 chain verification; V3 hash-chain writes; attestation metadata hashing; missing/partial governance metadata must fail closed instead of collapsing to a weaker published record | [decision_log.rs](../crates/mprd-core/src/decision_log.rs) | append-only publication is stronger, but it is still an audit surface, not the top-level execution/refinement theorem |

## RC1 Fuzz Campaign

The tracked smoke runner is:

- [tools/fuzz_smoke_rc1.sh](../tools/fuzz_smoke_rc1.sh)

The tracked workflow is:

- [fuzz-smoke.yml](../.github/workflows/fuzz-smoke.yml)

That workflow now runs automatically on pull requests and pushes that touch the tracked Tier-0 fuzz
surfaces, while `workflow_dispatch` remains available for longer or ASDE-inclusive runs.

The RC1 release claim should use a successful summary artifact from that workflow (or an equivalent
local replay using the same script) on the candidate commit.

## RC1 Network Replay Campaign

The tracked replay runner is:

- [replay_network_barriers_rc1.py](../tools/replay_network_barriers_rc1.py)

The tracked workflow is:

- [network-replay.yml](../.github/workflows/network-replay.yml)

The current committed replay receipt is:

- [rc1_network_replay_20260325.json](receipts/rc1_network_replay_20260325.json)

## Maintenance Rule

If a new Tier-0 parser, witness, or authority boundary is added, update this matrix in the same
change. Do not let new Tier-0 surfaces exist only as implied test coverage.
