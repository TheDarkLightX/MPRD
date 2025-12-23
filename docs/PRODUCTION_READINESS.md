# Production Readiness Status

`internal/specs/production_readiness_checklist.md` is the master checklist, but `/internal` is gitignored; this file tracks current repo status in a git-tracked location.

## Implemented (MUSTs)

- **Fail-closed ZK journal pinning (B-Full/C)**: `crates/mprd-risc0-shared/src/lib.rs`
- **Explicit domain-separated hashing policy (MUST)**: `crates/mprd-core/src/hash.rs`, `crates/mprd-risc0-shared/src/lib.rs`, `methods/guest/src/main.rs`, `methods/mpb_guest/src/main.rs`
- **Bind policy authorization context (MUST)**: `mprd-core::DecisionToken::policy_ref` + `mprd-risc0-shared::GuestJournalV3::{policy_epoch,registry_root}`
- **Registry-bound verifier (MUST)**: `crates/mprd-zk/src/registry_state.rs` (`RegistryBoundRisc0Verifier`)
- **Signed registry checkpoint trust anchor (MUST)**: `crates/mprd-zk/src/registry_state.rs` (`SignedRegistryStateV1`, `SignedStaticRegistryStateProvider`), `crates/mprd-zk/src/lib.rs` (`create_production_verifier_from_signed_registry_state`)
- **Weighted quorum registry checkpoint trust anchor (SHOULD)**: `crates/mprd-zk/src/registry_state.rs` (`WeightedQuorumSignedRegistryStateV1`, `WeightedQuorumSignedRegistryStateProvider`), `crates/mprd-zk/src/lib.rs` (`create_production_verifier_from_weighted_quorum_registry_state`)
- **Tau→artifact gap closure via governed mapping (MUST, if Tau is source)**: `crates/mprd-zk/src/registry_state.rs` (`AuthorizedPolicyV1::{policy_source_kind_id,policy_source_hash}`) + enforced in `crates/mprd-zk/src/lib.rs` (`create_production_verifier_from_signed_registry_state`)
- **Pinned toolchain for reproducible builds (MUST)**: `rust-toolchain.toml`, `.github/workflows/risc0-methods.yml`
- **MPB-in-guest (mpb-v1) trustless correctness (B-Full)**: `methods/mpb_guest/src/main.rs`, `crates/mprd-mpb/src/lib.rs`, `crates/mprd-zk/src/risc0_host.rs`
- **Pinned mpb-v1 fuel semantics (MUST)** via `limits_hash_mpb_v1()`: `crates/mprd-risc0-shared/src/lib.rs`, `methods/mpb_guest/src/main.rs`
- **Bounded mpb-v1 witness inputs (MUST)**: `crates/mprd-risc0-shared/src/lib.rs`, `methods/mpb_guest/src/main.rs`, `crates/mprd-zk/src/risc0_host.rs`
- **Signed guest image manifest (MUST)**: `crates/mprd-zk/src/manifest.rs` + routing support in `crates/mprd-zk/src/external_verifier.rs`
- **Guest image ID drift gate (MUST)**: `methods/src/expected_image_ids.rs`, `.github/workflows/risc0-methods.yml`
- **Production `mprd verify` defaults to registry-bound verification**: `crates/mprd-cli/src/commands/verify.rs` (requires `--registry-state` unless `--insecure-demo`)
- **Executor derives action from committed transcript (MUST)**: `crates/mprd-core/src/lib.rs` (`ProofBundle::chosen_action_preimage`), `crates/mprd-adapters/src/executors.rs`
- **Committed limits binding is enforced at execution (MUST)**: `crates/mprd-core/src/limits.rs`, `crates/mprd-core/src/lib.rs` (`ProofBundle::{limits_hash,limits_bytes}`), `crates/mprd-adapters/src/executors.rs` (fail-closed on mismatched/unknown limits)
- **Canonical action schema allowlists (MUST)**: `crates/mprd-core/src/validation.rs` (`validate_action_schema_v1`), enforced in `crates/mprd-adapters/src/executors.rs`
- **Proof-carrying HTTP/Webhook payloads (MUST)**: `crates/mprd-adapters/src/executors.rs` includes `token_signature_hex` + `proof_receipt_hex`/`receipt_hex`
- **Bounded inputs at pipeline boundary (MUST)**: `crates/mprd-core/src/validation.rs`, `crates/mprd-core/src/orchestrator.rs`
- **Persistent anti-replay storage option (MUST)**: `crates/mprd-core/src/anti_replay.rs` (`FileNonceStore`)
- **LowTrust distributed anti-replay storage option (MUST)**: `crates/mprd-core/src/anti_replay.rs` (`RedisDistributedNonceStore`)
- **Production config guardrails**: `crates/mprd-core/src/config.rs` (`validate_production`)
- **Nonce derivation helper (MUST)**: `crates/mprd-core/src/nonce.rs`
- **Mode B-Lite binding (MUST)**: `crates/mprd-zk/src/mpb_lite.rs`, `crates/mprd-proof/src/{prover,verifier}.rs`, `crates/mprd-zk/src/modes_v2.rs`
- **Hash canonicalization PBT (MUST)**: `crates/mprd-core/src/hash.rs`
- **State provenance binding (MUST)**: `mprd-core::StateRef` on `StateSnapshot`/`DecisionToken` + `mprd-risc0-shared::GuestJournalV3::{state_source_id,state_epoch,state_attestation_hash}`
- **State provenance strategy (MUST)**: signed snapshot v1 strategy scaffold + provider (`crates/mprd-core/src/state_provenance.rs`) + production config/env parsing (`crates/mprd-core/src/config.rs`) + executor fail-closed allowlist guard (`crates/mprd-core/src/components.rs`)
- **Mode C key management plan (MUST)**: `docs/MODE_C_KEY_MANAGEMENT.md`
- **Policy fetching + authorization anchoring (MUST)**: registry-bound proving path that resolves policy authorization and fetches policy artifacts by content ID (`crates/mprd-zk/src/policy_fetch.rs`, `crates/mprd-zk/src/registry_bound_attestor.rs`, `crates/mprd-zk/src/lib.rs` `create_registry_bound_mpb_v1_attestor_from_signed_registry_state`)
- **Registry-bound tau_compiled proving (MUST, if using tau_compiled_v1)**: production proving helper that enforces verifier-trusted registry policy authorization at the proving boundary and routes image IDs via the signed manifest (`crates/mprd-zk/src/registry_bound_attestor.rs`, `crates/mprd-zk/src/lib.rs` `create_registry_bound_tau_compiled_v1_attestor_from_signed_registry_state`)
- **Separate registry vs manifest verifying keys (MUST, if keys differ)**: production verifier constructor and CLI support for distinct verifying keys (`crates/mprd-zk/src/lib.rs` `create_production_verifier_from_signed_registry_state_with_manifest_key`, `crates/mprd-cli/src/commands/verify.rs`)

## Not Yet Implemented (remaining MUSTs)

- **On-chain executor finality + nonce management per chain**: required once on-chain action adapters exist.
- **Deployment wiring**: ensure deployments ship verifier-trusted `registry_state` checkpoints/manifests and all verifiers execute `ValidDecision(bundle, registry_state)` (not raw image-id verification). Helpful tooling exists:
  - `mprd deploy check-bundle` validates a production bundle (signed registry checkpoint + signed manifest + local policy artifacts).
  - `crates/mprd-zk/src/lib.rs` provides registry-bound attestor+verifier constructors for `mpb-v1` and `tau_compiled_v1`.
- **Persistent anti-replay is deployed**: configure `anti_replay.nonce_store_dir` in production deployments (not just the in-repo option).
- **Persistent anti-replay is deployed**:
  - HighTrust: configure `anti_replay.nonce_store_dir`
  - LowTrust: configure `low_trust.nonce_store_backend = "redis"` + `low_trust.redis_url`
- **State freshness SLA (SHOULD)**: deployment must use a state provenance provider that enforces freshness (e.g. `QuorumSignedSnapshotStateProvider`) and set `low_trust.max_state_staleness_ms` appropriately.
