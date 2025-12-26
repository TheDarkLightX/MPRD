# MPRD Decentralization Roadmap

> **Document status:** Draft (v0.1)  
> **Last updated:** 2025-12-26  
> **Scope:** Decentralizing the MPRD *governor / attestation / execution* pipeline into a multi-operator network, leveraging Tau Net for policy consensus and (eventually) staking + finality.

## Executive Summary

MPRD today is operationally centralized (single operator) but *verification-minimized* (Risc0 proofs + fail-closed verifiers). This roadmap turns MPRD into a decentralized network in three stages:

1. **Federation (permissioned, low-trust):** remove single points of failure using quorum-signed registry checkpoints and state attestations, distributed nonce tracking, and transparent proof publication.
2. **P2P (networked, partially permissionless):** add a real networking layer (gossip + content addressing) and begin using Tau Net as the shared substrate for policy distribution and proof publication.
3. **Full trustless (permissionless):** move policy authorization, operator staking (AGRS), anti-replay/finality, and (optionally) execution to Tau Net so no off-chain committee remains a security root.

The design constraint throughout is MPRD’s safety invariant:

> **Safety invariant:** every executed action satisfies `Allowed(policy, state, action) = true`  
> and execution happens only after `ValidDecision(bundle, registry_state) == true` (fail-closed).

---

## 1) Codebase Review (What You Already Have)

### 1.1 Structure overview

**Core Rust crates (`crates/`)**

- `crates/mprd-core/`: core types + invariants; pipeline orchestration; anti-replay; state provenance; policy algebra; artifact repository algorithms.
- `crates/mprd-zk/`: production verification/proving wiring; registry-state trust anchors; policy fetching; decentralization primitives; deployment modes.
- `crates/mprd-adapters/`: executors + adapters for external systems (HTTP/webhooks, etc.).
- `crates/mprd-cli/`: CLI + HTTP operator API (`mprd serve`) and operator tooling.
- `crates/mprd-models-market/`: decentralized proposer marketplace primitives (commit/reveal; signed snapshots; stake-weight helpers).
- `crates/mprd-asde/`: settlement/discount/merkle primitives (stake events, fee receipts, vouchers).
- `crates/mprd-mpb/`, `crates/mprd-proof/`, `crates/mprd-risc0-shared/`, `methods/`: executable policy evaluation (MPB), ZK guests, and shared ABI.
- `crates/mprd-krr/`: KRR layer (explanations/trust propagation) intended to sit above Tau/TML.

**Tools (`tools/`)**

- `tools/operator-ui/`: operator dashboard UI (talks to `mprd serve`).
- `tools/mcp-servers/`: development tooling (not decentralization-critical).

**Tau policies (`policies/`)**

- `policies/governance/canonical/`: canonical governance gates (quorum, timelock, escalation, conviction).
- `policies/tokenomics/canonical/`: canonical tokenomics v6 gates (action gate, PID update gate).
- Root specs like `policies/mprd_governance_gate.tau` (base governance gate).

### 1.2 Existing decentralization primitives (already implemented or scaffolded)

These are the building blocks that make decentralization a wiring and protocol problem (not a redesign):

- **Registry-bound verification/proving (production-grade):**
  - Registry-pinned verification (`policy_epoch`, `registry_root`) and image routing via manifest (`crates/mprd-zk/src/registry_state.rs`, `docs/PRODUCTION_ZK.md`).
  - Registry-bound proving via policy artifact stores (`crates/mprd-zk/src/policy_fetch.rs` + `crates/mprd-zk/src/registry_bound_attestor.rs`).
- **Trust modes and low-trust config schema:**
  - `TrustMode::{HighTrust, LowTrust}` + quorum signer/attestor lists + IPFS gateway lists + distributed nonce backends (`crates/mprd-core/src/config.rs`).
- **Quorum-signed state provenance:**
  - `SignedStateSnapshotV1` + `QuorumSignedStateSnapshotV1` + freshness enforcement provider (`crates/mprd-core/src/state_provenance.rs`).
- **Tau Net output attestation (trustless signal ingestion scaffold):**
  - Attestation schema, hash-chain replay guard, publication-by-hash store interface (`crates/mprd-core/src/tau_net_output_attestation.rs`, `internal/specs/tau_net_output_attestation.md`).
- **Distributed anti-replay backends:**
  - Durable single-node and multi-node nonce stores including Redis (`crates/mprd-core/src/anti_replay.rs`, `internal/specs/anti_replay_spec.md`).
- **Artifact repository algorithms (content distribution with acceptance rules):**
  - MST repo + commit chain + bootstrap from untrusted sources (`crates/mprd-core/src/artifact_repo/`, `crates/mprd-zk/src/artifact_repo_integration.rs`).
- **Decentralization module (interfaces + reference implementations):**
  - Multi-attestor + threshold verifier; policy stores (IPFS interface); commitment anchoring; on-chain registry interface (`crates/mprd-zk/src/decentralization.rs`).
- **Transparency log primitive (pre-testnet):**
  - Append-only hash-chained JSONL proof log, designed to be anchorable later (`crates/mprd-core/src/decision_log.rs`).

### 1.3 The big gaps (what’s missing for a decentralized *network*)

1. **Network layer:** no libp2p-based P2P node implementation; no gossip topics; no DHT for content.
2. **Tau Net client integration:** no concrete `TauNetworkClient` / on-chain policy registry integration (only specs/interfaces exist).
3. **On-chain finality & nonce/tx binding:** production checklist calls out on-chain executor finality + chain-scoped nonce management as “not yet implemented” (`docs/PRODUCTION_READINESS.md`).
4. **Operator set + staking enforcement:** tokenomics supports `AdmitOperator`, `StakeStart/End` etc, but there is no on-chain or network-enforced “who is a node” / “who can claim execution”.
5. **Permissionless incentives + slashing:** rewards/slashing criteria are specified conceptually, but not enforced by a chain module or immutable consensus process.

---

## 2) What It Takes to Decentralize MPRD (Requirements)

### 2.1 Minimal decentralized MPRD network contract

To call MPRD “decentralized” (beyond marketing), the network must provide:

1. **Decentralized policy ownership:** the active policy set is decided by Tau Net consensus (or an interim quorum), not by a single operator.
2. **Decentralized artifact distribution:** all verifiers can fetch policy artifacts, registry checkpoints, and state attestations by content hash from multiple sources.
3. **Decentralized anti-replay/execution uniqueness:** for a given action/nonce scope, at most one execution is finalized (chain finality preferred).
4. **Auditable proof publication:** proofs (or their commitments) are publicly retrievable and indexable; equivocation is detectable.
5. **Economic security:** operators bond/stake (AGRS) and can be penalized for provable misbehavior; rewards compensate costs (ZK proving, uptime, settlement fees).

### 2.2 Where Tau Net fits (best leverage points)

Tau Net can serve as:

- **Policy consensus + registry:** canonical store of policy hashes and authorization context (epoch/root). Nodes fetch by hash; verifiers fail-closed on unauthorized policies.
- **Proof log / transparency anchor:** publish proof commitments (or full receipts) as transactions/events; subscribe via gossip.
- **Staking + slashing:** AGRS staking for node operators; slash provable faults (e.g., double-claim, equivocation, invalid anchoring).
- **Nonce/finality substrate:** use Tau Net tx hashes / block refs as `nonce_or_tx_hash`, making replay and ordering a chain property.
- **State provenance channel:** produce and attest outputs of Tau specs (“Tau output attestation”) that become verifier-checkable state snapshots.

In the near-term, Tau Net can be used in “anchor-only” mode (commitments posted), while off-chain committees still do some signing. The roadmap below gradually eliminates committee roots.

---

## 3) Phased Roadmap (Federation → P2P → Full Trustless)

### Timeline legend

- **T0** = Tau Net alpha testnet launch (or your internal “Tau Net available” milestone).
- Estimates assume a small core team (2–5 engineers) and reuse of existing primitives in this repo.

| Phase | Target trust model | Outcome | Rough duration |
|------:|--------------------|---------|----------------|
| 0 | Single operator → multi-operator ready | Hardening + interfaces + runbooks | 2–4 weeks |
| 1 | **Federation** (permissioned LowTrust) | Multi-operator network without SPOFs | 6–10 weeks |
| 2 | **P2P** (networked) | Gossip + content routing; Tau Net policy/proof integration begins | 8–16 weeks |
| 3 | **Full trustless** (permissionless) | Tau Net enforces policy registry + staking + finality | 6–12+ months |

---

## Phase 0 — Decentralization Readiness (Pre-federation)

**Goal:** Ensure the repo’s existing “low-trust” primitives can be assembled into a repeatable deployment, with no hidden single-machine assumptions.

### Milestones

1. **Define the “node” boundary**
   - Decide what runs where: proposer(s), attestor, verifier, executor, router, state provider.
   - Produce a reference “node profile” (config templates) for:
     - *Router/Executor node* (takes requests, executes)
     - *Attestor node* (generates proofs; may be specialized hardware)
     - *State attestor node* (signs/provides state provenance)

2. **Production bundle standardization**
   - Treat the following as a single “bundle” that nodes must pin:
     - verifier-trusted registry checkpoint (signed)
     - signed guest image manifest
     - policy artifacts store (dir / artifact repo / IPFS)
   - Use and extend existing tooling (`mprd deploy check-bundle`, `docs/PRODUCTION_READINESS.md`).

3. **Turn LowTrust into an operational reality**
   - Document a concrete LowTrust config:
     - registry quorum signer set + threshold
     - state attestor set + threshold + max staleness
     - Redis-based distributed nonce store settings
     - IPFS gateways (at least 2) if used
   - Ensure the “fail-closed defaults” are safe and obvious.

### Tau Net dependencies

- None required. (Optional: start anchoring decision log heads on Tau Net once alpha is usable.)

### Timeline estimate

- **2–4 weeks**.

---

## Phase 1 — Federation (Permissioned Multi-Operator, “LowTrust”)

**Goal:** Run MPRD as a federation of independent operators where no single operator can:
(a) decide policy unilaterally, (b) fake state provenance, or (c) replay/duplicate execution.

**Trust model:** Permissioned membership, but with cryptographic quorum rules and fail-closed verifiers. This is the “bridge” phase before permissionless.

### Milestones and technical requirements

1. **Federated policy authorization (registry checkpoints)**
   - Adopt **quorum-signed registry checkpoints** as the verifier trust anchor (k-of-n).
   - Use `policy_epoch` + `registry_root` pinning already in the token/journal (`mprd-core::PolicyRef`).
   - Distribute checkpoints via:
     - the artifact repo commit chain (multi-source bootstrap) **or**
     - a controlled publication channel (S3 bucket / Git release) *temporarily*, but with multiple independent mirrors.

   *Implementation anchors:*
   - `crates/mprd-zk/src/registry_state.rs` (quorum-signed registry state)
   - `crates/mprd-core/src/artifact_repo/*` (multi-source bootstrap)

2. **Federated state provenance**
   - Replace “operator asserts the state” with **quorum-signed state snapshots** for any shared/global state.
   - Enforce freshness with `max_state_staleness_ms` and reject stale snapshots (fail-closed).

   *Implementation anchors:*
   - `crates/mprd-core/src/state_provenance.rs` (`QuorumSignedStateSnapshotV1`, provider)

3. **Distributed anti-replay (multi-node execution safety)**
   - Use a **distributed nonce store** so multiple executors can race safely:
     - Implement `validate_and_claim` semantics so exactly one executor “wins” a nonce.
     - Prefer Redis backend for the federation (operationally simple), or use Postgres/etcd if already standard.

   *Implementation anchors:*
   - `crates/mprd-core/src/anti_replay.rs` (`DistributedNonceStore`, Redis backend)
   - `crates/mprd-core/src/config.rs` (`LowTrustConfig.nonce_store_backend`)

4. **Proof publication (transparency)**
   - Require every executed decision to be published to a shared transparency log:
     - Start with `FileDecisionRecorder` + replicated append-only storage
     - Optionally anchor the log head (hash) periodically on Tau Net (if available) or another chain.

   *Implementation anchors:*
   - `crates/mprd-core/src/decision_log.rs`
   - `crates/mprd-zk/src/decentralization.rs` (`CommitmentAnchorStore` interface)

5. **Multi-attestor for high-risk actions (optional but recommended)**
   - For actions that change policy, keys, or tokenomics parameters, require **K-of-N attestors**:
     - either multiple independent ZK proofs (expensive but strong)
     - or multiple independent verifiers over one proof (cheaper but weaker against prover faults)

   *Implementation anchors:*
   - `crates/mprd-zk/src/decentralization.rs` (`MultiAttestor`, `ThresholdVerifier`)

6. **Federated operator set (off-chain governance, short-lived)**
   - Maintain a permissioned operator set while building the on-chain staking path:
     - operator identities are `OperatorId(Hash32)` compatible with tokenomics v6
     - publish the operator allowlist in the registry checkpoint (so verifiers can fail-closed)

### Tokenomics integration (AGRS staking in federation)

Federation is the right time to “turn on” the tokenomics state machine in a safe way without requiring full on-chain enforcement yet:

- Use tokenomics v6 as the canonical rules engine for:
  - admitting operators (`AdmitOperator`)
  - starting/ending stakes (`StakeStart`, `StakeEnd`)
  - crediting AGRS / tracking BCR and rewards
- Treat the tokenomics state as **quorum-attested state provenance** (same pattern as Phase 1.2).
- Start paying operators in a transparent way (even if settlement is off-chain):
  - publish payroll/checkpoints as signed artifacts
  - bind fee settlement receipts via `mprd-core::fee_router::settlement_receipt_hash_v1`

### Tau Net dependencies

- Optional in this phase:
  - anchor transparency log head hashes
  - publish registry checkpoint hashes as “checkpoint commits”

### Timeline estimate

- **6–10 weeks** (longer if you need new ops infrastructure for quorum signing and state attestation).

---

## Phase 2 — P2P Network (Gossip + Content Routing, Tau Net Integration Begins)

**Goal:** Move from “federated deployments” to an actual network:
nodes discover each other, fetch artifacts by hash, and subscribe to proof/checkpoint streams without centralized endpoints.

**Trust model:** still may start permissioned, but with the technical substrate needed for permissionless participation.

### Milestones and technical requirements

1. **Define the network protocols + wire formats**
   - Standardize P2P message types for:
     - registry checkpoints
     - policy artifacts (or pointers to content)
     - state attestations (quorum-signed snapshot or Tau output attestation envelope)
     - proof bundle publication
   - Use a bounded, kind-tagged envelope format to prevent blob confusion and DoS:
     - reuse `crates/mprd-core/src/wire.rs` (MPRDPACK v1) where possible.

2. **Implement Tau Net client interface (minimum viable)**
   - Build a concrete implementation of the Tau Net integration spec:
     - fetch policies by `policy_hash`
     - publish proof commitments (or proofs)
     - subscribe to proof/checkpoint gossip

   *Spec anchors:*
   - `internal/specs/tau_network_integration_spec.md`

3. **Distributed policy storage**
   - Make policies fetchable by content hash from multiple sources:
     - Tau Net registry (preferred)
     - artifact repo (MST) mirrored over P2P
     - IPFS gateways (as a transitional layer)
   - Enforce “hash matches content” everywhere (fail-closed).

   *Implementation anchors:*
   - `crates/mprd-zk/src/policy_fetch.rs` (artifact stores + validation)
   - `crates/mprd-zk/src/decentralization.rs` (`DistributedPolicyStore` interface)

4. **State provenance via Tau Net outputs (start integration)**
   - Begin using Tau Net output attestations for shared signals:
     - implement a `TauOutputAttestationStore` backend that retrieves by hash from the network
     - enforce replay/continuity via a durable `TauOutputReplayGuard`

   *Spec + code anchors:*
   - `internal/specs/tau_net_output_attestation.md`
   - `crates/mprd-core/src/tau_net_output_attestation.rs`

5. **Execution coordination over the network**
   - For non-chain executors: implement a network claim mechanism so only one node executes:
     - claim = (decision_id, nonce) acquisition in distributed nonce store
     - publish claim and execution result for audit
   - Preferably, start shifting side effects toward **on-chain execution** where the chain itself provides uniqueness and ordering (sets up Phase 3).

6. **Operational hardening at network scale**
   - Rate limits and bounded parsing on every ingress path (P2P + HTTP).
   - Caching layers for policy artifacts, registry checkpoints, and proofs.
   - Observability: metrics for verification failures by reason, proving latency, peer health.

### Tokenomics integration (AGRS staking for P2P participation)

Start using staking data as a *network input* (even if enforcement is not fully on-chain yet):

- stake-weighted peer scoring / routing (who to ask for proofs, who to accept checkpoints from)
- stake-weighted selection of committee participants (registry signers, state attestors)
- publish stake snapshots as part of state provenance so verifiers can audit stake-weighted thresholds

### Tau Net dependencies

- **Required** (to claim Phase 2 is complete):
  - policy fetch by hash (network state API)
  - a reliable transaction/gossip substrate to publish proof commitments or proofs
- **Nice-to-have:**
  - light-client-friendly headers so verifiers can validate “what the chain says” without trusting an RPC.

### Timeline estimate

- **8–16 weeks**, depending on Tau Net alpha maturity and libp2p integration complexity.

---

## Phase 3 — Full Trustless (Permissionless, Tau Net-Enforced)

**Goal:** Remove remaining off-chain trust roots. Tau Net becomes the source of truth for:
policy authorization, operator membership/stake, and execution uniqueness/finality.

### Milestones and technical requirements

1. **On-chain policy registry + authorization context**
   - Move from “signed registry checkpoints” to **Tau Net-derived registry state**:
     - verifiers validate the active policy set from Tau Net consensus state
     - `policy_epoch` and `registry_root` become chain-derived (or anchored by chain-final checkpoints)
   - Keep the existing MPRD pattern: proofs still bind to `(policy_epoch, registry_root)`; verifiers still evaluate `ValidDecision(bundle, registry_state)` fail-closed.

2. **On-chain staking for node operators (AGRS)**
   - Define the canonical operator set and stake amounts on Tau Net:
     - `AdmitOperator` becomes a governed action (policy-gated)
     - `StakeStart/StakeEnd` recorded on-chain; stake weights become chain state
   - Use stake to secure:
     - checkpoint publication (if still used)
     - execution rights / sequencing (see below)
     - slashing conditions

3. **On-chain nonce/finality and executor adapters**
   - Implement chain-scoped nonce/tx binding so replay is impossible once final:
     - use Tau Net tx hashes / block refs as `nonce_or_tx_hash`
   - Implement **on-chain executor adapters** (or chain-verified “verify-and-execute” modules):
     - executor derives exactly the committed action from `chosen_action_preimage`
     - on-chain verifier checks proof commitments before applying state changes

   *Spec anchors:*
   - `internal/specs/onchain_executor_spec.md`
   - `docs/PRODUCTION_READINESS.md` (“On-chain executor finality + nonce management per chain”)

4. **Slashing and dispute handling (provable faults only)**
   - Define slashable offenses that are objectively provable:
     - equivocation (e.g., double-signing conflicting checkpoints at same height)
     - publishing an anchored proof commitment that does not verify under the chain-authorized registry state
     - claiming execution rights and failing to execute within SLA (if the protocol uses claims)
   - Avoid slashing based on subjective quality; keep it correctness + liveness only.

5. **Economic finalization: reward flows**
   - Make operator compensation trustless:
     - service tips + protocol payroll distribution become chain-enforced where possible
     - BCR auction/burn/drip mechanics are driven by the Tau-gated tokenomics kernel
   - Publish settlement receipts as commitments (already supported by `mprd-core::fee_router`).

### Tau Net dependencies

Phase 3 requires Tau Net support for at least:

- an on-chain policy registry / state storage (or a native mechanism to publish and query policy hashes)
- an on-chain staking module (AGRS staking) plus slashing hooks
- a transaction/event mechanism suitable for proof publication and indexing
- sufficient finality guarantees for nonce binding and replay prevention

### Timeline estimate

- **6–12+ months** (heavily dependent on Tau Net feature readiness and audit cycles).

---

## 4) Risk Analysis (Key Risks + Mitigations)

| Risk | Phase(s) | Impact | Mitigation |
|------|----------|--------|------------|
| **Policy capture / key compromise** (registry signers) | 1–2 | Catastrophic (wrong policies authorized) | Quorum signing + HSM/airgap, rotation, publish signer set in verifier-trusted state, move to Tau Net governance in Phase 3 |
| **State provenance forgery** | 1–3 | Catastrophic (Allowed computed on fake state) | Quorum-signed snapshots; staleness bounds; later Tau output attestations anchored by chain; replay guards |
| **Double execution / replay under partitions** | 1–2 | High | Distributed nonce claim (atomic); idempotent executors; shift to chain-derived `nonce_or_tx_hash` in Phase 3 |
| **DoS via large blobs (policies/receipts)** | 1–3 | High | Keep bounded parsing everywhere; reuse MPRDPACK envelope; enforce max sizes at ingress; caching + backpressure |
| **ZK proving costs too high for operators** | 0–3 | Medium/High | Tiered modes (MPB-lite for low-value); proof markets; batching; hardware acceleration; explicit service fees |
| **Equivocation in publication layers** (checkpoints/logs) | 1–2 | Medium/High | Hash-chained logs; artifact repo equivocation detection; anchor heads on Tau Net; slash equivocation in Phase 3 |
| **Economic attacks / stake capture** | 2–3 | High | Stake caps, delegation limits, multi-class committees (app vs safety), slashing for provable faults only, conservative quorum thresholds |
| **Mismatch between Tau source and executed artifact** (“compiler middleman”) | 0–3 | High | Enforce `policy_source_hash -> policy_hash` mapping in registry state (already supported); eventually deterministic compilation or proof-of-compilation |
| **Tau Net availability / API instability (alpha)** | 2 | Medium | Keep artifact repo + quorum checkpoint fallbacks; design for “anchor-only” early; modular `TauNetworkClient` with graceful degradation |

---

## 5) Recommended Next Actions (Immediate)

If you want the fastest path to a credible “decentralization story” in time for Tau Net alpha:

1. **Ship Phase 0 as a deployable reference profile** (LowTrust config templates + bundle format + runbooks).
2. **Run a small federation** (3–7 operators) using:
   - quorum registry checkpoints
   - quorum state snapshots
   - Redis distributed nonce claiming
   - mandatory proof publication (decision log + anchored heads if possible)
3. **Implement the Tau Net client boundary** behind a trait (even if it’s stubbed until alpha stabilizes), so Phase 2 work doesn’t rewrite the pipeline.

---

## Appendix A — Key Specs and Code Anchors

- **Production ZK + registry-bound verification:** `docs/PRODUCTION_ZK.md`
- **Production readiness checklist:** `docs/PRODUCTION_READINESS.md`, `internal/specs/production_readiness_checklist.md`
- **Tau Net integration spec:** `internal/specs/tau_network_integration_spec.md`
- **Tau output attestation spec:** `internal/specs/tau_net_output_attestation.md`
- **On-chain executor spec:** `internal/specs/onchain_executor_spec.md`
- **Policy algebra framing:** `docs/POLICY_ALGEBRA.md`
- **Artifact repo algorithms:** `internal/specs/mprd_artifact_repo_algorithms_v1.md`
- **Tokenomics gates:** `policies/tokenomics/canonical/`, `internal/specs/mprd_tokenomics_v6_idea_spec.md`

## Appendix B — Tokenomics Stability Research

The Algorithmic CEO mechanism has formal stability guarantees, documented in local workspace artifacts:

| Artifact | Purpose |
|----------|---------|
| `internal/specs/mprd_ceo_ewma_stability_proofs.lean` | Lean proofs that integer EMA stays bounded between min/max of (ema, obs) |
| `internal/specs/mprd_ceo_stability_research_v1.md` | Data-backed stability report with tables and repro commands |
| `tools/tokenomics/ceo_simulation.py` | CEO simulation with `--json`, `--opi-adjust-bps`, `--opi-shock-sigma-bps` |
| `tools/tokenomics/ceo_stability_sweep.py` | Seeded parameter sweeps outputting CSV |
| `tools/tokenomics/eip1559_ewma_mitigation_sim.py` | EIP-1559-style EWMA mitigation experiment |

**Run Lean proofs:**
```bash
lean internal/specs/mprd_ceo_ewma_stability_proofs.lean
```

> **Note:** The `internal/` directory is gitignored; these are local workspace artifacts for research and formal verification.


