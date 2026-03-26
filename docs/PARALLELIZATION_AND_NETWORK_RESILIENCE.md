# Parallelization And Network Resilience

This note records the current formal boundary for pre or post-condition guided
parallelization in MPRD and the remaining network-resilience frontier.

## Current Formal Boundary

The local packet is:

- `proofs/lean/MPRD_ParallelIndependenceOracle.lean`
- `internal/shapeforge/mprd/esso/parallel_independence_oracle.yaml`
- `internal/shapeforge/mprd/tla/parallel_independence_oracle.tla`
- `docs/specs/serial_commit_network_barrier.tla`

What it proves:

- speculative `eval_candidates` and `refresh_cache` commute
- speculative steps preserve the later authority projection
- committed states still require a serial commit barrier
- private committed states still require `mode_c_key_allowed`

What it does not prove:

- concrete runtime scheduler refinement
- concrete read or write footprints for cache, registry, replay, selector, or source objects
- adversarial network resilience under partitions, stale checkpoints, or quorum degradation
- full minimized trust for Mode C

## Safe Rule

Parallelization is admissible only as:

1. a speculative phase over proved-independent work
2. a serial fail-closed commit barrier
3. `unknown`, stale, conflicting, or unproved cases serialize automatically

## Safe Early Lanes

- candidate evaluation over a fixed canonical candidate family
- cache refresh and other read-only artifact preparation
- local verified-kernel work queues with explicit disjoint writes

## Unsafe Lanes

- governance mutation
- replay consumption or nonce finalization
- selector commit
- Tau or source or artifact authority admission
- final execution authorization

## Network-Resilience Frontier

Current chaos evidence is strong on local admission and execution correctness.
It is not yet sufficient to claim strong adversarial network resilience.

The next required replayable disaster states are:

- stale registry checkpoint under partition
- checkpoint withholding
- quorum degradation
- distributed replay race across replicas
- Tau or API outage with fail-closed fallback
- Mode C key rotation or allowlist drift

The tracked RC1 replay script and receipt for the current model series are:

- `tools/replay_network_barriers_rc1.py`
- `docs/receipts/rc1_network_replay_20260325.json`
- `.github/workflows/network-replay.yml`

The current receipt is green across 14 tracked safety models:

- `serial_commit_network_barrier`: 1,274 distinct states, depth 12
- `distributed_replay_claim_barrier`: 63 distinct states, depth 7
- `distributed_replay_visibility_barrier`: 291 distinct states, depth 12
- `distributed_replay_lease_barrier`: 671 distinct states, depth 14
- `distributed_replay_split_brain_barrier`: 170 distinct states, depth 13
- `distributed_replay_direct_handoff_barrier`: 361 distinct states, depth 13
- `distributed_replay_quorum_barrier`: 21,888 distinct states, depth 16
- `distributed_replay_quorum_equivocation_barrier`: 150 distinct states, depth 13
- `distributed_replay_equivocation_recovery_barrier`: 132 distinct states, depth 9
- `distributed_replay_hidden_equivocation_barrier`: 250 distinct states, depth 13
- `distributed_effect_finalization_barrier`: 38 distinct states, depth 10
- `idempotent_http_effect_barrier`: 17 distinct states, depth 7
- `idempotent_http_startup_pending_barrier`: 26 distinct states, depth 7
- `idempotent_file_effect_barrier`: 9 distinct states, depth 5

Replay command:

```bash
TLA2TOOLS_JAR=/path/to/tla2tools.jar \
python3 tools/replay_network_barriers_rc1.py \
  --output docs/receipts/rc1_network_replay_20260325.json
```

The first tracked replay surface for this frontier is:

- `docs/specs/serial_commit_network_barrier.tla`
- `docs/specs/serial_commit_network_barrier.cfg`

It is intentionally narrow. It proves only that once local work is ready,
commit still rejects on stale checkpoints, withheld checkpoints, quorum
degradation, or Tau/API failure instead of silently treating cached state as
fresh authority.

Replay command:

```bash
cd docs/specs
java -cp ../../external/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup \
  -deadlock \
  -config serial_commit_network_barrier.cfg \
  serial_commit_network_barrier
```

The next tracked replay surface is:

- `docs/specs/distributed_replay_claim_barrier.tla`
- `docs/specs/distributed_replay_claim_barrier.cfg`

It is also intentionally narrow. It models two ready replicas behind one
atomic shared nonce-claim owner and proves the fail-closed shape:

- at most one replica can execute
- executed replicas must own the shared claim
- partitions or claim-store outages prevent ready replicas from executing on
  local readiness alone

What it does not prove:

- eventual rejection after outage or partition
- asymmetric connectivity or stale claim visibility
- lease expiry or split-brain claim-store behavior

Replay command:

```bash
cd docs/specs
java -cp ../../external/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup \
  -deadlock \
  -config distributed_replay_claim_barrier.cfg \
  distributed_replay_claim_barrier
```

The next tracked replay surface extends that claim with asymmetric visibility:

- `docs/specs/distributed_replay_visibility_barrier.tla`
- `docs/specs/distributed_replay_visibility_barrier.cfg`

It is still intentionally narrow. It models one atomic shared claim service,
but now with per-replica connectivity, local claim-owner views, and explicit
freshness. It proves the stronger safety shape:

- at most one replica can execute
- executed replicas must own the actual shared claim
- executed replicas must also hold a fresh local view of that ownership
- stale or disconnected local views cannot be used to execute on local
  readiness alone
- claimed replicas that lose freshness fail closed to rejected instead of
  executing on stale visibility

Modeling assumptions:

- claim acquisition and the claimant's local fresh-view update are atomic
- reconnect alone does not restore freshness; an explicit refresh step is still
  required

What it still does not prove:

- lease expiry or claim revocation
- split-brain claim-store behavior
- eventual convergence after recovery

Replay command:

```bash
cd docs/specs
java -cp ../../external/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup \
  -deadlock \
  -config distributed_replay_visibility_barrier.cfg \
  distributed_replay_visibility_barrier
```

The next tracked replay surface extends that series with lease expiry and
revocation:

- `docs/specs/distributed_replay_lease_barrier.tla`
- `docs/specs/distributed_replay_lease_barrier.cfg`

It is still intentionally narrow. It models one atomic shared claim service,
but now with per-replica owner-plus-epoch views and an explicit shared lease
epoch. It proves the stronger safety shape:

- at most one replica can execute
- executed replicas must hold the current shared owner and epoch
- fresh local views must match both actual owner and actual epoch
- claimed replicas fail closed to rejected if the lease expires or is revoked
  before execute

Modeling assumptions:

- claim acquisition and the claimant's local fresh owner-plus-epoch update are
  atomic
- lease expiry or revocation clears the shared owner and increments the shared
  epoch in one step
- reconnect alone does not restore freshness; an explicit refresh step is still
  required

What it still does not prove:

- split-brain claim-store behavior
- leased handoff between two non-`none` owners without a clearing step
- eventual rejection or execution after lease expiry or recovery
- eventual convergence after recovery

Replay command:

```bash
cd docs/specs
java -cp ../../external/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup \
  -deadlock \
  -config distributed_replay_lease_barrier.cfg \
  distributed_replay_lease_barrier
```

The next tracked replay surface extends that series with split-brain local
claim stores:

- `docs/specs/distributed_replay_split_brain_barrier.tla`
- `docs/specs/distributed_replay_split_brain_barrier.cfg`

It is still intentionally narrow. It models one local claim store per replica,
coupled while healthy and allowed to diverge under partition. The commit
barrier remains fail-closed and requires store agreement before execute, while
conflict reconciliation clears ownership instead of guessing a winner. It
proves the safety shape:

- at most one replica can execute
- executed replicas require both local stores to agree on the same owner and
  epoch
- split-brain store disagreement blocks execution
- reconciliation under disagreement rejects claimed replicas instead of
  executing under divergent ownership

Modeling assumptions:

- each replica has access only to its own local claim store view
- healthy mode keeps the two claim stores coupled
- conflict reconciliation clears ownership instead of performing direct
  ownership handoff

What it still does not prove:

- eventual convergence after split-brain
- direct winner selection between divergent claim histories
- a subsequent successful re-claim after reconciliation
- Byzantine store behavior or forged local views
- quorum-backed replicated claim services beyond the two-store abstraction

Replay command:

```bash
cd docs/specs
java -cp ../../external/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup \
  -deadlock \
  -config distributed_replay_split_brain_barrier.cfg \
  distributed_replay_split_brain_barrier
```

The next tracked replay surface extends the lease series with direct
owner-to-owner handoff:

- `docs/specs/distributed_replay_direct_handoff_barrier.tla`
- `docs/specs/distributed_replay_direct_handoff_barrier.cfg`

It is still intentionally narrow. It models one atomic shared claim service
with per-replica owner-plus-epoch views, but now allows direct handoff from one
non-`none` owner to the other without clearing through `none`. It proves the
safety shape:

- at most one replica can execute
- executed replicas must hold the current shared owner and epoch
- direct handoff invalidates the old claimant instead of letting it execute on
  stale ownership
- the new owner can execute only through the fresh post-handoff owner-plus-epoch
  view

Modeling assumptions:

- direct handoff is atomic at the shared claim service
- the recipient receives the fresh post-handoff owner-plus-epoch view in the
  same step
- the donor's freshness is invalidated in the same step
- no split-brain claim-store behavior is modeled here

What it still does not prove:

- split-brain or divergent local-claim histories
- handoff to a replica that is not already locally ready
- eventual progress after a failed handoff or disconnected recipient
- Byzantine shared-claim service behavior

Replay command:

```bash
cd docs/specs
java -cp ../../external/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup \
  -deadlock \
  -config distributed_replay_direct_handoff_barrier.cfg \
  distributed_replay_direct_handoff_barrier
```

The next tracked replay surface extends the replay series with a quorum-backed
claim service:

- `docs/specs/distributed_replay_quorum_barrier.tla`
- `docs/specs/distributed_replay_quorum_barrier.cfg`

It is still intentionally narrow. It models one 2-of-3 replicated claim
service, local quorum certificates at each replica, and degraded connectivity to
individual claim-store replicas. Claims and execution require a current quorum
certificate rather than unanimous store agreement. It proves the safety shape:

- at most one replica can execute
- executed replicas require a current quorum certificate for their owner and
  epoch
- stale claimed states cannot execute without first regaining a current quorum
  or taking the fail-closed rejection path
- degraded connectivity or minority lag stays fail-closed instead of executing
  on one-store or stale-cert evidence

Modeling assumptions:

- claims update one write quorum atomically
- local quorum certificates are refreshed explicitly and can become stale
- competing local certificates are not atomically invalidated; stale ones fail
  closed through the reject or execute guards
- no direct owner handoff is modeled in this packet
- no Byzantine store behavior is modeled here

What it still does not prove:

- split-brain or quorum-member equivocation
- liveness under degraded connectivity
- post-execution quorum sustainment after the barrier step
- quorum reconfiguration or membership churn
- direct owner-to-owner handoff under quorum replication

Replay command:

```bash
cd docs/specs
java -cp ../../external/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup \
  -deadlock \
  -config distributed_replay_quorum_barrier.cfg \
  distributed_replay_quorum_barrier
```

The next tracked replay surface extends that series with observable quorum
equivocation:

- `docs/specs/distributed_replay_quorum_equivocation_barrier.tla`
- `docs/specs/distributed_replay_quorum_equivocation_barrier.cfg`

It is still intentionally narrow. It models one quorum certificate per replica,
explicit peer-certificate visibility that can become stale, and the possibility
that conflicting same-epoch certificates exist due to equivocation. It proves
the safety shape:

- at most one replica can execute
- executed replicas require fresh peer-certificate visibility and no visible
  same-epoch owner conflict
- visible same-epoch owner conflict blocks execution and introduces a
  fail-closed rejection step from the claimed state
- visible equivocation cannot cross the execute barrier

Modeling assumptions:

- equivocation may exist before peer-certificate visibility catches up
- the barrier explicitly refreshes peer-certificate visibility before execute
- `effect_count` still models the earlier serial commit barrier, so the
  equivocation logic itself only blocks same-epoch visible conflicts
- this packet does not prove invisible equivocation is detected
- this packet does not model Byzantine certificate forgery beyond conflicting
  owner claims

What it still does not prove:

- hidden or never-shared equivocation
- quorum membership churn or threshold reconfiguration
- crash-fault claim-store replication details
- liveness after conflict detection

Replay command:

```bash
cd docs/specs
java -cp ../../external/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup \
  -deadlock \
  -config distributed_replay_quorum_equivocation_barrier.cfg \
  distributed_replay_quorum_equivocation_barrier
```

The next tracked replay surface extends that series with post-conflict recovery:

- `docs/specs/distributed_replay_equivocation_recovery_barrier.tla`
- `docs/specs/distributed_replay_equivocation_recovery_barrier.cfg`

It is still intentionally narrow. It models visible same-epoch equivocation,
an explicit recovery step that clears conflicting certificates and advances a
resolution epoch, and the requirement that only fresh post-resolution
certificates may cross the execute barrier. It proves the safety shape:

- at most one replica can execute
- visible conflict blocks execution, and the explicit recovery step clears
  conflicting certificates
- executed replicas require a fresh certificate strictly above the current
  resolution epoch
- stale pre-resolution certificates cannot survive recovery and then execute

Modeling assumptions:

- recovery is an explicit fail-closed step, not a liveness or fairness theorem
- hidden or never-shared equivocation is still outside this packet
- certificate freshness must be reacquired after recovery before execute
- the global `effect_count` barrier from the earlier serial-commit packet still
  carries the non-equivocation at-most-once part of the safety story
- this packet does not model Byzantine certificate forgery beyond conflicting
  owner claims

What it still does not prove:

- eventual recovery after visible conflict
- eventual successful progress after recovery
- hidden equivocation detection
- quorum reconfiguration or membership churn
- direct owner handoff combined with recovery

Replay command:

```bash
cd docs/specs
java -cp ../../external/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup \
  -deadlock \
  -config distributed_replay_equivocation_recovery_barrier.cfg \
  distributed_replay_equivocation_recovery_barrier
```

The next tracked replay surface isolates hidden or delayed certificate
visibility:

- `docs/specs/distributed_replay_hidden_equivocation_barrier.tla`
- `docs/specs/distributed_replay_hidden_equivocation_barrier.cfg`

It is still intentionally narrow. It models actual same-epoch conflicting
certificates, per-replica peer-certificate views that can be stale or absent,
and the requirement that execute only trusts a fresh peer view. It proves the
safety shape:

- at most one replica can execute, with the global `effect_count` barrier from
  the earlier serial-commit packet still carrying the non-equivocation
  at-most-once part of that safety story
- fresh peer views mirror the actual peer certificate state
- a hidden same-epoch conflict cannot cross execute while peer visibility is
  stale
- a visible same-epoch conflict blocks execute and enables a fail-closed
  rejection path from `claimed`

Modeling assumptions:

- peer visibility is refreshed explicitly; stale visibility is represented by
  `fresh12` and `fresh21`
- this packet is safety-only and does not prove eventual peer refresh
- this packet does not model Byzantine certificate forgery beyond conflicting
  owner claims

What it still does not prove:

- hidden-conflict detection without a fresh peer refresh
- eventual progress after link recovery
- quorum membership churn or threshold reconfiguration
- post-conflict recovery once a hidden conflict becomes visible

Replay command:

```bash
cd docs/specs
java -cp ../../external/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup \
  -deadlock \
  -config distributed_replay_hidden_equivocation_barrier.cfg \
  distributed_replay_hidden_equivocation_barrier
```

The next tracked replay surface isolates crash ordering between external effect
emission and nonce finalization:

- `docs/specs/distributed_effect_finalization_barrier.tla`
- `docs/specs/distributed_effect_finalization_barrier.cfg`

It is still intentionally narrow. It models one logical effect id, an initial
attempt plus one retry attempt, a durable effect-commit barrier that is written
atomically with the first external effect emission, and late nonce finalization
that may only complete after crash or recovery. It proves the safety shape:

- at most one external effect can be committed
- once the durable effect-commit barrier is written, retries cannot cross the
  execute barrier again before late finalization
- recovery may complete nonce finalization for an already committed effect
  without requiring a second external effect emission

Modeling assumptions:

- the durable effect-commit barrier is written atomically with the first
  external effect emission
- retries re-check that durable barrier before any new effect emission
- finalization may lag effect emission and may happen only after crash recovery
- this packet is safety-only and does not prove liveness or eventual cleanup

What it still does not prove:

- that the shipped runtime already implements this durable effect-commit
  barrier end to end
- atomicity or idempotence of any real external system beyond the modeled
  single effect id
- replicated or partitioned effect-log behavior
- multi-effect batches or cross-chain side-effect workflows

Replay command:

```bash
cd docs/specs
java -cp ../../external/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup \
  -deadlock \
  -config distributed_effect_finalization_barrier.cfg \
  distributed_effect_finalization_barrier
```

The next tracked replay surface narrows that runtime story to the shipped
adapter-facing HTTP barrier:

- `docs/specs/idempotent_http_effect_barrier.tla`
- `docs/specs/idempotent_http_effect_barrier.cfg`

It is still intentionally narrow. It models one initiator attempt, one retry
attempt, a local pending marker written before remote execution, and a local
committed marker written only after acknowledged success. It proves the safety
shape:

- at most one remote effect can be emitted
- retries fail closed instead of emitting a second remote effect while the
  pending marker is unresolved
- once the committed marker exists, retries short-circuit idempotently instead
  of crossing the remote execute boundary again

Modeling assumptions:

- the local pending marker is durable before the remote attempt begins
- retries check the same local journal before any remote attempt
- acknowledged success is the only path that promotes pending to committed
- this packet is safety-only and does not prove manual recovery or liveness

What it still does not prove:

- that every deployed remote executor honors the same idempotency key
- end-to-end exactly-once behavior across partitions or cross-service races
- webhook or other non-HTTP effect surfaces
- operator recovery policy for long-lived pending barriers

Replay command:

```bash
cd docs/specs
java -cp ../../external/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup \
  -deadlock \
  -config idempotent_http_effect_barrier.cfg \
  idempotent_http_effect_barrier
```

The next tracked replay surface narrows the deployment-startup rule for that
same shipped HTTP barrier:

- `docs/specs/idempotent_http_startup_pending_barrier.tla`
- `docs/specs/idempotent_http_startup_pending_barrier.cfg`

It is intentionally narrow. It models a restarted production server facing a
persisted `.pending.json` barrier from an earlier uncertain remote outcome. It
proves the safety shape:

- startup cannot enter serving state while an unresolved pending barrier exists
- retries stay blocked or rejected while the pending barrier remains unresolved
- explicit operator resolution may either clear the barrier when no effect is
  known durable, or promote it to committed when a durable effect is known

Modeling assumptions:

- the pending barrier persists across restart until explicit resolution
- the restart path checks the same local journal before serving requests
- manual resolution is modeled as a local operator action, not a liveness claim

What it still does not prove:

- that operator recovery is always correct or prompt
- remote-side confirmation or reconciliation protocols
- end-to-end exactly-once behavior across partitions or cross-service races

Replay command:

```bash
cd docs/specs
java -cp ../../external/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup \
  -deadlock \
  -config idempotent_http_startup_pending_barrier.cfg \
  idempotent_http_startup_pending_barrier
```

The next tracked replay surface narrows the local file-side-effect path:

- `docs/specs/idempotent_file_effect_barrier.tla`
- `docs/specs/idempotent_file_effect_barrier.cfg`

This packet is intentionally simpler than the HTTP barrier. For the shipped
`idempotent_file` sink, the per-nonce durable file is both the side effect and
the barrier, so the model treats the create as atomic and proves the local
safety shape:

- at most one local file effect can be emitted for the nonce
- once the per-nonce file exists, later writers short-circuit idempotently
- there is no separate pending state to recover because the file itself is the
  durable commit marker

Modeling assumptions:

- the underlying per-nonce file create is atomic for the local sink
- writers target the same per-nonce path
- this is a local single-filesystem safety model, not a distributed storage
  theorem

What it still does not prove:

- replicated or networked filesystem semantics
- cross-node races on shared storage beyond the single-file atomic create
- end-to-end exactly-once behavior across partitions or remote sinks

Replay command:

```bash
cd docs/specs
java -cp ../../external/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup \
  -deadlock \
  -config idempotent_file_effect_barrier.cfg \
  idempotent_file_effect_barrier
```

## Mode C

Mode C is currently strong as a private-lane verification boundary.

It is not yet full minimized trust because:

- the prover or operator still sees plaintext
- registry and governance authority remain part of the trust root
- source mapping and activation-tier admission are still separate boundaries

So any parallel optimization must preserve the Mode C commit gate and must not
be used to weaken authority admission.
