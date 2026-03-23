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
- partitions or claim-store outages force ready replicas to reject instead of
  executing on local readiness alone

Replay command:

```bash
cd docs/specs
java -cp ../../external/tla2tools/tla2tools.jar tlc2.TLC \
  -cleanup \
  -deadlock \
  -config distributed_replay_claim_barrier.cfg \
  distributed_replay_claim_barrier
```

## Mode C

Mode C is currently strong as a private-lane verification boundary.

It is not yet full minimized trust because:

- the prover or operator still sees plaintext
- registry and governance authority remain part of the trust root
- source mapping and activation-tier admission are still separate boundaries

So any parallel optimization must preserve the Mode C commit gate and must not
be used to weaken authority admission.
