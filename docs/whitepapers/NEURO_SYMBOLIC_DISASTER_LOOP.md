# What-If Witness Spaces

## A Neuro-Symbolic Disaster Loop for Fail-Closed Software Hardening

Date: 2026-04-24

Project: MPRD

Primary implementation: `tools/run_neuro_symbolic_disaster_loop.py`

Primary receipt:
`internal/assurance/sota_stack/receipts/neuro_symbolic_disaster_loop_latest.json`

Latest receipt hash at time of writing:
`sha256:b83ee1178c4bea460b9c7e3c67d5ccf1d7ac330e017746236fcfc7274c459561`

## Abstract

Modern software assurance still fails most often at composition boundaries. A
single parser, proof, test, or fuzz target may look safe in isolation, while the
system can still fail when a stale receipt, optional feature lane, retry path,
registry update, proof journal, selector decision, or executor boundary is
combined with another valid-looking state. The hard problem is not just "can this
function reject bad input?" but "what disaster states become reachable when safe
subsystems are wired together, evidence is stale, and the system is asked to
research or promote a new lane?"

The MPRD neuro-symbolic disaster loop is a bounded answer to that problem. The
"neuro" part proposes structured "what if?" hypotheses over a danger atlas:
single-surface disasters, composition edges, order inversions, re-entry paths,
fan-out, convergence, cycles, evidence failures, provenance drift, and optional
source-of-truth conflicts. The symbolic part is deterministic: it evaluates those
hypotheses against replayable receipts, checker references, git provenance,
synthetic fault mutations, and a fail-closed research gate.

The result is not a proof of global safety. It is a proof-shaped bounded
assurance artifact: for the current atlas, receipts, checker, and generated
witness space, the loop can state exactly what it checked, which states remain
researchable, which states are blocked, which evidence failures are rejected, and
which claims are outside scope. In the latest MPRD run, the gate checked 16,003
materialized what-ifs plus a compressed 75,599,999-combination independent
frontier, found 0 reachable disaster witnesses, observed 0 fail-closed failures
across receipt, blocker, provenance, and optional-conflict mutations, and opened
the bounded research gate.

## 1. The Problem

Most security hardening workflows are organized around local artifacts:

- unit tests for local invariants,
- fuzz targets for parsers and state machines,
- symbolic checks for extracted helpers,
- proof files for selected mathematical claims,
- CI gates for regressions.

These are necessary, but they leave a gap. Real failures often occur in the
space between artifacts. A receipt can be stale. A guided fuzz lane can be
unstable. A registry update can authorize a policy artifact that later changes a
selector decision. A proof journal can be valid for one candidate but replayed
against another. A retry can re-enter replay clearance after side effects have
already occurred. A checker can be edited locally after a receipt was generated.

Those are not just bugs in code paths. They are disaster states in a composed
research process. They answer questions like:

- What if a policy artifact is authorized by a stale registry root?
- What if selector admissibility is checked before certification drift is caught?
- What if replay clearance is correct locally, but transport retry re-presents
  the same claim?
- What if a stability receipt says a lane is stable while the atlas still says
  it is mixed?
- What if the checker that interprets the receipts is itself dirty?

Traditional test plans often handle these cases as ad hoc follow-up work. The
MPRD disaster loop makes them first-class objects.

## 2. Core Idea

The core idea is to treat hardening as bounded exploration of a witness space.

A witness space is a set of concrete or symbolic "what if?" hypotheses. Each
hypothesis names:

- the surfaces involved,
- the disaster state being tested,
- the kind of composition or evidence fault,
- the receipt or checker evidence required to decide it.

The loop has two roles:

1. Hypothesis generation asks the creative questions. This is the neuro-symbolic
   role normally supplied by an LLM, a human reviewer, a tactic database, or a
   search policy. It is allowed to be creative. It is not trusted.
2. Deterministic checking decides whether the hypothesis is researchable,
   blocked, or a reachable disaster witness. This is the symbolic role. It is the
   only promotion authority.

This separation is the central safety property of the method. The LLM can ask
"what if?" but it cannot declare the system safe. The checker can reject,
summarize, and gate. Promotion depends on replayable evidence, not on plausibility.

## 3. MPRD Implementation

The current implementation is `tools/run_neuro_symbolic_disaster_loop.py`.

Inputs:

- `internal/assurance/sota_stack/danger_atlas.json`
- mandatory campaign receipts under `internal/assurance/sota_stack/receipts/`
- optional lane compare and stability receipts,
- blocker and harness source references,
- current git head and checker worktree state.

Outputs:

- a JSON receipt,
- a Markdown receipt,
- stable timestamp-free hashes,
- compact result digests by default,
- optional full materialized results with `--full-results`,
- a strict gate via `tools/test.sh disaster-gate`.

The loop currently covers 11 surfaces:

| Surface | Example disaster states |
| --- | --- |
| `replay_nonce_claim` | duplicate side effects, nonce claimed twice, distributed claim race |
| `quorum_snapshot_attestation` | untrusted threshold, duplicate signer, drifted snapshot |
| `orchestrator_pipeline_ordering` | verify-fail-but-execute, record-before-verify, duplicate payload |
| `selector_candidate_family` | noncanonical family, out-of-bounds selection, hash mismatch |
| `operator_control_lifecycle` | invalid retention mutation, mode transition drift |
| `decision_token_proof_journal_binding` | decision commitment drift, journal state drift |
| `policy_artifact_run_lifecycle` | unauthorized artifact, source mapping gap, tamper |
| `registry_key_rotation_authorization` | insufficient quorum, rotated key still authorizes |
| `tau_policy_certification_boundary` | unsupported policy fail-open, tampered Tau certifies |
| `executor_side_effect_boundary` | invalid boundary reaches side effect, idempotency drift |
| `executor_transport_boundary` | invalid boundary reaches network, retry budget drift |

The atlas owns the composition graph. At the latest run, the frontier was
exhausted through depth 11, which equals the number of surfaces. The graph
includes forward composition edges such as registry-to-policy-artifact,
policy-artifact-to-Tau-certification, selector-to-orchestrator, orchestrator-to
journal binding, replay-to-executor-side-effect, and side-effect-to-transport.
It also includes re-entry edges such as transport retry back into replay and
journal replay back into orchestrator ordering.

## 4. Hypothesis Families

The latest materialized witness space contains 16,003 hypotheses:

| Family | Count |
| --- | ---: |
| `single_surface_disaster` | 47 |
| `receipt_fail_open_mutation` | 11 |
| `blocker_bypass_disaster` | 194 |
| `edge_composition_disaster` | 196 |
| `order_inversion_disaster` | 196 |
| `chain_researchability` | 71 |
| `chain_terminal_disaster` | 1,079 |
| `fanout_composition_disaster` | 64 |
| `convergence_composition_disaster` | 299 |
| `reentry_retry_disaster` | 66 |
| `cycle_amplification_disaster` | 66 |
| `independent_pair_coreachability` | 1,000 |
| `independent_triple_coreachability` | 12,714 |

The larger independent co-reachability space is represented in compressed form
rather than materialized into a huge receipt. The latest compressed frontier
contains 75,599,999 independent combinations through order 11. All are currently
researchable under the current bounded receipts.

## 5. Deterministic Classification

For each hypothesis, the checker computes one of three relevant outcomes:

- `REACHABLE_DISASTER_WITNESS`: the current evidence says a named disaster is
  reachable or a receipt reports a concrete failing condition.
- `UNKNOWN_BLOCKED`: the evidence is missing, stale, failed, unreferenced, or
  otherwise insufficient, so the hypothesis is rejected fail-closed.
- `NO_REACHABLE_WITNESS_BOUNDED`: the current bounded evidence contains no
  reachable witness for that generated hypothesis.

Researchability is a separate field:

- `researchable_under_current_bounded_receipts`
- `blocked_missing_or_failed_receipt`
- `blocked_for_promotion_due_optional_instability`
- `blocked_reachable_disaster_witness`

This distinction matters. "No witness found" is not automatically "safe to
research." A surface can have no reachable witness and still be blocked because
the optional lane is mixed, evidence is stale, or the checker is dirty.

## 6. Synthetic Fault Families

The loop does not merely classify the current happy path. It mutates the evidence
model to ensure the gate rejects common disaster-enabling evidence faults.

Latest synthetic checks:

| Fault family | Count | Passing condition | Failures |
| --- | ---: | --- | ---: |
| receipt-state mutation | 66 | missing, failed, nonzero, artifact-drift, stale, optional-mixed evidence blocks | 0 |
| blocker-state mutation | 22 | missing checker source or unreferenced harness blocks | 0 |
| provenance mutation | 16 | synthetic stale git heads block | 0 |
| optional-conflict mutation | 25 | stable-over-stale-atlas allowed; blocking receipts reject | 0 |

The optional-conflict family is important because it covers a subtle research
failure mode: two sources of truth can disagree. The gate now explicitly tests:

- atlas says mixed, newest receipt says stable,
- atlas says stable, receipt rejects,
- receipt decision is stable, next guidance rejects,
- one optional receipt is stable while another blocks,
- atlas says stable, optional receipt is missing.

Only the first case is researchable. The others block fail-closed.

## 7. Provenance and Dirty-Checker Handling

Receipts carry git provenance when the receipt schema supports it. The strict
gate rejects hard receipt head mismatches. Under disk pressure, however, rerunning
all fuzz receipts after every checker-only edit is wasteful and can be impossible.
The loop therefore uses a narrow compatibility rule:

- if the receipt head differs from the current head,
- and `git diff receipt_head..current_head` touches only
  `tools/run_neuro_symbolic_disaster_loop.py`,
- then the receipt is recorded as compatible checker-only drift;
- otherwise it remains a hard mismatch and the gate blocks.

This is intentionally conservative. At the latest run there were 12 compatible
checker-only drifts and 0 hard mismatches.

The gate also checks the worktree state of the checker itself. If
`tools/run_neuro_symbolic_disaster_loop.py` is dirty, the gate adds
`checker_worktree_dirty` and blocks. This prevents an uncommitted checker edit
from interpreting old receipts and claiming the research gate is open. Unrelated
dirty worktree files do not block this receipt, because the repo currently has
large unrelated local edits and the disaster gate needs a focused provenance
boundary.

## 8. Algorithm Sketch

```text
input:
  danger atlas A
  mandatory receipts Rm
  optional receipts Ro
  blocker source references B
  harness references H
  current git head g
  max depth d

build:
  surfaces S from A
  composition graph E from A
  re-entry graph Q from A
  surface checks C from Rm, Ro, B, H, g

generate:
  materialized hypotheses W:
    single-surface disasters
    receipt fail-open cases
    blocker bypasses
    edge compositions
    order inversions
    bounded chains
    terminal chain disasters
    fan-out and convergence cases
    re-entry and cycle-amplification cases
    independent pairs and triples

  compressed frontier F:
    independent combinations of order 4 through |S|

mutate:
  receipt-state faults
  blocker-state faults
  provenance faults
  optional source-of-truth conflicts

classify:
  for each hypothesis w in W:
    if mandatory evidence missing or failed:
      UNKNOWN_BLOCKED
    else if optional evidence blocks:
      NO_REACHABLE_WITNESS_BOUNDED, but not researchable
    else if a receipt records a concrete failing disaster:
      REACHABLE_DISASTER_WITNESS
    else:
      NO_REACHABLE_WITNESS_BOUNDED and researchable

gate:
  open only if:
    no reachable disaster witnesses
    no unknown mandatory blockers
    no optional research blockers
    graph frontier exhausted
    synthetic receipt, blocker, provenance, and optional-conflict checks pass
    receipt provenance has no hard mismatch
    gate-critical checker file is clean

output:
  compact receipt with result digests
  optional full receipt
  stable timestamp-free hash
```

## 9. What This Revolutionizes

The method is not revolutionary because it uses an LLM. The LLM is deliberately
untrusted. The shift is architectural.

### 9.1 Hardening Moves From Local Coverage to Compositional Witness Closure

Traditional hardening asks, "Did each component pass its tests?" This loop asks,
"Which composed disaster states are reachable under current evidence, and which
are blocked by missing or unstable evidence?"

That is a stronger operational question. It catches the class of failures where
each local component appears healthy, but the research process can still promote
or explore an unsafe composed state.

### 9.2 The LLM Becomes a Question Generator, Not an Authority

The LLM's strength is adversarial imagination: "what if the order is inverted?",
"what if retry re-enters replay?", "what if a stable receipt disagrees with the
atlas?", "what if the checker itself changed?" The method uses that strength
without trusting it. The deterministic checker owns promotion.

This creates a useful division of labor:

- neural or human creativity expands the witness space,
- symbolic checks decide the state,
- receipts preserve replay,
- fail-closed gates prevent optimism from becoming policy.

### 9.3 Evidence Failures Become Test Cases

Missing receipts, stale git heads, optional instability, unreferenced blocker
symbols, and dirty checkers are usually process failures. Here they are modeled
as explicit synthetic disaster states. The gate is tested against them on every
run.

### 9.4 "Safe to Research" Becomes a Machine-Checkable State

The loop does not merely say "no bug found." It says whether the bounded frontier
is open for research. That difference matters. Research can be unsafe if it is
allowed to optimize, promote, rank, or explore from stale evidence. The gate
therefore treats `UNKNOWN`, `TIMEOUT`, `INCONCLUSIVE`, missing artifacts, stale
receipts, and dirty checker state as reject conditions.

### 9.5 The Result Is Reproducible Under Disk Pressure

The receipt is compact by default, hash-stable, and can be replayed in full mode
with the same stable hash. It avoids heavy fuzz rebuilds unless runtime or
harness evidence changes. This matters in real engineering environments where
disk, time, and toolchains are constraints.

## 10. Current Result

At the latest recorded run:

- gate: `OPEN_FOR_BOUNDED_RESEARCH`
- materialized hypotheses: 16,003
- reachable disaster witnesses: 0
- unknown mandatory blockers: 0
- compressed independent frontier: 75,599,999 combinations
- optional research blocks: 0
- receipt-state synthetic checks: 66, failures 0
- blocker-state synthetic checks: 22, failures 0
- provenance synthetic checks: 16, failures 0
- optional-conflict synthetic checks: 25, failures 0
- hard receipt git mismatches: 0
- compatible checker-only receipt drifts: 12
- checker worktree dirty: false
- compact/full stable hash parity: passed

This result is meaningful because earlier runs did not open the gate. The gate
previously blocked on registry optional-lane instability, then on stale mandatory
receipt provenance, then on checker provenance. Those were not cosmetic failures.
They were exactly the kind of process-level disaster states the method is meant
to expose.

## 11. What It Proves

The word "prove" must be used carefully. The loop proves bounded statements about
the current model, not universal statements about all possible executions.

### Claim 1: Bounded No-Witness Result

Given:

- the current danger atlas,
- the current receipt set,
- the current checker,
- the generated hypothesis family,
- the exhausted simple-path depth 11 frontier,
- the strict gate conditions,

the latest run proves that no materialized generated hypothesis has a reachable
disaster witness under the checker. It also proves that the compressed
independent frontier is not blocked by optional or mandatory evidence under the
current receipt model.

This is a bounded negative result: no witness in this generated space.

### Claim 2: Fail-Closed Evidence Handling for Tested Fault Classes

The latest run proves that every synthetic receipt, blocker, provenance, and
optional-conflict mutation in the implemented mutation suite is handled according
to the expected fail-closed policy.

For example:

- missing mandatory receipt blocks,
- `ok=false` blocks,
- nonzero return code blocks,
- artifact drift blocks,
- missing blocker source blocks,
- unreferenced harness blocker blocks,
- stale synthetic git head blocks,
- blocking optional receipt overrides atlas stability,
- dirty checker blocks.

### Claim 3: Research Permission Is Conditional, Not Assumed

The gate proves that the current state is open for bounded research only because
all gate blockers are absent. If any blocker appears, the gate moves to a blocked
state. This was exercised in the development history: registry optional
instability, stale receipts, and dirty checker state each blocked the gate until
their evidence boundary was clarified.

### Claim 4: Receipt Reproducibility

The compact and full receipt modes produce the same stable timestamp-free hash
for the same semantic content. This proves that compact receipt storage is not
silently dropping safety-relevant content from the stable gate claim.

## 12. What It Does Not Prove

The loop does not prove global software safety.

It does not prove:

- that the danger atlas contains every possible disaster state,
- that the generated "what if?" families are complete,
- that all real-world executions are bounded by the modeled frontier,
- that every receipt's underlying fuzz campaign was exhaustive,
- that every harness perfectly refines production behavior,
- that the checker has been machine-proved correct,
- that optional receipts without `git_head` are permanently acceptable,
- that future code changes preserve the result,
- that cryptographic, network, OS, compiler, or deployment assumptions hold,
- that there are no bugs outside the named surfaces,
- that absence of a generated witness means absence of vulnerability.

It also does not give the LLM authority. The LLM can propose missing cases, but a
case is only promotable after deterministic replay says it is promotable. A
timeout, parse error, unknown state, missing receipt, stale receipt, or dirty
checker is not a weak pass. It is a reject.

## 13. Why the Boundary Is Still Valuable

Bounded results are often dismissed because they are not global proofs. That is a
mistake. Most engineering promotion decisions are bounded anyway. The difference
is whether the boundary is explicit.

The disaster loop makes the boundary explicit:

- exact surfaces,
- exact disaster states,
- exact graph edges,
- exact hypothesis families,
- exact receipts,
- exact git provenance,
- exact synthetic fault classes,
- exact gate blockers,
- exact stable hash.

This turns "we tested it" into a replayable claim:

> Under these artifacts and this checker, this witness space contains no
> reachable disaster witness, and these evidence-failure families reject
> fail-closed.

That is a much stronger basis for research and promotion than a checklist or a
green CI badge alone.

## 14. Design Principles

The MPRD loop suggests several general principles for hardening complex systems.

### Make Disaster States Concrete

Names such as `verify_fail_but_execute`,
`duplicate_side_effect_after_claim`, and
`unauthorized_policy_artifact_materializes` are better than generic "security
bug" labels. Concrete names make harnesses, receipts, and blockers auditable.

### Separate Witness Absence From Research Permission

No witness found is not the same as safe to research. Research permission also
requires stable optional lanes, current evidence, clean checker state, and
frontier exhaustion.

### Treat Evidence as Part of the State Machine

Receipts, provenance, optional guidance, and checker cleanliness are not external
bookkeeping. They are state variables in the assurance protocol.

### Prefer Deterministic Summaries Over Large Opaque Logs

The compact receipt keeps stable digests for full result arrays and can be
replayed in full mode. This preserves auditability without creating huge default
artifacts.

### Let Creative Search Be Untrusted

The LLM, human reviewer, or search heuristic should be free to generate strange
questions. But the promotion gate must remain deterministic and fail-closed.

## 15. Future Work

The current loop points to several next steps:

- Add graph-topology mutations: missing edge, inverted edge, duplicate edge,
  re-entry promoted to composition, and self-loop-at-surface.
- Upgrade older optional and non-fuzz receipt schemas to carry `git_head`, then
  make missing provenance a hard gate.
- Expand optional-conflict checks from per-surface synthetic cases to per-receipt
  pair conflicts once optional receipts carry provenance.
- Add content hashes for ignored internal artifacts so uncommitted atlas or
  receipt edits cannot silently change a gate claim.
- Connect selected claims to Lean, SMT, or ESSO obligations where the checker
  logic is small enough to formalize.
- Use Morph or ESSO to discover new graph edges and candidate disaster states,
  while keeping all promotion evidence deterministic.
- Generate minimal counterexample packets automatically when a reachable witness
  appears.

## 16. Conclusion

The neuro-symbolic disaster loop changes the shape of software hardening. It does
not ask an LLM whether the system is safe. It asks the LLM, human, and search
machinery to generate dangerous questions, then forces every answer through a
deterministic, receipt-backed, fail-closed checker.

That is the revolution: hardening becomes an adversarial witness-space discipline
rather than a collection of disconnected tests. It can say what is researchable,
what is blocked, what evidence failed, what the checker did, and what remains
outside the claim.

For MPRD, the current bounded witness space is open for research: 16,003
materialized what-ifs and 75,599,999 compressed independent combinations contain
0 reachable disaster witnesses under the current receipts, with synthetic
evidence faults rejecting fail-closed. That is not global safety. It is a precise,
replayable, and honest safety boundary. That boundary is exactly what high-stakes
software needs before it is allowed to learn, optimize, or promote new states.
