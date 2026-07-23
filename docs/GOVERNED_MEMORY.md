# Governed model memory

AnythingLLM demonstrates a useful product pattern: an observer extracts candidate facts from conversation, a reflector consolidates them, and a memory layer makes later interactions more useful. MPRD should adopt the capability without adopting direct model authority over durable state.

## Boundary

The model-facing shell may produce a `MemoryMutationProposal`. It may not write a memory record directly.

The pure policy core evaluates:

```text
(policy, existing_record, proposal)
    -> Result<AdmittedMemoryMutation, MemoryAdmissionError>
```

Only the constructor-gated admitted value is suitable input to a persistence shell. The shell should perform an atomic compare-and-swap on the expected revision and persist the mutation commitment with the resulting record.

## What admission binds

An admitted mutation commits to:

- proposal, memory, subject, and workspace identity;
- workspace or global scope;
- create versus update semantics;
- expected, previous, and next revisions;
- prior and proposed content commitments;
- canonical evidence-hash set;
- observation and optional expiry times; and
- the exact admission-policy hash.

Evidence order is canonicalized before commitment, so semantically identical evidence sets produce the same result. Duplicate and all-zero evidence hashes fail closed.

## Scope and retention

Workspace memory is the default. Global memory is disabled by the default policy and, when enabled, requires an explicit expiry unless policy says otherwise. The functional core receives all times as values; it does not read a clock.

## Authority and construction

`AdmittedMemoryMutation` has private fields and deliberately does not implement `Deserialize`. External code cannot construct or decode an admitted packet without passing through `admit_memory_mutation`.

This is still only one authority boundary. The imperative shell must additionally:

1. reload the current record;
2. compare its revision and content commitment with the admitted packet;
3. atomically persist the new record and commitment; and
4. emit an audit event or receipt only after the commit succeeds.

## Explicit non-guarantees

Admission does **not** prove that a memory is true, complete, unbiased, or still relevant. Evidence hashes bind provenance but do not establish semantic entailment. Higher-assurance deployments can require human approval, signed source receipts, rule-specific attestations, or ZK proofs before supplying admissible evidence.

The kernel also does not perform extraction, reflection, retrieval, persistence, deletion, networking, model calls, or scheduling. Those remain shell concerns and must not be allowed to bypass the admitted type.
