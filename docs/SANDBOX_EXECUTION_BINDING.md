# Policy-bound sandbox execution

A sandbox contains untrusted computation. It does not authorize that computation.

MPRD authorizes one exact sandbox plan through a canonical `sandbox_run` candidate. The candidate commits to:

- the Helix sandbox plan hash;
- the sandbox admission-policy hash;
- a whole reviewed runtime-profile hash;
- the externally enforced network-policy hash;
- a non-zero execution nonce and monotonic execution epoch;
- wall-clock, memory, and output-byte ceilings; and
- the requirement that execution produce a receipt.

The resulting candidate hash is the `chosen_action_hash` carried through MPRD's existing decision token and proof boundary.

## Action schema

The v1 action type is:

```text
sandbox_run
```

It has exactly ten parameters. Unknown keys fail closed, which prevents a proposer from smuggling an ambient host fallback, writable mount, extra credential, or uncommitted limit alongside the authorized plan.

The constructor sequence is:

```text
SandboxRunProposalV1
    -> sandbox_run_candidate_v1
    -> MPRD policy evaluation and selection
    -> candidate/proof/token verification
    -> admitted_sandbox_run_binding_v1
```

`AdmittedSandboxRunBindingV1` has private fields and does not implement `Deserialize`; it can only be reconstructed from a candidate whose action schema and canonical candidate hash agree.

## Runtime receipt binding

The sandbox adapter returns an untrusted `SandboxRuntimeReceiptRefV1`. MPRD validates that the receipt preserves:

- the exact plan hash;
- the exact runtime-profile hash;
- the exact execution nonce;
- non-zero receipt, output-manifest, and runtime-attestation commitments;
- coherent termination and exit-code semantics; and
- resource consumption no greater than the authorized ceilings.

A timeout, out-of-memory termination, policy denial, or runtime failure can be a structurally valid receipt, but it is never represented as successful execution.

## Anti-replay

This module binds the execution nonce into the candidate and receipt. Global freshness still requires MPRD's durable nonce validator or another authoritative anti-replay store before the executor launches the sandbox. Commitment is not uniqueness.

## Nonclaims

A validated sandbox receipt proves structural identity and resource binding. It does not prove that:

- the guest output is correct;
- the runtime attestation is authentic without backend-specific verification;
- the runtime actually enforced every profile property without a trusted adapter or attestation verifier; or
- an artifact is safe to publish or use in a later effect.

Those claims require separate policy, proof, or verification layers.
