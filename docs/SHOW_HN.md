# Show HN Launch Draft

## Recommended title

**Show HN: MPRD – deterministic gates for actions proposed by AI agents**

Alternative:

**Show HN: Model Proposes, Rules Decide – proof-carrying execution for AI agents**

## Post

Hi HN,

I built MPRD (Model Proposes, Rules Decide) around a simple separation: let a model be creative, but do not let the model itself authorize side effects.

The proposer can generate arbitrary candidate actions. A deterministic governor canonicalizes the relevant state and candidate, evaluates policy, and issues a narrowly scoped execution token only for an accepted action. The executor is a separate capability boundary and rejects execution without a valid token. Receipts and journals make the decision replayable.

The architecture is intentionally neuro-symbolic:

```text
model proposes -> deterministic policy decides -> token/receipt -> executor acts
```

The repository combines Rust implementation work with Lean 4 proof artifacts, Tau policy specifications, a policy-algebra/certification rail, and Risc0-based proof-carrying execution experiments.

The formal target is:

```text
for every action admitted through the modeled executor boundary,
the committed policy predicate held for the committed state/action pair
```

That is narrower than claiming that an entire production deployment is "formally safe." The proof only means something if the real executor, token verification, canonicalization, freshness/epoch rules, anti-replay checks, and trusted implementation boundary correspond to the model. I am trying to make those assumptions explicit and progressively shrink them.

A motivating failure class is stale or conflicting authorization: one subsystem decides that an action is permitted, while another side effect races ahead using different or older state. MPRD treats authorization as a proof-carrying state transition rather than a prompt-level instruction.

Useful entry points:

- README / architecture: https://github.com/TheDarkLightX/MPRD
- Lean proof bundle: `proofs/lean/`
- Policy certification: `docs/POLICY_CERTIFICATION.md`
- Production assumptions: `docs/PRODUCTION_READINESS.md`
- Security hardening: `docs/SECURITY_HARDENING_CHECKLIST.md`

I would especially value criticism of the trust boundary:

1. Which state commitments are still too weak?
2. Where can a confused-deputy or replay path bypass the intended executor boundary?
3. Which invariants are worth moving from tests/receipts into Lean or another proof layer?
4. What would make the system useful enough to integrate rather than merely interesting to inspect?

Repo: https://github.com/TheDarkLightX/MPRD

## Before posting

- Run the current Rust and Lean verification commands from a clean checkout.
- Make sure every linked document exists on `main`.
- Link one small runnable example near the top of the README if possible.
- Answer technical criticism with the exact modeled assumption or artifact; do not widen a local proof into an end-to-end claim.
- Keep the initial HN post technical. Do not ask for a job, stars, investment, or upvotes.
- If a commenter finds a real boundary bug, turn the criticism into a minimal reproducer and an issue.
