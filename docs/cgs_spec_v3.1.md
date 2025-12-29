# ESSO Codegen Synth (CGS) v3.1 — MPRD Implementation Notes

> **Status:** Implemented (MVP) in MPRD  
> **Last Updated:** 2025-12-29

This doc summarizes what CGS v3.1 features are implemented in this repo and how they map to the v3.1 spec.

## What’s Implemented

### Profiles (`--profile`)

CGS `synth` supports four profiles:
- `dev`, `ci`: Z3-only verification obligations.
- `release`, `audit`: Z3 + cvc5 cross-check required (fail-closed on missing solver, disagreement, UNKNOWN/TIMEOUT).

All profiles keep deterministic replay on by default (`--no-determinism-check` exists but is not recommended).

### Semantics Profile (pinned)

`synth_version="3.1"` requires `--semantics-profile <json>`.

MPRD currently supports exactly one pinned semantics profile (kernel + SMT agree):
- bounded ints with range checks
- `div` is total and returns `0` on divisor `0` (Z3-compatible Euclidean `div`)

The loaded profile is persisted to `artifacts/semantics_profile.json` and its hash is recorded in:
- `result.json` (`semantics_profile.hash`)
- `determinism.json` (`semantics_profile_hash`)

### Style Profile (pinned)

`synth_version="3.1"` accepts `--style-profile <json>` (or inline `style_profile` in `synth.json`).

The loaded profile is persisted to `artifacts/style_profile.json` and its hash is recorded in:
- `result.json` (`style_profile.hash`)
- `determinism.json` (`style_profile_hash`)

### Candidate Identity (`esso-candidate/v1`)

CGS emits a canonical candidate identity file:
- `artifacts/candidate_identity.json`
- `artifacts/candidate_identity.hash`

This captures:
- input `model_hash`
- `synth_hash`
- `semantics_profile_hash`
- `baseline_hash` (if provided)
- hole AST normal forms + source (`sygus`/`llm`)
- `style_profile_hash`

### Proof-Preserving Beautifier (MVP)

When `synth_version="3.1"`, CGS runs a best-effort beautifier over hole expressions:
- deterministic `ite`→`min/max` extraction where applicable
- proof of equivalence under domain constraints via Z3 before applying a rewrite
- never affects PASS: if equivalence is not proven, the rewrite is skipped

Output:
- `artifacts/beautify_report.json`

### Spec Debugger Mode (MVP)

On SyGuS `infeasible`, CGS emits:
- `artifacts/infeasible_report.json`
- `artifacts/infeasible_report.hash`

Current classifications:
- `SEMANTIC_UNSAT` when conflicting learned point constraints are detected
- otherwise `INCONCLUSIVE` (with deterministic grammar-widening repair suggestions)

### Typed Verification Claim

PASS results include a typed `claim` in `result.json` describing:
- method (`K_INDUCTION` + optional `BMC` for trace-equivalence)
- scope hashes (domain caps + semantics profile)
- per-property entries for invariants, hole semantic constraints, and equivalence checks

## CLI Examples

Basic synth:

```bash
python3 -m internal.tools.evolver synth internal/tools/evolver/examples/simple_counter.yaml \
  internal/tools/evolver/examples/simple_counter_synth_v3.json \
  --seed 1 \
  --output /tmp/esso_cgs_out
```

v3.1 with pinned profiles:

```bash
python3 -m internal.tools.evolver synth <model.yaml> <synth_v3_1.json> \
  --seed 42 \
  --profile release \
  --semantics-profile <semantics_profile.json> \
  --style-profile <style_profile.json> \
  --output /tmp/esso_cgs_v3_1
```

## Not Implemented Yet (v3.1/v3.x items)

- Full second-order infeasibility diagnosis (semantic feasibility test via bounded lookup-table encoding).
- Auto-apply repair synthesis modes (repairs are suggestions only).
- Full e-graph extraction with configurable rewrite sets (current is deterministic “e-graph lite” + targeted rewrites).
- Portfolio search engines (Enum/MCTS) and neural/LLM guidance beyond pinned hint packs.

