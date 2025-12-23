# Tau-MPRD Compiler

A compiler for the **Tau-MPRD** policy language subset, targeting the TCV (Tau Compiled Verifier) circuit format for use with MPRD's trust-minimized execution model.

## Overview

This compiler translates a restricted subset of the [Tau Language](https://github.com/IDNI/tau-lang) into a deterministic, bounded Boolean circuit representation that can be executed inside a zkVM guest.

**Key properties:**
- **Deterministic compilation**: Same source always produces identical artifact bytes and hash
- **Bounded execution**: All loops/recursion resolved at compile time
- **Fail-closed**: Any ambiguity or unsupported construct causes compilation failure
- **License-safe**: Does not link to or embed Tau language libraries

## Tau-MPRD Subset

The supported subset includes:

### Versions

- **v1 (default):** deterministic Boolean circuit + u64 comparisons (no general arithmetic).
- **v2 (`--v2`):** deterministic arithmetic DAG (bounded) + comparisons, suitable for weighted sums and other straight-line math.

### Temporal Operators
- `always <local_spec>` (or `[] <local_spec>`)

### Logical Connectives
- `&&` (and), `||` (or), `!` (not)

### Comparison Operators (on u64 operands)
- `=`, `!=`, `<`, `<=`, `>`, `>=`

### Arithmetic (v2 only)
- `+`, `-`
- `* <const>`, `/ <const>` (constant multiplier/divisor; division by zero is rejected)
- `min(a, b)`, `max(a, b)`, `clamp(x, lo, hi)`

### Operand References
- `state.<field_name>` - reference to state field (required prefix)
- `candidate.<field_name>` - reference to candidate parameter (required prefix)
- `state.<field_name>[t-k]` - temporal lookback (k ≤ 8)
- Integer literals (0-9+)

**Type note:** v1/v2 treat referenced fields as `u64`. In MPRD canonical preimages this means the referenced keys MUST encode as `Value::UInt(u64)`. If you want “boolean fields”, encode them as `UInt(0|1)`.

### NOT Supported (by design)
- `sometimes` / `<>` (non-deterministic)
- `ex` / `all` (quantifiers)
- Bitvector arithmetic (explicit `bv` operators)
- Recurrence relations with unbounded indices
- Stream I/O (`i1[t]`, `o1[t]`)

## Usage

```bash
# Compile Tau-MPRD source to TCV circuit format
tau-mprd-compile --input policy.tau --output policy.tcv

# Output includes:
# - policy_source_hash: SHA-256 of source bytes
# - policy_hash: SHA-256 of compiled artifact
# - artifact: CompiledTauPolicyV1 in canonical bytes
```

### Production wiring helpers

```bash
# Emit a full policy bundle for registry wiring (JSON)
tau-mprd-compile policy.tau --bundle > policy.bundle.json

# Emit only the required schema (keys + key hashes)
tau-mprd-compile policy.tau --schema > policy.schema.json

# Emit an AuthorizedPolicyV1 snippet for insertion into a signed registry_state checkpoint
tau-mprd-compile policy.tau --registry-entry > authorized_policy.json

# Compile using v2 (arithmetic DAG artifact)
tau-mprd-compile --v2 policy.tau --bundle > policy.v2.bundle.json
```

## Output Format

The compiler produces a `CompiledTauPolicyV1` artifact containing:
- Arithmetic predicates (comparisons on u64 operands)
- Boolean circuit (AND/OR/NOT gates, topologically sorted)
- Temporal field schema
- Output wire index

See `internal/specs/tcv_v2_tau_compiled_verifier.md` for the full artifact specification.

### Hashes

- `policy_source_hash = SHA-256("MPRD_TAU_SOURCE_V1" || tau_source_bytes)`
- `policy_hash = SHA-256("MPRD_TAU_COMPILED_POLICY_V1" || artifact_bytes)`

For v2 (`--v2`):

- `policy_hash = SHA-256("MPRD_TAU_COMPILED_POLICY_V2" || artifact_bytes)`

### Temporal lookback key convention

For `state.<field>[t-k]` (k ≥ 1), the compiled artifact references a key named:

`<field>_t_<k>`

This must exist in the canonical `state_preimage` fields map for in-guest extraction to succeed (fail-closed).

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Tau-MPRD Compiler Pipeline                    │
│                                                                 │
│  ┌─────────┐   ┌─────────┐   ┌──────────┐   ┌─────────────────┐ │
│  │  Lexer  │──▶│ Parser  │──▶│ Semantic │──▶│ IR Construction │ │
│  │         │   │  (AST)  │   │ Analysis │   │                 │ │
│  └─────────┘   └─────────┘   └──────────┘   └────────┬────────┘ │
│                                                      │          │
│                                                      ▼          │
│  ┌─────────────────┐   ┌──────────────┐   ┌─────────────────┐  │
│  │ Canonical Hash  │◀──│  Serializer  │◀──│ Code Generator  │  │
│  │ (policy_hash)   │   │              │   │ (Circuit/MPB)   │  │
│  └─────────────────┘   └──────────────┘   └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## License

MIT OR Apache-2.0

This tool is intentionally separate from the main MPRD workspace to maintain license boundaries. It parses a semantic subset compatible with Tau but does not depend on Tau language libraries.
