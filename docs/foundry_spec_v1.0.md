# ESSO Foundry (Internal) — v1.0 MVP

Foundry is an internal, deterministic wrapper around ESSO CGS that turns **REQ modules** into:

- canonical ESSO-IR (`model.json`)
- CGS inputs (`synth.json`, `semantics_profile.json`, `style_profile.json`)
- build outputs (`build/<req_id>/<req_version>/seed_<seed>/...`)
- a content-addressed evidence registry (`registry/objects/<sha256>`)
- a hash-chained ledger (`registry/ledger.jsonl`)

Foundry is designed to be **fail-closed** and **replayable**: it never accepts on `UNKNOWN/TIMEOUT/ERROR/DISAGREE`.

## Workspace Layout

`foundry init` creates:

```
foundry.toml
requirements/          # *.req.yaml modules
models/                # compiled snapshots (deterministic)
build/                 # CGS output bundles
ce/                    # optional CE corpus per req_id (reject-only)
policies/              # default semantics/style profiles
registry/
  objects/             # content-addressed objects
  ledger.jsonl         # hash-chain entries
```

## REQ Schema (foundry-req/v1)

Minimum shape:

```yaml
schema: foundry-req/v1
req_id: simple.counter
req_version: 0.1.0
criticality: critical            # critical|non_critical
semantics_profile: mprd_bounded_int_total_div0_v1
style_profile: default_pretty_v1
constants: {}
state:
  count: { type: nat, max: 3, init: 0 }
actions:
  - name: inc
    params: {}
    pre: ["count < 3"]
    eff: ["count' = count"]      # placeholder; CGS patches this
invariants:
  - name: count_bounds
    expr: "count >= 0 and count <= 3"
observations:
  - name: public
    exprs: [count]
synthesis:
  holes:
    - hole_id: count_next
      used_in: { action: inc, field: count }
      constraints: ["count_next == count + 1"]
```

## CLI

All commands emit JSON to stdout and return non-zero on failure.

- `python3 -m internal.tools.foundry init --root <dir>`
- `python3 -m internal.tools.foundry compile --root <dir>`
- `python3 -m internal.tools.foundry build --root <dir> --profile dev|ci`
- `python3 -m internal.tools.foundry release --root <dir>`
- `python3 -m internal.tools.foundry audit --root <dir>`

## Determinism & Evidence

- `models/**` outputs are deterministic for a fixed REQ module.
- CGS synthesis determinism is enforced by CGS itself (artifact hashing + determinism replay).
- `registry/objects/**` is content-addressed: the filename is the SHA-256 of the file bytes.
- `registry/ledger.jsonl` is a hash chain (append-only) using `prev_hash`.

## Current MVP Limitations (Intentional)

- Only the built-in semantics profile is supported end-to-end today:
  - `mprd_bounded_int_total_div0_v1` (`div/mod` by zero = 0, bounded Int with range checks).
- One-hole-use restriction (matches CGS v1.1): each hole targets exactly one `{action, field}`.
- Hole IDs must match `[a-z][a-z0-9_]*` (CGS/SyGuS requirement).
- No upgrade workflow yet (`foundry upgrade` is deferred).

