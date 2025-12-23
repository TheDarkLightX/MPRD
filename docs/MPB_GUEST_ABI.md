# MPB-in-Guest (mpb-v1) ABI and Verification Semantics

This document specifies the Risc0 **MPB guest** witness ABI and the **fail-closed** verifier checks for `policy_exec_kind = mpb-v1`.

## Versioning

- **Journal ABI**: `GuestJournalV3` (`journal_version = 3`)
- **Witness ABI**: `MpbGuestInputV3`

The journal is the verified public statement; the witness format may evolve without a journal version bump as long as verifiers pin the **image ID** and validate journal fields fail-closed.

## Policy identity (`policy_hash`)

For `mpb-v1`, `policy_hash` is the content identity of a canonical MPB policy artifact:

- MPB bytecode bytes
- Canonical variable bindings `(name -> reg)`

The guest recomputes `policy_hash` from the witness policy artifact and commits it in the journal.

## Register mapping + ID

The mapping from MPRD state/action encodings to MPB registers is identified by:

- `mpb_register_mapping_id = id("MPRD_ID_V1", "mprd.mpb.register_mapping.v1")`

Mapping rule (mpb-v1):

Inputs are the canonical hash preimage bytes used by `mprd-core`:

1. For each `(name, reg)` binding:
   - if `name == "score"`, use `candidate.score`
   - else use `state.fields[name]` if present in the canonical `state_preimage`
   - else use `candidate.params[name]` if present in the canonical `candidate_preimage`
   - else use `0`
2. Convert values deterministically into `i64` (fail-closed on malformed encodings).

## Limits

`limits_hash = H("MPRD_LIMITS_V1" || canonical_limits_bytes)`

For `mpb-v1`, `canonical_limits_bytes` is currently:

- `TAG_MPB_FUEL_LIMIT (0x01) || MPB_FUEL_LIMIT_V1 (u32 LE)`

This pins and commits the mpb-v1 per-candidate fuel semantics. Future limits can extend `canonical_limits_bytes` by appending additional fixed tags in canonical order.

## Required verifier checks (fail-closed)

After verifying the receipt against an allowed image ID:

- `journal_version == 3`
- Allowlist-check:
  - `policy_exec_kind_id == mpb-v1`
  - `policy_exec_version_id == v1`
  - `state_encoding_id` / `action_encoding_id` are recognized
- `decision_commitment` recomputes correctly
- Binding checks vs token/proof:
  - `policy_hash`, `state_hash`, `candidate_set_hash`, `chosen_action_hash`
  - `policy_epoch`, `registry_root` (policy authorization context)
  - `state_source_id`, `state_epoch`, `state_attestation_hash` (state provenance binding)
  - `nonce_or_tx_hash`
- `limits_hash == limits_hash_mpb_v1()` (pins fuel semantics)
- `allowed == true`
