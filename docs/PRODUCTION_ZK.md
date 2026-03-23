# MPRD Production ZK Proofs

This document explains how to use Risc0 ZK proofs in MPRD production deployments.

MPRD currently includes two Risc0 guests:

- `MPRD_GUEST_*`: transitional “host-trusted” guest (does not re-evaluate policy in-guest)
- `MPRD_MPB_GUEST_*`: mpb-v1 guest (executes MPB + selection in-guest)
- `MPRD_TAU_COMPILED_GUEST_*`: tau_compiled_v1 guest (executes compiled Tau circuit + selection in-guest)

Both guests commit a fail-closed, versioned journal (`mprd-risc0-shared`) that binds:
- exec kind/version IDs
- encoding IDs
- nonce/anti-replay binding
- policy authorization context (`policy_epoch`, `registry_root`)
- state provenance context (`state_source_id`, `state_epoch`, `state_attestation_hash`)

## Signed Guest Image Manifest (Recommended)

For production verifiers, prefer routing image IDs from a signed manifest:

- `crates/mprd-zk/src/manifest.rs` (`GuestImageManifestV1`)
- Mapping: `(policy_exec_kind_id, policy_exec_version_id) -> image_id`

This prevents image routing from depending on untrusted hints and makes the allowlist auditable.

Note: production deployments may use distinct signing keys for:
- registry checkpoints (policy authorization context), and
- guest image manifests (exec-kind image allowlist).

## Registry-Bound Verification (Recommended)

For production “fail-closed” verification, prefer evaluating:

- `ValidDecision(bundle, registry_state) == true`

via `crates/mprd-zk/src/registry_state.rs` (`RegistryBoundRisc0Verifier`), which:
- selects the allowed `image_id` from verifier-trusted `registry_state` *before* receipt verification
- checks `policy_hash` is authorized at exactly `(policy_epoch, registry_root)`

Current runtime policy admission is therefore fail-closed on verifier-trusted
cryptographic authority, not on arbitrary uploaded spec files. A node only
treats a policy as live after a trusted signed or committee-authenticated
registry checkpoint is accepted, the guest manifest verifies, `policy_ref`
matches the same `(policy_epoch, registry_root)`, the `policy_hash` is listed
in the checkpoint, and the authorized exec kind routes through the manifest.
Today that authority is pseudonymous public-key material (single key, signer
set, or signer-weight map), not yet a first-class owner-namespace assignment or
certification-tier system.
The formal ShapeForge bundle now also has a local governance-execution bridge
packet: execution-time `governance_ok` should depend on both a resolved live
policy and an admitted governance update. That packet is proved locally, but the
runtime refinement from concrete registry and governance objects into the
execution slice's `governance_ok` bit is still an open boundary.
The formal ShapeForge bundle now also has a local selector-contract-binding
packet: execution should require both `chosen_index` selecting the same
`chosen_action_hash` and `chosen_action_preimage` hashing back to that same
selected candidate. Candidate-family admission is also stricter now: the core
canonicalizer sorts unique candidate hashes into ascending canonical-hash order,
rejects score-agnostic duplicate executable payloads, and the guest/attestor/
verifier surfaces reject noncanonical sorted-unique families. MPB-lite artifact
admission now also carries aligned `candidate_preimages`, so local and external
verifiers reject duplicate executable payloads across the full family and fail
closed if that witness is missing. The aligned family witness is now the
authoritative chosen-action source for MPB-lite artifacts; current
`mpb_lite_v3` artifacts omit the redundant duplicated `candidate_hashes` and
the always-empty duplicate `chosen_action_preimage`, while legacy v1/v2
duplicates are only accepted when they normalize exactly to that same family
and chosen member. The runtime still lacks a replayable refinement edge from the
concrete candidate-set and preimage objects into the formal selector-binding
state, and broader semantic canonicalization beyond action type plus sorted
params remains open.

On operator decision-log paths, MPB-lite v2/v3 proofs can now deduplicate the
persisted chosen-action blob when the stored receipt replayably derives the
same chosen preimage. The store records a sentinel instead of
`chosen_action_preimage.bin`, and both operator blob export and HTTP download
surfaces resolve that sentinel through the same fail-closed receipt-to-preimage
helper in `crates/mprd-cli/src/operator/store.rs`.

If Tau source bytes are treated as the governed policy source-of-truth while executing MPB bytecode, publish a governed mapping in `registry_state` and require it fail-closed:

- `crates/mprd-zk/src/registry_state.rs`: `AuthorizedPolicyV1::{policy_source_kind_id, policy_source_hash, policy_source_intent_kind_id}`
- `crates/mprd-zk/src/lib.rs`: `create_production_verifier_from_signed_registry_state()` requires the mapping by default

Current production helper factories enforce this conservatively once selected: they require
`policy_source_*` presence uniformly and do not branch on `policy_source_kind_id` at the public
boundary.

For deployment inspection, `mprd deploy check-bundle` now reports deterministically sorted
per-policy source-governance rows in human output, and `--format json` emits the same partition
in a machine-readable bundle report. `source_governance` stays tri-valued
(`TauGovernedMapped | OtherMapped | Unmapped`), and the per-policy
`source_intent_classification` field reports the signed source-intent witness
(`TauDeclared | OtherDeclared | Undeclared`) without upgrading it into governance proof. The per-policy
`source_boundary_classification` field further splits `Unmapped` into
`TauCompiledCarrierUnmapped | OtherCarrierUnmapped`, so operators can see when a missing mapping
occurs on a Tau carrier and whether that carrier was explicitly Tau-intended, without overclaiming
full source governance. The same checked report now also exposes
`strict_selector_aliases`, so accepted strict carrier selectors are queryable from the bundle JSON
and strict failure packets instead of being reconstructed from docs or tests. The report also exposes
`artifact_hash_validated` plus `source_artifact_witness_state`
(`Ready | BlockedMissingSourceMapping | BlockedArtifactValidation`), so source mapping and exact
artifact-byte validation can be tracked as a single deploy-boundary witness without treating that
artifact witness as compiler equivalence. The deploy surface also exposes
`--format normalized-json` and `--format digest`, both derived from the same checked report object
but with local artifact paths stripped, so equivalent bundle checks can be compared safely across
different checkout roots. If operator intent is explicit, repeat
`--strict-governed-source <exec-kind>` to require those exec kinds to be `TauGovernedMapped`;
failures are deterministic and include a stable strict-failure digest. For automation, add
`--strict-governed-source-failure-format json|digest` to emit the structured strict failure witness
on stdout before exiting nonzero, rather than scraping stderr. Strict governed-source rejection now
uses a dedicated exit code (`2`) so automation can distinguish it from generic command failure,
while ordinary bundle-validation failures stay on the generic exit code (`1`).
Built-in exec kinds accept both their friendly labels and their canonical lowercase hex ids on
this strict surface.
If operator intent also requires a full source-plus-artifact witness, repeat
`--strict-source-artifact-witness <exec-kind>` to require
`source_artifact_witness_state = Ready` for those exec kinds. That is stricter than governed-source
mapping alone: selected exec kinds must have both source mapping and exact local artifact-byte
validation at the deploy boundary. For automation, add
`--strict-source-artifact-witness-failure-format json|digest` to emit the structured strict
failure witness on stdout before exiting nonzero. Strict source-artifact-witness rejection uses its
own dedicated exit code (`3`), which stays distinct from governed-source rejection (`2`) and from
generic bundle-validation failure (`1`).
Built-in exec kinds accept the same label-or-canonical-hex aliases on this stricter surface too.
If both strict modes are declared for the same exec kind, governed-source runs first and
source-artifact witness runs second. That keeps source mapping as the antecedent contract for the
stronger source-plus-artifact readiness check.
The issue-kind to response mapping is pinned in
`internal/shapeforge/mprd/evidence/strict_governed_source_response_matrix.json`, so remediation
logic does not have to be reconstructed from prose or tests, and the machine failure packet now
embeds the corresponding `classification`, `required_response`, signed intent classification, and
boundary classification data directly. That lets automation distinguish the stronger
`tau_declared_mapping_missing` case from a generic `policy_not_tau_governed` rejection without
treating source intent as equivalent to governed mapping.
External consumers can query the same contract from the binary with
`mprd deploy strict-governed-source-response-matrix --format human|json|digest`, and the JSON
export is regression-checked against the pinned artifact bytes.
The sibling source-artifact contract is pinned in
`internal/shapeforge/mprd/evidence/strict_source_artifact_witness_response_matrix.json`, and
external consumers can query it with
`mprd deploy strict-source-artifact-witness-response-matrix --format human|json|digest`.
The built-in strict selector language is also pinned independently of bundle contents in
`internal/shapeforge/mprd/evidence/strict_selector_alias_matrix.json`, and external consumers can
query it with `mprd deploy strict-selector-alias-matrix --format human|json|digest`. That matrix
stays intentionally limited to built-in selector families; non-built-in exec-kind selectors remain
bundle-discovered through per-policy `strict_selector_aliases` rows.
Human rows, JSON stdout,
normalized JSON, digest output, and strict-mode success/failure paths are regression-tested end to
end against scrambled bundle fixtures, including cross-checks that human strict-failure fields and
machine failure packets describe the same rejection.

If your registry checkpoint key and manifest key differ, use:
- `crates/mprd-zk/src/lib.rs`: `create_production_verifier_from_signed_registry_state_with_manifest_key()`
- `mprd verify`: `--manifest-key-hex`

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        MPRD Pipeline                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐ │
│  │ Proposer  │──>│  Policy   │──>│ Selector  │──>│ Attestor  │ │
│  │  (Model)  │   │  Engine   │   │           │   │ (Risc0)   │ │
│  └───────────┘   └───────────┘   └───────────┘   └─────┬─────┘ │
│                                                         │       │
│                                                         ▼       │
│  ┌───────────┐   ┌───────────┐   ┌───────────────────────────┐ │
│  │ Executor  │<──│ Verifier  │<──│ Receipt (ZK Proof)        │ │
│  │           │   │ (Risc0)   │   │ • policy_hash             │ │
│  └───────────┘   └───────────┘   │ • state_hash              │ │
│                                   │ • action_hash             │ │
│                                   │ • encoding IDs             │ │
│                                   │ • exec kind/version IDs    │ │
│                                   │ • nonce + limits hash       │ │
│                                   │ • selector_contract: ✓      │ │
│                                   └───────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Setup

### 1. Install Risc0 Toolchain

```bash
# Install cargo-risczero
cargo install cargo-risczero

# Install the RISC-V toolchain
cargo risczero install

# Verify installation
cargo risczero --version
```

### 2. Build the Guest Program

```bash
cd crates/mprd-risc0-methods
cargo build --release
```

This generates:
- `MPRD_GUEST_ELF` / `MPRD_GUEST_ID`: transitional host-trusted guest
- `MPRD_MPB_GUEST_ELF` / `MPRD_MPB_GUEST_ID`: MPB-in-guest program

### 3. Add ZK Dependencies in mprd-zk

```toml
# In your Cargo.toml
[dependencies]
mprd-zk = { path = "../mprd-zk" }
mprd-risc0-methods = { path = "../mprd-risc0-methods" }
```

## Usage

### Generating Proofs

```rust
use mprd_risc0_methods::{MPRD_GUEST_ELF, MPRD_GUEST_ID};
use mprd_zk::create_risc0_attestor;

// Create the attestor
// Convert Risc0 digest ([u32; 8]) -> [u8; 32] for verifier/attestor configuration.
let mut image_id = [0u8; 32];
for (i, word) in MPRD_GUEST_ID.iter().enumerate() {
    image_id[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
}
let attestor = create_risc0_attestor(MPRD_GUEST_ELF, image_id);

// Generate a ZK proof
// Note: you must pass the RuleVerdict for the chosen action so the guest can
// validate the selector contract (Allowed = true).
let proof = attestor.attest_with_verdict(&token, &decision, &state, &candidates, &verdict)?;

// The proof contains:
// - risc0_receipt: Serialized zkVM receipt (~100KB-1MB)
// - attestation_metadata: {"zk_backend": "risc0", "image_id": "..."}
```

### Verifying Proofs

#### Recommended (Production): Registry-bound `ValidDecision`

In production, verifiers should fail-closed evaluate:

- `ValidDecision(bundle, registry_state) == true`

using a verifier-trusted signed registry checkpoint (policy authorization + ImageID routing):

```rust,ignore
use mprd_core::TokenVerifyingKey;
use mprd_zk::create_production_verifier_from_signed_registry_state;
use mprd_zk::registry_state::SignedRegistryStateV1;

let registry_vk = TokenVerifyingKey::from_hex("...")?;
let signed_registry_state: SignedRegistryStateV1 = serde_json::from_slice(registry_state_bytes)?;
let verifier = create_production_verifier_from_signed_registry_state(
    signed_registry_state,
    &registry_vk,
)?;

let status = verifier.verify(&token, &proof);
```

#### Dev-only: Verify against an explicit ImageID

```rust
use mprd_risc0_methods::MPRD_GUEST_ID;
use mprd_zk::create_risc0_verifier;
use mprd_core::ZkLocalVerifier;

// Convert Risc0 digest ([u32; 8]) -> [u8; 32]
let mut image_id = [0u8; 32];
for (i, word) in MPRD_GUEST_ID.iter().enumerate() {
    image_id[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
}

// Create the verifier with the expected image ID
let verifier = create_risc0_verifier(image_id);

// Verify the proof
match verifier.verify(&token, &proof) {
    VerificationStatus::Success => {
        // Proof is valid - execute the action
        executor.execute(&token, &proof)?;
    }
    VerificationStatus::Failure(reason) => {
        // Proof is invalid - reject the action
        tracing::error!("Proof verification failed: {}", reason);
    }
}
```

## What Gets Proven

The ZK proof cryptographically attests to:

1. **Selector Contract Satisfaction**
   ```
   Sel(policy, state, candidates) = action
   => action ∈ candidates ∧ Allowed(policy, state, action) = true
   ```

   Notes:
   - `MPRD_GUEST_*` is transitional and does not yet recompute `Allowed(...)` in-guest.
   - `MPRD_MPB_GUEST_*` executes MPB and deterministic selection in-guest.

2. **Hash + ID Binding**
   - `policy_hash`, `state_hash`, `candidate_set_hash`, `chosen_action_hash`
   - `state_encoding_id`, `action_encoding_id`
   - `policy_exec_kind_id`, `policy_exec_version_id`
   - `nonce_or_tx_hash` (anti-replay binding)
   - `limits_hash` (enforceable limits binding; mpb-v1 pins fuel semantics)
   - `state_source_id`, `state_epoch`, `state_attestation_hash` (state provenance binding)

3. **Decision Commitment**
   The guest commits `decision_commitment` binding the full public transcript in `GuestJournalV3`
   (including `journal_version`, IDs, commitments, `policy_epoch`, `registry_root`, `state_source_id/state_epoch/state_attestation_hash`, `nonce_or_tx_hash`, and `limits_hash`).

## Security Properties

### Trustlessness
- Third parties can verify proofs without trusting the operator
- The operator cannot forge proofs for actions that violate the policy

### Code Binding
- The image ID cryptographically binds the guest program
- Any modification to the guest changes the image ID
- Verifiers reject proofs from unauthorized guest programs

### Non-Repudiation
- The receipt is a permanent record of the decision
- The operator cannot later deny they made the decision

## Performance

| Operation | Time (approx) | Size |
|-----------|---------------|------|
| Proof Generation | 10-60 seconds | - |
| Receipt Size | - | 100KB-1MB |
| Verification | 10-100 ms | - |

### Optimization Tips

1. **Parallel Proving**: Use multiple cores
   ```rust
   // Risc0 automatically uses available cores
   ```

2. **Proof Caching**: Cache receipts for repeated decisions

3. **Batching**: Prove multiple decisions in one receipt (future)

## Development Mode

For faster iteration during development you can:

- Run **Mode A (LocalTrusted)** without ZK proof generation, relying only on
  signatures and anti-replay for internal systems.
- Use **Mode B-Lite (MPB)** to get computational proofs via the custom MPB
  bytecode VM. These are faster than full ZK but are *not* cryptographic in
  the same way as Risc0. Treat them as strong internal checks, not as a full
  trustless guarantee.

In all cases, the Risc0-based path described above remains the canonical
cryptographic option for public, adversarial, or high-assurance deployments.

## Deployment Modes

### Mode A: Local (No ZK)
- Fast execution without proofs
- Trust the operator
- Good for internal systems

### Mode B: Trustless (Real ZK)
- Every decision generates a proof
- Third parties can verify
- Required for public deployments

### Mode C: Private (ZK + Encryption)
- Proofs without revealing inputs
- Uses commitment schemes
- Maximum privacy

## Troubleshooting

### "Proving failed: ..."
- Ensure Risc0 toolchain is installed
- Check that guest program compiles
- Verify input serialization

### "Receipt verification failed: ..."
- Image ID mismatch (guest was recompiled?)
- Corrupted receipt data
- Wrong verifier image ID

### "Failed to decode journal: ..."
- Guest/host output type mismatch
- Serialization format changed
