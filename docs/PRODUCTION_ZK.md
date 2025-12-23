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

If Tau source bytes are treated as the governed policy source-of-truth while executing MPB bytecode, publish a governed mapping in `registry_state` and require it fail-closed:

- `crates/mprd-zk/src/registry_state.rs`: `AuthorizedPolicyV1::{policy_source_kind_id, policy_source_hash}`
- `crates/mprd-zk/src/lib.rs`: `create_production_verifier_from_signed_registry_state()` requires the mapping by default

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
