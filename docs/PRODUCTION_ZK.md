# MPRD Production ZK Proofs

This document explains how to use Risc0 ZK proofs in MPRD production deployments.

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
│                                   │ • selector_contract: ✓    │ │
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
- `MPRD_GUEST_ELF`: The compiled guest program
- `MPRD_GUEST_ID`: The image ID (32-byte hash)

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
let attestor = create_risc0_attestor(MPRD_GUEST_ELF, MPRD_GUEST_ID);

// Generate a ZK proof
// Note: you must pass the RuleVerdict for the chosen action so the guest can
// validate the selector contract (Allowed = true).
let proof = attestor.attest_with_verdict(&decision, &state, &candidates, &verdict)?;

// The proof contains:
// - risc0_receipt: Serialized zkVM receipt (~100KB-1MB)
// - attestation_metadata: {"zk_backend": "risc0", "image_id": "..."}
```

### Verifying Proofs

```rust
use mprd_risc0_methods::MPRD_GUEST_ID;
use mprd_zk::create_risc0_verifier;
use mprd_core::ZkLocalVerifier;

// Create the verifier with the expected image ID
let verifier = create_risc0_verifier(MPRD_GUEST_ID);

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

2. **Hash Binding**
   - `policy_hash` = SHA256(policy)
   - `state_hash` = SHA256(state)
   - `candidate_set_hash` = SHA256(candidates)
   - `chosen_action_hash` = SHA256(action)

3. **Decision Commitment**
   ```
   commitment = SHA256(policy_hash || state_hash || candidates_hash || action_hash || satisfied)
   ```

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
