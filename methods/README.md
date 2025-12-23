# MPRD Risc0 Methods

This crate builds the MPRD guest program for Risc0 zkVM and exports the ELF binary and image ID.

## Prerequisites

1. Install Risc0 toolchain:
```bash
cargo install cargo-risczero
cargo risczero install
```

2. Install Rust RISC-V target:
```bash
rustup target add riscv32im-risc0-zkvm-elf
```

## Building

```bash
cargo build -p mprd-risc0-methods
```

This will:
1. Compile `mprd-risc0-guest` to RISC-V ELF
2. Generate the image ID (cryptographic hash of the ELF)
3. Export `MPRD_GUEST_ELF` and `MPRD_GUEST_ID` constants

## Usage

```rust
use mprd_risc0_methods::{MPRD_GUEST_ELF, MPRD_GUEST_ID};
use mprd_zk::{create_real_risc0_attestor, create_real_risc0_verifier};

// Create attestor with the guest ELF
let attestor = create_real_risc0_attestor(MPRD_GUEST_ELF, MPRD_GUEST_ID);

// Generate proof
let proof = attestor.attest(&token, &decision, &state, &candidates)?;

// Create verifier with the image ID
let verifier = create_real_risc0_verifier(MPRD_GUEST_ID);

// Verify proof
let status = verifier.verify(&token, &proof);
```

## What the Guest Proves

The guest program verifies:

1. **Selector Contract**: `Sel(p, s, C) = a => a ∈ C ∧ Allowed(p, s, a)`
2. **Hash Commitments**: Policy, state, candidates, and action hashes are correctly computed
3. **Decision Binding**: The decision commitment cryptographically binds all inputs

## Output (Journal)

The proof commits to:
- `policy_hash`: SHA256 of the policy
- `state_hash`: SHA256 of the state
- `candidate_set_hash`: SHA256 of all candidates
- `chosen_action_hash`: SHA256 of the selected action
- `decision_commitment`: Binding commitment of the decision
- `selector_contract_satisfied`: Boolean indicating the invariant holds

## Security

- The image ID is a cryptographic commitment to the guest code
- Any change to the guest program changes the image ID
- Verifiers check the proof against the expected image ID
- This prevents malicious operators from substituting a weaker guest program
