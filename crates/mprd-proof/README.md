# mprd-proof

Proof generation utilities for MPRD.

## Overview

This crate provides utilities for generating and verifying cryptographic proofs:

- **Hash computation**: SHA-256 based hashing for state, policy, and decisions
- **Signature verification**: Ed25519 signature utilities
- **Commitment schemes**: Pedersen-style commitments

## Usage

```rust
use mprd_proof::{compute_hash, verify_signature};

let hash = compute_hash(&data);
let valid = verify_signature(&pubkey, &message, &signature);
```

## Testing

```bash
cargo test -p mprd-proof
```
