# mprd-risc0-shared

Shared types between Risc0 host and guest for MPRD.

## Overview

This crate contains types that must be shared between the Risc0 host (prover) and guest (verifier):

- **GuestInput**: Input structure passed to the ZK guest
- **GuestOutput**: Output structure returned from the ZK guest
- **Serialization**: Bincode-compatible serialization

## Usage

This crate is used internally by `mprd-zk` and the Risc0 guest methods. It should not be used directly by application code.

## Testing

```bash
cargo test -p mprd-risc0-shared
```
