# mprd-adapters

External system adapters for MPRD integration.

## Overview

This crate provides adapters for integrating MPRD with external systems:

- **LLM Adapters**: Interface with language models for action proposals
- **Chain Adapters**: Interface with blockchain/distributed ledgers
- **Storage Adapters**: Interface with external storage systems

## Usage

Adapters implement standard traits to allow MPRD to communicate with external systems while maintaining the safety invariant that the model can only propose, never execute.

### Proposers

- `HttpProposer`: calls an HTTP endpoint to fetch candidate actions for a given state snapshot.

## Testing

```bash
cargo test -p mprd-adapters
```
