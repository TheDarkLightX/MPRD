# mprd-core

Core types and logic for the MPRD (Model Proposes, Rules Decide) system.

## Overview

This crate provides the foundational types and interfaces for MPRD:

- **Selector**: Chooses the best allowed action from candidates
- **Orchestrator**: Coordinates the proposal → decision → execution flow
- **Types**: Core data structures (Decision, CandidateAction, RuleVerdict, etc.)

## Key Types

```rust
// Minimal token that executors consume, binding policy, state and action.
pub struct DecisionToken {
    pub policy_hash: Hash32,
    pub policy_ref: PolicyRef,
    pub state_hash: Hash32,
    pub chosen_action_hash: Hash32,
    pub nonce_or_tx_hash: Hash32,
    pub timestamp_ms: i64,
    pub signature: Vec<u8>,
}

// Proof bundle produced by an attestor (e.g. Risc0 host).
pub struct ProofBundle {
    pub policy_hash: Hash32,
    pub state_hash: Hash32,
    pub candidate_set_hash: Hash32,
    pub chosen_action_hash: Hash32,
    pub limits_hash: Hash32,
    pub limits_bytes: Vec<u8>,
    pub chosen_action_preimage: Vec<u8>,
    pub risc0_receipt: Vec<u8>,
}
```

## Usage

```rust
use mprd_core::{DefaultSelector, Selector, CandidateAction, RuleVerdict};

let selector = DefaultSelector;
let decision = selector.select(
    &policy_hash,
    &state,
    &candidates,
    &verdicts,
)?;
```

## Testing

```bash
cargo test -p mprd-core
```
