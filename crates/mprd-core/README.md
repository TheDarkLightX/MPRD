# mprd-core

Core types and logic for the MPRD (Model Proposes, Rules Decide) system.

## Overview

This crate provides the foundational types and interfaces for MPRD:

- **Selector**: Chooses the best allowed action from candidates
- **Orchestrator**: Coordinates the proposal → decision → execution flow
- **Types**: Core data structures (Decision, CandidateAction, RuleVerdict, etc.)

## Key Types

```rust
// Decision token - proof that an action was allowed
pub struct Decision {
    pub chosen_action: CandidateAction,
    pub decision_hash: Hash32,
    pub timestamp: u64,
}

// Rule verdict from policy evaluation
pub enum RuleVerdict {
    Allowed,
    Denied { reason: String },
}

// Proof bundle for verification
pub struct ProofBundle {
    pub policy_hash: Hash32,
    pub state_hash: Hash32,
    pub decision_hash: Hash32,
    pub proof_data: Vec<u8>,
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
