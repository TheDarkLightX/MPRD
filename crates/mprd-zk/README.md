# mprd-zk

Zero-knowledge proof infrastructure and governance profiles for MPRD.

## Overview

This crate provides:

- **Deployment Modes**: Local, Risc0 (ZK), MPB, Private
- **Governance Profiles**: Single-owner, Committee, Hybrid governance
- **Tau Integration**: Runner for Tau governance specifications
- **Decentralization**: Multi-attestor, threshold verification, distributed storage

## Key Types

### Governance Profile

```rust
use mprd_zk::{GovernanceProfile, UpdateKind, GovernanceGateInput};

// Create hybrid governance
let profile = GovernanceProfile::hybrid(
    2, app_members,      // 2-of-N app committee
    3, safety_members,   // 3-of-N safety committee  
    "chain_id", "app_id",
)?;

// Check authorization
let input = profile.check_authorization(
    UpdateKind::PolicyTweak,
    &app_signatures,
    &safety_signatures,
    link_ok,
);

// Validate
assert!(GovernanceProfile::would_accept(&input));
```

### Tau Governance Runner

```rust
use mprd_zk::TauGovernanceRunner;

let runner = TauGovernanceRunner::new("/path/to/tau", work_dir);
runner.write_inputs(&gate_input)?;
// Execute Tau spec, then:
let accepted = runner.read_output()?;
```

### Deployment Modes

```rust
use mprd_zk::{ProductionConfig, ProductionBackend};

// Production: Risc0 ZK proofs (recommended)
// Prefer registry-bound verification (`ValidDecision(bundle, registry_state)`), see docs/PRODUCTION_ZK.md.
let config = ProductionConfig::risc0_mpb_v1(image_id, policy_bytecode, policy_variables);

// Development: Local mode (no proofs)
let config = ProductionConfig::local_testing();
```

## Exports

```rust
pub use {
    // Governance
    UpdateKind, GovernanceMode, ProfileConfig,
    GovernanceProfile, GovernanceGateInput, TauGovernanceRunner,
    
    // Decentralization
    ThresholdConfig, MultiAttestor, ThresholdVerifier,
    
    // Privacy
    Commitment, EncryptedState, SelectiveDisclosure,
    
    // Modes
    DeploymentMode, ProductionConfig,
};
```

## Testing

```bash
# Run all tests
cargo test -p mprd-zk

# Run governance tests
cargo test -p mprd-zk -- governance

# Run Tau interpreter tests
cargo test -p mprd-zk --test tau_interpreter_output_tests
```
