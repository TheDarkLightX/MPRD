# MPRD Governance Specifications

## Overview

This directory contains Tau governance specifications for MPRD decision-making.

**Note:** The `archive/`, `inputs/`, and `outputs/` directories are gitignored as they contain experimental specs and runtime artifacts.

## Canonical Specs (Recommended)

The `canonical/` directory contains the **production-ready** Tau governance specifications:

| Spec | Purpose | Pattern |
|------|---------|---------|
| **mprd_governance_gate.tau** | Main governance gate | bv[8] ternary decode |
| **mprd_committee_quorum.tau** | M-of-N committee voting | sbf Boolean |
| **mprd_timelock.tau** | Two-phase commit with delay | sbf delay chain |
| **mprd_escalation.tau** | Risk-tiered authorization | bv[8] + sbf |
| **mprd_conviction.tau** | Time-weighted voting | sbf delay chain |

## Best Overall: `mprd_governance_gate.tau`

This is the **recommended canonical spec** for MPRD governance decisions.
Uses **sbf-only** (pure Boolean) logic for maximum reliability.

```
┌─────────────────────────────────────────────────────────────┐
│  mprd_governance_gate.tau (sbf-only)                        │
├─────────────────────────────────────────────────────────────┤
│  Inputs (host decodes UpdateKind to one-hot):               │
│    i_is_policy_tweak   : sbf  (1 if UpdateKind::PolicyTweak)│
│    i_is_safety_change  : sbf  (1 if UpdateKind::SafetyChange)│
│    i_is_cap_expand     : sbf  (1 if UpdateKind::CapExpand)  │
│    i_profile_app_ok    : sbf                                │
│    i_profile_safety_ok : sbf                                │
│    i_link_ok           : sbf                                │
├─────────────────────────────────────────────────────────────┤
│  Output:                                                    │
│    o_accept            : sbf                                │
├─────────────────────────────────────────────────────────────┤
│  Logic (one-hot enforced):                                  │
│    PolicyTweak:      app_ok && link_ok                     │
│    SafetyChange:     safety_ok && link_ok                  │
│    CapabilityExpand: app_ok && safety_ok && link_ok        │
└─────────────────────────────────────────────────────────────┘
```

## Integration with Rust

```rust
use mprd_zk::{GovernanceProfile, GovernanceGateInput, UpdateKind};

// Create profile
let profile = GovernanceProfile::hybrid(app_config, safety_config, chain_id, app_id)?;

// Check authorization (produces Tau input)
let gate_input: GovernanceGateInput = profile.check_authorization(
    UpdateKind::PolicyTweak,
    &app_signatures,
    &safety_signatures,
    prev_hash,
    new_hash,
);

// Rust-side validation (mirrors Tau spec)
let accepted = GovernanceProfile::would_accept(&gate_input);
```

## Design Principles

1. **Host computes, Tau validates** - Complex arithmetic in Rust, Boolean logic in Tau
2. **bv[8] for enums** - Use ternary decode: `(x = {#x01}:bv[8]) ? then : else`
3. **sbf for flags** - Pure Boolean logic always works
4. **Delay chains for time** - Use `o[t] = o[t-1]` pattern, not bv counters

## Archive

The `archive/` directory contains experimental approaches that were tested during development. See `APPROACH_COMPARISON.md` for detailed analysis.
