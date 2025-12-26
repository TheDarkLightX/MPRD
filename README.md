# MPRD: Model Proposes, Rules Decide

## Harnessing Intelligence

Steam is raw power. Uncontained, it dissipates uselessly into the air. But channel it through a piston, and it moves locomotives across continents. Wind is the same: formless and fleeting until caught by a sail, where it becomes the force that carried civilizations across oceans.

**Intelligence is no different.**

An AI model generates immense creative potential. Ideas, strategies, solutions. But without structure, that potential is either wasted or dangerous. MPRD is the engine that harnesses this force. The model proposes; the rules decide. Every action that executes has passed through a governor that enforces what is allowed. Not by hope, not by training, not by alignment theater. By *architecture*.

The model cannot execute. The executor cannot act without a valid token. The token cannot be minted unless the rules allow it. This is the piston. This is the sail. This is how raw intelligence becomes useful work.

```
┌─────────────────────────────────────────────────────────────┐
│                    The MPRD Engine                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│    ╭──────────╮      ╭──────────╮      ╭──────────╮        │
│    │  Steam   │ ───▶ │  Piston  │ ───▶ │  Motion  │        │
│    │  (AI)    │      │  (Rules) │      │ (Action) │        │
│    ╰──────────╯      ╰──────────╯      ╰──────────╯        │
│                                                             │
│    Proposes          Governs           Executes             │
│    (unbounded)       (bounded)         (only if allowed)    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## The Safety Invariant

```
∀ executed_action: Allowed(policy, state, action) = true
```

This isn't a goal. It's a guarantee. The architecture enforces it:

1. **Proposer cannot execute**: zero direct capability, like steam without a cylinder
2. **Executor is the ONLY path to action**: single, guarded channel
3. **No token, no execution**: the piston won't move without pressure
4. **Tokens only mint for allowed actions**: the governor controls the valve
5. **ZK attestation**: third parties can verify without trusting the operator

### The Proof-Carrying “Codec”

MPRD treats model output as untrusted and high-entropy: the model can propose anything, but cannot execute. A deterministic governance layer canonicalizes state/candidates, commits to them (hashes/IDs/epochs/nonces/limits), and produces a small, versioned proof-carrying transcript (token + receipt/journal) that can cross hostile networks. Verifiers then fail-closed check that transcript against allowlisted code (image IDs from a trusted registry/manifest) and that it matches the token commitments. The executor performs side effects only for the single committed action and only once (anti-replay), turning untrusted proposals into verifiable, permissioned execution.

## Architecture

| Layer | Role | Capability |
|-------|------|------------|
| **Proposer (Model)** | The Steam | Generates ideas, cannot act |
| **Governor (Tau)** | The Piston | Decides what's allowed, issues tokens |
| **Executor** | The Motion | Acts only with valid tokens |

## Deployment Modes

| Mode | Trust | Use Case |
|------|-------|----------|
| **A (Local)** | Operator | Internal testing only |
| **B-Full (Risc0)** | Trustless | **Production default**, ZK proofs |
| **B-Lite (MPB)** | Computational | Experimental, internal only |
| **C (Private)** | Trustless + Private | Privacy-required scenarios |

## Project Structure

```
MPRD/
├── crates/
│   ├── mprd-core/        # Core types, selector, orchestrator
│   ├── mprd-zk/          # ZK infrastructure, governance profiles
│   ├── mprd-adapters/    # External system adapters
│   ├── mprd-proof/       # Proof generation utilities
│   ├── mprd-cli/         # Command-line interface
│   └── mprd-risc0-shared/ # Shared Risc0 types
├── methods/              # Risc0 guest methods
├── policies/             # Tau governance specifications
│   └── governance/
│       └── canonical/    # Production-ready governance specs
└── docs/                 # Documentation
```

## Key Features

### Governance Profiles
```rust
use mprd_zk::{GovernanceProfile, UpdateKind, GovernanceGateInput};

// Create hybrid governance (separate app/safety committees)
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

// Validate (mirrors Tau spec logic)
let accepted = GovernanceProfile::would_accept(&input);
```

### Canonical Tau Specs
Production-ready governance specifications in `policies/governance/canonical/`:

| Spec | Purpose |
|------|---------|
| `mprd_governance_gate.tau` | Main governance gate (sbf-only) |
| `mprd_committee_quorum.tau` | M-of-N committee voting |
| `mprd_timelock.tau` | Two-phase commit with delay |
| `mprd_escalation.tau` | Risk-tiered authorization |
| `mprd_conviction.tau` | Time-weighted voting |

## Building

```bash
# Build all crates
cargo build

# Run tests
cargo test

# Run with ZK proofs (requires Risc0)
cargo build --release
```

## Documentation

| Topic | Description |
|-------|-------------|
| [**SDK Quickstart**](docs/SDK_QUICKSTART.md) | Get started in 5 minutes |
| [**Policy Algebra**](docs/POLICY_ALGEBRA.md) | How to write Tau governance specs |
| [**Production Readiness**](docs/PRODUCTION_READINESS.md) | Pre-deployment checklist |
| [**Security Hardening**](docs/SECURITY_HARDENING_CHECKLIST.md) | Security best practices |
| [**Testing Guide**](docs/TESTING.md) | Testing strategies and commands |
| [**CEO Menu Modes**](docs/CEO_MENU_MODES.md) | Algorithmic tokenomics controller |
| [**ZK Production**](docs/PRODUCTION_ZK.md) | ZK proof deployment guide |

## Testing

```bash
# Run all tests
cargo test

# Run governance tests
cargo test -p mprd-zk -- governance

# Run Tau interpreter tests
cargo test -p mprd-zk --test tau_interpreter_output_tests
```

## Operator Console Retention

The operator console keeps a local decision history on disk. Retention can be controlled at runtime:

- `MPRD_OPERATOR_DECISION_RETENTION_DAYS` (default `30`, `0` disables time-based pruning)
- `MPRD_OPERATOR_DECISION_MAX` (default `10000`, `0` disables size cap)

Settings are persisted in the operator store (`settings.json`) and can be updated live via `POST /api/settings`.
You can trigger an immediate prune via `POST /api/settings/prune`.

## License

See LICENSE file for details.

**Note:** This repository does not include IDNI/Tau licensed code. The `external/` directory is gitignored and must be populated separately with appropriate licenses.
