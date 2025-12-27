//! Operator Services (spec-aligned kernels)
//!
//! This crate contains minimal, auditable state-machine kernels aligned with:
//! - Proof Market v6: `internal/specs/operator_services_lean_proofs_v6.lean`
//! - OPI Oracle v6: `internal/specs/opi_oracle_spec_v6.md`
//! - Optimistic Relay v15: `internal/specs/optimistic_relay_spec_v15.md`

pub mod optimistic_relay;
pub mod opi_oracle;
pub mod proof_market;
pub mod types;
