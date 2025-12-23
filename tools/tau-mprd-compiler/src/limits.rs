//! Shared hard limits for Tau-MPRD v1 (compile-time and artifact bounds).
//!
//! These limits are intended to match the TCV v2 artifact bounds used by MPRD.

/// Maximum temporal lookback depth (t-1..t-k).
pub const MAX_LOOKBACK_V1: usize = 8;

/// Maximum number of arithmetic predicates per compiled policy.
pub const MAX_PREDICATES_V1: usize = 32;

/// Maximum key length for field names.
pub const MAX_KEY_LENGTH_V1: usize = 64;

/// Maximum number of circuit gates.
pub const MAX_GATES_V1: usize = 4096;

/// Maximum number of temporal fields in the compiled artifact.
pub const MAX_TEMPORAL_FIELDS_V1: usize = 16;

/// Maximum number of wires addressable by the circuit.
///
/// The circuit interpreter sizes its wire array based on the maximum referenced index.
/// This prevents DoS via extremely large wire indices.
pub const MAX_WIRES_V1: usize = MAX_GATES_V1 + 256;

/// Maximum compiled artifact size in bytes.
pub const MAX_ARTIFACT_BYTES_V1: usize = 64 * 1024;

