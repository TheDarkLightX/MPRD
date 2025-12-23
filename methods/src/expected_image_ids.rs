//! Locked guest image IDs (drift gate).
//!
//! These constants are a production safety rail: CI fails closed if the embedded guest image IDs
//! change unexpectedly. When guest code changes intentionally, regenerate these values and update
//! any deployment manifests accordingly.

/// Expected image ID for the transitional host-trusted guest (`MPRD_GUEST_ID`).
pub const EXPECTED_MPRD_GUEST_ID: [u32; 8] = [
    3465960277, 2168673795, 557795225, 528479520, 3368524173, 581526617, 4272345278, 2741048113,
];

/// Expected image ID for the MPB-in-guest (`MPRD_MPB_GUEST_ID`).
pub const EXPECTED_MPRD_MPB_GUEST_ID: [u32; 8] = [
    4059904540, 2976606814, 3007898183, 1565334555, 1799074207, 4063355457, 3567998270, 2375812191,
];

/// Expected image ID for the Tau-compiled guest (`MPRD_TAU_COMPILED_GUEST_ID`).
///
/// This is a placeholder until the new method is built and image IDs are regenerated.
/// Regenerate with:
/// `RISC0_SKIP_BUILD=0 cargo run -p mprd-risc0-methods --bin print_image_ids`
pub const EXPECTED_MPRD_TAU_COMPILED_GUEST_ID: [u32; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
