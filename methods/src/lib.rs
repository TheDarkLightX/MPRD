//! MPRD Risc0 Methods
//!
//! This crate provides the compiled guest ELF binary and image ID.
//!
//! The guest program verifies MPRD decisions:
//! - Checks that the chosen action is in the candidate set
//! - Verifies the policy allowed the chosen action
//! - Computes hash commitments
//!
//! # Usage
//!
//! ```rust,ignore
//! use mprd_risc0_methods::{MPRD_GUEST_ELF, MPRD_GUEST_ID};
//!
//! // Use ELF for proving
//! let receipt = prover.prove(env, MPRD_GUEST_ELF)?;
//!
//! // Use ID for verification
//! receipt.verify(MPRD_GUEST_ID)?;
//! ```
//!
//! For MPB-in-guest proofs, use:
//!
//! ```rust,ignore
//! use mprd_risc0_methods::{MPRD_MPB_GUEST_ELF, MPRD_MPB_GUEST_ID};
//! ```

// Include the generated methods
include!(concat!(env!("OUT_DIR"), "/methods.rs"));

#[cfg(test)]
mod expected_image_ids;

#[cfg(test)]
mod tests {
    use super::expected_image_ids::{
        EXPECTED_MPRD_GUEST_ID, EXPECTED_MPRD_MPB_GUEST_ID, EXPECTED_MPRD_TAU_COMPILED_GUEST_ID,
    };
    use super::*;

    #[test]
    fn methods_are_embedded() {
        if std::env::var("RISC0_SKIP_BUILD").as_deref() == Ok("1") {
            eprintln!("Skipping: RISC0_SKIP_BUILD=1 (embedded guest artifacts may be absent)");
            return;
        }

        let force = std::env::var("RISC0_FORCE_BUILD").as_deref() == Ok("1");
        let guest_zero = MPRD_GUEST_ID.iter().all(|w| *w == 0);
        let mpb_zero = MPRD_MPB_GUEST_ID.iter().all(|w| *w == 0);
        let tau_zero = MPRD_TAU_COMPILED_GUEST_ID.iter().all(|w| *w == 0);

        // Fallback behavior: when the Risc0 toolchain/target isn't installed, build scripts may
        // generate placeholder (all-zero) IDs. This must not fail default developer builds; only
        // fail-closed when explicitly requested.
        if (guest_zero || mpb_zero || tau_zero) && !force {
            eprintln!("Skipping: Risc0 methods not embedded (placeholder all-zero image IDs). Install the Risc0 toolchain/target or set RISC0_FORCE_BUILD=1 to fail-closed.");
            return;
        }

        assert!(
            !guest_zero,
            "Risc0 guest image ID is all-zero (methods not embedded). Ensure Risc0 toolchain is installed and build without RISC0_SKIP_BUILD=1"
        );

        assert!(
            !mpb_zero,
            "Risc0 MPB guest image ID is all-zero (methods not embedded). Ensure Risc0 toolchain is installed and build without RISC0_SKIP_BUILD=1"
        );

        assert!(
            !tau_zero,
            "Risc0 Tau-compiled guest image ID is all-zero (methods not embedded). Ensure Risc0 toolchain is installed and build without RISC0_SKIP_BUILD=1"
        );

        assert_eq!(
            MPRD_GUEST_ID, EXPECTED_MPRD_GUEST_ID,
            "Risc0 guest image ID drift detected. Regenerate with `cargo run -p mprd-risc0-methods --bin print_image_ids` and update any signed manifests."
        );
        assert_eq!(
            MPRD_MPB_GUEST_ID, EXPECTED_MPRD_MPB_GUEST_ID,
            "Risc0 MPB guest image ID drift detected. Regenerate with `cargo run -p mprd-risc0-methods --bin print_image_ids` and update any signed manifests."
        );

        if EXPECTED_MPRD_TAU_COMPILED_GUEST_ID.iter().all(|w| *w == 0) {
            eprintln!("Skipping tau_compiled_guest drift gate: expected ID is placeholder (all-zero). Regenerate expected IDs with `cargo run -p mprd-risc0-methods --bin print_image_ids`.");
            return;
        }
        assert_eq!(
            MPRD_TAU_COMPILED_GUEST_ID, EXPECTED_MPRD_TAU_COMPILED_GUEST_ID,
            "Risc0 Tau-compiled guest image ID drift detected. Regenerate with `cargo run -p mprd-risc0-methods --bin print_image_ids` and update any signed manifests."
        );
    }
}
