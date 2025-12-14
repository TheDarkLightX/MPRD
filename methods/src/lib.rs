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

// Include the generated methods
include!(concat!(env!("OUT_DIR"), "/methods.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn methods_are_embedded() {
        if std::env::var("RISC0_SKIP_BUILD").as_deref() == Ok("1") {
            eprintln!("Skipping: RISC0_SKIP_BUILD=1 (embedded guest artifacts may be absent)");
            return;
        }

        assert!(
            !MPRD_GUEST_ELF.is_empty(),
            "Risc0 guest ELF is empty (methods not embedded). Ensure Risc0 toolchain is installed and build without RISC0_SKIP_BUILD=1"
        );

        assert!(
            !MPRD_GUEST_ID.iter().all(|w| *w == 0),
            "Risc0 guest image ID is all-zero (methods not embedded). Ensure Risc0 toolchain is installed and build without RISC0_SKIP_BUILD=1"
        );
    }
}
