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
