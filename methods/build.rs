//! Build script for MPRD Risc0 methods.
//!
//! This compiles the guest program to RISC-V ELF and generates the image ID.

fn main() {
    // Build the guest program
    risc0_build::embed_methods();
}
