//! Build script for MPRD Risc0 methods.
//!
//! This compiles the guest program to RISC-V ELF and generates the image ID.

fn main() {
    println!("cargo:rerun-if-env-changed=RISC0_SKIP_BUILD");
    println!("cargo:rerun-if-env-changed=RISC0_FORCE_BUILD");

    let out_dir = std::path::PathBuf::from(
        std::env::var_os("OUT_DIR").expect("OUT_DIR must be set by Cargo"),
    );
    let methods_rs = out_dir.join("methods.rs");

    let write_placeholder = || {
        // Keep this in sync with the constants referenced by downstream crates/tests.
        let stub = r#"// @generated (placeholder)
// Risc0 methods are not embedded in this build.
//
// - Set `RISC0_SKIP_BUILD=0` and ensure the Risc0 toolchain + target are installed to embed real methods.
// - Or set `RISC0_SKIP_BUILD=1` to silence method embedding entirely (IDs remain all-zero).

pub const MPRD_GUEST_ELF: &[u8] = &[];
pub const MPRD_MPB_GUEST_ELF: &[u8] = &[];
pub const MPRD_TAU_COMPILED_GUEST_ELF: &[u8] = &[];

pub const MPRD_GUEST_ID: [u32; 8] = [0; 8];
pub const MPRD_MPB_GUEST_ID: [u32; 8] = [0; 8];
pub const MPRD_TAU_COMPILED_GUEST_ID: [u32; 8] = [0; 8];
"#;
        std::fs::write(&methods_rs, stub).expect("write placeholder methods.rs");
    };

    if std::env::var("RISC0_SKIP_BUILD").as_deref() == Ok("1") {
        println!(
            "cargo:warning=RISC0_SKIP_BUILD=1: using placeholder methods (ELF empty, IDs all-zero)"
        );
        write_placeholder();
        return;
    }

    let force = std::env::var("RISC0_FORCE_BUILD").as_deref() == Ok("1");

    // If the Risc0 toolchain/target isn't installed, allow non-proof tasks (clippy, docs, etc.)
    // to proceed with placeholders. Production builds should set RISC0_FORCE_BUILD=1.
    let target_ok = std::process::Command::new("rustup")
        .args(["target", "list", "--installed", "--toolchain", "risc0"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .is_some_and(|out| out.lines().any(|l| l.trim() == "riscv32im-risc0-zkvm-elf"));

    if !target_ok && !force {
        println!("cargo:warning=Risc0 target `riscv32im-risc0-zkvm-elf` not installed for toolchain `risc0`; using placeholder methods. Set RISC0_FORCE_BUILD=1 to fail-closed, or install with `rustup target add riscv32im-risc0-zkvm-elf --toolchain risc0`.");
        write_placeholder();
        return;
    }

    // Build the guest program (fail-closed if it errors; placeholder would mask real issues).
    risc0_build::embed_methods();
}
