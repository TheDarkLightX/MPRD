# Guest Build Provenance (Risc0)

The production checklist requires guest builds to be reproducible and pinned.

## What “pinned” means

- Pin the `risc0-zkvm` dependency version in `methods/Cargo.toml` (already in `Cargo.lock`).
- Pin the toolchain used to build guest images:
  - Rust toolchain version (`rust-toolchain.toml`)
  - `cargo-risczero` version
  - RISC-V target/toolchain installed by Risc0

## Recommended practice

- Build guests in CI in a clean environment with the pinned toolchain.
- Export:
  - `MPRD_GUEST_ID` / `MPRD_MPB_GUEST_ID`
  - a signed manifest mapping exec kind/version to image IDs (`docs/GUEST_IMAGE_MANIFEST.md`)
- Fail CI if image IDs change unexpectedly without an explicit approval/migration step.

## Manual build (developer machine)

```
cargo build -p mprd-risc0-methods --release
```

Then use the generated IDs to create/update the manifest.
