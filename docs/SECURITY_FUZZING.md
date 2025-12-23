# Security Fuzzing (Internal)

This repo includes libFuzzer targets under `fuzz/` for security-critical parsing and state-machine behavior.

## Low-disk workflow

Fuzz builds produce large artifacts. If disk is tight, remove build output directories:

- `rm -rf target/`
- `rm -rf fuzz/target/`

## Running fuzz targets

Fuzzing with Rust sanitizers typically requires a nightly toolchain. Prefer running through `tools/fuzz.sh`, which applies required flags/workarounds automatically.

On some nightly toolchains, the `zerocopy` dependency enables AVX-512 impls that require an additional nightly `stdarch` feature. `tools/fuzz.sh` sets the needed `RUSTFLAGS` workaround (`--cfg no_zerocopy_simd_x86_avx12_1_89_0`) automatically.

Install cargo-fuzz if needed:

- `cargo install cargo-fuzz`

Run a target with a hard time limit (recommended):

- `tools/fuzz.sh run anti_replay_state_machine --no-default-features -- -max_total_time=60`
- `tools/fuzz.sh run tau_output_attestation_envelope_v1 --no-default-features -- -max_total_time=60`
- `tools/fuzz.sh run decoded_journal_metamorphic_v3 --features zk -- -max_total_time=60`

If disk is tight, prefer `--no-default-features` for core-only fuzz targets.

If you can’t use nightly/sanitizers (or you’re blocked on a nightly toolchain issue), you can still run coverage-guided fuzzing on stable with sanitizers disabled (lower bug-finding power):

- `cd fuzz && cargo fuzz run -s none limits_bytes_v1 -- -max_total_time=60`

To reset corpora/artifacts (useful when disk is tight or after a toolchain upgrade):

- `rm -rf fuzz/corpus/anti_replay_state_machine fuzz/artifacts/anti_replay_state_machine`

Other useful targets:

- `tools/fuzz.sh run candidate_preimage_v1 --no-default-features -- -max_total_time=60`
- `tools/fuzz.sh run limits_bytes_v1 --no-default-features -- -max_total_time=60`
- `tools/fuzz.sh run mpb_artifact_deser --features zk -- -max_total_time=60`
- `tools/fuzz.sh run receipt_deser --features zk -- -max_total_time=60`

## What `anti_replay_state_machine` checks

- High-trust mode: a nonce is only consumed after a successful execution; retries after failure are allowed.
- Low-trust distributed mode: a nonce is claimed before execution; any retry is rejected (prevents double execution races).
- In both modes: expired/future tokens fail-closed without side effects.
