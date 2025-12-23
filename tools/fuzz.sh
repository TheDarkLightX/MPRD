#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}/fuzz"

# Work around `zerocopy` enabling AVX-512 impls that require a nightly `stdarch` feature on some
# toolchains used by cargo-fuzz.
export RUSTFLAGS="--cfg no_zerocopy_simd_x86_avx12_1_89_0 ${RUSTFLAGS:-}"

# LeakSanitizer commonly fails in constrained/sandboxed environments (e.g. ptrace restrictions).
# Prefer continuing fuzzing with ASAN but without leak detection unless the caller overrides.
if [[ "${ASAN_OPTIONS:-}" != *"detect_leaks="* ]]; then
  export ASAN_OPTIONS="detect_leaks=0${ASAN_OPTIONS:+:${ASAN_OPTIONS}}"
fi

exec cargo fuzz "$@"
