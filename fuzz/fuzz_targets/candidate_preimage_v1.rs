#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic for arbitrary bytes.
    let _ = mprd_core::validation::decode_candidate_preimage_v1(data);
});

