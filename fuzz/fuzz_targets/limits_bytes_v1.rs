#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic for arbitrary bytes.
    let _ = mprd_core::limits::parse_limits_v1(data);

    // Binding should always succeed when the hash is computed from the same bytes.
    let h = mprd_core::limits::limits_hash_v1(data);
    let _ = mprd_core::limits::verify_limits_binding_v1(&h, data);
});

