#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // High-consequence boundary: untrusted envelope bytes are parsed and may be used as
    // provenance inputs. This parser must be bounded, non-panicking, and canonical.
    let Ok(att) = mprd_core::tau_net_output_attestation::TauOutputAttestationV1::from_envelope_bytes_v1(data) else {
        return;
    };

    // If decoding succeeds, re-encoding must succeed and roundtrip to an equivalent attestation.
    let h1 = att.attestation_hash_v1().expect("attestation hash");
    let bytes2 = att.envelope_bytes_v1().expect("encode");
    let att2 =
        mprd_core::tau_net_output_attestation::TauOutputAttestationV1::from_envelope_bytes_v1(
            &bytes2,
        )
        .expect("decode roundtrip");
    let h2 = att2.attestation_hash_v1().expect("attestation hash 2");
    assert_eq!(h1, h2);
});

