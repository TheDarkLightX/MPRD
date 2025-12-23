#![no_main]

use libfuzzer_sys::fuzz_target;
use mprd_core::{Hash32, VerificationStatus};
use mprd_core::hash::sha256_domain;
use mprd_generators::{decoded_mpb_v1_fixture, GenSeed};
use mprd_risc0_shared::compute_decision_commitment_v3;
use mprd_zk::risc0_host::Risc0Verifier;

#[cfg(not(feature = "zk"))]
compile_error!("decoded_journal_metamorphic_v3 requires the `zk` feature (build with `--features zk`).");

fn seed_from_bytes(data: &[u8]) -> GenSeed {
    GenSeed(sha256_domain(b"MPRD_FUZZ_SEED_V1", data).0)
}

fn mutate_hash32(orig: [u8; 32], data: &[u8]) -> [u8; 32] {
    let mut out = orig;
    if out == [0u8; 32] {
        out[0] = 1;
    }
    // Guaranteed change.
    out[0] ^= 0x01;
    // Add some data-dependent diffusion.
    if !data.is_empty() {
        out[1] ^= data[0];
    }
    out
}

fuzz_target!(|data: &[u8]| {
    // Metamorphic verifier fuzzing (decoded journal boundary):
    // - Start from a valid, self-consistent fixture.
    // - Mutate exactly one journal field (token/proof fixed).
    // - Optionally recompute decision_commitment to ensure we exercise explicit field checks.
    // - The verifier MUST reject (fail-closed) for any real mutation.
    let fixture = decoded_mpb_v1_fixture(seed_from_bytes(data));
    let token = fixture.token;
    let proof = fixture.proof;
    let mut journal = fixture.journal;

    let Some(tag) = data.get(0).copied() else { return; };
    let recompute = (tag & 0x80) != 0;
    let which = (tag & 0x7f) % 18;

    // 0 = no mutation (should pass)
    // 1.. = mutate one field (should fail)
    match which {
        0 => {}
        1 => journal.journal_version ^= 1,
        2 => journal.state_encoding_id = mutate_hash32(journal.state_encoding_id, &data[1..]),
        3 => journal.action_encoding_id = mutate_hash32(journal.action_encoding_id, &data[1..]),
        4 => journal.policy_exec_kind_id = mutate_hash32(journal.policy_exec_kind_id, &data[1..]),
        5 => journal.policy_exec_version_id =
            mutate_hash32(journal.policy_exec_version_id, &data[1..]),
        6 => journal.policy_hash = mutate_hash32(journal.policy_hash, &data[1..]),
        7 => journal.policy_epoch ^= 1,
        8 => journal.registry_root = mutate_hash32(journal.registry_root, &data[1..]),
        9 => journal.state_source_id = mutate_hash32(journal.state_source_id, &data[1..]),
        10 => journal.state_epoch ^= 1,
        11 => {
            journal.state_attestation_hash =
                mutate_hash32(journal.state_attestation_hash, &data[1..])
        }
        12 => journal.state_hash = mutate_hash32(journal.state_hash, &data[1..]),
        13 => journal.candidate_set_hash = mutate_hash32(journal.candidate_set_hash, &data[1..]),
        14 => journal.chosen_action_hash = mutate_hash32(journal.chosen_action_hash, &data[1..]),
        15 => journal.nonce_or_tx_hash = mutate_hash32(journal.nonce_or_tx_hash, &data[1..]),
        16 => journal.limits_hash = mutate_hash32(journal.limits_hash, &data[1..]),
        17 => journal.allowed = !journal.allowed,
        _ => {}
    }

    // For many fields, we'd otherwise fail at the commitment check and never exercise the
    // per-field comparisons. Recompute when asked (but do not allow an attacker-controlled
    // decision_commitment to pass if other checks were missing).
    if recompute && which != 0 {
        journal.decision_commitment = compute_decision_commitment_v3(&journal);
    }

    let verifier = Risc0Verifier::mpb_v1([1u8; 32]);
    let status = verifier.verify_decoded_journal_fuzz(&token, &proof, &journal);

    if which == 0 {
        if !matches!(status, VerificationStatus::Success) {
            panic!("expected success for unmodified fixture");
        }
    } else {
        if matches!(status, VerificationStatus::Success) {
            // This indicates a missing fail-closed check.
            panic!("mutation unexpectedly accepted");
        }

        // Stronger: the verifier must never accept a journal that no longer binds the token.
        if Hash32(journal.policy_hash) == token.policy_hash
            && Hash32(journal.state_hash) == token.state_hash
            && Hash32(journal.chosen_action_hash) == token.chosen_action_hash
            && Hash32(journal.nonce_or_tx_hash) == token.nonce_or_tx_hash
        {
            // Nothing to assert here; this branch is a guard against mistakenly
            // mutating a field that isn't bound to the token. The panic above remains
            // the security requirement.
        }
    }
});
