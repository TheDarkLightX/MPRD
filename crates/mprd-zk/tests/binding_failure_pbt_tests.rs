//! Binding-failure tests (fail-closed) for B-Full receipts.

use mprd_core::hash::{hash_candidate, hash_state};
use mprd_core::ZkLocalVerifier;
use mprd_core::{
    CandidateAction, Decision, DecisionToken, Hash32, PolicyRef, Score, StateRef, StateSnapshot,
    Value, VerificationStatus,
};
use mprd_risc0_methods::{MPRD_MPB_GUEST_ELF, MPRD_MPB_GUEST_ID};
use mprd_zk::risc0_host::{MpbPolicyArtifactV1, Risc0MpbAttestor, Risc0Verifier};
use std::collections::HashMap;
use std::sync::Arc;

fn should_skip_due_to_missing_risc0_methods() -> bool {
    if !MPRD_MPB_GUEST_ELF.is_empty() {
        return false;
    }
    eprintln!("Skipping: Risc0 MPB guest ELF is empty (methods not embedded)");
    true
}

fn should_skip_due_to_r0vm_mismatch(err: &dyn std::fmt::Display) -> bool {
    let msg = err.to_string();
    msg.contains("r0vm server") && msg.contains("risc0-zkvm") && msg.contains("not compatible")
}

fn dummy_hash(byte: u8) -> Hash32 {
    Hash32([byte; 32])
}

fn dummy_policy_ref() -> PolicyRef {
    PolicyRef {
        policy_epoch: 1,
        registry_root: dummy_hash(99),
    }
}

fn mpb_image_id_bytes() -> [u8; 32] {
    let mut image_id = [0u8; 32];
    for (i, word) in MPRD_MPB_GUEST_ID.iter().enumerate() {
        image_id[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    image_id
}

fn make_valid_mpb_v1_proof(
) -> Result<(DecisionToken, mprd_core::ProofBundle, [u8; 32]), mprd_core::MprdError> {
    let mut state = StateSnapshot {
        fields: HashMap::from([("balance".into(), Value::UInt(10000))]),
        policy_inputs: HashMap::new(),
        state_hash: Hash32([0u8; 32]),
        state_ref: StateRef::unknown(),
    };
    state.state_hash = hash_state(&state);

    let mut chosen_action = CandidateAction {
        action_type: "ACTION".into(),
        params: HashMap::from([("param".into(), Value::Int(42))]),
        score: Score(100),
        candidate_hash: Hash32([0u8; 32]),
    };
    chosen_action.candidate_hash = hash_candidate(&chosen_action);
    let candidates = vec![chosen_action.clone()];

    let policy_bytecode = mprd_core::mpb::BytecodeBuilder::new()
        .push_i64(1)
        .halt()
        .build();
    let policy_hash = Hash32(mprd_mpb::policy_hash_v1(&policy_bytecode, &[]));

    let decision = Decision {
        chosen_index: 0,
        chosen_action: chosen_action.clone(),
        policy_hash: policy_hash.clone(),
        decision_commitment: Hash32([0u8; 32]),
    };

    let token = DecisionToken {
        policy_hash: policy_hash.clone(),
        policy_ref: dummy_policy_ref(),
        state_hash: state.state_hash.clone(),
        state_ref: state.state_ref.clone(),
        chosen_action_hash: chosen_action.candidate_hash.clone(),
        nonce_or_tx_hash: dummy_hash(5),
        timestamp_ms: 0,
        signature: vec![],
    };

    let image_id = mpb_image_id_bytes();

    let mut store: HashMap<mprd_core::PolicyHash, MpbPolicyArtifactV1> = HashMap::new();
    store.insert(
        policy_hash.clone(),
        MpbPolicyArtifactV1 {
            bytecode: policy_bytecode,
            variables: vec![],
        },
    );
    let provider = Arc::new(store) as Arc<dyn mprd_zk::MpbPolicyProvider>;
    let attestor = Risc0MpbAttestor::new(
        MPRD_MPB_GUEST_ELF,
        image_id,
        mprd_risc0_shared::MPB_FUEL_LIMIT_V1,
        provider,
    );

    let proof = attestor.attest(&token, &decision, &state, &candidates)?;
    Ok((token, proof, image_id))
}

#[test]
fn tampering_any_bound_field_fails_closed_b_full() {
    if should_skip_due_to_missing_risc0_methods() {
        return;
    }

    let (token, proof, image_id) = match make_valid_mpb_v1_proof() {
        Ok(v) => v,
        Err(e) => {
            if should_skip_due_to_r0vm_mismatch(&e) {
                return;
            }
            panic!("failed to build valid proof: {e}");
        }
    };

    let verifier = Risc0Verifier::mpb_v1(image_id);
    assert!(matches!(
        verifier.verify(&token, &proof),
        VerificationStatus::Success
    ));

    // Token field tampering.
    {
        let mut t = token.clone();
        t.policy_hash.0[0] ^= 1;
        assert!(matches!(
            verifier.verify(&t, &proof),
            VerificationStatus::Failure(_)
        ));
    }
    {
        let mut t = token.clone();
        t.policy_ref.policy_epoch ^= 1;
        assert!(matches!(
            verifier.verify(&t, &proof),
            VerificationStatus::Failure(_)
        ));
    }
    {
        let mut t = token.clone();
        t.policy_ref.registry_root.0[0] ^= 1;
        assert!(matches!(
            verifier.verify(&t, &proof),
            VerificationStatus::Failure(_)
        ));
    }
    {
        let mut t = token.clone();
        t.state_hash.0[0] ^= 1;
        assert!(matches!(
            verifier.verify(&t, &proof),
            VerificationStatus::Failure(_)
        ));
    }
    {
        let mut t = token.clone();
        t.state_ref.state_source_id.0[0] ^= 1;
        assert!(matches!(
            verifier.verify(&t, &proof),
            VerificationStatus::Failure(_)
        ));
    }
    {
        let mut t = token.clone();
        t.state_ref.state_epoch ^= 1;
        assert!(matches!(
            verifier.verify(&t, &proof),
            VerificationStatus::Failure(_)
        ));
    }
    {
        let mut t = token.clone();
        t.state_ref.state_attestation_hash.0[0] ^= 1;
        assert!(matches!(
            verifier.verify(&t, &proof),
            VerificationStatus::Failure(_)
        ));
    }
    {
        let mut t = token.clone();
        t.chosen_action_hash.0[0] ^= 1;
        assert!(matches!(
            verifier.verify(&t, &proof),
            VerificationStatus::Failure(_)
        ));
    }
    {
        let mut t = token.clone();
        t.nonce_or_tx_hash.0[0] ^= 1;
        assert!(matches!(
            verifier.verify(&t, &proof),
            VerificationStatus::Failure(_)
        ));
    }

    // Proof field tampering.
    {
        let mut p = proof.clone();
        p.policy_hash.0[0] ^= 1;
        assert!(matches!(
            verifier.verify(&token, &p),
            VerificationStatus::Failure(_)
        ));
    }
    {
        let mut p = proof.clone();
        p.state_hash.0[0] ^= 1;
        assert!(matches!(
            verifier.verify(&token, &p),
            VerificationStatus::Failure(_)
        ));
    }
    {
        let mut p = proof.clone();
        p.candidate_set_hash.0[0] ^= 1;
        assert!(matches!(
            verifier.verify(&token, &p),
            VerificationStatus::Failure(_)
        ));
    }
    {
        let mut p = proof.clone();
        p.chosen_action_hash.0[0] ^= 1;
        assert!(matches!(
            verifier.verify(&token, &p),
            VerificationStatus::Failure(_)
        ));
    }
    {
        let mut p = proof.clone();
        p.limits_bytes.push(0);
        assert!(matches!(
            verifier.verify(&token, &p),
            VerificationStatus::Failure(_)
        ));
    }
    {
        let mut p = proof.clone();
        p.risc0_receipt[0] ^= 1;
        assert!(matches!(
            verifier.verify(&token, &p),
            VerificationStatus::Failure(_)
        ));
    }
}
