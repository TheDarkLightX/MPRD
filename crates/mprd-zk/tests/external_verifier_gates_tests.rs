use mprd_core::TokenSigningKey;
use mprd_zk::external_verifier::{ExternalVerifier, VerificationRequest};
use mprd_zk::manifest::{GuestImageEntryV1, GuestImageManifestV1};
use mprd_zk::modes_v2::DeploymentMode;
use mprd_zk::VerificationStep;
use proptest::prelude::*;

fn req(mode: DeploymentMode) -> VerificationRequest {
    VerificationRequest {
        mode,
        policy_hash: [0u8; 32],
        policy_epoch: 1,
        registry_root: [0u8; 32],
        state_source_id: [0u8; 32],
        state_epoch: 2,
        state_attestation_hash: [0u8; 32],
        state_hash: [0u8; 32],
        candidate_set_hash: [0u8; 32],
        chosen_action_hash: [0u8; 32],
        nonce_or_tx_hash: [0u8; 32],
        proof_data: Vec::new(),
        metadata: std::collections::HashMap::new(),
    }
}

fn find_step<'a>(
    response: &'a mprd_zk::external_verifier::VerificationResponse,
    name: &str,
) -> Option<&'a VerificationStep> {
    response.steps.iter().find(|s| s.name == name)
}

#[test]
fn request_json_denies_unknown_fields() {
    let json = r#"{
        "mode":"local_trusted",
        "policy_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "policy_epoch":1,
        "registry_root":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "state_source_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "state_epoch":2,
        "state_attestation_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "state_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "candidate_set_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "chosen_action_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "nonce_or_tx_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "proof_data":"",
        "metadata":{},
        "unexpected_field":"nope"
    }"#;

    let parsed: Result<VerificationRequest, _> = serde_json::from_str(json);
    assert!(parsed.is_err());
}

#[test]
fn trustless_lite_requires_mode_marker_and_fails_closed_without_required_metadata() {
    let verifier = ExternalVerifier::new();

    let mut r = req(DeploymentMode::TrustlessLite);
    r.proof_data = vec![0u8; 8];
    let resp = verifier.verify(&r);
    assert!(!resp.valid);
    assert_eq!(resp.error.as_deref(), Some("Missing B-Lite mode marker"));

    let mut r2 = req(DeploymentMode::TrustlessLite);
    r2.proof_data = vec![0u8; 8];
    r2.metadata.insert("mode".into(), "B-Lite".into());
    let resp2 = verifier.verify(&r2);
    assert!(!resp2.valid);
    assert_eq!(resp2.error.as_deref(), Some("Missing MPB metadata"));
}

#[test]
fn trustless_full_fails_closed_on_empty_receipt() {
    let verifier = ExternalVerifier::with_risc0_image([1u8; 32]);
    let r = req(DeploymentMode::TrustlessFull);
    let resp = verifier.verify(&r);
    assert!(!resp.valid);
    assert_eq!(resp.error.as_deref(), Some("Empty Risc0 receipt"));
    assert_eq!(
        find_step(&resp, "Receipt presence").map(|s| s.passed),
        Some(false)
    );
}

#[test]
fn trustless_full_requires_image_id_before_parsing_untrusted_receipt_bytes() {
    let verifier = ExternalVerifier::new();
    let mut r = req(DeploymentMode::TrustlessFull);
    r.proof_data = vec![0u8; 1];

    let resp = verifier.verify(&r);
    assert!(!resp.valid);
    assert_eq!(resp.error.as_deref(), Some("Risc0 image ID not configured"));
    assert!(find_step(&resp, "Receipt deserialization").is_none());
}

#[test]
fn trustless_full_rejects_all_zero_image_id() {
    let verifier = ExternalVerifier::with_risc0_image([0u8; 32]);
    let mut r = req(DeploymentMode::TrustlessFull);
    r.proof_data = vec![0u8; 1];
    let resp = verifier.verify(&r);
    assert!(!resp.valid);
    assert_eq!(
        resp.error.as_deref(),
        Some("Invalid (all-zero) Risc0 image ID")
    );
}

#[test]
fn with_verified_manifest_rejects_invalid_signature() {
    let signer = TokenSigningKey::from_seed(&[1u8; 32]);
    let wrong_vk = TokenSigningKey::from_seed(&[2u8; 32]).verifying_key();
    let entries = vec![GuestImageEntryV1 {
        policy_exec_kind_id: mprd_risc0_shared::policy_exec_kind_mpb_id_v1(),
        policy_exec_version_id: mprd_risc0_shared::policy_exec_version_id_v1(),
        image_id: [7u8; 32],
    }];

    let manifest = GuestImageManifestV1::sign(&signer, 123, entries).expect("sign");
    let out = ExternalVerifier::with_verified_manifest(manifest, &wrong_vk);
    match out {
        Ok(_) => panic!("expected signature verification to fail"),
        Err(e) => assert!(e.contains("Invalid manifest signature"), "got: {e}"),
    }
}

#[test]
fn private_mode_enforces_encryption_metadata_and_key_binding() {
    let verifier = ExternalVerifier::with_risc0_image([1u8; 32]);

    // Missing marker
    let r = req(DeploymentMode::Private);
    let resp = verifier.verify(&r);
    assert!(!resp.valid);
    assert_eq!(resp.error.as_deref(), Some("Missing Mode C marker"));

    // Missing encryption_algorithm
    let mut r2 = req(DeploymentMode::Private);
    r2.metadata.insert("mode".into(), "C".into());
    let resp2 = verifier.verify(&r2);
    assert!(!resp2.valid);
    assert_eq!(
        resp2.error.as_deref(),
        Some("Missing encryption_algorithm metadata for Mode C")
    );

    // Unsupported algorithm
    let mut r3 = req(DeploymentMode::Private);
    r3.metadata.insert("mode".into(), "C".into());
    r3.metadata
        .insert("encryption_algorithm".into(), "NOPE".into());
    let resp3 = verifier.verify(&r3);
    assert!(!resp3.valid);
    assert_eq!(
        resp3.error.as_deref(),
        Some("Unsupported encryption_algorithm for Mode C")
    );

    // Invalid encrypted_state JSON
    let mut r4 = req(DeploymentMode::Private);
    r4.metadata.insert("mode".into(), "C".into());
    r4.metadata
        .insert("encryption_algorithm".into(), "AES-256-GCM".into());
    r4.metadata
        .insert("encrypted_state".into(), "not-json".into());
    let resp4 = verifier.verify(&r4);
    assert!(!resp4.valid);
    assert_eq!(
        resp4.error.as_deref(),
        Some("Invalid encrypted_state metadata")
    );

    // Encryption key_id mismatch
    let mut r5 = req(DeploymentMode::Private);
    r5.metadata.insert("mode".into(), "C".into());
    r5.metadata
        .insert("encryption_algorithm".into(), "AES-256-GCM".into());
    r5.metadata.insert(
        "encrypted_state".into(),
        r#"{"state_commitment":{"hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"scheme":"Sha256"},"field_commitments":{},"ciphertext":[0],"nonce":[0,0,0,0,0,0,0,0,0,0,0,0],"key_id":"k_actual"}"#.into(),
    );
    r5.metadata
        .insert("encryption_key_id".into(), "k_expected".into());
    let resp5 = verifier.verify(&r5);
    assert!(!resp5.valid);
    assert_eq!(
        resp5.error.as_deref(),
        Some("Encryption key_id mismatch for Mode C")
    );
    assert_eq!(
        find_step(&resp5, "Encryption key binding").map(|s| s.passed),
        Some(false)
    );
}

proptest! {
    #[test]
    fn verifier_never_panics_on_small_untrusted_inputs(proof_data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let verifier = ExternalVerifier::with_risc0_image([1u8; 32]);

        let mut r = req(DeploymentMode::TrustlessFull);
        r.proof_data = proof_data;
        let resp = verifier.verify(&r);

        prop_assert_eq!(resp.mode, r.mode);
        prop_assert!(!resp.steps.is_empty());
    }
}
