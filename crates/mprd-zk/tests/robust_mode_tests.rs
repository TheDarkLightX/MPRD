//! Comprehensive integration tests for robust deployment modes.
//!
//! Tests security invariants, validation, and error handling.

use mprd_core::ZkAttestor;
use mprd_core::ZkLocalVerifier;
use mprd_core::{
    components::{LoggingExecutorAdapter, SimpleProposer, SimpleStateProvider},
    orchestrator::{run_once, RunOnceInputs},
    CandidateAction, DefaultSelector, Hash32, PolicyEngine, PolicyHash, Result, RuleVerdict,
    StateSnapshot, Value, VerificationStatus,
};
use mprd_risc0_methods::{MPRD_GUEST_ELF, MPRD_GUEST_ID};
use mprd_zk::modes_v2::{DeploymentMode, ModeConfig};
use mprd_zk::{
    create_robust_attestor, ModeError, RobustMpbAttestor, RobustMpbVerifier, RobustPrivateAttestor,
    RobustPrivateVerifier, RobustRisc0Attestor, RobustRisc0Verifier, SecurityChecker,
};
use std::collections::HashMap;

// =============================================================================
// Test Policy Engine
// =============================================================================

struct AllowAllPolicyEngine;

impl PolicyEngine for AllowAllPolicyEngine {
    fn evaluate(
        &self,
        _policy_hash: &PolicyHash,
        _state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<Vec<RuleVerdict>> {
        Ok(candidates
            .iter()
            .map(|_| RuleVerdict {
                allowed: true,
                reasons: vec![],
                limits: HashMap::new(),
            })
            .collect())
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

fn dummy_hash(byte: u8) -> Hash32 {
    Hash32([byte; 32])
}

fn should_skip_due_to_missing_risc0_methods() -> bool {
    if !MPRD_GUEST_ELF.is_empty() {
        return false;
    }

    eprintln!("Skipping: Risc0 guest ELF is empty (methods not embedded)");
    true
}

fn should_skip_due_to_r0vm_mismatch(err: &dyn std::fmt::Display) -> bool {
    let msg = err.to_string();
    msg.contains("r0vm server") && msg.contains("risc0-zkvm") && msg.contains("not compatible")
}

// =============================================================================
// Configuration Validation Tests
// =============================================================================

#[test]
fn mode_b_lite_requires_minimum_spot_checks() {
    // 16+ spot checks required for security
    let mut config = ModeConfig::mode_b_lite();
    config.mpb_spot_checks = 8;

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert!(matches!(err, ModeError::InvalidConfig(_)));
}

#[test]
fn mode_b_full_requires_image_id() {
    let mut config = ModeConfig::mode_b_full([0u8; 32]);
    config.risc0_image_id = None;

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert!(matches!(err, ModeError::MissingConfig { .. }));
}

#[test]
fn mode_c_requires_encryption_key() {
    let mut config = ModeConfig::mode_c([0u8; 32], "key");
    config.encryption_key_id = None;

    let result = config.validate();
    assert!(result.is_err());
}

#[test]
fn factory_validates_before_creating() {
    // Invalid config should fail
    let mut config = ModeConfig::mode_b_lite();
    config.mpb_spot_checks = 4; // Too low

    let result = create_robust_attestor(&config);
    assert!(result.is_err());
}

// =============================================================================
// Security Invariant Tests
// =============================================================================

#[test]
fn security_checker_enforces_s5_binding() {
    let checker = SecurityChecker::strict();

    let token = mprd_core::DecisionToken {
        policy_hash: dummy_hash(1),
        state_hash: dummy_hash(2),
        chosen_action_hash: dummy_hash(3),
        nonce_or_tx_hash: dummy_hash(4),
        timestamp_ms: 0,
        signature: vec![],
    };

    // Matching proof should pass
    let proof = mprd_core::ProofBundle {
        policy_hash: dummy_hash(1),
        state_hash: dummy_hash(2),
        candidate_set_hash: dummy_hash(5),
        chosen_action_hash: dummy_hash(3),
        risc0_receipt: vec![],
        attestation_metadata: HashMap::new(),
    };

    assert!(checker.check_binding(&token, &proof).is_ok());

    // Mismatched proof should fail
    let bad_proof = mprd_core::ProofBundle {
        policy_hash: dummy_hash(99), // Mismatch!
        state_hash: dummy_hash(2),
        candidate_set_hash: dummy_hash(5),
        chosen_action_hash: dummy_hash(3),
        risc0_receipt: vec![],
        attestation_metadata: HashMap::new(),
    };

    assert!(checker.check_binding(&token, &bad_proof).is_err());
}

#[test]
fn security_checker_rejects_zero_hashes() {
    let checker = SecurityChecker::strict();
    let zero_hash = Hash32([0u8; 32]);

    let result = checker.check_hash_validity(&zero_hash, "test_hash");
    assert!(result.is_err());
}

#[test]
fn binding_commitment_is_deterministic() {
    let c1 = SecurityChecker::compute_binding_commitment(
        &dummy_hash(1),
        &dummy_hash(2),
        &dummy_hash(3),
        &dummy_hash(4),
    );

    let c2 = SecurityChecker::compute_binding_commitment(
        &dummy_hash(1),
        &dummy_hash(2),
        &dummy_hash(3),
        &dummy_hash(4),
    );

    assert_eq!(c1, c2);

    // Different inputs → different commitment
    let c3 = SecurityChecker::compute_binding_commitment(
        &dummy_hash(1),
        &dummy_hash(2),
        &dummy_hash(3),
        &dummy_hash(5), // Different
    );

    assert_ne!(c1, c3);
}

// =============================================================================
// Robust Mode B-Lite Tests
// =============================================================================

#[test]
fn robust_mpb_attestor_generates_binding_commitment() {
    let attestor = RobustMpbAttestor::default_config().expect("Should create");

    let state = StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::new(),
        state_hash: dummy_hash(1),
    };

    let decision = mprd_core::Decision {
        chosen_index: 0,
        chosen_action: CandidateAction {
            action_type: "TEST".into(),
            params: HashMap::new(),
            score: mprd_core::Score(10),
            candidate_hash: dummy_hash(2),
        },
        policy_hash: dummy_hash(3),
        decision_commitment: dummy_hash(4),
    };

    let result = attestor.attest(&decision, &state, &[]);
    assert!(result.is_ok());

    let proof = result.unwrap();

    // Should have binding commitment
    assert!(proof
        .attestation_metadata
        .contains_key("binding_commitment"));

    // Should have security metadata
    assert!(proof.attestation_metadata.contains_key("security_bits"));
    assert!(proof.attestation_metadata.contains_key("spot_checks"));
}

#[test]
fn robust_mpb_verifier_validates_binding_commitment() {
    let attestor = RobustMpbAttestor::default_config().expect("Should create");
    let verifier = RobustMpbVerifier::default_config().expect("Should create");

    let state = StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::new(),
        state_hash: dummy_hash(1),
    };

    let decision = mprd_core::Decision {
        chosen_index: 0,
        chosen_action: CandidateAction {
            action_type: "TEST".into(),
            params: HashMap::new(),
            score: mprd_core::Score(10),
            candidate_hash: dummy_hash(2),
        },
        policy_hash: dummy_hash(3),
        decision_commitment: dummy_hash(4),
    };

    let proof = attestor.attest(&decision, &state, &[]).unwrap();

    let token = mprd_core::DecisionToken {
        policy_hash: dummy_hash(3),
        state_hash: dummy_hash(1),
        chosen_action_hash: dummy_hash(2),
        nonce_or_tx_hash: dummy_hash(5),
        timestamp_ms: 0,
        signature: vec![],
    };

    let status = verifier.verify(&token, &proof);
    assert_eq!(status, VerificationStatus::Success);
}

#[test]
fn robust_mpb_verifier_rejects_tampered_binding() {
    let verifier = RobustMpbVerifier::default_config().expect("Should create");

    let token = mprd_core::DecisionToken {
        policy_hash: dummy_hash(1),
        state_hash: dummy_hash(2),
        chosen_action_hash: dummy_hash(3),
        nonce_or_tx_hash: dummy_hash(4),
        timestamp_ms: 0,
        signature: vec![],
    };

    let mut metadata = HashMap::new();
    metadata.insert("mode".into(), "B-Lite".into());
    metadata.insert("proof_type".into(), "MPB".into());
    metadata.insert("binding_commitment".into(), "tampered_value".into());

    let proof = mprd_core::ProofBundle {
        policy_hash: dummy_hash(1),
        state_hash: dummy_hash(2),
        candidate_set_hash: dummy_hash(5),
        chosen_action_hash: dummy_hash(3),
        risc0_receipt: vec![],
        attestation_metadata: metadata,
    };

    let status = verifier.verify(&token, &proof);
    assert!(matches!(status, VerificationStatus::Failure(_)));
}

// =============================================================================
// Robust Mode B-Full Tests
// =============================================================================

#[test]
fn robust_risc0_attestor_reports_availability() {
    let config = ModeConfig::mode_b_full([0u8; 32]);
    let attestor = RobustRisc0Attestor::new(config, None).expect("Should create");

    let (available, reason) = attestor.availability_status();
    assert!(!available);
    assert_eq!(reason, "method_elf not provided");
}

#[test]
fn robust_risc0_verifier_requires_receipt() {
    let config = ModeConfig::mode_b_full([0u8; 32]);
    let verifier = RobustRisc0Verifier::new(config).expect("Should create");

    let token = mprd_core::DecisionToken {
        policy_hash: dummy_hash(1),
        state_hash: dummy_hash(2),
        chosen_action_hash: dummy_hash(3),
        nonce_or_tx_hash: dummy_hash(4),
        timestamp_ms: 0,
        signature: vec![],
    };

    let proof = mprd_core::ProofBundle {
        policy_hash: dummy_hash(1),
        state_hash: dummy_hash(2),
        candidate_set_hash: dummy_hash(5),
        chosen_action_hash: dummy_hash(3),
        risc0_receipt: vec![], // Empty!
        attestation_metadata: HashMap::new(),
    };

    let status = verifier.verify(&token, &proof);
    assert!(matches!(status, VerificationStatus::Failure(_)));
}

// =============================================================================
// End-to-End Integration Tests
// =============================================================================

#[test]
fn full_pipeline_with_robust_b_lite() {
    let state_provider =
        SimpleStateProvider::new(HashMap::from([("balance".into(), Value::UInt(10000))]));

    let proposer = SimpleProposer::single(
        "ACTION",
        HashMap::from([("param".into(), Value::Int(42))]),
        100,
    );

    let policy_engine = AllowAllPolicyEngine;
    let selector = DefaultSelector;
    let policy_hash = dummy_hash(1);

    let token_factory = mprd_core::components::SignedDecisionTokenFactory::default_for_testing();
    let attestor = RobustMpbAttestor::default_config().expect("Should create");
    let verifier = RobustMpbVerifier::default_config().expect("Should create");
    let executor = LoggingExecutorAdapter::new();

    let result = run_once(RunOnceInputs {
        state_provider: &state_provider,
        proposer: &proposer,
        policy_engine: &policy_engine,
        selector: &selector,
        token_factory: &token_factory,
        attestor: &attestor,
        verifier: &verifier,
        executor: &executor,
        policy_hash: &policy_hash,
    });

    assert!(result.is_ok(), "Pipeline should succeed: {:?}", result);
    assert_eq!(
        executor.get_log().len(),
        1,
        "Should have executed one action"
    );
}

#[test]
fn full_pipeline_with_robust_b_full() {
    if should_skip_due_to_missing_risc0_methods() {
        return;
    }

    let state_provider =
        SimpleStateProvider::new(HashMap::from([("balance".into(), Value::UInt(10000))]));

    let proposer = SimpleProposer::single(
        "ACTION",
        HashMap::from([("param".into(), Value::Int(42))]),
        100,
    );

    let policy_engine = AllowAllPolicyEngine;
    let selector = DefaultSelector;
    let policy_hash = dummy_hash(2);

    let token_factory = mprd_core::components::SignedDecisionTokenFactory::default_for_testing();

    // MPRD_GUEST_ID is a Risc0 digest ([u32; 8]); convert to [u8; 32] for ModeConfig.
    let mut image_id = [0u8; 32];
    for (i, word) in MPRD_GUEST_ID.iter().enumerate() {
        image_id[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    let config = ModeConfig::mode_b_full(image_id);
    let attestor = RobustRisc0Attestor::new(config.clone(), Some(MPRD_GUEST_ELF))
        .expect("Risc0 attestor should be created");
    let verifier = RobustRisc0Verifier::new(config).expect("Risc0 verifier should be created");

    let executor = LoggingExecutorAdapter::new();

    let result = run_once(RunOnceInputs {
        state_provider: &state_provider,
        proposer: &proposer,
        policy_engine: &policy_engine,
        selector: &selector,
        token_factory: &token_factory,
        attestor: &attestor,
        verifier: &verifier,
        executor: &executor,
        policy_hash: &policy_hash,
    });

    if let Err(e) = &result {
        if should_skip_due_to_r0vm_mismatch(e) {
            return;
        }
    }

    assert!(
        result.is_ok(),
        "B-Full pipeline should succeed: {:?}",
        result
    );
    assert_eq!(
        executor.get_log().len(),
        1,
        "Should have executed one action"
    );
}

// =============================================================================
// Robust Mode C Tests
// =============================================================================

#[test]
fn robust_private_attestor_emits_mode_c_metadata() {
    if should_skip_due_to_missing_risc0_methods() {
        return;
    }

    // Convert Risc0 guest ID to image_id bytes, same as B-Full tests
    let mut image_id = [0u8; 32];
    for (i, word) in MPRD_GUEST_ID.iter().enumerate() {
        image_id[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    let config = ModeConfig::mode_c(image_id, "test-key");
    let attestor = RobustPrivateAttestor::new(
        config.clone(),
        mprd_zk::modes_v2::EncryptionConfig::default(),
    )
    .expect("Private attestor should be created");

    let state = StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::new(),
        state_hash: dummy_hash(1),
    };

    let chosen_action = CandidateAction {
        action_type: "TEST".into(),
        params: HashMap::new(),
        score: mprd_core::Score(10),
        candidate_hash: dummy_hash(2),
    };

    let candidates = vec![chosen_action.clone()];

    let decision = mprd_core::Decision {
        chosen_index: 0,
        chosen_action,
        policy_hash: dummy_hash(3),
        decision_commitment: dummy_hash(4),
    };

    let proof = match attestor.attest(&decision, &state, &candidates) {
        Ok(p) => p,
        Err(e) => {
            if should_skip_due_to_r0vm_mismatch(&e) {
                return;
            }
            panic!("Mode C attestation should succeed: {e}");
        }
    };

    let mode = proof.attestation_metadata.get("mode").cloned();
    assert_eq!(mode.as_deref(), Some(DeploymentMode::Private.as_str()));

    assert!(proof.attestation_metadata.contains_key("encryption_key_id"));
    assert!(proof
        .attestation_metadata
        .contains_key("encryption_algorithm"));

    let enc_json = proof
        .attestation_metadata
        .get("encrypted_state")
        .expect("encrypted_state metadata should be present");

    let parsed: mprd_zk::EncryptedState =
        serde_json::from_str(enc_json).expect("encrypted_state should be valid JSON");

    let expected_key = config
        .encryption_key_id
        .as_ref()
        .expect("config should contain encryption_key_id");
    assert_eq!(&parsed.key_id, expected_key);
}

#[test]
fn robust_private_verifier_rejects_tampered_encrypted_state() {
    if should_skip_due_to_missing_risc0_methods() {
        return;
    }

    let mut image_id = [0u8; 32];
    for (i, word) in MPRD_GUEST_ID.iter().enumerate() {
        image_id[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    let config = ModeConfig::mode_c(image_id, "test-key");
    let attestor = RobustPrivateAttestor::new(
        config.clone(),
        mprd_zk::modes_v2::EncryptionConfig::default(),
    )
    .expect("Private attestor should be created");
    let verifier =
        RobustPrivateVerifier::new(config.clone()).expect("Private verifier should be created");

    let state = StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::new(),
        state_hash: dummy_hash(1),
    };

    let chosen_action = CandidateAction {
        action_type: "TEST".into(),
        params: HashMap::new(),
        score: mprd_core::Score(10),
        candidate_hash: dummy_hash(2),
    };

    let candidates = vec![chosen_action.clone()];

    let decision = mprd_core::Decision {
        chosen_index: 0,
        chosen_action,
        policy_hash: dummy_hash(3),
        decision_commitment: dummy_hash(4),
    };

    let mut proof = match attestor.attest(&decision, &state, &candidates) {
        Ok(p) => p,
        Err(e) => {
            if should_skip_due_to_r0vm_mismatch(&e) {
                return;
            }
            panic!("Mode C attestation should succeed: {e}");
        }
    };

    // Tamper with encrypted_state key_id while keeping JSON well-formed
    if let Some(enc_json) = proof.attestation_metadata.get_mut("encrypted_state") {
        let mut parsed: mprd_zk::EncryptedState = serde_json::from_str(enc_json)
            .expect("encrypted_state should be valid JSON before tampering");
        parsed.key_id = "different-key".into();
        *enc_json = serde_json::to_string(&parsed).expect("re-serialization should succeed");
    }

    let token = mprd_core::DecisionToken {
        policy_hash: decision.policy_hash.clone(),
        state_hash: state.state_hash.clone(),
        chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
        nonce_or_tx_hash: dummy_hash(5),
        timestamp_ms: 0,
        signature: vec![],
    };

    let status = verifier.verify(&token, &proof);
    assert!(matches!(status, VerificationStatus::Failure(_)));
}

#[test]
fn mode_properties() {
    // Mode A: No ZK, no encryption
    assert!(!DeploymentMode::LocalTrusted.requires_zk());
    assert!(!DeploymentMode::LocalTrusted.requires_encryption());

    // Mode B-Lite: No ZK (computational only)
    assert!(!DeploymentMode::TrustlessLite.requires_zk());

    // Mode B-Full: ZK required
    assert!(DeploymentMode::TrustlessFull.requires_zk());
    assert!(!DeploymentMode::TrustlessFull.requires_encryption());

    // Mode C: ZK + encryption
    assert!(DeploymentMode::Private.requires_zk());
    assert!(DeploymentMode::Private.requires_encryption());
}
