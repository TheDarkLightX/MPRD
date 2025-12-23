//! Comprehensive integration tests for robust deployment modes.
//!
//! Tests security invariants, validation, and error handling.

use mprd_core::ZkAttestor;
use mprd_core::ZkLocalVerifier;
use mprd_core::{
    components::{LoggingExecutorAdapter, SimpleProposer, SimpleStateProvider},
    orchestrator::DecisionTokenFactory,
    orchestrator::{run_once, RunOnceInputs},
    CandidateAction, DefaultSelector, Hash32, PolicyEngine, PolicyHash, PolicyRef, Proposer,
    Result, RuleVerdict, Selector, StateProvider, StateSnapshot, Value, VerificationStatus,
};
use mprd_core::{Score, StateRef, TokenSigningKey};
use mprd_risc0_methods::{MPRD_GUEST_ELF, MPRD_GUEST_ID, MPRD_MPB_GUEST_ELF, MPRD_MPB_GUEST_ID};
use mprd_risc0_shared::{
    policy_exec_kind_host_trusted_id_v0, policy_exec_kind_mpb_id_v1, policy_exec_version_id_v1,
};
use mprd_zk::manifest::{GuestImageEntryV1, GuestImageManifestV1};
use mprd_zk::modes_v2::{DeploymentMode, ModeConfig};
use mprd_zk::registry_state::{
    AuthorizedPolicyV1, RegistryBoundRisc0Verifier, RegistryStateV1, StaticRegistryStateProvider,
};
use mprd_zk::risc0_host::MpbPolicyArtifactV1;
use mprd_zk::{
    create_robust_attestor, ModeError, RobustMpbAttestor, RobustMpbVerifier, RobustPrivateAttestor,
    RobustPrivateVerifier, RobustRisc0Attestor, RobustRisc0Verifier, SecurityChecker,
};
use std::collections::HashMap;
use std::sync::Arc;

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

fn dummy_policy_ref() -> PolicyRef {
    PolicyRef {
        policy_epoch: 1,
        registry_root: dummy_hash(99),
    }
}

fn should_skip_due_to_missing_risc0_methods() -> bool {
    if !MPRD_GUEST_ELF.is_empty() && !MPRD_MPB_GUEST_ELF.is_empty() {
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
    config.mpb_policy_bytecode = Some(
        mprd_core::mpb::BytecodeBuilder::new()
            .push_i64(1)
            .halt()
            .build(),
    );
    config.mpb_policy_variables = Some(vec![]);
    config.mpb_spot_checks = 8;

    let result = config.validate();
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert!(matches!(err, ModeError::InvalidConfig(_)));
}

#[test]
fn mode_b_full_requires_image_id() {
    let mut config = ModeConfig::mode_b_full([0u8; 32]);
    config.mpb_policy_bytecode = Some(vec![0xFF]);
    config.mpb_policy_variables = Some(vec![]);
    config.risc0_image_id_mpb = None;

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
        policy_ref: dummy_policy_ref(),
        state_hash: dummy_hash(2),
        state_ref: mprd_core::StateRef::unknown(),
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
        limits_hash: dummy_hash(6),
        limits_bytes: vec![],
        chosen_action_preimage: vec![],
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
        limits_hash: dummy_hash(6),
        limits_bytes: vec![],
        chosen_action_preimage: vec![],
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
    let policy_bytecode = mprd_core::mpb::BytecodeBuilder::new()
        .push_i64(1)
        .halt()
        .build();
    let policy_hash = Hash32(mprd_mpb::policy_hash_v1(&policy_bytecode, &[]));

    let mut cfg = ModeConfig::mode_b_lite();
    cfg.mpb_policy_bytecode = Some(policy_bytecode);
    cfg.mpb_policy_variables = Some(vec![]);
    let attestor = RobustMpbAttestor::new(cfg).expect("attestor");

    let mut state = StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::new(),
        state_hash: dummy_hash(0),
        state_ref: mprd_core::StateRef::unknown(),
    };
    state.state_hash = mprd_core::hash::hash_state(&state);

    let mut candidate = CandidateAction {
        action_type: "TEST".into(),
        params: HashMap::new(),
        score: mprd_core::Score(10),
        candidate_hash: dummy_hash(0),
    };
    candidate.candidate_hash = mprd_core::hash::hash_candidate(&candidate);
    let candidates = vec![candidate.clone()];

    let decision = mprd_core::Decision {
        chosen_index: 0,
        chosen_action: candidate,
        policy_hash: policy_hash.clone(),
        decision_commitment: dummy_hash(4),
    };

    let token = mprd_core::DecisionToken {
        policy_hash,
        policy_ref: dummy_policy_ref(),
        state_hash: state.state_hash.clone(),
        state_ref: state.state_ref.clone(),
        chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
        nonce_or_tx_hash: dummy_hash(5),
        timestamp_ms: 0,
        signature: vec![],
    };

    let proof = attestor
        .attest(&token, &decision, &state, &candidates)
        .expect("attest");

    assert_eq!(
        proof.attestation_metadata.get("proof_backend"),
        Some(&"mpb_lite_v1".to_string())
    );
    assert!(!proof.risc0_receipt.is_empty());
    assert!(!proof.limits_bytes.is_empty());
}

#[test]
fn robust_mpb_verifier_validates_binding_commitment() {
    let policy_bytecode = mprd_core::mpb::BytecodeBuilder::new()
        .push_i64(1)
        .halt()
        .build();
    let policy_hash = Hash32(mprd_mpb::policy_hash_v1(&policy_bytecode, &[]));

    let mut cfg = ModeConfig::mode_b_lite();
    cfg.mpb_policy_bytecode = Some(policy_bytecode);
    cfg.mpb_policy_variables = Some(vec![]);
    let attestor = RobustMpbAttestor::new(cfg).expect("attestor");

    let verifier = RobustMpbVerifier::default_config().expect("verifier");

    let mut state = StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::new(),
        state_hash: dummy_hash(0),
        state_ref: mprd_core::StateRef::unknown(),
    };
    state.state_hash = mprd_core::hash::hash_state(&state);

    let mut candidate = CandidateAction {
        action_type: "TEST".into(),
        params: HashMap::new(),
        score: mprd_core::Score(10),
        candidate_hash: dummy_hash(0),
    };
    candidate.candidate_hash = mprd_core::hash::hash_candidate(&candidate);
    let candidates = vec![candidate.clone()];

    let decision = mprd_core::Decision {
        chosen_index: 0,
        chosen_action: candidate,
        policy_hash: policy_hash.clone(),
        decision_commitment: dummy_hash(4),
    };

    let token = mprd_core::DecisionToken {
        policy_hash,
        policy_ref: dummy_policy_ref(),
        state_hash: state.state_hash.clone(),
        state_ref: state.state_ref.clone(),
        chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
        nonce_or_tx_hash: dummy_hash(9),
        timestamp_ms: 0,
        signature: vec![],
    };

    let proof = attestor
        .attest(&token, &decision, &state, &candidates)
        .expect("proof");

    assert_eq!(verifier.verify(&token, &proof), VerificationStatus::Success);
}

#[test]
fn robust_mpb_verifier_rejects_tampered_binding() {
    let policy_bytecode = mprd_core::mpb::BytecodeBuilder::new()
        .push_i64(1)
        .halt()
        .build();
    let policy_hash = Hash32(mprd_mpb::policy_hash_v1(&policy_bytecode, &[]));

    let mut cfg = ModeConfig::mode_b_lite();
    cfg.mpb_policy_bytecode = Some(policy_bytecode);
    cfg.mpb_policy_variables = Some(vec![]);
    let attestor = RobustMpbAttestor::new(cfg).expect("attestor");

    let verifier = RobustMpbVerifier::default_config().expect("verifier");

    let mut state = StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::new(),
        state_hash: dummy_hash(0),
        state_ref: mprd_core::StateRef::unknown(),
    };
    state.state_hash = mprd_core::hash::hash_state(&state);

    let mut candidate = CandidateAction {
        action_type: "TEST".into(),
        params: HashMap::new(),
        score: mprd_core::Score(10),
        candidate_hash: dummy_hash(0),
    };
    candidate.candidate_hash = mprd_core::hash::hash_candidate(&candidate);
    let candidates = vec![candidate.clone()];

    let decision = mprd_core::Decision {
        chosen_index: 0,
        chosen_action: candidate,
        policy_hash: policy_hash.clone(),
        decision_commitment: dummy_hash(4),
    };

    let mut token = mprd_core::DecisionToken {
        policy_hash,
        policy_ref: dummy_policy_ref(),
        state_hash: state.state_hash.clone(),
        state_ref: state.state_ref.clone(),
        chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
        nonce_or_tx_hash: dummy_hash(9),
        timestamp_ms: 0,
        signature: vec![],
    };

    let proof = attestor
        .attest(&token, &decision, &state, &candidates)
        .expect("proof");

    // Tamper: change token nonce; verifier must reject because nonce is bound via proof.context_hash.
    token.nonce_or_tx_hash = dummy_hash(123);
    let status = verifier.verify(&token, &proof);
    assert!(matches!(status, VerificationStatus::Failure(_)));
}

// =============================================================================
// Robust Mode B-Full Tests
// =============================================================================

#[test]
fn robust_risc0_attestor_reports_availability() {
    let config = ModeConfig::mode_b_full([0u8; 32]);
    let provider = Arc::new(HashMap::<mprd_core::PolicyHash, MpbPolicyArtifactV1>::new())
        as Arc<dyn mprd_zk::MpbPolicyProvider>;
    let attestor = RobustRisc0Attestor::new(config, None, Some(provider)).expect("Should create");

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
        policy_ref: dummy_policy_ref(),
        state_hash: dummy_hash(2),
        state_ref: mprd_core::StateRef::unknown(),
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
        limits_hash: dummy_hash(6),
        limits_bytes: vec![],
        chosen_action_preimage: vec![],
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

    let selector = DefaultSelector;
    let policy_bytecode = mprd_core::mpb::BytecodeBuilder::new()
        .push_i64(1)
        .halt()
        .build();
    let mut policy_engine = mprd_core::mpb::MpbPolicyEngine::new();
    let policy_hash = policy_engine.register(mprd_core::mpb::MpbPolicy::new(
        policy_bytecode.clone(),
        HashMap::new(),
    ));

    let token_factory = mprd_core::components::SignedDecisionTokenFactory::default_for_testing();
    let mut attestor_cfg = ModeConfig::mode_b_lite();
    attestor_cfg.mpb_policy_bytecode = Some(policy_bytecode);
    attestor_cfg.mpb_policy_variables = Some(vec![]);
    let attestor = RobustMpbAttestor::new(attestor_cfg).expect("Should create");

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
        policy_ref: dummy_policy_ref(),
        nonce_or_tx_hash: None,
        metrics: None,
        audit_recorder: None,
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
    let policy_bytecode = mprd_core::mpb::BytecodeBuilder::new()
        .push_i64(1)
        .halt()
        .build();
    let policy_hash = Hash32(mprd_mpb::policy_hash_v1(&policy_bytecode, &[]));

    let token_factory = mprd_core::components::SignedDecisionTokenFactory::default_for_testing();

    // MPRD_MPB_GUEST_ID is a Risc0 digest ([u32; 8]); convert to [u8; 32] for ModeConfig.
    let mut image_id = [0u8; 32];
    for (i, word) in MPRD_MPB_GUEST_ID.iter().enumerate() {
        image_id[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    let config = ModeConfig::mode_b_full(image_id);
    let mut store: HashMap<mprd_core::PolicyHash, MpbPolicyArtifactV1> = HashMap::new();
    store.insert(
        policy_hash.clone(),
        MpbPolicyArtifactV1 {
            bytecode: policy_bytecode,
            variables: vec![],
        },
    );
    let provider = Arc::new(store) as Arc<dyn mprd_zk::MpbPolicyProvider>;

    let attestor =
        RobustRisc0Attestor::new(config.clone(), Some(MPRD_MPB_GUEST_ELF), Some(provider))
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
        policy_ref: dummy_policy_ref(),
        nonce_or_tx_hash: None,
        metrics: None,
        audit_recorder: None,
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

#[test]
fn registry_bound_verifier_rejects_wrong_image_id_routing() {
    if should_skip_due_to_missing_risc0_methods() {
        return;
    }

    // Minimal valid state/candidate/decision/token for mpb-v1 guest.
    let mut state = StateSnapshot {
        fields: HashMap::from([("balance".into(), Value::UInt(10000))]),
        policy_inputs: HashMap::new(),
        state_hash: Hash32([0u8; 32]),
        state_ref: StateRef::unknown(),
    };
    state.state_hash = mprd_core::hash::hash_state(&state);

    let mut chosen_action = CandidateAction {
        action_type: "ACTION".into(),
        params: HashMap::from([("param".into(), Value::Int(42))]),
        score: Score(100),
        candidate_hash: Hash32([0u8; 32]),
    };
    chosen_action.candidate_hash = mprd_core::hash::hash_candidate(&chosen_action);
    let candidates = vec![chosen_action.clone()];

    let policy_bytecode = mprd_core::mpb::BytecodeBuilder::new()
        .push_i64(1)
        .halt()
        .build();
    let policy_hash = Hash32(mprd_mpb::policy_hash_v1(&policy_bytecode, &[]));

    let decision = mprd_core::Decision {
        chosen_index: 0,
        chosen_action: chosen_action.clone(),
        policy_hash: policy_hash.clone(),
        decision_commitment: Hash32([0u8; 32]),
    };

    let token = mprd_core::DecisionToken {
        policy_hash: policy_hash.clone(),
        policy_ref: dummy_policy_ref(),
        state_hash: state.state_hash.clone(),
        state_ref: state.state_ref.clone(),
        chosen_action_hash: chosen_action.candidate_hash.clone(),
        nonce_or_tx_hash: dummy_hash(5),
        timestamp_ms: 0,
        signature: vec![],
    };

    // Convert Risc0 digest ([u32; 8]) to [u8; 32] for attestation.
    let mut mpb_image_id = [0u8; 32];
    for (i, word) in MPRD_MPB_GUEST_ID.iter().enumerate() {
        mpb_image_id[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    // Prove with the correct mpb guest image.
    let config = ModeConfig::mode_b_full(mpb_image_id);
    let mut store: HashMap<mprd_core::PolicyHash, MpbPolicyArtifactV1> = HashMap::new();
    store.insert(
        policy_hash.clone(),
        MpbPolicyArtifactV1 {
            bytecode: policy_bytecode,
            variables: vec![],
        },
    );
    let provider = Arc::new(store) as Arc<dyn mprd_zk::MpbPolicyProvider>;

    let attestor =
        RobustRisc0Attestor::new(config.clone(), Some(MPRD_MPB_GUEST_ELF), Some(provider))
            .expect("Risc0 attestor should be created");

    let proof = match attestor.attest(&token, &decision, &state, &candidates) {
        Ok(p) => p,
        Err(e) => {
            if should_skip_due_to_r0vm_mismatch(&e) {
                return;
            }
            panic!("Attestation should succeed: {e}");
        }
    };

    // Build a signed manifest that routes mpb-v1 to the WRONG image_id.
    let signing_key = TokenSigningKey::from_seed(&[201u8; 32]);
    let vk = signing_key.verifying_key();
    let wrong_image_id = [0xAAu8; 32];
    let manifest = GuestImageManifestV1::sign(
        &signing_key,
        123,
        vec![GuestImageEntryV1 {
            policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            image_id: wrong_image_id,
        }],
    )
    .expect("manifest");

    let registry_state = RegistryStateV1 {
        policy_epoch: token.policy_ref.policy_epoch,
        registry_root: token.policy_ref.registry_root.clone(),
        authorized_policies: vec![AuthorizedPolicyV1 {
            policy_hash: policy_hash.clone(),
            policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            policy_source_kind_id: None,
            policy_source_hash: None,
        }],
        guest_image_manifest: manifest,
    };

    let provider = Arc::new(StaticRegistryStateProvider(registry_state))
        as Arc<dyn mprd_zk::registry_state::RegistryStateProvider>;
    let registry_bound = RegistryBoundRisc0Verifier::new(provider, vk);
    let status = registry_bound.verify(&token, &proof);
    assert!(matches!(status, VerificationStatus::Failure(_)));
}

#[test]
fn registry_bound_verifier_rejects_unauthorized_policy_hash() {
    if should_skip_due_to_missing_risc0_methods() {
        return;
    }

    // Use the happy-path B-Full pipeline to obtain a valid token/proof pair.
    let state_provider =
        SimpleStateProvider::new(HashMap::from([("balance".into(), Value::UInt(10000))]));
    let proposer = SimpleProposer::single(
        "ACTION",
        HashMap::from([("param".into(), Value::Int(42))]),
        100,
    );
    let policy_engine = AllowAllPolicyEngine;
    let selector = DefaultSelector;
    let policy_bytecode = mprd_core::mpb::BytecodeBuilder::new()
        .push_i64(1)
        .halt()
        .build();
    let policy_hash = Hash32(mprd_mpb::policy_hash_v1(&policy_bytecode, &[]));
    let token_factory = mprd_core::components::SignedDecisionTokenFactory::default_for_testing();

    let mut mpb_image_id = [0u8; 32];
    for (i, word) in MPRD_MPB_GUEST_ID.iter().enumerate() {
        mpb_image_id[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    let config = ModeConfig::mode_b_full(mpb_image_id);
    let mut store: HashMap<mprd_core::PolicyHash, MpbPolicyArtifactV1> = HashMap::new();
    store.insert(
        policy_hash.clone(),
        MpbPolicyArtifactV1 {
            bytecode: policy_bytecode,
            variables: vec![],
        },
    );
    let provider = Arc::new(store) as Arc<dyn mprd_zk::MpbPolicyProvider>;
    let attestor =
        RobustRisc0Attestor::new(config.clone(), Some(MPRD_MPB_GUEST_ELF), Some(provider))
            .expect("Risc0 attestor should be created");
    let verifier =
        RobustRisc0Verifier::new(config.clone()).expect("Risc0 verifier should be created");

    // Manually assemble the pipeline steps so we can extract token/proof.
    let mut state = state_provider.snapshot().expect("state");
    state.state_hash = mprd_core::hash::hash_state(&state);
    let mut candidates = proposer.propose(&state).expect("candidates");
    for c in &mut candidates {
        c.candidate_hash = mprd_core::hash::hash_candidate(c);
    }
    let verdicts = policy_engine
        .evaluate(&policy_hash, &state, &candidates)
        .expect("verdicts");
    let decision = selector
        .select(&policy_hash, &state, &candidates, &verdicts)
        .expect("decision");
    let token = token_factory
        .create(&decision, &state, None, &dummy_policy_ref())
        .expect("token");
    let proof = match attestor.attest(&token, &decision, &state, &candidates) {
        Ok(p) => p,
        Err(e) => {
            if should_skip_due_to_r0vm_mismatch(&e) {
                return;
            }
            panic!("Attestation should succeed: {e}");
        }
    };

    // Sanity: the robust verifier accepts the proof.
    let ok = verifier.verify(&token, &proof);
    assert!(matches!(ok, VerificationStatus::Success));

    // Registry state that DOES NOT authorize this policy_hash should fail before receipt verification.
    let signing_key = TokenSigningKey::from_seed(&[202u8; 32]);
    let vk = signing_key.verifying_key();
    let manifest = GuestImageManifestV1::sign(
        &signing_key,
        123,
        vec![GuestImageEntryV1 {
            policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            image_id: mpb_image_id,
        }],
    )
    .expect("manifest");

    let registry_state = RegistryStateV1 {
        policy_epoch: token.policy_ref.policy_epoch,
        registry_root: token.policy_ref.registry_root.clone(),
        authorized_policies: vec![], // deny-by-default
        guest_image_manifest: manifest,
    };
    let provider = Arc::new(StaticRegistryStateProvider(registry_state))
        as Arc<dyn mprd_zk::registry_state::RegistryStateProvider>;
    let registry_bound = RegistryBoundRisc0Verifier::new(provider, vk);

    let status = registry_bound.verify(&token, &proof);
    assert!(matches!(status, VerificationStatus::Failure(_)));
}

#[test]
fn verifier_rejects_exec_kind_mismatch_even_with_valid_receipt() {
    if should_skip_due_to_missing_risc0_methods() {
        return;
    }

    // Build a valid mpb-v1 proof.
    let mut state = StateSnapshot {
        fields: HashMap::from([("balance".into(), Value::UInt(10000))]),
        policy_inputs: HashMap::new(),
        state_hash: Hash32([0u8; 32]),
        state_ref: StateRef::unknown(),
    };
    state.state_hash = mprd_core::hash::hash_state(&state);

    let mut chosen_action = CandidateAction {
        action_type: "ACTION".into(),
        params: HashMap::new(),
        score: Score(1),
        candidate_hash: Hash32([0u8; 32]),
    };
    chosen_action.candidate_hash = mprd_core::hash::hash_candidate(&chosen_action);
    let candidates = vec![chosen_action.clone()];

    let policy_bytecode = mprd_core::mpb::BytecodeBuilder::new()
        .push_i64(1)
        .halt()
        .build();
    let policy_hash = Hash32(mprd_mpb::policy_hash_v1(&policy_bytecode, &[]));

    let decision = mprd_core::Decision {
        chosen_index: 0,
        chosen_action: chosen_action.clone(),
        policy_hash: policy_hash.clone(),
        decision_commitment: Hash32([0u8; 32]),
    };
    let token = mprd_core::DecisionToken {
        policy_hash: policy_hash.clone(),
        policy_ref: dummy_policy_ref(),
        state_hash: state.state_hash.clone(),
        state_ref: state.state_ref.clone(),
        chosen_action_hash: chosen_action.candidate_hash.clone(),
        nonce_or_tx_hash: dummy_hash(5),
        timestamp_ms: 0,
        signature: vec![],
    };

    let mut mpb_image_id = [0u8; 32];
    for (i, word) in MPRD_MPB_GUEST_ID.iter().enumerate() {
        mpb_image_id[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    let config = ModeConfig::mode_b_full(mpb_image_id);
    let mut store: HashMap<mprd_core::PolicyHash, MpbPolicyArtifactV1> = HashMap::new();
    store.insert(
        policy_hash.clone(),
        MpbPolicyArtifactV1 {
            bytecode: policy_bytecode,
            variables: vec![],
        },
    );
    let provider = Arc::new(store) as Arc<dyn mprd_zk::MpbPolicyProvider>;
    let attestor = RobustRisc0Attestor::new(config, Some(MPRD_MPB_GUEST_ELF), Some(provider))
        .expect("Risc0 attestor should be created");
    let proof = match attestor.attest(&token, &decision, &state, &candidates) {
        Ok(p) => p,
        Err(e) => {
            if should_skip_due_to_r0vm_mismatch(&e) {
                return;
            }
            panic!("Attestation should succeed: {e}");
        }
    };

    // Verify the receipt under the correct image_id but enforce the wrong exec kind ID.
    let wrong_kind_verifier = mprd_zk::risc0_host::Risc0Verifier::new(
        mpb_image_id,
        policy_exec_kind_host_trusted_id_v0(),
        policy_exec_version_id_v1(),
    );
    let status = wrong_kind_verifier.verify(&token, &proof);
    assert!(matches!(status, VerificationStatus::Failure(_)));
}

#[test]
fn mpb_v1_out_of_fuel_denies_without_executor_side_effects() {
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

    // Build a program that will exceed MPB_FUEL_LIMIT_V1 without using jumps:
    // repeat (push 1; pop) to consume fuel while keeping stack bounded.
    let mut bytecode = Vec::new();
    for _ in 0..6000 {
        bytecode.push(mprd_core::mpb::OpCode::Push as u8);
        bytecode.extend_from_slice(&1i64.to_le_bytes());
        bytecode.push(mprd_core::mpb::OpCode::Pop as u8);
    }
    bytecode.push(mprd_core::mpb::OpCode::Push as u8);
    bytecode.extend_from_slice(&1i64.to_le_bytes());
    bytecode.push(mprd_core::mpb::OpCode::Halt as u8);

    let policy_hash = Hash32(mprd_mpb::policy_hash_v1(&bytecode, &[]));
    let token_factory = mprd_core::components::SignedDecisionTokenFactory::default_for_testing();

    // Convert Risc0 digest ([u32; 8]) to [u8; 32].
    let mut image_id = [0u8; 32];
    for (i, word) in MPRD_MPB_GUEST_ID.iter().enumerate() {
        image_id[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    let config = ModeConfig::mode_b_full(image_id);
    let mut store: HashMap<mprd_core::PolicyHash, MpbPolicyArtifactV1> = HashMap::new();
    store.insert(
        policy_hash.clone(),
        MpbPolicyArtifactV1 {
            bytecode,
            variables: vec![],
        },
    );
    let provider = Arc::new(store) as Arc<dyn mprd_zk::MpbPolicyProvider>;

    let attestor =
        RobustRisc0Attestor::new(config.clone(), Some(MPRD_MPB_GUEST_ELF), Some(provider))
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
        policy_ref: dummy_policy_ref(),
        nonce_or_tx_hash: None,
        metrics: None,
        audit_recorder: None,
    });

    if let Err(e) = &result {
        if should_skip_due_to_r0vm_mismatch(e) {
            return;
        }
    }

    assert!(result.is_err(), "Expected denial due to out-of-fuel");
    assert_eq!(executor.get_log().len(), 0, "No side effects on denial");
}

#[test]
fn mpb_v1_invalid_bytecode_denies_without_executor_side_effects() {
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

    // Invalid opcode 0x00 => guest should deterministically deny (no panic).
    let bytecode = vec![0x00];
    let policy_hash = Hash32(mprd_mpb::policy_hash_v1(&bytecode, &[]));
    let token_factory = mprd_core::components::SignedDecisionTokenFactory::default_for_testing();

    let mut image_id = [0u8; 32];
    for (i, word) in MPRD_MPB_GUEST_ID.iter().enumerate() {
        image_id[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    let config = ModeConfig::mode_b_full(image_id);
    let mut store: HashMap<mprd_core::PolicyHash, MpbPolicyArtifactV1> = HashMap::new();
    store.insert(
        policy_hash.clone(),
        MpbPolicyArtifactV1 {
            bytecode,
            variables: vec![],
        },
    );
    let provider = Arc::new(store) as Arc<dyn mprd_zk::MpbPolicyProvider>;

    let attestor =
        RobustRisc0Attestor::new(config.clone(), Some(MPRD_MPB_GUEST_ELF), Some(provider))
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
        policy_ref: dummy_policy_ref(),
        nonce_or_tx_hash: None,
        metrics: None,
        audit_recorder: None,
    });

    if let Err(e) = &result {
        if should_skip_due_to_r0vm_mismatch(e) {
            return;
        }
    }

    assert!(result.is_err(), "Expected denial due to invalid bytecode");
    assert_eq!(executor.get_log().len(), 0, "No side effects on denial");
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
    let encryption_config = mprd_zk::modes_v2::EncryptionConfig {
        master_key: Some([42u8; 32]),
        ..Default::default()
    };
    let attestor = RobustPrivateAttestor::new(config.clone(), encryption_config)
        .expect("Private attestor should be created");

    let state = StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::new(),
        state_hash: dummy_hash(1),
        state_ref: mprd_core::StateRef::unknown(),
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

    let token = mprd_core::DecisionToken {
        policy_hash: decision.policy_hash.clone(),
        policy_ref: dummy_policy_ref(),
        state_hash: state.state_hash.clone(),
        state_ref: state.state_ref.clone(),
        chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
        nonce_or_tx_hash: dummy_hash(5),
        timestamp_ms: 0,
        signature: vec![],
    };

    let proof = match attestor.attest(&token, &decision, &state, &candidates) {
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
    let encryption_config = mprd_zk::modes_v2::EncryptionConfig {
        master_key: Some([42u8; 32]),
        ..Default::default()
    };
    let attestor = RobustPrivateAttestor::new(config.clone(), encryption_config)
        .expect("Private attestor should be created");
    let verifier =
        RobustPrivateVerifier::new(config.clone()).expect("Private verifier should be created");

    let state = StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::new(),
        state_hash: dummy_hash(1),
        state_ref: mprd_core::StateRef::unknown(),
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

    let token = mprd_core::DecisionToken {
        policy_hash: decision.policy_hash.clone(),
        policy_ref: dummy_policy_ref(),
        state_hash: state.state_hash.clone(),
        state_ref: state.state_ref.clone(),
        chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
        nonce_or_tx_hash: dummy_hash(5),
        timestamp_ms: 0,
        signature: vec![],
    };

    let mut proof = match attestor.attest(&token, &decision, &state, &candidates) {
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
