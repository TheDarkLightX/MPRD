//! Integration tests for MPRD deployment modes.
//!
//! Tests the complete flow for each deployment mode:
//! - Mode A: Local trusted
//! - Mode B-Lite: Computational proofs (MPB)
//! - Mode B-Full: Cryptographic ZK (Risc0) - infrastructure only
//! - Mode C: Private (encryption + ZK) - infrastructure only

use mprd_core::{
    components::{SimpleProposer, SimpleStateProvider},
    orchestrator::{run_once, RunOnceInputs},
    CandidateAction, DefaultSelector, Hash32, PolicyEngine, PolicyHash, PolicyRef, Result,
    RuleVerdict, StateSnapshot, Value,
};
use mprd_zk::modes_v2::{DeploymentMode, EncryptionConfig, ModeConfig};
use mprd_zk::{
    create_robust_attestor, create_robust_private_attestor, create_robust_verifier,
    ExternalVerifier, RobustMpbAttestor, RobustMpbVerifier, VerificationRequest,
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

fn dummy_policy_ref() -> PolicyRef {
    PolicyRef {
        policy_epoch: 1,
        registry_root: dummy_hash(99),
    }
}

fn setup_components() -> (
    SimpleStateProvider,
    SimpleProposer,
    AllowAllPolicyEngine,
    DefaultSelector,
    Hash32,
) {
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

    (
        state_provider,
        proposer,
        policy_engine,
        selector,
        policy_hash,
    )
}

// =============================================================================
// Mode A: Local Trusted
// =============================================================================

#[test]
fn mode_a_local_trusted_flow() {
    let (state_provider, proposer, policy_engine, selector, policy_hash) = setup_components();

    // Mode A uses stub components from mprd-core
    let token_factory = mprd_core::components::SignedDecisionTokenFactory::default_for_testing();
    let attestor = mprd_core::components::StubZkAttestor::new();
    let verifier = mprd_core::components::StubZkLocalVerifier::new();
    let executor = mprd_core::components::LoggingExecutorAdapter::new();

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

    assert!(result.is_ok(), "Mode A should succeed");
    assert_eq!(executor.get_log().len(), 1);
}

// =============================================================================
// Mode B-Lite: Computational Proofs (MPB)
// =============================================================================

#[test]
fn mode_b_lite_attestation_flow() {
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

    // Mode B-Lite uses MPB attestor/verifier
    let token_factory = mprd_core::components::SignedDecisionTokenFactory::default_for_testing();
    let mut attestor_cfg = ModeConfig::mode_b_lite();
    attestor_cfg.mpb_policy_bytecode = Some(policy_bytecode);
    attestor_cfg.mpb_policy_variables = Some(vec![]);
    let attestor = RobustMpbAttestor::new(attestor_cfg).expect("attestor");
    let verifier = RobustMpbVerifier::default_config().expect("verifier");
    let executor = mprd_core::components::LoggingExecutorAdapter::new();

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

    assert!(result.is_ok(), "Mode B-Lite should succeed");
    assert_eq!(executor.get_log().len(), 1);
}

#[test]
fn mode_b_lite_external_verification() {
    let verifier = ExternalVerifier::new();

    let request = VerificationRequest {
        mode: DeploymentMode::TrustlessLite,
        policy_hash: [1u8; 32],
        policy_epoch: 1,
        registry_root: [9u8; 32],
        state_source_id: [7u8; 32],
        state_epoch: 123,
        state_attestation_hash: [6u8; 32],
        state_hash: [2u8; 32],
        candidate_set_hash: [3u8; 32],
        chosen_action_hash: [4u8; 32],
        nonce_or_tx_hash: [8u8; 32],
        proof_data: vec![],
        metadata: HashMap::from([
            ("mode".into(), "B-Lite".into()),
            ("proof_type".into(), "MPB".into()),
        ]),
    };

    let response = verifier.verify(&request);
    assert!(
        !response.valid,
        "External verification must fail-closed when required B-Lite metadata is missing"
    );
    assert_eq!(response.error.as_deref(), Some("Missing MPB metadata"));
}

// =============================================================================
// Mode B-Full: Cryptographic ZK (Risc0)
// =============================================================================

#[test]
fn mode_b_full_requires_risc0() {
    let mut config = ModeConfig::mode_b_full([0u8; 32]);
    config.mpb_policy_bytecode = Some(
        mprd_core::mpb::BytecodeBuilder::new()
            .push_i64(1)
            .halt()
            .build(),
    );
    config.mpb_policy_variables = Some(vec![]);

    let result = create_robust_attestor(&config);
    assert!(result.is_err(), "B-Full should reject all-zero image_id");
}

#[test]
fn mode_b_full_external_verifier_requires_image_id() {
    let verifier = ExternalVerifier::new(); // No image ID

    let request = VerificationRequest {
        mode: DeploymentMode::TrustlessFull,
        policy_hash: [1u8; 32],
        policy_epoch: 1,
        registry_root: [9u8; 32],
        state_source_id: [7u8; 32],
        state_epoch: 123,
        state_attestation_hash: [6u8; 32],
        state_hash: [2u8; 32],
        candidate_set_hash: [3u8; 32],
        chosen_action_hash: [4u8; 32],
        nonce_or_tx_hash: [8u8; 32],
        proof_data: vec![1, 2, 3],
        metadata: HashMap::new(),
    };

    let response = verifier.verify(&request);
    assert!(!response.valid, "Should fail without image ID");
}

// =============================================================================
// Mode C: Private (Encryption + ZK)
// =============================================================================

#[test]
fn mode_c_private_attestor_requires_master_key() {
    let config = ModeConfig::mode_c([1u8; 32], "test-key");
    let encryption_config = EncryptionConfig::default();

    let result = create_robust_private_attestor(&config, encryption_config);
    assert!(result.is_err(), "Mode C should require a master_key");
}

#[test]
fn mode_c_private_attestor_builds_with_master_key() {
    let config = ModeConfig::mode_c([1u8; 32], "test-key");
    let encryption_config = EncryptionConfig::with_master_key("test-key", [9u8; 32]);

    let result = create_robust_private_attestor(&config, encryption_config);
    assert!(result.is_ok(), "Mode C should accept a master_key");
}

// =============================================================================
// Factory Functions
// =============================================================================

#[test]
fn factory_creates_correct_attestors() {
    // Mode A
    let mut config_a = ModeConfig::mode_a();
    config_a.strict_security = false;
    assert!(create_robust_attestor(&config_a).is_ok());

    // Mode B-Lite
    let policy_bytecode = mprd_core::mpb::BytecodeBuilder::new()
        .push_i64(1)
        .halt()
        .build();
    let mut config_b_lite = ModeConfig::mode_b_lite();
    config_b_lite.mpb_policy_bytecode = Some(policy_bytecode.clone());
    config_b_lite.mpb_policy_variables = Some(vec![]);
    assert!(create_robust_attestor(&config_b_lite).is_ok());

    // Mode B-Full
    let mut config_b_full = ModeConfig::mode_b_full([1u8; 32]);
    config_b_full.mpb_policy_bytecode = Some(policy_bytecode);
    config_b_full.mpb_policy_variables = Some(vec![]);
    assert!(create_robust_attestor(&config_b_full).is_ok());

    // Mode C
    let config_c = ModeConfig::mode_c([1u8; 32], "key");
    let encryption_config = EncryptionConfig::with_master_key("key", [5u8; 32]);
    assert!(create_robust_private_attestor(&config_c, encryption_config).is_ok());
}

#[test]
fn factory_creates_correct_verifiers() {
    // Mode A
    let mut config_a = ModeConfig::mode_a();
    config_a.strict_security = false;
    assert!(create_robust_verifier(&config_a).is_ok());

    // Mode B-Lite
    let config_b_lite = ModeConfig::mode_b_lite();
    assert!(create_robust_verifier(&config_b_lite).is_ok());

    // Mode B-Full
    let config_b_full = ModeConfig::mode_b_full([1u8; 32]);
    assert!(create_robust_verifier(&config_b_full).is_ok());

    // Mode C
    let config_c = ModeConfig::mode_c([1u8; 32], "key");
    assert!(create_robust_verifier(&config_c).is_ok());
}

// =============================================================================
// Mode Configuration
// =============================================================================

#[test]
fn mode_config_serialization() {
    let config = ModeConfig::mode_b_lite();

    let json = serde_json::to_string(&config).expect("Serialization should succeed");
    let deserialized: ModeConfig =
        serde_json::from_str(&json).expect("Deserialization should succeed");
    assert_eq!(deserialized.mode, DeploymentMode::TrustlessLite);
}
