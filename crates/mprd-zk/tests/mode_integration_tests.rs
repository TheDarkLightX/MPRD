//! Integration tests for MPRD deployment modes.
//!
//! Tests the complete flow for each deployment mode:
//! - Mode A: Local trusted
//! - Mode B-Lite: Computational proofs (MPB)
//! - Mode B-Full: Cryptographic ZK (Risc0) - infrastructure only
//! - Mode C: Private (encryption + ZK) - infrastructure only

#![allow(deprecated)]

use mprd_core::{
    components::{SimpleProposer, SimpleStateProvider},
    orchestrator::{run_once, RunOnceInputs},
    CandidateAction, DefaultSelector, Hash32, PolicyEngine, PolicyHash, PolicyRef, Result,
    RuleVerdict, StateSnapshot, Value,
};
use mprd_zk::{
    create_attestor, create_verifier, DeploymentMode, ExternalVerifier, ModeConfig,
    MpbTrustlessAttestor, MpbTrustlessVerifier, VerificationRequest,
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
    let (state_provider, proposer, policy_engine, selector, policy_hash) = setup_components();

    // Mode B-Lite uses MPB attestor/verifier
    let token_factory = mprd_core::components::SignedDecisionTokenFactory::default_for_testing();
    let attestor = MpbTrustlessAttestor::default_config();
    let verifier = MpbTrustlessVerifier::default_config();
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
    let config = ModeConfig::mode_b_full([0u8; 32]);
    let attestor = create_attestor(&config);

    let state = StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::new(),
        state_hash: dummy_hash(1),
        state_ref: mprd_core::StateRef::unknown(),
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

    // Mode B-Full should fail until Risc0 is wired
    let token = mprd_core::DecisionToken {
        policy_hash: decision.policy_hash.clone(),
        policy_ref: dummy_policy_ref(),
        state_hash: state.state_hash.clone(),
        state_ref: mprd_core::StateRef::unknown(),
        chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
        nonce_or_tx_hash: dummy_hash(9),
        timestamp_ms: 0,
        signature: vec![],
    };
    let result = attestor.attest(&token, &decision, &state, &[]);
    assert!(result.is_err(), "B-Full should fail without Risc0");
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
fn mode_c_not_yet_implemented() {
    let config = ModeConfig::mode_c([0u8; 32], "test-key");
    let attestor = create_attestor(&config);

    let state = StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::new(),
        state_hash: dummy_hash(1),
        state_ref: mprd_core::StateRef::unknown(),
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

    // Mode C should fail until implemented
    let token = mprd_core::DecisionToken {
        policy_hash: decision.policy_hash.clone(),
        policy_ref: dummy_policy_ref(),
        state_hash: state.state_hash.clone(),
        state_ref: mprd_core::StateRef::unknown(),
        chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
        nonce_or_tx_hash: dummy_hash(9),
        timestamp_ms: 0,
        signature: vec![],
    };
    let result = attestor.attest(&token, &decision, &state, &[]);
    assert!(result.is_err(), "Mode C should fail until implemented");
}

// =============================================================================
// Factory Functions
// =============================================================================

#[test]
fn factory_creates_correct_attestors() {
    // Mode A
    let config_a = ModeConfig::mode_a();
    let _attestor_a = create_attestor(&config_a);

    // Mode B-Lite
    let config_b_lite = ModeConfig::mode_b_lite();
    let _attestor_b_lite = create_attestor(&config_b_lite);

    // Mode B-Full
    let config_b_full = ModeConfig::mode_b_full([0u8; 32]);
    let _attestor_b_full = create_attestor(&config_b_full);

    // Mode C
    let config_c = ModeConfig::mode_c([0u8; 32], "key");
    let _attestor_c = create_attestor(&config_c);
}

#[test]
fn factory_creates_correct_verifiers() {
    // Mode A
    let config_a = ModeConfig::mode_a();
    let _verifier_a = create_verifier(&config_a);

    // Mode B-Lite
    let config_b_lite = ModeConfig::mode_b_lite();
    let _verifier_b_lite = create_verifier(&config_b_lite);

    // Mode B-Full
    let config_b_full = ModeConfig::mode_b_full([0u8; 32]);
    let _verifier_b_full = create_verifier(&config_b_full);

    // Mode C
    let config_c = ModeConfig::mode_c([0u8; 32], "key");
    let _verifier_c = create_verifier(&config_c);
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
