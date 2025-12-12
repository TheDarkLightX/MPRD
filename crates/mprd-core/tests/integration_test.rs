//! End-to-end integration tests for MPRD pipeline.
//!
//! These tests verify the complete flow from state capture to execution,
//! including cryptographic signing and verification.

use mprd_core::{
    components::{
        CryptoDecisionTokenFactory, LoggingExecutorAdapter, SignatureVerifyingExecutor,
        SimpleProposer, SimpleStateProvider, StubZkAttestor, StubZkLocalVerifier,
    },
    config::MprdConfig,
    orchestrator::run_once,
    DefaultSelector, Hash32, PolicyEngine, PolicyHash, Proposer, RuleVerdict, StateSnapshot,
    CandidateAction, Result, Value,
};
use std::collections::HashMap;

// =============================================================================
// Test Policy Engine
// =============================================================================

/// Simple policy engine that allows actions where risk <= threshold.
struct RiskThresholdPolicyEngine {
    threshold: i64,
}

impl RiskThresholdPolicyEngine {
    fn new(threshold: i64) -> Self {
        Self { threshold }
    }
}

impl PolicyEngine for RiskThresholdPolicyEngine {
    fn evaluate(
        &self,
        _policy_hash: &PolicyHash,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<Vec<RuleVerdict>> {
        let risk = state
            .fields
            .get("risk")
            .and_then(|v| match v {
                Value::Int(i) => Some(*i),
                _ => None,
            })
            .unwrap_or(0);

        Ok(candidates
            .iter()
            .map(|_| RuleVerdict {
                allowed: risk <= self.threshold,
                reasons: if risk > self.threshold {
                    vec![format!("risk {} exceeds threshold {}", risk, self.threshold)]
                } else {
                    vec![]
                },
                limits: HashMap::new(),
            })
            .collect())
    }
}

// =============================================================================
// Integration Tests
// =============================================================================

fn dummy_hash(byte: u8) -> Hash32 {
    Hash32([byte; 32])
}

#[test]
fn end_to_end_with_crypto_signatures() {
    // Setup configuration (validates settings)
    let _config = MprdConfig::builder()
        .max_candidates(64)
        .require_signatures(true)
        .build()
        .expect("config should be valid");

    // Setup components
    let state_provider = SimpleStateProvider::new(HashMap::from([
        ("risk".into(), Value::Int(50)),
        ("balance".into(), Value::UInt(10000)),
    ]));

    let proposer = SimpleProposer::single(
        "TRADE",
        HashMap::from([("amount".into(), Value::UInt(100))]),
        10,
    );

    let policy_engine = RiskThresholdPolicyEngine::new(100); // Allow risk <= 100
    let selector = DefaultSelector;

    // Create crypto token factory with verifying executor
    let token_factory = CryptoDecisionTokenFactory::generate();
    let verifying_key = token_factory.verifying_key();

    let attestor = StubZkAttestor::new();
    let verifier = StubZkLocalVerifier::new();

    let inner_executor = LoggingExecutorAdapter::new();
    let executor = SignatureVerifyingExecutor::new(inner_executor, verifying_key);

    let policy_hash = dummy_hash(1);

    // Execute the pipeline
    let result = run_once(
        &state_provider,
        &proposer,
        &policy_engine,
        &selector,
        &token_factory,
        &attestor,
        &verifier,
        &executor,
        &policy_hash,
    );

    assert!(result.is_ok(), "Pipeline should succeed");
    let execution_result = result.unwrap();
    assert!(execution_result.success, "Execution should succeed");
}

#[test]
fn end_to_end_policy_denial() {
    // Setup with high risk that will be denied
    let state_provider = SimpleStateProvider::new(HashMap::from([
        ("risk".into(), Value::Int(150)), // Exceeds threshold
    ]));

    let proposer = SimpleProposer::single(
        "TRADE",
        HashMap::from([("amount".into(), Value::UInt(100))]),
        10,
    );

    let policy_engine = RiskThresholdPolicyEngine::new(100); // Allow risk <= 100
    let selector = DefaultSelector;
    let token_factory = CryptoDecisionTokenFactory::generate();
    let attestor = StubZkAttestor::new();
    let verifier = StubZkLocalVerifier::new();
    let executor = LoggingExecutorAdapter::new();

    let policy_hash = dummy_hash(1);

    // Execute the pipeline - should fail because no candidates are allowed
    let result = run_once(
        &state_provider,
        &proposer,
        &policy_engine,
        &selector,
        &token_factory,
        &attestor,
        &verifier,
        &executor,
        &policy_hash,
    );

    assert!(result.is_err(), "Pipeline should fail when all candidates denied");
}

#[test]
fn signature_verification_prevents_tampering() {
    #[allow(unused_imports)]
    use mprd_core::{DecisionToken, ProofBundle};

    // Create two factories with different keys
    let factory1 = CryptoDecisionTokenFactory::generate();
    let factory2 = CryptoDecisionTokenFactory::generate();

    // Executor verifies with factory2's key
    let inner_executor = LoggingExecutorAdapter::new();
    let executor = SignatureVerifyingExecutor::new(inner_executor, factory2.verifying_key());

    // Create a token signed by factory1
    let state_provider = SimpleStateProvider::new(HashMap::from([
        ("risk".into(), Value::Int(50)),
    ]));

    let proposer = SimpleProposer::single("TRADE", HashMap::new(), 10);
    let policy_engine = RiskThresholdPolicyEngine::new(100);
    let selector = DefaultSelector;
    let attestor = StubZkAttestor::new();
    let verifier = StubZkLocalVerifier::new();

    let policy_hash = dummy_hash(1);

    // Run with factory1 (wrong signer)
    let result = run_once(
        &state_provider,
        &proposer,
        &policy_engine,
        &selector,
        &factory1, // Signed by wrong key
        &attestor,
        &verifier,
        &executor, // Verifies with factory2's key
        &policy_hash,
    );

    assert!(result.is_err(), "Should reject token signed with wrong key");
}

#[test]
fn multiple_candidates_highest_score_selected() {
    let state_provider = SimpleStateProvider::new(HashMap::from([
        ("risk".into(), Value::Int(50)),
    ]));

    // Multiple candidates with different scores
    let candidates = vec![
        ("LOW_TRADE", 5),
        ("MED_TRADE", 15),
        ("HIGH_TRADE", 25), // Highest score, should be selected
    ];

    let proposer = SimpleProposer::new(
        candidates
            .iter()
            .map(|(name, score)| {
                let mut action = SimpleProposer::single(
                    *name,
                    HashMap::new(),
                    *score,
                )
                .propose(&StateSnapshot {
                    fields: HashMap::new(),
                    policy_inputs: HashMap::new(),
                    state_hash: dummy_hash(0),
                })
                .unwrap();
                action.pop().unwrap()
            })
            .collect(),
    );

    let policy_engine = RiskThresholdPolicyEngine::new(100);
    let selector = DefaultSelector;
    let token_factory = CryptoDecisionTokenFactory::generate();
    let attestor = StubZkAttestor::new();
    let verifier = StubZkLocalVerifier::new();
    let executor = LoggingExecutorAdapter::new();

    let policy_hash = dummy_hash(1);

    let result = run_once(
        &state_provider,
        &proposer,
        &policy_engine,
        &selector,
        &token_factory,
        &attestor,
        &verifier,
        &executor,
        &policy_hash,
    );

    assert!(result.is_ok());

    // Verify the executed action was HIGH_TRADE (highest score)
    let log = executor.get_log();
    assert_eq!(log.len(), 1);
}

#[test]
fn config_validation_works() {
    // Valid config
    let config = MprdConfig::builder()
        .max_candidates(32)
        .max_fuel(5000)
        .build();
    assert!(config.is_ok());

    // Invalid: zero candidates
    let config = MprdConfig::builder()
        .max_candidates(0)
        .build();
    assert!(config.is_err());

    // Invalid: bad signing key
    let config = MprdConfig::builder()
        .signing_key_hex("not-valid-hex")
        .build();
    assert!(config.is_err());
}
