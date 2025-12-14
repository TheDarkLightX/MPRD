//! End-to-End Pipeline Tests
//!
//! These tests verify the complete MPRD pipeline from proposal to execution.

use mprd_core::anti_replay::{AntiReplayConfig, InMemoryNonceTracker, NonceValidator};
use mprd_core::components::{
    CryptoDecisionTokenFactory, LoggingExecutorAdapter, SignatureVerifyingExecutor,
    SignedDecisionTokenFactory, SimpleStateProvider, StubZkAttestor, StubZkLocalVerifier,
};
use mprd_core::orchestrator::DecisionTokenFactory;
use mprd_core::StateProvider;
use mprd_core::{
    CandidateAction, DecisionToken, DefaultSelector, ExecutorAdapter, Hash32, PolicyEngine,
    PolicyHash, Result, RuleVerdict, Score, Selector, StateSnapshot, Value, VerificationStatus,
    ZkAttestor, ZkLocalVerifier,
};
use std::collections::HashMap;

// =============================================================================
// Test Fixtures
// =============================================================================

fn dummy_hash(b: u8) -> Hash32 {
    Hash32([b; 32])
}

/// Simple allow-all policy engine for testing.
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

/// Policy engine that denies high-risk actions.
struct RiskThresholdPolicyEngine {
    max_risk: i64,
}

impl PolicyEngine for RiskThresholdPolicyEngine {
    fn evaluate(
        &self,
        _policy_hash: &PolicyHash,
        _state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<Vec<RuleVerdict>> {
        Ok(candidates
            .iter()
            .map(|c| {
                let risk = match c.params.get("risk") {
                    Some(Value::Int(r)) => *r,
                    Some(Value::UInt(r)) => *r as i64,
                    _ => 0,
                };

                let allowed = risk <= self.max_risk;
                RuleVerdict {
                    allowed,
                    reasons: if allowed {
                        vec![]
                    } else {
                        vec!["risk too high".into()]
                    },
                    limits: HashMap::new(),
                }
            })
            .collect())
    }
}

// =============================================================================
// E2E Test: Basic Pipeline
// =============================================================================

#[test]
fn e2e_basic_pipeline_selects_highest_score() {
    // Setup
    let policy_hash = dummy_hash(1);
    let policy_engine = AllowAllPolicyEngine;
    let selector = DefaultSelector;
    let token_factory = SignedDecisionTokenFactory::default_for_testing();
    let attestor = StubZkAttestor::new();
    let verifier = StubZkLocalVerifier::new();
    let executor = LoggingExecutorAdapter::new();

    // State
    let state_provider =
        SimpleStateProvider::new(HashMap::from([("balance".into(), Value::UInt(1000))]));
    let state = state_provider.snapshot().unwrap();

    // Candidates
    let candidates = vec![
        CandidateAction {
            action_type: "LOW_SCORE".into(),
            params: HashMap::new(),
            score: Score(10),
            candidate_hash: dummy_hash(2),
        },
        CandidateAction {
            action_type: "HIGH_SCORE".into(),
            params: HashMap::new(),
            score: Score(100),
            candidate_hash: dummy_hash(3),
        },
    ];

    // Evaluate
    let verdicts = policy_engine
        .evaluate(&policy_hash, &state, &candidates)
        .unwrap();

    // Select
    let decision = selector
        .select(&policy_hash, &state, &candidates, &verdicts)
        .unwrap();

    // Verify selector chose high score
    assert_eq!(decision.chosen_index, 1);
    assert_eq!(decision.chosen_action.action_type, "HIGH_SCORE");

    // Create token
    let token = token_factory.create(&decision, &state).unwrap();

    // Attest
    let proof = attestor.attest(&decision, &state, &candidates).unwrap();

    // Verify
    let status = verifier.verify(&token, &proof);
    assert_eq!(status, VerificationStatus::Success);

    // Execute
    let result = executor.execute(&token, &proof).unwrap();
    assert!(result.success);

    // Verify log
    let log = executor.get_log();
    assert_eq!(log.len(), 1);
}

// =============================================================================
// E2E Test: Risk Threshold Policy
// =============================================================================

#[test]
fn e2e_risk_threshold_blocks_high_risk() {
    let policy_hash = dummy_hash(10);
    let policy_engine = RiskThresholdPolicyEngine { max_risk: 50 };
    let selector = DefaultSelector;

    let state = StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::new(),
        state_hash: dummy_hash(11),
    };

    // Two candidates: one safe, one risky
    let candidates = vec![
        CandidateAction {
            action_type: "RISKY".into(),
            params: HashMap::from([("risk".into(), Value::Int(100))]),
            score: Score(1000), // High score but too risky
            candidate_hash: dummy_hash(12),
        },
        CandidateAction {
            action_type: "SAFE".into(),
            params: HashMap::from([("risk".into(), Value::Int(10))]),
            score: Score(50),
            candidate_hash: dummy_hash(13),
        },
    ];

    // Evaluate
    let verdicts = policy_engine
        .evaluate(&policy_hash, &state, &candidates)
        .unwrap();

    // First should be denied, second allowed
    assert!(!verdicts[0].allowed);
    assert!(verdicts[1].allowed);

    // Select should pick the safe one (only allowed option)
    let decision = selector
        .select(&policy_hash, &state, &candidates, &verdicts)
        .unwrap();

    assert_eq!(decision.chosen_index, 1);
    assert_eq!(decision.chosen_action.action_type, "SAFE");
}

// =============================================================================
// E2E Test: Cryptographic Token Verification
// =============================================================================

#[test]
fn e2e_crypto_tokens_verify_correctly() {
    let policy_hash = dummy_hash(20);
    let selector = DefaultSelector;

    // Production crypto factory
    let token_factory = CryptoDecisionTokenFactory::generate();
    let verifying_key = token_factory.verifying_key();

    let state = StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::new(),
        state_hash: dummy_hash(21),
    };

    let candidates = vec![CandidateAction {
        action_type: "ACTION".into(),
        params: HashMap::new(),
        score: Score(100),
        candidate_hash: dummy_hash(22),
    }];

    let verdicts = vec![RuleVerdict {
        allowed: true,
        reasons: vec![],
        limits: HashMap::new(),
    }];

    let decision = selector
        .select(&policy_hash, &state, &candidates, &verdicts)
        .unwrap();
    let token = token_factory.create(&decision, &state).unwrap();

    // Verify signature
    let verify_result = verifying_key.verify_token(&token, &token.signature);
    assert!(verify_result.is_ok());
}

// =============================================================================
// E2E Test: Signature Verification Blocks Wrong Key
// =============================================================================

#[test]
fn e2e_wrong_key_signature_rejected() {
    let policy_hash = dummy_hash(30);
    let selector = DefaultSelector;

    // Create token with one key
    let token_factory = CryptoDecisionTokenFactory::generate();

    // Verify with different key
    let wrong_factory = CryptoDecisionTokenFactory::generate();
    let wrong_verifying_key = wrong_factory.verifying_key();

    let state = StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::new(),
        state_hash: dummy_hash(31),
    };

    let candidates = vec![CandidateAction {
        action_type: "ACTION".into(),
        params: HashMap::new(),
        score: Score(100),
        candidate_hash: dummy_hash(32),
    }];

    let verdicts = vec![RuleVerdict {
        allowed: true,
        reasons: vec![],
        limits: HashMap::new(),
    }];

    let decision = selector
        .select(&policy_hash, &state, &candidates, &verdicts)
        .unwrap();
    let token = token_factory.create(&decision, &state).unwrap();

    // Verify with wrong key should fail
    let verify_result = wrong_verifying_key.verify_token(&token, &token.signature);
    assert!(verify_result.is_err());
}

// =============================================================================
// E2E Test: Anti-Replay Protection
// =============================================================================

#[test]
fn e2e_anti_replay_blocks_duplicate_nonce() {
    let config = AntiReplayConfig {
        max_token_age_ms: 60_000,   // 60 second window
        nonce_retention_ms: 10_000, // 10 second retention window for this test
        max_future_skew_ms: 1_000,  // 1 second future tolerance
        max_tracked_nonces: 1_000,
    };
    let tracker = InMemoryNonceTracker::with_config(config);

    let token = DecisionToken {
        policy_hash: dummy_hash(40),
        state_hash: dummy_hash(41),
        chosen_action_hash: dummy_hash(42),
        nonce_or_tx_hash: dummy_hash(43),
        timestamp_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64,
        signature: vec![1, 2, 3],
    };

    // First validation should pass
    let result1 = tracker.validate(&token);
    assert!(result1.is_ok());

    // Mark as used to simulate a successful execution
    tracker.mark_used(&token).unwrap();

    // Second validation with same nonce should fail
    let result2 = tracker.validate(&token);
    assert!(result2.is_err());
}

// =============================================================================
// E2E Test: No Allowed Candidates
// =============================================================================

#[test]
fn e2e_no_allowed_candidates_returns_error() {
    let policy_hash = dummy_hash(50);
    let policy_engine = RiskThresholdPolicyEngine { max_risk: 0 }; // Deny everything
    let selector = DefaultSelector;

    let state = StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::new(),
        state_hash: dummy_hash(51),
    };

    let candidates = vec![CandidateAction {
        action_type: "RISKY".into(),
        params: HashMap::from([("risk".into(), Value::Int(100))]),
        score: Score(100),
        candidate_hash: dummy_hash(52),
    }];

    let verdicts = policy_engine
        .evaluate(&policy_hash, &state, &candidates)
        .unwrap();

    // All denied
    assert!(verdicts.iter().all(|v| !v.allowed));

    // Selection should fail
    let result = selector.select(&policy_hash, &state, &candidates, &verdicts);
    assert!(result.is_err());
}

// =============================================================================
// E2E Test: Full Pipeline with Signature Verification
// =============================================================================

#[test]
fn e2e_full_pipeline_with_signature_verification() {
    let policy_hash = dummy_hash(60);
    let policy_engine = AllowAllPolicyEngine;
    let selector = DefaultSelector;

    let token_factory = CryptoDecisionTokenFactory::generate();
    let verifying_key = token_factory.verifying_key();

    let attestor = StubZkAttestor::new();
    let verifier = StubZkLocalVerifier::new();

    // Executor with signature verification
    let inner_executor = LoggingExecutorAdapter::new();
    let executor = SignatureVerifyingExecutor::new(inner_executor, verifying_key);

    let state = StateSnapshot {
        fields: HashMap::from([("user_id".into(), Value::String("alice".into()))]),
        policy_inputs: HashMap::new(),
        state_hash: dummy_hash(61),
    };

    let candidates = vec![CandidateAction {
        action_type: "TRANSFER".into(),
        params: HashMap::from([
            ("amount".into(), Value::UInt(100)),
            ("to".into(), Value::String("bob".into())),
        ]),
        score: Score(100),
        candidate_hash: dummy_hash(62),
    }];

    // Full pipeline
    let verdicts = policy_engine
        .evaluate(&policy_hash, &state, &candidates)
        .unwrap();
    let decision = selector
        .select(&policy_hash, &state, &candidates, &verdicts)
        .unwrap();
    let token = token_factory.create(&decision, &state).unwrap();
    let proof = attestor.attest(&decision, &state, &candidates).unwrap();

    // Verify ZK
    assert_eq!(verifier.verify(&token, &proof), VerificationStatus::Success);

    // Execute with signature check
    let result = executor.execute(&token, &proof).unwrap();
    assert!(result.success);
}
