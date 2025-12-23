//! End-to-end acceptance tests: executor runs only after verification success.

use mprd_core::components::{LoggingExecutorAdapter, SimpleProposer, SimpleStateProvider};
use mprd_core::orchestrator::{run_once, RunOnceInputs};
use mprd_core::{
    DefaultSelector, Hash32, PolicyEngine, PolicyHash, Result, RuleVerdict, StateSnapshot, Value,
};
use mprd_risc0_methods::{MPRD_GUEST_ELF, MPRD_GUEST_ID, MPRD_MPB_GUEST_ELF, MPRD_MPB_GUEST_ID};
use mprd_zk::modes_v2::{
    ModeConfig, RobustMpbAttestor, RobustMpbVerifier, RobustRisc0Attestor, RobustRisc0Verifier,
};
use mprd_zk::risc0_host::MpbPolicyArtifactV1;
use std::collections::HashMap;
use std::sync::Arc;

struct AllowAllPolicyEngine;

impl PolicyEngine for AllowAllPolicyEngine {
    fn evaluate(
        &self,
        _policy_hash: &PolicyHash,
        _state: &StateSnapshot,
        candidates: &[mprd_core::CandidateAction],
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

fn dummy_hash(byte: u8) -> Hash32 {
    Hash32([byte; 32])
}

fn dummy_policy_ref() -> mprd_core::PolicyRef {
    mprd_core::PolicyRef {
        policy_epoch: 1,
        registry_root: dummy_hash(99),
    }
}

fn should_skip_due_to_missing_risc0_methods() -> bool {
    if !MPRD_MPB_GUEST_ELF.is_empty() && !MPRD_GUEST_ELF.is_empty() {
        return false;
    }
    eprintln!("Skipping: Risc0 guest ELF(s) are empty (methods not embedded)");
    true
}

fn should_skip_due_to_r0vm_mismatch(err: &dyn std::fmt::Display) -> bool {
    let msg = err.to_string();
    msg.contains("r0vm server") && msg.contains("risc0-zkvm") && msg.contains("not compatible")
}

#[test]
fn b_full_executor_does_not_run_on_verification_failure() {
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

    let mut image_id = [0u8; 32];
    for (i, word) in MPRD_MPB_GUEST_ID.iter().enumerate() {
        image_id[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    let mut store: HashMap<mprd_core::PolicyHash, MpbPolicyArtifactV1> = HashMap::new();
    store.insert(
        policy_hash.clone(),
        MpbPolicyArtifactV1 {
            bytecode: policy_bytecode,
            variables: vec![],
        },
    );
    let provider = Arc::new(store) as Arc<dyn mprd_zk::MpbPolicyProvider>;

    let attestor_cfg = ModeConfig::mode_b_full(image_id);
    let attestor = RobustRisc0Attestor::new(attestor_cfg, Some(MPRD_MPB_GUEST_ELF), Some(provider))
        .expect("attestor");

    // Wrong image id => verification must fail (and executor must not run).
    let mut wrong_image_id = image_id;
    wrong_image_id[0] ^= 1;
    let verifier_cfg = ModeConfig::mode_b_full(wrong_image_id);
    let verifier = RobustRisc0Verifier::new(verifier_cfg).expect("verifier");

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

    assert!(result.is_err(), "expected verification failure");
    assert_eq!(executor.get_log().len(), 0, "no side effects on failure");
}

#[test]
fn b_lite_executor_does_not_run_on_verification_failure() {
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
    let attestor = RobustMpbAttestor::new(attestor_cfg).expect("attestor");

    // Wrong fuel limit => verifier must fail.
    let mut verifier_cfg = ModeConfig::mode_b_lite();
    verifier_cfg.mpb_max_fuel = 123;
    let verifier = RobustMpbVerifier::new(verifier_cfg).expect("verifier");

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

    assert!(result.is_err(), "expected verification failure");
    assert_eq!(executor.get_log().len(), 0, "no side effects on failure");
}

struct AlwaysFailVerifier;

impl mprd_core::ZkLocalVerifier for AlwaysFailVerifier {
    fn verify(
        &self,
        _token: &mprd_core::DecisionToken,
        _proof: &mprd_core::ProofBundle,
    ) -> mprd_core::VerificationStatus {
        mprd_core::VerificationStatus::Failure("forced failure".into())
    }
}

#[test]
fn mode_a_executor_does_not_run_when_verifier_fails() {
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
    let attestor = mprd_core::components::StubZkAttestor::new();
    let verifier = AlwaysFailVerifier;
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

    assert!(result.is_err(), "expected verification failure");
    assert_eq!(executor.get_log().len(), 0, "no side effects on failure");
}

#[test]
fn mode_c_executor_does_not_run_on_verification_failure() {
    if should_skip_due_to_missing_risc0_methods() {
        return;
    }

    // Convert Risc0 digest ([u32; 8]) to [u8; 32].
    let mut image_id = [0u8; 32];
    for (i, word) in MPRD_GUEST_ID.iter().enumerate() {
        image_id[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
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
    let policy_hash = dummy_hash(7);
    let token_factory = mprd_core::components::SignedDecisionTokenFactory::default_for_testing();

    let config = ModeConfig::mode_c(image_id, "test-key");
    let encryption_config = mprd_zk::modes_v2::EncryptionConfig {
        master_key: Some([42u8; 32]),
        ..Default::default()
    };
    let attestor = mprd_zk::modes_v2::RobustPrivateAttestor::new(config.clone(), encryption_config)
        .expect("attestor");

    // Wrong key_id expected by the verifier => fail closed.
    let mut bad_verifier_cfg = config.clone();
    bad_verifier_cfg.encryption_key_id = Some("different-key".into());
    let verifier =
        mprd_zk::modes_v2::RobustPrivateVerifier::new(bad_verifier_cfg).expect("verifier");

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

    assert!(result.is_err(), "expected verification failure");
    assert_eq!(executor.get_log().len(), 0, "no side effects on failure");
}
