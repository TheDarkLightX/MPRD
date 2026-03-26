use super::{build_app, AppState, SignedRegistryExecutionReadyBridge};
use crate::operator::api as op_api;
use crate::operator::auth::ApiKeyConfig;
use crate::operator::store::OperatorStore;
use crate::test_support::EnvGuard;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use mprd_core::orchestrator::ExecutionReadyBridge;
use mprd_core::{
    CandidateAction, Decision, DecisionToken, Hash32, PolicyRef, ProofBundle, RuleVerdict, Score,
    StateProvider, StateRef, StateSnapshot, VerificationStatus, ZkAttestor, ZkLocalVerifier,
};
use mprd_risc0_shared::{policy_exec_kind_mpb_id_v1, policy_exec_version_id_v1};
use mprd_zk::manifest::{GuestImageEntryV1, GuestImageManifestV1};
use mprd_zk::registry_state::{AuthorizedPolicyV1, RegistryStateV1, SignedRegistryStateV1};
use mprd_zk::{ModeConfig, RobustMpbAttestor};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tower::ServiceExt;

fn test_state(tmp: &tempfile::TempDir) -> AppState {
    let policy_dir = tmp.path().join("policies");
    std::fs::create_dir_all(&policy_dir).expect("policy dir");

    let store_dir = tmp.path().join("store");
    let store = OperatorStore::new(&store_dir).expect("store");

    let (live_tx, _live_rx) = tokio::sync::broadcast::channel::<String>(16);

    AppState {
        store,
        store_dir,
        policy_dir,
        insecure_demo: false,
        live_tx,
        config: super::super::MprdConfigFile::default(),
        cegis_metrics: Arc::new(RwLock::new(mprd_core::cegis::ProposerMetrics::default())),
    }
}

fn sample_mpb_lite_decision_inputs() -> (
    DecisionToken,
    ProofBundle,
    StateSnapshot,
    Vec<CandidateAction>,
    Vec<RuleVerdict>,
    Decision,
) {
    let policy_bytecode = mprd_core::mpb::BytecodeBuilder::new()
        .push_i64(1)
        .halt()
        .build();
    let policy_hash = mprd_zk::mpb_lite::policy_hash_from_artifact_v1(&policy_bytecode, &[]);

    let mut cfg = ModeConfig::mode_b_lite();
    cfg.mpb_policy_bytecode = Some(policy_bytecode);
    cfg.mpb_policy_variables = Some(vec![]);
    let attestor = RobustMpbAttestor::new(cfg).expect("attestor");

    let state = StateSnapshot {
        fields: HashMap::new(),
        policy_inputs: HashMap::new(),
        state_hash: mprd_core::hash::hash_state(&StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: Hash32([0u8; 32]),
            state_ref: StateRef::unknown(),
        }),
        state_ref: StateRef::unknown(),
    };

    let mut candidate = CandidateAction {
        action_type: "TEST".into(),
        params: HashMap::new(),
        score: Score(10),
        candidate_hash: Hash32([0u8; 32]),
    };
    candidate.candidate_hash = mprd_core::hash::hash_candidate(&candidate);
    let candidates = vec![candidate.clone()];

    let decision = Decision {
        chosen_index: 0,
        chosen_action: candidate,
        policy_hash,
        decision_commitment: Hash32([4u8; 32]),
    };

    let token = DecisionToken {
        policy_hash,
        policy_ref: PolicyRef {
            policy_epoch: 1,
            registry_root: Hash32([9u8; 32]),
        },
        state_hash: state.state_hash,
        state_ref: state.state_ref.clone(),
        chosen_action_hash: decision.chosen_action.candidate_hash,
        nonce_or_tx_hash: Hash32([10u8; 32]),
        timestamp_ms: 1,
        signature: vec![],
    };

    let proof = attestor
        .attest(&token, &decision, &state, &candidates)
        .expect("mpb-lite proof");
    let verdicts = vec![RuleVerdict {
        allowed: true,
        reasons: vec![],
        limits: HashMap::new(),
    }];

    (token, proof, state, candidates, verdicts, decision)
}

fn sample_signed_registry_bridge() -> SignedRegistryExecutionReadyBridge {
    let key = mprd_core::crypto::TokenSigningKey::from_seed(&[41u8; 32]);
    let vk = key.verifying_key();
    let manifest = GuestImageManifestV1::sign(
        &key,
        123,
        vec![GuestImageEntryV1 {
            policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            image_id: [7u8; 32],
        }],
    )
    .expect("manifest");
    let state = RegistryStateV1 {
        policy_epoch: 1,
        registry_root: Hash32([9u8; 32]),
        authorized_policies: vec![AuthorizedPolicyV1 {
            policy_hash: Hash32([3u8; 32]),
            policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            policy_source_kind_id: None,
            policy_source_hash: None,
        }],
        guest_image_manifest: manifest,
    };
    SignedRegistryExecutionReadyBridge {
        signed_registry_state: SignedRegistryStateV1::sign(&key, 456, state).expect("sign"),
        registry_state_verifying_key: vk.clone(),
        manifest_verifying_key: vk,
    }
}

struct AcceptingVerifier;

impl ZkLocalVerifier for AcceptingVerifier {
    fn verify(&self, _token: &DecisionToken, _proof: &ProofBundle) -> VerificationStatus {
        VerificationStatus::Success
    }
}

async fn read_json<T: DeserializeOwned>(res: axum::http::Response<Body>) -> T {
    let bytes = axum::body::to_bytes(res.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("json")
}

fn write_pending_http_barrier(
    root: &std::path::Path,
    policy_hash_hex: &str,
    idempotency_key_v1: &str,
    timestamp_ms: i64,
) -> std::path::PathBuf {
    let policy_dir = root.join(policy_hash_hex);
    std::fs::create_dir_all(&policy_dir).expect("policy dir");
    let path = policy_dir.join(format!("{idempotency_key_v1}.pending.json"));
    let payload = serde_json::json!({
        "idempotency_key_v1": idempotency_key_v1,
        "policy_hash": policy_hash_hex,
        "state_hash": format!("{:064x}", 0x22),
        "action_hash": format!("{:064x}", 0x33),
        "nonce_or_tx_hash": format!("{:064x}", 0x44),
        "timestamp_ms": timestamp_ms,
    });
    std::fs::write(&path, serde_json::to_vec(&payload).expect("payload")).expect("write barrier");
    path
}

fn write_committed_http_barrier(
    root: &std::path::Path,
    policy_hash_hex: &str,
    idempotency_key_v1: &str,
    timestamp_ms: i64,
) -> std::path::PathBuf {
    let policy_dir = root.join(policy_hash_hex);
    std::fs::create_dir_all(&policy_dir).expect("policy dir");
    let path = policy_dir.join(format!("{idempotency_key_v1}.committed.json"));
    let payload = serde_json::json!({
        "idempotency_key_v1": idempotency_key_v1,
        "policy_hash": policy_hash_hex,
        "state_hash": format!("{:064x}", 0x55),
        "action_hash": format!("{:064x}", 0x66),
        "nonce_or_tx_hash": format!("{:064x}", 0x77),
        "timestamp_ms": timestamp_ms,
    });
    std::fs::write(&path, serde_json::to_vec(&payload).expect("payload")).expect("write barrier");
    path
}

fn write_simple_decision(
    store: &OperatorStore,
    timestamp_ms: i64,
    allowed: bool,
    execution_success: Option<bool>,
) -> String {
    write_simple_decision_with_policy(
        store,
        timestamp_ms,
        Hash32([1u8; 32]),
        allowed,
        execution_success,
    )
}

fn write_simple_decision_with_policy(
    store: &OperatorStore,
    timestamp_ms: i64,
    policy_hash: Hash32,
    allowed: bool,
    execution_success: Option<bool>,
) -> String {
    let state_hash = Hash32([2u8; 32]);
    let chosen_action_hash = Hash32([3u8; 32]);
    let nonce_or_tx_hash = Hash32([4u8; 32]);

    let token = DecisionToken {
        policy_hash,
        policy_ref: PolicyRef {
            policy_epoch: 1,
            registry_root: Hash32([9u8; 32]),
        },
        state_hash,
        state_ref: StateRef::unknown(),
        chosen_action_hash,
        nonce_or_tx_hash,
        timestamp_ms,
        signature: vec![],
    };

    let candidate = CandidateAction {
        action_type: "X".into(),
        params: std::collections::HashMap::new(),
        score: Score(0),
        candidate_hash: Hash32([5u8; 32]),
    };

    let decision = Decision {
        chosen_index: 0,
        chosen_action: candidate.clone(),
        policy_hash,
        decision_commitment: Hash32([6u8; 32]),
    };

    let verdicts = vec![RuleVerdict {
        allowed,
        reasons: vec![],
        limits: std::collections::HashMap::new(),
    }];

    let state = StateSnapshot {
        fields: std::collections::HashMap::new(),
        policy_inputs: std::collections::HashMap::new(),
        state_hash,
        state_ref: StateRef::unknown(),
    };

    let proof = ProofBundle {
        policy_hash,
        state_hash,
        candidate_set_hash: Hash32([7u8; 32]),
        chosen_action_hash,
        limits_hash: Hash32([8u8; 32]),
        limits_bytes: vec![],
        chosen_action_preimage: vec![],
        risc0_receipt: vec![],
        attestation_metadata: std::collections::HashMap::new(),
    };

    let id = store
        .write_verified_decision(&token, &proof, &state, &[candidate], &verdicts, &decision)
        .expect("write decision");

    if let Some(success) = execution_success {
        let _ = store.write_execution_result(
            &id,
            success,
            None,
            "test".into(),
            if success { 1 } else { 2 },
        );
    }

    id
}

#[tokio::test]
async fn health_is_unauthed_even_when_api_key_enabled() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let app = build_app(
        state,
        ApiKeyConfig {
            api_key: Some("secret".into()),
        },
    );

    let res = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[test]
fn signed_registry_ready_bridge_rejects_unvalidated_governance_witness() {
    let bridge = sample_signed_registry_bridge();
    let (token, proof, state, _candidates, _verdicts, _decision) =
        sample_mpb_lite_decision_inputs();
    let governance = mprd_core::governance_admission_witness_from_fields_v1(
        mprd_core::GovernanceUpdateKindV1::PolicyTweak,
        true,
        false,
        true,
    )
    .expect("governance witness");

    let verified =
        mprd_core::verify_for_execution(&AcceptingVerifier, &token, &proof).expect("verified");

    let err = bridge
        .prepare_execution_ready(verified, &state, Some(governance))
        .expect_err("governance witness must fail closed without concrete gate input");

    assert!(
        err.to_string()
            .contains("requires a concrete governance gate packet"),
        "unexpected error: {err}"
    );
}

#[test]
fn production_request_state_is_rejected() {
    let err = super::require_no_request_state_in_production(Some(&HashMap::new()))
        .expect_err("production path must reject caller-supplied state");
    assert!(
        err.to_string()
            .contains("request-supplied state is demo-only"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_signed_state_provider_from_config_accepts_signed_snapshot() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let key = mprd_core::crypto::TokenSigningKey::from_seed(&[77u8; 32]);
    let vk = key.verifying_key();
    let snapshot_path = tmp.path().join("signed_state.json");
    let signed = mprd_core::state_provenance::SignedStateSnapshotV1::sign(
        &key,
        42,
        HashMap::from([("balance".into(), mprd_core::Value::UInt(100))]),
        HashMap::new(),
    )
    .expect("sign snapshot");
    std::fs::write(
        &snapshot_path,
        serde_json::to_vec_pretty(&signed).expect("serialize snapshot"),
    )
    .expect("write snapshot");

    let mut config = super::super::MprdConfigFile::default();
    config.state_snapshot_path = Some(snapshot_path);
    config.state_verifying_key_hex = Some(hex::encode(vk.to_bytes()));

    let provider =
        super::load_signed_state_provider_from_config(&config).expect("provider must load");
    let state = provider.snapshot().expect("provider snapshot");

    assert_eq!(
        state.state_ref.state_source_id,
        mprd_core::state_provenance::state_source_id_signed_snapshot_v1()
    );
    assert_eq!(state.state_ref.state_epoch, 42);
}

#[tokio::test]
async fn api_requires_key_when_configured() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let app = build_app(
        state,
        ApiKeyConfig {
            api_key: Some("secret".into()),
        },
    );

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn api_does_not_require_key_when_not_configured() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let app = build_app(state, ApiKeyConfig { api_key: None });

    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn api_status_reports_typed_idempotent_http_effect_barrier_summary() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut state = test_state(&tmp);
    let root = tmp.path().join("http_effects");
    write_pending_http_barrier(&root, "deadbeef", "stuck", 1);

    state.config.execution.executor_type = "idempotent_http".into();
    state.config.execution.http_url = Some("http://127.0.0.1:8080".into());
    state.config.execution.effect_journal_dir = Some(root.clone());

    let app = build_app(state, ApiKeyConfig { api_key: None });
    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body: op_api::SystemStatus = read_json(res).await;
    assert!(matches!(
        body.components.executor.status,
        op_api::HealthLevel::Degraded
    ));
    let summary = body
        .components
        .executor
        .effect_barrier_summary
        .expect("typed effect barrier summary");
    assert_eq!(summary.pending_entries, 1);
    assert_eq!(summary.committed_entries, 0);
    assert_eq!(
        summary.root_path.as_deref(),
        Some(root.to_str().expect("utf8 root"))
    );
}

#[tokio::test]
async fn api_pending_effect_barriers_returns_sorted_http_pending_entries() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut state = test_state(&tmp);
    let root = tmp.path().join("http_effects");
    let older = write_pending_http_barrier(&root, "bbbb", "older", 10);
    let newer = write_pending_http_barrier(&root, "aaaa", "newer", 20);

    state.config.execution.executor_type = "idempotent_http".into();
    state.config.execution.http_url = Some("http://127.0.0.1:8080".into());
    state.config.execution.effect_journal_dir = Some(root);

    let app = build_app(state, ApiKeyConfig { api_key: None });
    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/effect-barriers/pending")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body: Vec<op_api::PendingEffectBarrier> = read_json(res).await;
    assert_eq!(body.len(), 2);
    assert_eq!(body[0].idempotency_key_v1, "newer");
    assert_eq!(body[0].timestamp_ms, 20);
    assert_eq!(body[0].barrier_path, newer.display().to_string());
    assert_eq!(body[1].idempotency_key_v1, "older");
    assert_eq!(body[1].timestamp_ms, 10);
    assert_eq!(body[1].barrier_path, older.display().to_string());
}

#[tokio::test]
async fn api_committed_effect_barriers_returns_sorted_http_committed_entries() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut state = test_state(&tmp);
    let root = tmp.path().join("http_effects");
    let older = write_committed_http_barrier(&root, "cccc", "older-committed", 30);
    let newer = write_committed_http_barrier(&root, "aaaa", "newer-committed", 40);
    state.config.execution.executor_type = "idempotent_http".into();
    state.config.execution.http_url = Some("http://127.0.0.1:8080".into());
    state.config.execution.effect_journal_dir = Some(root.clone());
    let app = build_app(state, ApiKeyConfig { api_key: None });

    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/effect-barriers/committed")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Vec<op_api::CommittedEffectBarrier> = read_json(res).await;
    assert_eq!(body.len(), 2);
    assert_eq!(body[0].barrier_path, newer.display().to_string());
    assert_eq!(body[0].policy_hash, "aaaa");
    assert_eq!(body[0].idempotency_key_v1, "newer-committed");
    assert_eq!(body[0].timestamp_ms, 40);
    assert_eq!(body[1].barrier_path, older.display().to_string());
    assert_eq!(body[1].policy_hash, "cccc");
    assert_eq!(body[1].idempotency_key_v1, "older-committed");
    assert_eq!(body[1].timestamp_ms, 30);
}

#[tokio::test]
async fn api_resolve_pending_effect_barrier_dry_run_leaves_file_in_place() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut state = test_state(&tmp);
    let root = tmp.path().join("http_effects");
    let barrier = write_pending_http_barrier(
        &root,
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        1234,
    );

    state.config.execution.executor_type = "idempotent_http".into();
    state.config.execution.http_url = Some("http://127.0.0.1:8080".into());
    state.config.execution.effect_journal_dir = Some(root);

    let app = build_app(state, ApiKeyConfig { api_key: None });
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/effect-barriers/pending/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/resolve")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&op_api::ResolvePendingEffectBarrierRequest {
                        resolution: op_api::PendingEffectBarrierResolution::Clear,
                        dry_run: true,
                    })
                    .expect("request body"),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body: op_api::ResolvePendingEffectBarrierResult = read_json(res).await;
    assert!(body.success);
    assert!(body.dry_run);
    assert_eq!(body.barrier.barrier_path, barrier.display().to_string());
    assert!(barrier.exists(), "dry run must not remove barrier");
}

#[tokio::test]
async fn api_resolve_pending_effect_barrier_promotes_to_committed() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut state = test_state(&tmp);
    let root = tmp.path().join("http_effects");
    let barrier = write_pending_http_barrier(
        &root,
        "feedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        5678,
    );
    let committed = root
        .join("feedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed")
        .join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.committed.json");

    state.config.execution.executor_type = "idempotent_http".into();
    state.config.execution.http_url = Some("http://127.0.0.1:8080".into());
    state.config.execution.effect_journal_dir = Some(root.clone());

    let app = build_app(state, ApiKeyConfig { api_key: None });
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/effect-barriers/pending/feedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/resolve")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&op_api::ResolvePendingEffectBarrierRequest {
                        resolution: op_api::PendingEffectBarrierResolution::PromoteToCommitted,
                        dry_run: false,
                    })
                    .expect("request body"),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body: op_api::ResolvePendingEffectBarrierResult = read_json(res).await;
    assert!(body.success);
    assert!(!body.dry_run);
    assert_eq!(
        body.committed_barrier_path.as_deref(),
        Some(committed.to_str().expect("utf8 path"))
    );
    assert!(!barrier.exists(), "pending barrier must be removed");
    assert!(committed.exists(), "committed barrier must exist");

    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/effect-barriers/pending")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let pending: Vec<op_api::PendingEffectBarrier> = read_json(res).await;
    assert!(
        pending.is_empty(),
        "pending inventory must be empty after promote"
    );
}

#[tokio::test]
async fn api_alerts_include_unresolved_pending_http_barriers() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut state = test_state(&tmp);
    let root = tmp.path().join("http_effects");
    let barrier = write_pending_http_barrier(&root, "deadbeef", "pending-alert", 1234);

    state.config.mode = "trustless".into();
    state.config.execution.executor_type = "idempotent_http".into();
    state.config.execution.http_url = Some("http://127.0.0.1:8080".into());
    state.config.execution.effect_journal_dir = Some(root);

    let app = build_app(state, ApiKeyConfig { api_key: None });
    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body: Vec<op_api::Alert> = read_json(res).await;
    let alert = body
        .into_iter()
        .find(|alert| alert.id == "pending_http_effect_barrier:pending-alert")
        .expect("pending barrier alert");
    assert!(matches!(alert.severity, op_api::AlertSeverity::Critical));
    assert!(matches!(alert.alert_type, op_api::AlertType::Anomaly));
    assert!(
        alert.message.contains(&barrier.display().to_string()),
        "unexpected message: {}",
        alert.message
    );
}

#[tokio::test]
async fn decision_blob_serves_receipt_derived_mpb_lite_chosen_preimage() {
    let _g = EnvGuard::set_many(&[("MPRD_OPERATOR_STORE_SENSITIVE", "1")]);
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let (token, proof, state_snapshot, candidates, verdicts, decision) =
        sample_mpb_lite_decision_inputs();
    let id = state
        .store
        .write_verified_decision(
            &token,
            &proof,
            &state_snapshot,
            &candidates,
            &verdicts,
            &decision,
        )
        .expect("write decision");
    assert!(!state
        .store_dir
        .join("decisions")
        .join(&id)
        .join("chosen_action_preimage.bin")
        .exists());

    let app = build_app(state, ApiKeyConfig { api_key: None });
    let res = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/decisions/{id}/blob/chosen_action_preimage.bin"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read body");
    assert_eq!(bytes.as_ref(), proof.chosen_action_preimage.as_slice());
}

#[tokio::test]
async fn decision_detail_reports_receipt_derived_chosen_preimage_storage() {
    let _g = EnvGuard::set_many(&[("MPRD_OPERATOR_STORE_SENSITIVE", "1")]);
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let (token, proof, state_snapshot, candidates, verdicts, decision) =
        sample_mpb_lite_decision_inputs();
    let id = state
        .store
        .write_verified_decision(
            &token,
            &proof,
            &state_snapshot,
            &candidates,
            &verdicts,
            &decision,
        )
        .expect("write decision");

    let app = build_app(state, ApiKeyConfig { api_key: None });
    let res = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/decisions/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = read_json(res).await;
    assert_eq!(
        body["proof"]["chosenActionPreimageStorage"],
        serde_json::Value::String("derived_from_receipt".into())
    );
}

#[tokio::test]
async fn decision_detail_reports_attestation_execution_and_ready_packet_hashes() {
    let _g = EnvGuard::set_many(&[("MPRD_OPERATOR_STORE_SENSITIVE", "1")]);
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let (token, mut proof, state_snapshot, candidates, verdicts, decision) =
        sample_mpb_lite_decision_inputs();
    let expected_registry_checkpoint_attestation_hash = hex::encode([0xcdu8; 32]);
    proof.attestation_metadata.insert(
        mprd_zk::registry_state::REGISTRY_AUTH_METADATA_CHECKPOINT_ATTESTATION_HASH_V1.into(),
        expected_registry_checkpoint_attestation_hash.clone(),
    );
    let expected_registry_authorization_hash = hex::encode([0xeeu8; 32]);
    proof.attestation_metadata.insert(
        mprd_zk::registry_state::REGISTRY_AUTH_METADATA_RESOLUTION_HASH_V1.into(),
        expected_registry_authorization_hash.clone(),
    );
    let expected_execution_authorization_hash = hex::encode([0xabu8; 32]);
    proof.attestation_metadata.insert(
        mprd_core::EXECUTION_AUTH_ATTESTATION_METADATA_HASH_V1.into(),
        expected_execution_authorization_hash.clone(),
    );
    let expected_execution_ready_packet_hash = hex::encode([0x44u8; 32]);
    let expected_execution_binding_vector_hash = hex::encode([0x54u8; 32]);
    let expected_execution_boundary_refinement_hash = hex::encode([0x55u8; 32]);
    proof
        .attestation_metadata
        .insert("custom_key".into(), "custom_value".into());
    let expected_attestation_metadata_hash = hex::encode(
        mprd_core::decision_log::attestation_metadata_hash_v1(&proof.attestation_metadata).0,
    );

    let id = state
        .store
        .write_verified_decision(
            &token,
            &proof,
            &state_snapshot,
            &candidates,
            &verdicts,
            &decision,
        )
        .expect("write decision");
    state
        .store
        .write_execution_ready_packet_hash(&id, &mprd_core::Hash32([0x44u8; 32]))
        .expect("write ready hash");
    state
        .store
        .write_execution_binding_vector_hash(&id, &mprd_core::Hash32([0x54u8; 32]))
        .expect("write binding hash");
    state
        .store
        .write_execution_boundary_refinement_hash(&id, &mprd_core::Hash32([0x55u8; 32]))
        .expect("write refinement hash");

    let app = build_app(state, ApiKeyConfig { api_key: None });
    let res = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/decisions/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: op_api::DecisionDetail = read_json(res).await;
    assert_eq!(
        body.proof.attestation_metadata_hash,
        expected_attestation_metadata_hash
    );
    assert_eq!(
        body.proof.execution_authorization_hash.as_deref(),
        Some(expected_execution_authorization_hash.as_str())
    );
    assert_eq!(
        body.proof.registry_checkpoint_attestation_hash.as_deref(),
        Some(expected_registry_checkpoint_attestation_hash.as_str())
    );
    assert_eq!(
        body.proof.registry_authorization_hash.as_deref(),
        Some(expected_registry_authorization_hash.as_str())
    );
    assert_eq!(
        body.proof.execution_ready_packet_hash.as_deref(),
        Some(expected_execution_ready_packet_hash.as_str())
    );
    assert_eq!(
        body.proof.execution_binding_vector_hash.as_deref(),
        Some(expected_execution_binding_vector_hash.as_str())
    );
    assert_eq!(
        body.proof.execution_boundary_refinement_hash.as_deref(),
        Some(expected_execution_boundary_refinement_hash.as_str())
    );
}

#[tokio::test]
async fn decision_export_reports_receipt_derived_chosen_preimage_storage_and_url() {
    let _g = EnvGuard::set_many(&[("MPRD_OPERATOR_STORE_SENSITIVE", "1")]);
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let (token, proof, state_snapshot, candidates, verdicts, decision) =
        sample_mpb_lite_decision_inputs();
    let id = state
        .store
        .write_verified_decision(
            &token,
            &proof,
            &state_snapshot,
            &candidates,
            &verdicts,
            &decision,
        )
        .expect("write decision");

    let app = build_app(state, ApiKeyConfig { api_key: None });
    let res = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/decisions/{id}/export"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: op_api::DecisionExport = read_json(res).await;
    assert_eq!(
        body.chosen_action_preimage_storage,
        op_api::ChosenActionPreimageStorage::DerivedFromReceipt
    );
    let expected_url = format!("/api/decisions/{id}/blob/chosen_action_preimage.bin");
    assert_eq!(
        body.chosen_action_preimage_url.as_deref(),
        Some(expected_url.as_str())
    );
}

#[tokio::test]
async fn decision_export_reports_inline_chosen_preimage_storage_and_url() {
    let _g = EnvGuard::set_many(&[("MPRD_OPERATOR_STORE_SENSITIVE", "1")]);
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let id = write_simple_decision(&state.store, 1, true, None);

    let app = build_app(state, ApiKeyConfig { api_key: None });
    let res = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/decisions/{id}/export"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: op_api::DecisionExport = read_json(res).await;
    assert_eq!(
        body.chosen_action_preimage_storage,
        op_api::ChosenActionPreimageStorage::InlineBlob
    );
    let expected_url = format!("/api/decisions/{id}/blob/chosen_action_preimage.bin");
    assert_eq!(
        body.chosen_action_preimage_url.as_deref(),
        Some(expected_url.as_str())
    );
}

#[tokio::test]
async fn decision_export_omits_preimage_url_when_not_stored() {
    let _g = EnvGuard::set_many(&[("MPRD_OPERATOR_STORE_SENSITIVE", "0")]);
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let id = write_simple_decision(&state.store, 1, true, None);

    let app = build_app(state, ApiKeyConfig { api_key: None });
    let res = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/decisions/{id}/export"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: op_api::DecisionExport = read_json(res).await;
    assert_eq!(
        body.chosen_action_preimage_storage,
        op_api::ChosenActionPreimageStorage::NotStored
    );
    assert_eq!(body.chosen_action_preimage_url, None);
}

#[tokio::test]
async fn autopilot_state_defaults_and_transition_is_guarded_by_anchors() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let app = build_app(state, ApiKeyConfig { api_key: None });

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/autopilot")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: op_api::AutopilotState = read_json(res).await;
    assert!(matches!(body.mode, op_api::AutopilotMode::Manual));
    assert!(!body
        .can_transition_to
        .iter()
        .any(|m| matches!(m, op_api::AutopilotMode::Autopilot)));

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/autopilot/mode")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"mode":"autopilot"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/autopilot/mode")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"mode":"assisted"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: op_api::AutopilotState = read_json(res).await;
    assert!(matches!(body.mode, op_api::AutopilotMode::Assisted));
}

#[tokio::test]
async fn autopilot_ack_updates_timestamp() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let app = build_app(state, ApiKeyConfig { api_key: None });

    let before = {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/autopilot")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body: op_api::AutopilotState = read_json(res).await;
        body.last_human_ack
    };

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/autopilot/ack")
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: op_api::AutopilotState = read_json(res).await;
    assert!(body.last_human_ack >= before);
}

#[tokio::test]
async fn decisions_end_date_is_inclusive() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let store = state.store.clone();
    let app = build_app(state, ApiKeyConfig { api_key: None });

    let _newer = write_simple_decision(&store, 2_000, true, Some(true));
    let _older = write_simple_decision(&store, 1_000, true, Some(true));

    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/decisions?endDate=1000")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let out: op_api::PaginatedResponse<op_api::DecisionSummary> = read_json(res).await;
    assert_eq!(out.total, 1);
    assert_eq!(out.data[0].timestamp, 1_000);
}

#[tokio::test]
async fn decisions_filter_by_policy_hash() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let store = state.store.clone();
    let app = build_app(state, ApiKeyConfig { api_key: None });

    let want_policy = Hash32([9u8; 32]);
    let other_policy = Hash32([8u8; 32]);

    let _a = write_simple_decision_with_policy(&store, 1_000, want_policy, true, Some(true));
    let _b = write_simple_decision_with_policy(&store, 2_000, other_policy, true, Some(true));

    let want_hex = hex::encode(want_policy.0);
    let res = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/decisions?policyHash={want_hex}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let out: op_api::PaginatedResponse<op_api::DecisionSummary> = read_json(res).await;
    assert_eq!(out.total, 1);
    assert_eq!(out.data[0].policy_hash, want_hex);
}

#[tokio::test]
async fn decisions_list_reports_receipt_derived_chosen_preimage_storage() {
    let _g = EnvGuard::set_many(&[("MPRD_OPERATOR_STORE_SENSITIVE", "1")]);
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let app = build_app(state.clone(), ApiKeyConfig { api_key: None });
    let (token, proof, state_snapshot, candidates, verdicts, decision) =
        sample_mpb_lite_decision_inputs();
    state
        .store
        .write_verified_decision(
            &token,
            &proof,
            &state_snapshot,
            &candidates,
            &verdicts,
            &decision,
        )
        .expect("write decision");

    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/decisions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let out: op_api::PaginatedResponse<op_api::DecisionSummary> = read_json(res).await;
    assert_eq!(out.total, 1);
    assert_eq!(
        out.data[0].chosen_action_preimage_storage,
        Some(op_api::ChosenActionPreimageStorage::DerivedFromReceipt)
    );
}

#[tokio::test]
async fn decisions_list_reports_not_stored_chosen_preimage_storage() {
    let _g = EnvGuard::set_many(&[("MPRD_OPERATOR_STORE_SENSITIVE", "0")]);
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let store = state.store.clone();
    let app = build_app(state, ApiKeyConfig { api_key: None });
    let _id = write_simple_decision(&store, 1_000, true, Some(true));

    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/decisions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let out: op_api::PaginatedResponse<op_api::DecisionSummary> = read_json(res).await;
    assert_eq!(out.total, 1);
    assert_eq!(
        out.data[0].chosen_action_preimage_storage,
        Some(op_api::ChosenActionPreimageStorage::NotStored)
    );
}

#[tokio::test]
async fn settings_update_applies_when_only_one_field_is_present() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let store = state.store.clone();
    let app = build_app(state, ApiKeyConfig { api_key: None });

    let before = store.decision_max();
    let desired = if before == 0 { 100 } else { before + 1 };

    let body = serde_json::json!({ "decisionMax": desired }).to_string();
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/settings")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let out: op_api::OperatorSettings = read_json(res).await;
    assert!(matches!(
        out.deployment_mode,
        op_api::DeploymentMode::Trustless
    ));
    assert_eq!(out.decision_max, desired);
    assert_eq!(store.decision_max(), desired);
}

#[tokio::test]
async fn settings_report_state_trust_anchors_when_configured() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let registry_path = tmp.path().join("registry_state.json");
    let state_path = tmp.path().join("signed_state.json");
    std::fs::write(&registry_path, b"{}").expect("write registry");
    std::fs::write(&state_path, b"{}").expect("write state");

    let mut state = test_state(&tmp);
    state.config.registry_state_path = Some(registry_path);
    state.config.registry_verifying_key_hex = Some("00".into());
    state.config.state_snapshot_path = Some(state_path);
    state.config.state_verifying_key_hex = Some("11".into());

    let app = build_app(state, ApiKeyConfig { api_key: None });
    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let out: op_api::OperatorSettings = read_json(res).await;
    assert!(out.trust_anchors_configured);
    assert!(out.trust_anchors.registry_state_path.is_some());
    assert!(out.trust_anchors.state_snapshot_path.is_some());
    assert!(out.trust_anchors.registry_key_fingerprint.is_some());
    assert!(out.trust_anchors.state_key_fingerprint.is_some());
}

#[tokio::test]
async fn metrics_reflect_recent_decisions_and_success_rate() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let store = state.store.clone();
    let app = build_app(state, ApiKeyConfig { api_key: None });

    let now = super::now_ms();
    let _a = write_simple_decision(&store, now - 1, true, Some(true));
    let _b = write_simple_decision(&store, now - 2, false, Some(false));

    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let out: op_api::MetricsSummary = read_json(res).await;
    assert_eq!(out.decisions.total, 2);
    assert_eq!(out.decisions.allowed, 1);
    assert_eq!(out.decisions.denied, 1);
    assert_eq!(out.success_rate.value, 50.0);
}

#[tokio::test]
async fn cegis_metrics_endpoint_returns_defaults() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let app = build_app(state, ApiKeyConfig { api_key: None });

    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/cegis/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let out: op_api::CegisMetricsSummary = read_json(res).await;
    assert_eq!(out.proposals_total, 0);
    assert_eq!(out.proposals_valid, 0);
    assert_eq!(out.proposals_invalid, 0);
    assert_eq!(out.counterexamples_captured, 0);
    assert_eq!(out.time_to_first_valid_ms, None);
}

#[tokio::test]
async fn incident_snooze_ttl_is_capped_to_seven_days() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);
    let store = state.store.clone();
    let app = build_app(state, ApiKeyConfig { api_key: None });

    let start = super::now_ms();
    let req = serde_json::json!({ "ttlMs": 999_999_999_999u64 });
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/incidents/inc_test/snooze")
                .header("content-type", "application/json")
                .body(Body::from(req.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let out: op_api::SnoozeResult = read_json(res).await;
    let cap = (7u64 * 24 * 60 * 60 * 1000) as i64;
    let delta = out.snoozed_until - start;
    assert!(
        delta >= cap,
        "expected snooze to be capped near 7 days, got delta={delta}"
    );
    assert!(
        delta <= cap + 2_000,
        "expected snooze to be capped near 7 days, got delta={delta}"
    );

    assert!(store.incident_snoozed_until("inc_test").is_some());
}

#[tokio::test]
async fn live_socket_forwards_broadcast_messages() {
    struct TestSocket {
        outgoing: tokio::sync::mpsc::UnboundedSender<axum::extract::ws::Message>,
        incoming:
            tokio::sync::mpsc::UnboundedReceiver<Result<axum::extract::ws::Message, Infallible>>,
    }

    impl futures_util::Stream for TestSocket {
        type Item = Result<axum::extract::ws::Message, Infallible>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Pin::new(&mut self.incoming).poll_recv(cx)
        }
    }

    impl futures_util::Sink<axum::extract::ws::Message> for TestSocket {
        type Error = Infallible;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(
            self: Pin<&mut Self>,
            item: axum::extract::ws::Message,
        ) -> Result<(), Self::Error> {
            self.outgoing.send(item).expect("outgoing");
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
    let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
    let socket = TestSocket {
        outgoing: out_tx,
        incoming: in_rx,
    };

    let (live_tx, _) = tokio::sync::broadcast::channel::<String>(16);
    let live_rx = live_tx.subscribe();

    let task = tokio::spawn(super::live_socket(socket, live_rx));

    live_tx.send("hello".into()).expect("send");
    let msg = tokio::time::timeout(std::time::Duration::from_secs(1), out_rx.recv())
        .await
        .expect("timeout")
        .expect("msg");
    assert_eq!(msg.into_text().expect("text"), "hello");

    in_tx
        .send(Ok(axum::extract::ws::Message::Close(None)))
        .expect("close");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("task exit");
}
