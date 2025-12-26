use super::{build_app, AppState};
use crate::operator::api as op_api;
use crate::operator::auth::ApiKeyConfig;
use crate::operator::store::OperatorStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use mprd_core::{
    CandidateAction, Decision, DecisionToken, Hash32, PolicyRef, ProofBundle, RuleVerdict, Score,
    StateRef, StateSnapshot,
};
use serde::de::DeserializeOwned;
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

async fn read_json<T: DeserializeOwned>(res: axum::http::Response<Body>) -> T {
    let bytes = axum::body::to_bytes(res.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("json")
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
        policy_hash: policy_hash.clone(),
        policy_ref: PolicyRef {
            policy_epoch: 1,
            registry_root: Hash32([9u8; 32]),
        },
        state_hash: state_hash.clone(),
        state_ref: StateRef::unknown(),
        chosen_action_hash: chosen_action_hash.clone(),
        nonce_or_tx_hash: nonce_or_tx_hash.clone(),
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
        policy_hash: policy_hash.clone(),
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
        state_hash: state_hash.clone(),
        state_ref: StateRef::unknown(),
    };

    let proof = ProofBundle {
        policy_hash: policy_hash.clone(),
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

    let _a =
        write_simple_decision_with_policy(&store, 1_000, want_policy.clone(), true, Some(true));
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
