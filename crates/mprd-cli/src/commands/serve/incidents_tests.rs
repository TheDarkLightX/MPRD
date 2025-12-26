use super::{build_incidents, normalize_incident_message, AppState};
use crate::operator::api as op_api;
use crate::operator::store::OperatorStore;
use std::sync::{Arc, RwLock};

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

fn alert(id: &str, ts: i64, msg: &str) -> op_api::Alert {
    op_api::Alert {
        id: id.into(),
        timestamp: ts,
        severity: op_api::AlertSeverity::Warning,
        alert_type: op_api::AlertType::ExecutionError,
        message: msg.into(),
        decision_id: None,
        acknowledged: false,
    }
}

#[test]
fn normalize_incident_message_preserves_non_hex_distinctions() {
    let a = normalize_incident_message("network down");
    let b = normalize_incident_message("disk full");
    assert_ne!(a, b);
}

#[test]
fn normalize_incident_message_does_not_treat_plain_zero_as_0x_prefix() {
    let out = normalize_incident_message("status 0 ok");
    assert_eq!(out, "status 0 ok");
    assert!(!out.contains("0x…"));
}

#[test]
fn build_incidents_does_not_collapse_unrelated_messages() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);

    let alerts = vec![
        alert("a1", 1_000, "network down"),
        alert("a2", 2_000, "disk full"),
    ];

    let incidents = build_incidents(&state, alerts, true);
    assert_eq!(incidents.len(), 2);
}

#[test]
fn build_incidents_flapping_window_is_ten_minutes() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let state = test_state(&tmp);

    let within = vec![
        alert("a1", 0, "err 0xaaa"),
        alert("a2", 100, "err 0xbbb"),
        alert("a3", 10 * 60 * 1000, "err 0xccc"),
    ];
    let incidents = build_incidents(&state, within, true);
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0].0.flapping, Some(true));

    let over = vec![
        alert("b1", 0, "err 0xaaa"),
        alert("b2", 100, "err 0xbbb"),
        alert("b3", 10 * 60 * 1000 + 1, "err 0xccc"),
    ];
    let incidents2 = build_incidents(&state, over, true);
    assert_eq!(incidents2.len(), 1);
    assert_eq!(incidents2[0].0.flapping, Some(false));
}
