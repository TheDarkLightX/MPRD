use super::{
    compute_system_status, trust_anchors_configured_with, validate_retention_update,
    validate_serve_startup_config,
};
use crate::operator::api as op_api;

fn health(status: op_api::HealthLevel) -> op_api::ComponentHealth {
    op_api::ComponentHealth {
        status,
        version: None,
        last_check: 1,
        message: None,
    }
}

fn components(
    tau: op_api::HealthLevel,
    risc0: op_api::HealthLevel,
    executor: op_api::HealthLevel,
) -> op_api::SystemComponents {
    op_api::SystemComponents {
        tau: health(tau),
        ipfs: health(op_api::HealthLevel::Healthy),
        risc0: health(risc0),
        executor: health(executor),
    }
}

#[test]
fn trust_anchors_configured_requires_existing_path_and_decodable_key() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let registry_path = tmp.path().join("registry_state.json");
    let signed_state_path = tmp.path().join("signed_state.json");
    std::fs::write(&registry_path, b"{}").expect("write registry");
    std::fs::write(&signed_state_path, b"{}").expect("write state");

    assert!(!trust_anchors_configured_with(
        None,
        Some("00"),
        Some(signed_state_path.as_path()),
        Some("00")
    ));
    assert!(!trust_anchors_configured_with(
        Some(registry_path.as_path()),
        None,
        Some(signed_state_path.as_path()),
        Some("00")
    ));
    assert!(!trust_anchors_configured_with(
        Some(registry_path.as_path()),
        Some("not-hex"),
        Some(signed_state_path.as_path()),
        Some("00")
    ));
    assert!(!trust_anchors_configured_with(
        Some(registry_path.as_path()),
        Some("00"),
        None,
        Some("00")
    ));
    assert!(!trust_anchors_configured_with(
        Some(registry_path.as_path()),
        Some("00"),
        Some(signed_state_path.as_path()),
        Some("not-hex")
    ));
    assert!(trust_anchors_configured_with(
        Some(registry_path.as_path()),
        Some("00"),
        Some(signed_state_path.as_path()),
        Some("00")
    ));
}

#[test]
fn system_status_is_critical_when_trust_anchors_missing_in_trustless_mode() {
    let config = super::super::MprdConfigFile {
        mode: "trustless".into(),
        ..super::super::MprdConfigFile::default()
    };

    let now = 123;
    let out = compute_system_status(
        &config,
        now,
        components(
            op_api::HealthLevel::Healthy,
            op_api::HealthLevel::Healthy,
            op_api::HealthLevel::Healthy,
        ),
        false,
    );

    assert!(matches!(out.overall, op_api::OverallStatus::Critical));
    assert_eq!(
        out.components.risc0.message.as_deref(),
        Some("trust anchors missing (fail-closed)")
    );
    assert_eq!(out.components.risc0.last_check, now);
}

#[test]
fn system_status_is_degraded_when_executor_unavailable() {
    let config = super::super::MprdConfigFile::default();
    let out = compute_system_status(
        &config,
        0,
        components(
            op_api::HealthLevel::Healthy,
            op_api::HealthLevel::Healthy,
            op_api::HealthLevel::Unavailable,
        ),
        true,
    );
    assert!(matches!(out.overall, op_api::OverallStatus::Degraded));
}

#[test]
fn system_status_is_critical_when_risc0_unavailable_in_private_mode() {
    let config = super::super::MprdConfigFile {
        mode: "private".into(),
        ..super::super::MprdConfigFile::default()
    };

    let out = compute_system_status(
        &config,
        0,
        components(
            op_api::HealthLevel::Healthy,
            op_api::HealthLevel::Unavailable,
            op_api::HealthLevel::Healthy,
        ),
        true,
    );
    assert!(matches!(out.overall, op_api::OverallStatus::Critical));
}

#[test]
fn system_status_is_not_critical_when_risc0_unavailable_in_local_mode() {
    let config = super::super::MprdConfigFile {
        mode: "local".into(),
        ..super::super::MprdConfigFile::default()
    };

    let out = compute_system_status(
        &config,
        0,
        components(
            op_api::HealthLevel::Healthy,
            op_api::HealthLevel::Unavailable,
            op_api::HealthLevel::Healthy,
        ),
        true,
    );

    assert!(!matches!(out.overall, op_api::OverallStatus::Critical));
}

#[test]
fn system_status_degrades_on_tau_unavailable_only_when_tau_binary_configured() {
    let config = super::super::MprdConfigFile {
        mode: "local".into(),
        tau_binary: Some("tau".into()),
        ..super::super::MprdConfigFile::default()
    };

    let out = compute_system_status(
        &config,
        0,
        components(
            op_api::HealthLevel::Unavailable,
            op_api::HealthLevel::Healthy,
            op_api::HealthLevel::Healthy,
        ),
        true,
    );
    assert!(matches!(out.overall, op_api::OverallStatus::Degraded));

    let mut config2 = config.clone();
    config2.tau_binary = None;
    let out2 = compute_system_status(
        &config2,
        0,
        components(
            op_api::HealthLevel::Unavailable,
            op_api::HealthLevel::Healthy,
            op_api::HealthLevel::Healthy,
        ),
        true,
    );
    assert!(matches!(out2.overall, op_api::OverallStatus::Operational));
}

#[test]
fn serve_startup_validation_rejects_trustless_mode_without_full_state_anchors() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let registry_path = tmp.path().join("registry_state.json");
    std::fs::write(&registry_path, b"{}").expect("write registry");

    let config = super::super::MprdConfigFile {
        mode: "trustless".into(),
        registry_state_path: Some(registry_path),
        registry_verifying_key_hex: Some("00".into()),
        ..super::super::MprdConfigFile::default()
    };

    let err = validate_serve_startup_config(&config, false)
        .expect_err("trustless serve must fail closed without signed state anchors");
    assert!(
        err.to_string()
            .contains("requires configured trust anchors"),
        "unexpected error: {err}"
    );
}

#[test]
fn serve_startup_validation_accepts_trustless_mode_with_full_state_anchors() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let registry_path = tmp.path().join("registry_state.json");
    let state_path = tmp.path().join("signed_state.json");
    std::fs::write(&registry_path, b"{}").expect("write registry");
    std::fs::write(&state_path, b"{}").expect("write state");

    let config = super::super::MprdConfigFile {
        mode: "trustless".into(),
        registry_state_path: Some(registry_path),
        registry_verifying_key_hex: Some("00".into()),
        state_snapshot_path: Some(state_path),
        state_verifying_key_hex: Some("11".into()),
        ..super::super::MprdConfigFile::default()
    };

    validate_serve_startup_config(&config, false)
        .expect("full trust anchors should allow trustless serve startup");
}

#[test]
fn retention_update_rejects_retention_days_that_overflow_ms() {
    let per_day_ms = 24u128 * 60 * 60 * 1000;
    let max_days = (i64::MAX as u128) / per_day_ms;
    let req = op_api::OperatorSettingsUpdate {
        decision_retention_days: Some((max_days + 1) as u64),
        decision_max: None,
    };
    assert!(validate_retention_update(&req).is_err());
}
