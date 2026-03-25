use super::{
    compute_system_status, trust_anchors_configured_with, validate_retention_update,
    validate_serve_startup_config,
};
use crate::operator::api as op_api;
use mprd_core::crypto::TokenSigningKey;
use mprd_core::{Hash32, Value};
use mprd_risc0_shared::{policy_exec_kind_mpb_id_v1, policy_exec_version_id_v1};
use mprd_zk::manifest::{GuestImageEntryV1, GuestImageManifestV1};
use mprd_zk::registry_state::{AuthorizedPolicyV1, RegistryStateV1, SignedRegistryStateV1};
use std::collections::HashMap;

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

fn encode_mpb_artifact(bytecode: &[u8], vars: &[(&str, u8)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(bytecode.len() as u32).to_le_bytes());
    out.extend_from_slice(bytecode);
    out.extend_from_slice(&(vars.len() as u32).to_le_bytes());
    for (name, reg) in vars {
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.push(*reg);
    }
    out
}

fn valid_trustless_serve_config(tmp: &tempfile::TempDir) -> super::super::MprdConfigFile {
    let registry_key = TokenSigningKey::from_seed(&[0x21; 32]);
    let state_key = TokenSigningKey::from_seed(&[0x22; 32]);
    let token_seed = [0x23; 32];

    let registry_path = tmp.path().join("registry_state.json");
    let state_path = tmp.path().join("signed_state.json");
    let artifacts_dir = tmp.path().join("policy_artifacts");
    std::fs::create_dir_all(&artifacts_dir).expect("artifact dir");

    let bytecode = mprd_core::mpb::BytecodeBuilder::new()
        .push_i64(1)
        .halt()
        .build();
    let policy_hash = Hash32(mprd_mpb::policy_hash_v1(&bytecode, &[]));
    let artifact_bytes = encode_mpb_artifact(&bytecode, &[]);
    std::fs::write(
        artifacts_dir.join(hex::encode(policy_hash.0)),
        artifact_bytes,
    )
    .expect("write artifact");

    let manifest = GuestImageManifestV1::sign(
        &registry_key,
        1,
        vec![GuestImageEntryV1 {
            policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            image_id: [7u8; 32],
        }],
    )
    .expect("manifest");
    let registry = SignedRegistryStateV1::sign(
        &registry_key,
        2,
        RegistryStateV1 {
            policy_epoch: 1,
            registry_root: Hash32([9u8; 32]),
            authorized_policies: vec![AuthorizedPolicyV1 {
                policy_hash,
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: None,
                policy_source_hash: None,
            }],
            guest_image_manifest: manifest,
        },
    )
    .expect("signed registry");
    std::fs::write(
        &registry_path,
        serde_json::to_vec_pretty(&registry).expect("serialize registry"),
    )
    .expect("write registry");

    let signed_state = mprd_core::state_provenance::SignedStateSnapshotV1::sign(
        &state_key,
        42,
        HashMap::from([("balance".into(), Value::UInt(100))]),
        HashMap::new(),
    )
    .expect("signed state");
    std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&signed_state).expect("serialize state"),
    )
    .expect("write state");

    super::super::MprdConfigFile {
        mode: "trustless".into(),
        registry_state_path: Some(registry_path),
        registry_verifying_key_hex: Some(hex::encode(registry_key.verifying_key().to_bytes())),
        state_snapshot_path: Some(state_path),
        state_verifying_key_hex: Some(hex::encode(state_key.verifying_key().to_bytes())),
        token_signing_key_hex: Some(hex::encode(token_seed)),
        policy_artifacts_dir: Some(artifacts_dir),
        ..super::super::MprdConfigFile::default()
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
fn serve_startup_validation_accepts_local_mode_without_trust_anchors() {
    let config = super::super::MprdConfigFile {
        mode: "local".into(),
        ..super::super::MprdConfigFile::default()
    };

    validate_serve_startup_config(&config, false)
        .expect("local mode should not require production trust anchors at startup");
}

#[test]
fn serve_startup_validation_accepts_trustless_mode_with_full_state_anchors() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = valid_trustless_serve_config(&tmp);

    validate_serve_startup_config(&config, false)
        .expect("full trust anchors should allow trustless serve startup");
}

#[test]
fn serve_startup_validation_rejects_invalid_signed_state_snapshot() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = valid_trustless_serve_config(&tmp);
    let state_path = config
        .state_snapshot_path
        .clone()
        .expect("state snapshot path");
    std::fs::write(&state_path, b"{\"version\":999}").expect("overwrite invalid state");

    let err = validate_serve_startup_config(&config, false)
        .expect_err("startup must fail closed on invalid signed state snapshot");
    assert!(
        err.to_string()
            .contains("Invalid signed state snapshot JSON")
            || err
                .to_string()
                .contains("unsupported signed snapshot version"),
        "unexpected error: {err}"
    );
}

#[test]
fn serve_startup_validation_rejects_missing_policy_artifact_bundle() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = valid_trustless_serve_config(&tmp);
    let artifacts_dir = config
        .policy_artifacts_dir
        .clone()
        .expect("policy artifacts dir");
    std::fs::remove_dir_all(&artifacts_dir).expect("remove artifacts dir");
    std::fs::create_dir_all(&artifacts_dir).expect("recreate empty artifacts dir");

    let err = validate_serve_startup_config(&config, false)
        .expect_err("startup must fail closed on missing artifact bundle");
    assert!(
        err.to_string().contains("missing policy artifact file")
            || err.to_string().contains("MissingPolicyArtifact"),
        "unexpected error: {err}"
    );
}

#[test]
fn serve_startup_validation_rejects_missing_token_signing_key() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut config = valid_trustless_serve_config(&tmp);
    config.token_signing_key_hex = None;

    let err = validate_serve_startup_config(&config, false)
        .expect_err("startup must fail closed when token signing key is missing");
    assert!(
        err.to_string().contains("Missing token_signing_key_hex"),
        "unexpected error: {err}"
    );
}

#[test]
fn serve_startup_validation_rejects_missing_persistent_nonce_store() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut config = valid_trustless_serve_config(&tmp);
    config.anti_replay = Some(super::super::AntiReplayConfig {
        nonce_store_dir: None,
    });

    let err = validate_serve_startup_config(&config, false)
        .expect_err("startup must fail closed without persistent anti-replay");
    assert!(
        err.to_string()
            .contains("Production requires anti_replay.nonce_store_dir"),
        "unexpected error: {err}"
    );
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
