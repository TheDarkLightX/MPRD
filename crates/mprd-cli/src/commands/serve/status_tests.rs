use super::{
    compute_system_status, executor_component_health, select_production_serve_policy,
    trust_anchors_configured_with, validate_retention_update, validate_serve_startup_config,
};
use crate::operator::api as op_api;
use mprd_core::crypto::TokenSigningKey;
use mprd_core::{Hash32, Value};
use mprd_risc0_shared::{
    policy_exec_kind_mpb_id_v1, policy_exec_kind_tau_compiled_id_v1, policy_exec_version_id_v1,
};
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
                policy_source_kind_id: Some([0x31u8; 32]),
                policy_source_hash: Some(Hash32([0x41u8; 32])),
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
fn production_serve_policy_selection_prefers_authorized_mpb_policy() {
    let key = TokenSigningKey::from_seed(&[0x51; 32]);
    let manifest = GuestImageManifestV1::sign(
        &key,
        1,
        vec![
            GuestImageEntryV1 {
                policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                image_id: [0x11; 32],
            },
            GuestImageEntryV1 {
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                image_id: [0x22; 32],
            },
        ],
    )
    .expect("manifest");
    let tau_policy = AuthorizedPolicyV1 {
        policy_hash: Hash32([0x10; 32]),
        policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
        policy_exec_version_id: policy_exec_version_id_v1(),
        policy_source_kind_id: Some([0x61; 32]),
        policy_source_hash: Some(Hash32([0x71; 32])),
    };
    let mpb_policy = AuthorizedPolicyV1 {
        policy_hash: Hash32([0x20; 32]),
        policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
        policy_exec_version_id: policy_exec_version_id_v1(),
        policy_source_kind_id: Some([0x62; 32]),
        policy_source_hash: Some(Hash32([0x72; 32])),
    };
    let state = RegistryStateV1 {
        policy_epoch: 1,
        registry_root: Hash32([0x33; 32]),
        authorized_policies: vec![tau_policy, mpb_policy.clone()],
        guest_image_manifest: manifest,
    };

    let selected = select_production_serve_policy(&state).expect("select mpb policy");
    assert_eq!(selected.policy_hash, mpb_policy.policy_hash);
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
fn serve_startup_validation_accepts_trustless_mode_with_idempotent_file_executor() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut config = valid_trustless_serve_config(&tmp);
    config.execution.executor_type = "idempotent_file".into();
    config.execution.audit_file = Some(tmp.path().join("audit_root"));

    validate_serve_startup_config(&config, false)
        .expect("trustless serve should accept idempotent file executor");
}

#[test]
fn serve_startup_validation_accepts_trustless_mode_with_idempotent_http_executor() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut config = valid_trustless_serve_config(&tmp);
    config.execution.executor_type = "idempotent_http".into();
    config.execution.http_url = Some("http://127.0.0.1:8080".into());
    config.execution.effect_journal_dir = Some(tmp.path().join("http_effects"));

    validate_serve_startup_config(&config, false)
        .expect("trustless serve should accept idempotent http executor");
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
fn serve_startup_validation_rejects_missing_required_policy_source_mapping() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config = valid_trustless_serve_config(&tmp);
    let registry_path = config.registry_state_path.clone().expect("registry path");
    let registry_json = std::fs::read_to_string(&registry_path).expect("read registry");
    let mut signed: SignedRegistryStateV1 =
        serde_json::from_str(&registry_json).expect("parse signed registry");
    signed.state.authorized_policies[0].policy_source_kind_id = None;
    signed.state.authorized_policies[0].policy_source_hash = None;
    let resigned = SignedRegistryStateV1::sign(
        &TokenSigningKey::from_seed(&[0x21; 32]),
        signed.signed_at_ms,
        signed.state,
    )
    .expect("re-sign registry");
    std::fs::write(
        &registry_path,
        serde_json::to_vec_pretty(&resigned).expect("serialize registry"),
    )
    .expect("rewrite registry");

    let err = validate_serve_startup_config(&config, false)
        .expect_err("startup must fail closed on missing required policy source mapping");
    assert!(
        err.to_string()
            .contains("authorized policy missing required policy_source mapping"),
        "unexpected error: {err}"
    );
}

#[test]
fn serve_startup_validation_rejects_plain_file_executor_in_trustless_mode() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut config = valid_trustless_serve_config(&tmp);
    config.execution.executor_type = "file".into();
    config.execution.audit_file = Some(tmp.path().join("audit.jsonl"));

    let err = validate_serve_startup_config(&config, false)
        .expect_err("trustless serve must reject non-idempotent file executor");
    assert!(
        err.to_string()
            .contains("requires execution.executor_type=idempotent_file"),
        "unexpected error: {err}"
    );
}

#[test]
fn serve_startup_validation_rejects_plain_http_executor_in_trustless_mode() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut config = valid_trustless_serve_config(&tmp);
    config.execution.executor_type = "http".into();
    config.execution.http_url = Some("http://127.0.0.1:8080".into());

    let err = validate_serve_startup_config(&config, false)
        .expect_err("trustless serve must reject non-idempotent http executor");
    assert!(
        err.to_string()
            .contains("requires execution.executor_type=idempotent_http"),
        "unexpected error: {err}"
    );
}

#[test]
fn serve_startup_validation_rejects_idempotent_http_without_effect_journal_dir() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut config = valid_trustless_serve_config(&tmp);
    config.execution.executor_type = "idempotent_http".into();
    config.execution.http_url = Some("http://127.0.0.1:8080".into());
    config.execution.effect_journal_dir = None;

    let err = validate_serve_startup_config(&config, false)
        .expect_err("idempotent http executor must require effect journal dir");
    assert!(
        err.to_string()
            .contains("executor_type=idempotent_http requires execution.effect_journal_dir"),
        "unexpected error: {err}"
    );
}

#[test]
fn serve_startup_validation_rejects_unresolved_idempotent_http_pending_barriers() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut config = valid_trustless_serve_config(&tmp);
    let root = tmp.path().join("http_effects");
    let policy_dir = root.join("deadbeef");
    std::fs::create_dir_all(&policy_dir).expect("policy dir");
    std::fs::write(policy_dir.join("stuck.pending.json"), b"{}\n").expect("pending marker");

    config.execution.executor_type = "idempotent_http".into();
    config.execution.http_url = Some("http://127.0.0.1:8080".into());
    config.execution.effect_journal_dir = Some(root.clone());

    let err = validate_serve_startup_config(&config, false)
        .expect_err("startup must fail closed on unresolved pending barriers");
    assert!(
        err.to_string()
            .contains("refuses startup with 1 unresolved idempotent_http pending barrier"),
        "unexpected error: {err}"
    );
    assert!(
        err.to_string().contains(&root.display().to_string()),
        "unexpected error: {err}"
    );
}

#[test]
fn executor_component_health_reports_idempotent_file_root() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut config = super::super::MprdConfigFile::default();
    config.execution.executor_type = "idempotent_file".into();
    config.execution.audit_file = Some(tmp.path().join("audit_root"));

    let health = executor_component_health(&config);
    assert!(matches!(health.status, op_api::HealthLevel::Healthy));
    assert!(
        health
            .message
            .as_deref()
            .is_some_and(|m| m.contains("idempotent audit root:")),
        "unexpected health message: {:?}",
        health.message
    );
}

#[test]
fn executor_component_health_reports_idempotent_http_root() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut config = super::super::MprdConfigFile::default();
    config.execution.executor_type = "idempotent_http".into();
    config.execution.http_url = Some("http://127.0.0.1:8080".into());
    config.execution.effect_journal_dir = Some(tmp.path().join("http_effects"));

    let health = executor_component_health(&config);
    assert!(matches!(health.status, op_api::HealthLevel::Healthy));
    assert!(
        health
            .message
            .as_deref()
            .is_some_and(|m| m.contains("effect journal root:") && m.contains("pending barriers: 0")),
        "unexpected health message: {:?}",
        health.message
    );
}

#[test]
fn executor_component_health_degrades_on_unresolved_idempotent_http_pending_barriers() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let root = tmp.path().join("http_effects");
    let policy_dir = root.join("deadbeef");
    std::fs::create_dir_all(&policy_dir).expect("policy dir");
    std::fs::write(policy_dir.join("stuck.pending.json"), b"{}\n").expect("pending marker");

    let mut config = super::super::MprdConfigFile::default();
    config.execution.executor_type = "idempotent_http".into();
    config.execution.http_url = Some("http://127.0.0.1:8080".into());
    config.execution.effect_journal_dir = Some(root);

    let health = executor_component_health(&config);
    assert!(matches!(health.status, op_api::HealthLevel::Degraded));
    assert!(
        health
            .message
            .as_deref()
            .is_some_and(|m| m.contains("pending barriers: 1")),
        "unexpected health message: {:?}",
        health.message
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
fn serve_startup_validation_rejects_unusable_persistent_nonce_store() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut config = valid_trustless_serve_config(&tmp);
    let nonce_store_path = tmp.path().join("nonce-store-file");
    std::fs::write(&nonce_store_path, b"not a directory").expect("write blocking file");
    config.anti_replay = Some(super::super::AntiReplayConfig {
        nonce_store_dir: Some(nonce_store_path),
    });

    let err = validate_serve_startup_config(&config, false)
        .expect_err("startup must fail closed when persistent anti-replay cannot initialize");
    assert!(
        err.to_string().contains("Failed to create nonce_store_dir")
            || err.to_string().contains("Not a directory")
            || err.to_string().contains("File exists"),
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
