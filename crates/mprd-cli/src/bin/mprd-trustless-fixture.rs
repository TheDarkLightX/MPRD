use anyhow::{Context, Result};
use clap::Parser;
use mprd_core::mpb::BytecodeBuilder;
use mprd_core::state_provenance::{state_source_id_signed_snapshot_v1, SignedStateSnapshotV1};
use mprd_core::{Hash32, TokenSigningKey, Value as CoreValue};
use mprd_risc0_shared::{
    policy_exec_kind_mpb_id_v1, policy_exec_version_id_v1, policy_source_kind_tau_id_v1,
};
use mprd_zk::manifest::{GuestImageEntryV1, GuestImageManifestV1};
use mprd_zk::registry_state::{AuthorizedPolicyV1, RegistryStateV1, SignedRegistryStateV1};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "mprd-trustless-fixture")]
#[command(about = "Generate a deterministic trustless CLI fixture")]
struct Args {
    /// Output directory for the generated fixture.
    #[arg(long)]
    output: PathBuf,

    /// Registry signing seed byte value repeated across 32 bytes.
    #[arg(long, default_value_t = 73)]
    registry_seed_byte: u8,

    /// Token signing seed byte value repeated across 32 bytes.
    #[arg(long, default_value_t = 7)]
    token_seed_byte: u8,
}

#[derive(Serialize)]
struct FixtureSummary {
    fixture_root: String,
    config_path: String,
    registry_state_path: String,
    artifact_path: String,
    token_signing_key_env_var: String,
    token_signing_key_env_path: String,
    signed_state_path: String,
    candidates_path: String,
    serve_request_path: String,
    policy_hash_hex: String,
}

fn embedded_mpb_image_id_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, word) in mprd_risc0_methods::MPRD_MPB_GUEST_ID.iter().enumerate() {
        out[idx * 4..(idx + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn fixture_mpb_image_id_bytes() -> [u8; 32] {
    let embedded = embedded_mpb_image_id_bytes();
    if embedded == [0u8; 32] {
        // Placeholder Risc0 builds still need a nonzero signed route so wiring fixtures can
        // exercise registry/manifest checks. Production release verification separately rejects
        // local placeholder methods.
        [0x6d; 32]
    } else {
        embedded
    }
}

fn encode_mpb_policy_artifact_bytes_v1(bytecode: &[u8], vars: &[(&str, u8)]) -> Vec<u8> {
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

fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let root = args.output;
    let mprd_dir = root.join(".mprd");
    let policies_dir = mprd_dir.join("policies");
    let artifacts_dir = mprd_dir.join("policy-artifacts");
    let anti_replay_dir = mprd_dir.join("anti_replay");
    let operator_dir = mprd_dir.join("operator");

    ensure_dir(&policies_dir)?;
    ensure_dir(&artifacts_dir)?;
    ensure_dir(&anti_replay_dir)?;
    ensure_dir(&operator_dir)?;

    let registry_seed = [args.registry_seed_byte; 32];
    let token_seed = [args.token_seed_byte; 32];
    let registry_signer = TokenSigningKey::from_seed(&registry_seed);
    let token_signing_key_env_var = "MPRD_TOKEN_SIGNING_KEY_HEX";
    let token_signing_key_hex = hex::encode(token_seed);
    let policy_bytecode = BytecodeBuilder::new().push_i64(1).halt().build();
    let policy_hash = Hash32(mprd_mpb::policy_hash_v1(&policy_bytecode, &[]));
    let artifact_path = artifacts_dir.join(hex::encode(policy_hash.0));
    fs::write(
        &artifact_path,
        encode_mpb_policy_artifact_bytes_v1(&policy_bytecode, &[]),
    )
    .with_context(|| format!("write {}", artifact_path.display()))?;

    let manifest = GuestImageManifestV1::sign(
        &registry_signer,
        123,
        vec![GuestImageEntryV1 {
            policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            image_id: fixture_mpb_image_id_bytes(),
        }],
    )?;

    let signed_registry_state = SignedRegistryStateV1::sign(
        &registry_signer,
        456,
        RegistryStateV1 {
            policy_epoch: 11,
            registry_root: Hash32([0x77; 32]),
            authorized_policies: vec![AuthorizedPolicyV1 {
                policy_hash,
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: Some(policy_source_kind_tau_id_v1()),
                policy_source_hash: Some(Hash32([0x41; 32])),
            }],
            guest_image_manifest: manifest,
        },
    )?;
    let registry_state_path = mprd_dir.join("registry_state.json");
    fs::write(
        &registry_state_path,
        serde_json::to_vec_pretty(&signed_registry_state)?,
    )
    .with_context(|| format!("write {}", registry_state_path.display()))?;

    let mut state_fields = HashMap::new();
    state_fields.insert("balance".to_string(), CoreValue::UInt(100));
    state_fields.insert("region".to_string(), CoreValue::String("us".into()));
    let signed_state =
        SignedStateSnapshotV1::sign(&registry_signer, 1, state_fields, HashMap::new())?;
    let signed_state_path = root.join("signed_state.json");
    fs::write(
        &signed_state_path,
        serde_json::to_vec_pretty(&signed_state)?,
    )
    .with_context(|| format!("write {}", signed_state_path.display()))?;

    let candidates = json!([
        {
            "action_type": "noop",
            "params": {},
            "score": 0
        }
    ]);
    let candidates_path = root.join("candidates.json");
    fs::write(&candidates_path, serde_json::to_vec_pretty(&candidates)?)
        .with_context(|| format!("write {}", candidates_path.display()))?;

    let serve_request = json!({
        "policy_hash": hex::encode(policy_hash.0),
        "signed_state": signed_state,
        "candidates": candidates,
    });
    let serve_request_path = root.join("serve_request.json");
    fs::write(
        &serve_request_path,
        serde_json::to_vec_pretty(&serve_request)?,
    )
    .with_context(|| format!("write {}", serve_request_path.display()))?;

    let token_env_path = root.join("token_signing_key.env");
    fs::write(
        &token_env_path,
        format!("{token_signing_key_env_var}={token_signing_key_hex}\n"),
    )
    .with_context(|| format!("write {}", token_env_path.display()))?;

    let config = json!({
        "mode": "trustless",
        "policy_storage": {
            "storage_type": "local",
            "local_dir": ".mprd/policies",
            "ipfs_url": null
        },
        "tau_binary": null,
        "risc0_image_id": hex::encode(fixture_mpb_image_id_bytes()),
        "execution": {
            "executor_type": "noop",
            "http_url": null,
            "audit_file": ".mprd/audit.jsonl"
        },
        "anti_replay": {
            "nonce_store_dir": ".mprd/anti_replay"
        },
        "state_provenance": {
            "require_provenance": true,
            "allowed_state_source_ids_hex": [
                hex::encode(state_source_id_signed_snapshot_v1().0)
            ]
        },
        "registry_state_path": ".mprd/registry_state.json",
        "registry_verifying_key_hex": hex::encode(registry_signer.verifying_key().to_bytes()),
        "token_signing_key_hex": null,
        "token_signing_key_env_var": token_signing_key_env_var,
        "policy_artifacts_dir": ".mprd/policy-artifacts"
    });
    let config_path = mprd_dir.join("config.json");
    fs::write(&config_path, serde_json::to_vec_pretty(&config)?)
        .with_context(|| format!("write {}", config_path.display()))?;

    let summary = FixtureSummary {
        fixture_root: root.display().to_string(),
        config_path: config_path.display().to_string(),
        registry_state_path: registry_state_path.display().to_string(),
        artifact_path: artifact_path.display().to_string(),
        token_signing_key_env_var: token_signing_key_env_var.into(),
        token_signing_key_env_path: token_env_path.display().to_string(),
        signed_state_path: signed_state_path.display().to_string(),
        candidates_path: candidates_path.display().to_string(),
        serve_request_path: serve_request_path.display().to_string(),
        policy_hash_hex: hex::encode(policy_hash.0),
    };
    let summary_path = root.join("fixture-summary.json");
    fs::write(&summary_path, serde_json::to_vec_pretty(&summary)?)
        .with_context(|| format!("write {}", summary_path.display()))?;

    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}
