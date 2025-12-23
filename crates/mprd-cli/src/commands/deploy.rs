//! Production deployment wiring checks.
//!
//! This command validates that a deployment bundle is self-consistent and fail-closed:
//! - signed registry checkpoint verifies under a verifier-trusted key
//! - signed guest image manifest verifies under its verifier-trusted key
//! - every authorized policy has a local policy artifact file (content-addressed by policy_hash)
//! - every authorized policy's exec kind/version resolves to an image_id in the manifest

use anyhow::{Context, Result};
use mprd_core::{Hash32, PolicyRef, TokenVerifyingKey};
use mprd_risc0_shared::{
    decode_compiled_tau_policy_v1, policy_exec_kind_mpb_id_v1, policy_exec_kind_tau_compiled_id_v1,
    policy_exec_version_id_v1, tau_compiled_policy_hash_v1,
};
use mprd_zk::policy_artifacts::decode_mpb_policy_artifact_bytes_v1;
use mprd_zk::policy_fetch::{DirPolicyArtifactStore, PolicyArtifactStore};
use mprd_zk::registry_state::{AuthorizedPolicyV1, RegistryStateProvider, SignedRegistryStateV1};

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
enum BundleCheckError {
    #[error("missing policy artifact file for policy_hash={policy_hash_hex}")]
    MissingPolicyArtifact { policy_hash_hex: String },
}

pub fn check_bundle(
    registry_state_path: PathBuf,
    registry_key_hex: String,
    manifest_key_hex: Option<String>,
    policy_artifacts_dir: PathBuf,
) -> Result<()> {
    let registry_vk =
        TokenVerifyingKey::from_hex(&registry_key_hex).context("Invalid --registry-key-hex")?;
    let manifest_vk = match manifest_key_hex.as_deref() {
        None => registry_vk.clone(),
        Some(hex) => TokenVerifyingKey::from_hex(hex).context("Invalid --manifest-key-hex")?,
    };

    let json = fs::read_to_string(&registry_state_path).with_context(|| {
        format!(
            "Failed to read registry_state file: {}",
            registry_state_path.display()
        )
    })?;
    let signed: SignedRegistryStateV1 =
        serde_json::from_str(&json).context("Failed to parse registry_state JSON")?;

    let provider = Arc::new(
        mprd_zk::registry_state::SignedStaticRegistryStateProvider::new(signed, registry_vk),
    );
    let state = RegistryStateProvider::get(provider.as_ref())
        .context("Failed to verify signed registry_state")?;

    state
        .verify_manifest(&manifest_vk)
        .context("Failed to verify signed guest image manifest")?;

    let policy_ref = PolicyRef {
        policy_epoch: state.policy_epoch,
        registry_root: state.registry_root,
    };

    let store = DirPolicyArtifactStore::new(&policy_artifacts_dir);
    let mut ok = 0usize;
    let mut skipped = 0usize;

    for ap in &state.authorized_policies {
        // Ensure manifest routing is complete.
        state
            .guest_image_manifest
            .image_id_for(&ap.policy_exec_kind_id, &ap.policy_exec_version_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "manifest missing image_id for exec kind/version (policy_hash={})",
                    hex::encode(ap.policy_hash.0)
                )
            })?;

        match ap.policy_exec_kind_id {
            kind if kind == policy_exec_kind_mpb_id_v1()
                && ap.policy_exec_version_id == policy_exec_version_id_v1() =>
            {
                validate_mpb_policy_artifact(&store, &policy_ref, ap)?;
                ok += 1;
            }
            kind if kind == policy_exec_kind_tau_compiled_id_v1()
                && ap.policy_exec_version_id == policy_exec_version_id_v1() =>
            {
                validate_tau_compiled_policy_artifact(&store, &policy_ref, ap)?;
                ok += 1;
            }
            _ => {
                // Other exec kinds may not use local artifact bytes in this deployment bundle.
                skipped += 1;
            }
        }
    }

    println!("✅ Bundle check passed");
    println!("   policy_epoch:  {}", policy_ref.policy_epoch);
    println!(
        "   registry_root: {}",
        hex::encode(policy_ref.registry_root.0)
    );
    println!(
        "   policies: {} validated, {} skipped, {} total",
        ok,
        skipped,
        state.authorized_policies.len()
    );
    println!(
        "   policy_artifacts_dir: {}",
        policy_artifacts_dir.display()
    );
    Ok(())
}

fn validate_mpb_policy_artifact(
    store: &DirPolicyArtifactStore,
    _policy_ref: &PolicyRef,
    ap: &AuthorizedPolicyV1,
) -> Result<()> {
    let bytes = store
        .get(&ap.policy_hash)
        .context("Failed to read policy artifact store")?
        .ok_or_else(|| BundleCheckError::MissingPolicyArtifact {
            policy_hash_hex: hex::encode(ap.policy_hash.0),
        })?;

    let artifact = decode_mpb_policy_artifact_bytes_v1(&bytes)
        .context("invalid mpb-v1 policy artifact bytes")?;

    let refs: Vec<(&[u8], u8)> = artifact
        .variables
        .iter()
        .map(|(name, reg)| (name.as_bytes(), *reg))
        .collect();
    let computed = Hash32(mprd_mpb::policy_hash_v1(&artifact.bytecode, &refs));
    if computed != ap.policy_hash {
        anyhow::bail!(
            "mpb policy_hash mismatch (artifact tamper) policy_hash={}",
            hex::encode(ap.policy_hash.0)
        );
    }
    Ok(())
}

fn validate_tau_compiled_policy_artifact(
    store: &DirPolicyArtifactStore,
    _policy_ref: &PolicyRef,
    ap: &AuthorizedPolicyV1,
) -> Result<()> {
    let bytes = store
        .get(&ap.policy_hash)
        .context("Failed to read policy artifact store")?
        .ok_or_else(|| BundleCheckError::MissingPolicyArtifact {
            policy_hash_hex: hex::encode(ap.policy_hash.0),
        })?;

    let computed = Hash32(tau_compiled_policy_hash_v1(&bytes));
    if computed != ap.policy_hash {
        anyhow::bail!(
            "tau_compiled policy_hash mismatch (artifact tamper) policy_hash={}",
            hex::encode(ap.policy_hash.0)
        );
    }

    decode_compiled_tau_policy_v1(&bytes)
        .map_err(|e| anyhow::anyhow!("invalid compiled Tau policy bytes: {e:?}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mprd_core::TokenSigningKey;
    use mprd_zk::manifest::{GuestImageEntryV1, GuestImageManifestV1};
    use mprd_zk::registry_state::{AuthorizedPolicyV1, RegistryStateV1, SignedRegistryStateV1};
    use std::path::Path;

    fn tmpdir(prefix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("{prefix}-{}-{}", std::process::id(), now));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
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

    fn encode_minimal_compiled_tau_policy_bytes() -> Vec<u8> {
        // Same layout as `mprd_risc0_shared::decode_compiled_tau_policy_v1`.
        let mut out = Vec::new();
        out.extend_from_slice(&1u32.to_le_bytes()); // version
        out.extend_from_slice(&1u32.to_le_bytes()); // predicate_count
        out.extend_from_slice(&0u32.to_le_bytes()); // predicate_idx
        out.push(4u8); // Equals
                       // left operand
        out.push(2u8); // Constant
        out.extend_from_slice(&[0u8; 32]);
        out.push(0u8); // U64
        out.extend_from_slice(&1u64.to_le_bytes());
        // right operand
        out.push(2u8);
        out.extend_from_slice(&[0u8; 32]);
        out.push(0u8);
        out.extend_from_slice(&1u64.to_le_bytes());
        // gate_count
        out.extend_from_slice(&1u32.to_le_bytes());
        // gate: PredicateInput -> wire 0
        out.push(3u8);
        out.extend_from_slice(&0u32.to_le_bytes()); // out_wire
        out.extend_from_slice(&0u32.to_le_bytes()); // in1 (pred idx)
        out.extend_from_slice(&0u32.to_le_bytes()); // in2
                                                    // output_wire
        out.extend_from_slice(&0u32.to_le_bytes());
        // temporal_fields count
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    #[test]
    fn check_bundle_accepts_valid_minimal_bundle() {
        let artifacts_dir = tmpdir("mprd-artifacts");
        let bundle_dir = tmpdir("mprd-bundle");

        let registry_signer = TokenSigningKey::from_seed(&[211u8; 32]);
        let manifest_signer = TokenSigningKey::from_seed(&[212u8; 32]);
        let registry_vk_hex = hex::encode(registry_signer.verifying_key().to_bytes());
        let manifest_vk_hex = hex::encode(manifest_signer.verifying_key().to_bytes());

        // MPB artifact
        let mpb_bytecode = vec![0xFF];
        let mpb_vars = [("a", 0u8)];
        let mpb_bytes = encode_mpb_artifact(&mpb_bytecode, &[("a", 0)]);
        let refs: Vec<(&[u8], u8)> = mpb_vars.iter().map(|(n, r)| (n.as_bytes(), *r)).collect();
        let mpb_policy_hash = Hash32(mprd_mpb::policy_hash_v1(&mpb_bytecode, &refs));
        write_file(
            &artifacts_dir.join(hex::encode(mpb_policy_hash.0)),
            &mpb_bytes,
        );

        // Tau-compiled artifact
        let tau_bytes = encode_minimal_compiled_tau_policy_bytes();
        let tau_policy_hash = Hash32(tau_compiled_policy_hash_v1(&tau_bytes));
        // keep: `tau_policy_hash` is used below; no need to keep the hex string here.
        write_file(
            &artifacts_dir.join(hex::encode(tau_policy_hash.0)),
            &tau_bytes,
        );

        // Signed manifest
        let manifest = GuestImageManifestV1::sign(
            &manifest_signer,
            123,
            vec![
                GuestImageEntryV1 {
                    policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                    policy_exec_version_id: policy_exec_version_id_v1(),
                    image_id: [9u8; 32],
                },
                GuestImageEntryV1 {
                    policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
                    policy_exec_version_id: policy_exec_version_id_v1(),
                    image_id: [8u8; 32],
                },
            ],
        )
        .unwrap();

        let mut policies = vec![
            AuthorizedPolicyV1 {
                policy_hash: mpb_policy_hash,
                policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: None,
                policy_source_hash: None,
            },
            AuthorizedPolicyV1 {
                policy_hash: tau_policy_hash,
                policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                policy_source_kind_id: None,
                policy_source_hash: None,
            },
        ];
        policies.sort_by(|a, b| a.policy_hash.0.cmp(&b.policy_hash.0));

        let state = RegistryStateV1 {
            policy_epoch: 1,
            registry_root: Hash32([7u8; 32]),
            authorized_policies: policies,
            guest_image_manifest: manifest,
        };
        let signed = SignedRegistryStateV1::sign(&registry_signer, 456, state).unwrap();
        let registry_state_path = bundle_dir.join("registry_state.json");
        write_file(
            &registry_state_path,
            serde_json::to_string_pretty(&signed).unwrap().as_bytes(),
        );

        check_bundle(
            registry_state_path,
            registry_vk_hex,
            Some(manifest_vk_hex),
            artifacts_dir,
        )
        .unwrap();
    }

    #[test]
    fn check_bundle_fails_closed_on_missing_policy_artifact() {
        let artifacts_dir = tmpdir("mprd-artifacts-missing");
        let bundle_dir = tmpdir("mprd-bundle-missing");

        let registry_signer = TokenSigningKey::from_seed(&[213u8; 32]);
        let manifest_signer = TokenSigningKey::from_seed(&[214u8; 32]);
        let registry_vk_hex = hex::encode(registry_signer.verifying_key().to_bytes());
        let manifest_vk_hex = hex::encode(manifest_signer.verifying_key().to_bytes());

        let tau_bytes = encode_minimal_compiled_tau_policy_bytes();
        let tau_policy_hash = Hash32(tau_compiled_policy_hash_v1(&tau_bytes));
        let tau_policy_hash_hex = hex::encode(tau_policy_hash.0);

        let manifest = GuestImageManifestV1::sign(
            &manifest_signer,
            123,
            vec![GuestImageEntryV1 {
                policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                image_id: [8u8; 32],
            }],
        )
        .unwrap();

        let policies = vec![AuthorizedPolicyV1 {
            policy_hash: tau_policy_hash,
            policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            policy_source_kind_id: None,
            policy_source_hash: None,
        }];

        let state = RegistryStateV1 {
            policy_epoch: 1,
            registry_root: Hash32([7u8; 32]),
            authorized_policies: policies,
            guest_image_manifest: manifest,
        };
        let signed = SignedRegistryStateV1::sign(&registry_signer, 456, state).unwrap();
        let registry_state_path = bundle_dir.join("registry_state.json");
        write_file(
            &registry_state_path,
            serde_json::to_string_pretty(&signed).unwrap().as_bytes(),
        );

        let err = check_bundle(
            registry_state_path,
            registry_vk_hex,
            Some(manifest_vk_hex),
            artifacts_dir,
        )
        .unwrap_err();
        assert_eq!(
            err.downcast_ref::<BundleCheckError>(),
            Some(&BundleCheckError::MissingPolicyArtifact {
                policy_hash_hex: tau_policy_hash_hex,
            })
        );
    }
}
