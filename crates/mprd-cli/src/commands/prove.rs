//! `mprd prove` command implementation

use anyhow::{Context, Result};
use mprd_core::crypto::TokenSigningKey;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

use mprd_core::{
    hash::{hash_candidate, hash_state},
    CandidateAction, Decision, DecisionToken, Hash32, PolicyRef, Score, StateRef, StateSnapshot,
    Value,
};
use mprd_risc0_methods::{MPRD_MPB_GUEST_ELF, MPRD_MPB_GUEST_ID};
use mprd_risc0_shared::MPB_FUEL_LIMIT_V1;
use mprd_zk::policy_fetch::{DirPolicyArtifactStore, PolicyArtifactStore};
use mprd_zk::registry_state::SignedRegistryStateV1;
use mprd_zk::{MpbPolicyArtifactV1, Risc0MpbAttestor};
use std::sync::Arc;

fn json_number_to_value(n: &serde_json::Number) -> Option<Value> {
    let Some(i) = n.as_i64() else {
        return n.as_u64().map(Value::UInt);
    };

    if i < 0 {
        return Some(Value::Int(i));
    }

    n.as_u64().map(Value::UInt)
}

fn json_to_value(v: serde_json::Value) -> Option<Value> {
    match v {
        serde_json::Value::Bool(b) => Some(Value::Bool(b)),
        serde_json::Value::Number(n) => json_number_to_value(&n),
        serde_json::Value::String(s) => Some(Value::String(s)),
        _ => None,
    }
}

fn json_to_value_strict(field: &str, v: serde_json::Value) -> Result<Value> {
    json_to_value(v).ok_or_else(|| anyhow::anyhow!("Unsupported JSON value for field `{field}`"))
}

fn parse_hash32_hex(hex_str: &str, name: &str) -> Result<Hash32> {
    let bytes = hex::decode(hex_str).with_context(|| format!("Invalid hex for {name}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("{name} must be 32 bytes (64 hex chars)");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Hash32(arr))
}

fn now_ms() -> i64 {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_millis(0))
        .as_millis();
    i64::try_from(ms).unwrap_or(0)
}

fn default_token_output_path(proof_output: &std::path::Path) -> PathBuf {
    let parent = proof_output
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let file = proof_output
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "proof.json".to_string());
    parent.join(format!("{file}.token.json"))
}

#[derive(Debug, Error, PartialEq, Eq)]
enum ProveCommandError {
    #[error(
        "Refusing to prove without production trust anchors. Provide `--registry-state` + keys + policy artifacts (recommended), or re-run with `--insecure-demo` to acknowledge demo-only behavior."
    )]
    InsecureDemoRequired,
}

#[derive(Clone, Debug)]
pub(crate) struct ProveProductionArgs {
    pub registry_state_path: PathBuf,
    pub registry_key_hex: Option<String>,
    pub manifest_key_hex: Option<String>,
    pub policy_artifacts_dir: Option<PathBuf>,
    pub token_signing_key_hex: Option<String>,
    pub nonce_or_tx_hash_hex: Option<String>,
    pub timestamp_ms: Option<i64>,
    pub state_source_id_hex: Option<String>,
    pub state_epoch: Option<u64>,
    pub state_attestation_hash_hex: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct ProveCommand {
    pub decision_path: PathBuf,
    pub state_path: PathBuf,
    pub candidates_path: PathBuf,
    pub output_path: PathBuf,
    pub token_output: Option<PathBuf>,
    pub production: Option<ProveProductionArgs>,
    pub insecure_demo: bool,
    pub config_path: Option<PathBuf>,
}

pub fn run(cmd: ProveCommand) -> Result<()> {
    let ProveCommand {
        decision_path,
        state_path,
        candidates_path,
        output_path,
        token_output,
        production,
        insecure_demo,
        config_path: _config_path,
    } = cmd;

    let production_enabled = production.is_some();
    if !production_enabled && !insecure_demo {
        return Err(ProveCommandError::InsecureDemoRequired.into());
    }

    println!("🔐 Generating ZK proof...");
    println!();

    // Load decision
    #[derive(serde::Deserialize)]
    struct DecisionInput {
        #[serde(default)]
        chosen_index: Option<usize>,
        policy_hash: String,
    }

    let decision_json = fs::read_to_string(&decision_path)
        .with_context(|| format!("Failed to read decision file: {}", decision_path.display()))?;
    let decision_input: DecisionInput =
        serde_json::from_str(&decision_json).context("Failed to parse decision JSON")?;

    // Load state
    let state_json = fs::read_to_string(&state_path)
        .with_context(|| format!("Failed to read state file: {}", state_path.display()))?;
    let state_fields: HashMap<String, serde_json::Value> =
        serde_json::from_str(&state_json).context("Failed to parse state JSON")?;

    let fields: HashMap<String, Value> = state_fields
        .into_iter()
        .map(|(key, value)| {
            let v = json_to_value_strict(&key, value)?;
            Ok((key, v))
        })
        .collect::<Result<HashMap<_, _>>>()?;

    let mut state = StateSnapshot {
        fields,
        policy_inputs: HashMap::new(),
        state_hash: Hash32([0u8; 32]),
        state_ref: StateRef::unknown(),
    };
    state.state_hash = hash_state(&state);

    // Load candidates
    #[derive(serde::Deserialize)]
    struct CandidateInput {
        action_type: String,
        params: HashMap<String, serde_json::Value>,
        score: i64,
    }

    let candidates_json = fs::read_to_string(&candidates_path).with_context(|| {
        format!(
            "Failed to read candidates file: {}",
            candidates_path.display()
        )
    })?;
    let candidate_inputs: Vec<CandidateInput> =
        serde_json::from_str(&candidates_json).context("Failed to parse candidates JSON")?;

    let candidates: Vec<CandidateAction> = candidate_inputs
        .into_iter()
        .map(|c| {
            let params: HashMap<String, Value> = c
                .params
                .into_iter()
                .map(|(key, value)| {
                    let v = json_to_value_strict(&key, value)?;
                    Ok((key, v))
                })
                .collect::<Result<HashMap<_, _>>>()?;

            let mut action = CandidateAction {
                action_type: c.action_type,
                params,
                score: Score(c.score),
                candidate_hash: Hash32([0u8; 32]),
            };
            action.candidate_hash = hash_candidate(&action);
            Ok(action)
        })
        .collect::<Result<Vec<_>>>()?;

    // Parse policy hash
    let policy_hash = parse_hash32_hex(&decision_input.policy_hash, "policy_hash")?;

    let token_out_path = token_output.unwrap_or_else(|| default_token_output_path(&output_path));

    if let Some(prod) = production {
        let ProveProductionArgs {
            registry_state_path: registry_path,
            registry_key_hex,
            manifest_key_hex,
            policy_artifacts_dir,
            token_signing_key_hex,
            nonce_or_tx_hash_hex,
            timestamp_ms,
            state_source_id_hex,
            state_epoch,
            state_attestation_hash_hex,
        } = prod;

        let registry_key_hex = registry_key_hex
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("--registry-key-hex is required"))?;
        let registry_vk = mprd_core::TokenVerifyingKey::from_hex(registry_key_hex)
            .context("Invalid --registry-key-hex")?;

        let manifest_vk = match manifest_key_hex.as_deref().map(str::trim) {
            None | Some("") => registry_vk.clone(),
            Some(hex) => {
                mprd_core::TokenVerifyingKey::from_hex(hex).context("Invalid --manifest-key-hex")?
            }
        };

        let policy_artifacts_dir = policy_artifacts_dir
            .ok_or_else(|| anyhow::anyhow!("--policy-artifacts-dir is required"))?;

        let token_signing_key_hex = token_signing_key_hex
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("--token-signing-key-hex is required"))?;
        let signing_key = TokenSigningKey::from_hex(token_signing_key_hex)
            .context("Invalid --token-signing-key-hex")?;

        let nonce_hex = nonce_or_tx_hash_hex
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("--nonce-or-tx-hash-hex is required"))?;
        let nonce_or_tx_hash = parse_hash32_hex(nonce_hex, "nonce_or_tx_hash")?;

        let state_source_id_hex = state_source_id_hex
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("--state-source-id-hex is required"))?;
        let state_attestation_hash_hex = state_attestation_hash_hex
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("--state-attestation-hash-hex is required"))?;
        let state_epoch =
            state_epoch.ok_or_else(|| anyhow::anyhow!("--state-epoch is required"))?;

        let state_source_id = parse_hash32_hex(state_source_id_hex, "state_source_id")?;
        let state_attestation_hash =
            parse_hash32_hex(state_attestation_hash_hex, "state_attestation_hash")?;
        if state_source_id == Hash32([0u8; 32]) || state_attestation_hash == Hash32([0u8; 32]) {
            anyhow::bail!(
                "Refusing to prove: state provenance fields must be non-zero in production mode"
            );
        }
        state.state_ref = StateRef {
            state_source_id,
            state_epoch,
            state_attestation_hash,
        };

        let json = fs::read_to_string(&registry_path).with_context(|| {
            format!(
                "Failed to read registry_state file: {}",
                registry_path.display()
            )
        })?;
        let signed: SignedRegistryStateV1 =
            serde_json::from_str(&json).context("Failed to parse registry_state JSON")?;

        // Load and validate the policy artifact (used both for deterministic selection and proving).
        let store = DirPolicyArtifactStore::new(policy_artifacts_dir.clone());
        let policy_bytes = store
            .get(&policy_hash)
            .context("Failed to read policy artifact")?
            .ok_or_else(|| anyhow::anyhow!("Policy artifact not found for policy_hash"))?;
        let artifact =
            mprd_zk::policy_artifacts::decode_mpb_policy_artifact_bytes_v1(&policy_bytes)
                .context("Invalid mpb policy artifact bytes")?;

        let bindings_owned: Vec<(Vec<u8>, u8)> = artifact
            .variables
            .iter()
            .map(|(name, reg)| (name.as_bytes().to_vec(), *reg))
            .collect();
        let bindings: Vec<(&[u8], u8)> = bindings_owned
            .iter()
            .map(|(name, reg)| (name.as_slice(), *reg))
            .collect();
        let computed_policy_hash = Hash32(mprd_mpb::policy_hash_v1(&artifact.bytecode, &bindings));
        if computed_policy_hash != policy_hash {
            anyhow::bail!(
                "Policy artifact hash mismatch (expected {}, got {})",
                hex::encode(policy_hash.0),
                hex::encode(computed_policy_hash.0)
            );
        }

        // Deterministic MPB selection (must match `methods/mpb_guest`).
        let state_preimage = mprd_core::hash::state_hash_preimage(&state);
        let mut best: Option<(usize, i64)> = None;
        for (idx, cand) in candidates.iter().enumerate() {
            let cand_preimage = mprd_core::hash::candidate_hash_preimage(cand);
            let regs =
                mprd_mpb::registers_from_preimages_v1(&state_preimage, &cand_preimage, &bindings)
                    .map_err(|_| anyhow::anyhow!("malformed state/candidate encoding"))?;
            let mut vm = mprd_mpb::MpbVm::with_fuel(&regs, MPB_FUEL_LIMIT_V1);
            let allowed = vm
                .execute(&artifact.bytecode)
                .map(|v| v != 0)
                .unwrap_or(false);
            if !allowed {
                continue;
            }
            let score = cand.score.0;
            match best {
                None => best = Some((idx, score)),
                Some((_best_idx, best_score)) => {
                    if score > best_score {
                        best = Some((idx, score));
                    }
                }
            }
        }

        let Some((chosen_index, _)) = best else {
            anyhow::bail!("Policy denied all candidates (no allowable action to prove)");
        };
        if let Some(user_idx) = decision_input.chosen_index {
            if user_idx != chosen_index {
                anyhow::bail!(
                    "chosen_index mismatch: policy selects {chosen_index}, but decision file specifies {user_idx}"
                );
            }
        }

        let chosen_action = candidates
            .get(chosen_index)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("chosen_index out of range"))?;
        let mut decision = Decision {
            chosen_index,
            chosen_action,
            policy_hash: policy_hash.clone(),
            decision_commitment: Hash32([0u8; 32]),
        };
        decision.decision_commitment = mprd_core::hash::hash_decision(&decision);

        let store_for_attestor = DirPolicyArtifactStore::new(policy_artifacts_dir);
        let (policy_ref, attestor) =
            mprd_zk::create_registry_bound_mpb_v1_attestor_from_signed_registry_state(
                signed,
                registry_vk,
                manifest_vk,
                store_for_attestor,
                MPB_FUEL_LIMIT_V1,
            )
            .context("Failed to create registry-bound mpb-v1 attestor")?;

        let timestamp_ms = timestamp_ms.unwrap_or_else(now_ms);

        let mut token = DecisionToken {
            policy_hash: decision.policy_hash.clone(),
            policy_ref: policy_ref.clone(),
            state_hash: state.state_hash.clone(),
            state_ref: state.state_ref.clone(),
            chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
            nonce_or_tx_hash,
            timestamp_ms,
            signature: Vec::new(),
        };
        token.signature = signing_key.sign_token(&token).to_vec();

        let proof = attestor
            .attest(&token, &decision, &state, &candidates)
            .map_err(|e| anyhow::anyhow!(e))
            .context("Failed to generate proof")?;

        let proof_output = serde_json::json!({
            "policy_hash": hex::encode(proof.policy_hash.0),
            "state_hash": hex::encode(proof.state_hash.0),
            "candidate_set_hash": hex::encode(proof.candidate_set_hash.0),
            "chosen_action_hash": hex::encode(proof.chosen_action_hash.0),
            "limits_hash": hex::encode(proof.limits_hash.0),
            "limits_bytes_hex": hex::encode(&proof.limits_bytes),
            "chosen_action_preimage_hex": hex::encode(&proof.chosen_action_preimage),
            "risc0_receipt": hex::encode(&proof.risc0_receipt),
            "attestation_metadata": proof.attestation_metadata,
        });

        let proof_json = serde_json::to_string_pretty(&proof_output)?;
        fs::write(&output_path, &proof_json)
            .with_context(|| format!("Failed to write proof file: {}", output_path.display()))?;

        let token_output = serde_json::json!({
            "policy_hash": hex::encode(token.policy_hash.0),
            "policy_epoch": token.policy_ref.policy_epoch,
            "registry_root": hex::encode(token.policy_ref.registry_root.0),
            "state_hash": hex::encode(token.state_hash.0),
            "state_source_id": Some(hex::encode(token.state_ref.state_source_id.0)),
            "state_epoch": Some(token.state_ref.state_epoch),
            "state_attestation_hash": Some(hex::encode(token.state_ref.state_attestation_hash.0)),
            "chosen_action_hash": hex::encode(token.chosen_action_hash.0),
            "nonce_or_tx_hash": hex::encode(token.nonce_or_tx_hash.0),
            "timestamp_ms": token.timestamp_ms,
            "signature": hex::encode(&token.signature),
        });
        let token_json = serde_json::to_string_pretty(&token_output)?;
        fs::write(&token_out_path, &token_json)
            .with_context(|| format!("Failed to write token file: {}", token_out_path.display()))?;

        println!("✅ Proof generated successfully");
        println!();
        println!("   Proof:  {}", output_path.display());
        println!("   Token:  {}", token_out_path.display());
        println!("   Receipt size: {} bytes", proof.risc0_receipt.len());
        println!();
        println!(
            "Verify with: mprd verify --proof {} --token {} --registry-state {} --registry-key-hex <vk_hex>",
            output_path.display(),
            token_out_path.display(),
            registry_path.display(),
        );

        return Ok(());
    }

    // Build decision
    let chosen_index = decision_input
        .chosen_index
        .ok_or_else(|| anyhow::anyhow!("decision.chosen_index is required in demo mode"))?;
    if chosen_index >= candidates.len() {
        anyhow::bail!(
            "chosen_index {} out of range (candidates: {})",
            chosen_index,
            candidates.len()
        );
    }

    let chosen_action = candidates[chosen_index].clone();

    let mut decision = Decision {
        chosen_index,
        chosen_action,
        policy_hash: policy_hash.clone(),
        decision_commitment: Hash32([0u8; 32]),
    };
    decision.decision_commitment = mprd_core::hash::hash_decision(&decision);

    println!(
        "   Decision: index {} -> {}",
        chosen_index, decision.chosen_action.action_type
    );
    println!("   Policy:   {}", decision_input.policy_hash);
    println!("   Candidates: {}", candidates.len());
    println!();

    // Demo-only: use MPB-in-guest with an allow-all policy (PUSH 1; HALT) and deterministic
    // selection in-guest. This avoids the host-trusted verdict path.
    //
    // NOTE: This is still `--insecure-demo` because:
    // - token is unsigned and uses placeholder policy/state provenance refs
    // - policy is an embedded allow-all bytecode, not fetched/authorized from registry_state
    let allow_all_bytecode = mprd_core::mpb::BytecodeBuilder::new()
        .push_i64(1)
        .halt()
        .build();
    let allow_all_policy_hash = Hash32(mprd_mpb::policy_hash_v1(&allow_all_bytecode, &[]));
    if policy_hash != allow_all_policy_hash {
        anyhow::bail!(
            "Demo-only: `mprd prove` currently supports only the embedded allow-all MPB policy. Expected policy_hash={}, got {}",
            hex::encode(allow_all_policy_hash.0),
            hex::encode(policy_hash.0)
        );
    }

    // Deterministic selection in mpb_guest: highest score wins (ties -> first).
    let mut expected_index = 0usize;
    let mut best_score = i64::MIN;
    for (i, c) in candidates.iter().enumerate() {
        if c.score.0 > best_score {
            best_score = c.score.0;
            expected_index = i;
        }
    }
    if chosen_index != expected_index {
        anyhow::bail!(
            "Chosen index does not match deterministic in-guest selection for the embedded allow-all policy. Expected chosen_index={}, got {}",
            expected_index,
            chosen_index
        );
    }

    // Create attestor and generate proof (MPB-in-guest).
    let mut image_id = [0u8; 32];
    for (i, word) in MPRD_MPB_GUEST_ID.iter().enumerate() {
        image_id[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    let mut policy_store = HashMap::new();
    policy_store.insert(
        policy_hash.clone(),
        MpbPolicyArtifactV1 {
            bytecode: allow_all_bytecode,
            variables: vec![],
        },
    );
    let attestor = Risc0MpbAttestor::new(
        MPRD_MPB_GUEST_ELF,
        image_id,
        MPB_FUEL_LIMIT_V1,
        Arc::new(policy_store),
    );

    // NOTE: demo-only token. In production, `nonce_or_tx_hash` MUST be derived from the triggering
    // request (or chain tx hash) and tokens MUST be signed.
    let mut token = DecisionToken {
        policy_hash: decision.policy_hash.clone(),
        policy_ref: PolicyRef {
            policy_epoch: 0,
            registry_root: Hash32([0u8; 32]),
        },
        state_hash: state.state_hash.clone(),
        state_ref: state.state_ref.clone(),
        chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
        nonce_or_tx_hash: Hash32([0u8; 32]),
        timestamp_ms: 0,
        signature: Vec::new(),
    };
    // Demo-only signing: produces a stable, non-empty signature so `mprd verify` can parse it,
    // but is not a production key.
    let demo_seed = [0xABu8; 32];
    let demo_signing_key = TokenSigningKey::from_seed(&demo_seed);
    token.signature = demo_signing_key.sign_token(&token).to_vec();

    let proof = attestor
        .attest(&token, &decision, &state, &candidates)
        .context("Failed to generate proof")?;

    // Serialize proof to JSON
    let proof_output = serde_json::json!({
        "policy_hash": hex::encode(proof.policy_hash.0),
        "state_hash": hex::encode(proof.state_hash.0),
        "candidate_set_hash": hex::encode(proof.candidate_set_hash.0),
        "chosen_action_hash": hex::encode(proof.chosen_action_hash.0),
        "limits_hash": hex::encode(proof.limits_hash.0),
        "limits_bytes_hex": hex::encode(&proof.limits_bytes),
        "chosen_action_preimage_hex": hex::encode(&proof.chosen_action_preimage),
        "risc0_receipt": hex::encode(&proof.risc0_receipt),
        "attestation_metadata": proof.attestation_metadata,
    });

    let proof_json = serde_json::to_string_pretty(&proof_output)?;
    fs::write(&output_path, &proof_json)
        .with_context(|| format!("Failed to write proof file: {}", output_path.display()))?;

    let token_output = serde_json::json!({
        "policy_hash": hex::encode(token.policy_hash.0),
        "policy_epoch": token.policy_ref.policy_epoch,
        "registry_root": hex::encode(token.policy_ref.registry_root.0),
        "state_hash": hex::encode(token.state_hash.0),
        "state_source_id": Option::<String>::None,
        "state_epoch": Option::<u64>::None,
        "state_attestation_hash": Option::<String>::None,
        "chosen_action_hash": hex::encode(token.chosen_action_hash.0),
        "nonce_or_tx_hash": hex::encode(token.nonce_or_tx_hash.0),
        "timestamp_ms": token.timestamp_ms,
        "signature": hex::encode(&token.signature),
    });
    let token_json = serde_json::to_string_pretty(&token_output)?;
    fs::write(&token_out_path, &token_json)
        .with_context(|| format!("Failed to write token file: {}", token_out_path.display()))?;

    println!("✅ Proof generated successfully");
    println!();
    println!("   Proof:  {}", output_path.display());
    println!("   Token:  {}", token_out_path.display());
    println!("   Receipt size: {} bytes", proof.risc0_receipt.len());
    println!();
    println!(
        "Verify with: mprd verify --proof {} --token {} --image-id {} --insecure-demo",
        output_path.display(),
        token_out_path.display(),
        hex::encode(image_id),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_fails_closed_without_insecure_demo_flag() {
        let err = run(ProveCommand {
            decision_path: PathBuf::from("missing-decision.json"),
            state_path: PathBuf::from("missing-state.json"),
            candidates_path: PathBuf::from("missing-candidates.json"),
            output_path: PathBuf::from("missing-output.json"),
            token_output: None,
            production: None,
            insecure_demo: false,
            config_path: None,
        })
        .expect_err("should refuse to prove without explicit insecure_demo");

        assert_eq!(
            err.downcast_ref::<ProveCommandError>(),
            Some(&ProveCommandError::InsecureDemoRequired)
        );
    }
}
