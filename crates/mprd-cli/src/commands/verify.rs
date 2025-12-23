//! `mprd verify` command implementation

use anyhow::{Context, Result};
use base64::Engine;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

use mprd_core::{
    DecisionToken, Hash32, PolicyRef, ProofBundle, StateRef, VerificationStatus, ZkLocalVerifier,
};
use mprd_zk::{
    create_production_verifier_from_signed_registry_state_with_manifest_key, create_risc0_verifier,
};

#[derive(Debug, Error, PartialEq, Eq)]
enum VerifyCommandError {
    #[error(
        "Refusing to verify without --registry-state. Re-run with --insecure-demo to acknowledge dev-only verification against a raw --image-id."
    )]
    RegistryStateRequired,
}

pub fn run(
    proof_path: PathBuf,
    token_path: PathBuf,
    image_id_hex: Option<String>,
    registry_state_path: Option<PathBuf>,
    registry_key_hex: Option<String>,
    manifest_key_hex: Option<String>,
    insecure_demo: bool,
) -> Result<()> {
    println!("🔍 Verifying proof bundle...");
    println!();

    // Fail-closed: require production registry-state verification unless explicitly acknowledged.
    if registry_state_path.is_none() && !insecure_demo {
        return Err(VerifyCommandError::RegistryStateRequired.into());
    }

    if registry_state_path.is_some()
        && registry_key_hex
            .as_deref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
    {
        anyhow::bail!("--registry-key-hex is required when --registry-state is provided");
    }

    // Load proof
    let proof_json = fs::read_to_string(&proof_path)
        .with_context(|| format!("Failed to read proof file: {}", proof_path.display()))?;

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ProofInput {
        policy_hash: String,
        state_hash: String,
        candidate_set_hash: String,
        chosen_action_hash: String,
        /// Optional hex-encoded canonical limits bytes. Defaults to empty.
        limits_bytes_hex: Option<String>,
        chosen_action_preimage_hex: Option<String>,
        risc0_receipt: String, // base64 or hex
        attestation_metadata: HashMap<String, String>,
    }

    let proof_input: ProofInput =
        serde_json::from_str(&proof_json).context("Failed to parse proof JSON")?;

    // Load token
    let token_json = fs::read_to_string(&token_path)
        .with_context(|| format!("Failed to read token file: {}", token_path.display()))?;

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TokenInput {
        policy_hash: String,
        policy_epoch: u64,
        registry_root: String,
        state_hash: String,
        state_source_id: Option<String>,
        state_epoch: Option<u64>,
        state_attestation_hash: Option<String>,
        chosen_action_hash: String,
        nonce_or_tx_hash: String,
        timestamp_ms: i64,
        signature: String, // hex
    }

    let token_input: TokenInput =
        serde_json::from_str(&token_json).context("Failed to parse token JSON")?;

    // Parse hashes
    fn parse_hash(hex: &str) -> Result<Hash32> {
        let bytes = hex::decode(hex).context("Invalid hex")?;
        if bytes.len() != 32 {
            anyhow::bail!("Hash must be 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Hash32(arr))
    }

    fn decode_receipt(encoded: &str) -> Result<Vec<u8>> {
        // Fail closed: accept only valid hex or valid base64 and reject empty payloads.
        // This prevents confusing "success" paths when decoding produces no bytes.
        // Prefer hex if it parses; otherwise try base64.
        if let Ok(bytes) = hex::decode(encoded) {
            if !bytes.is_empty() {
                return Ok(bytes);
            }
        }

        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .context("Receipt is not valid hex or base64")?;
        if bytes.is_empty() {
            anyhow::bail!("Receipt decoded to empty bytes");
        }
        Ok(bytes)
    }

    fn decode_signature_hex(hex_sig: &str) -> Result<Vec<u8>> {
        let bytes = hex::decode(hex_sig).context("Invalid signature hex")?;
        if bytes.is_empty() {
            anyhow::bail!("Signature decoded to empty bytes");
        }
        Ok(bytes)
    }

    let limits_bytes = proof_input
        .limits_bytes_hex
        .as_deref()
        .map(hex::decode)
        .transpose()
        .context("Invalid limits_bytes_hex")?
        .unwrap_or_default();
    let limits_hash = mprd_core::limits::limits_hash_v1(&limits_bytes);

    let proof = ProofBundle {
        policy_hash: parse_hash(&proof_input.policy_hash)?,
        state_hash: parse_hash(&proof_input.state_hash)?,
        candidate_set_hash: parse_hash(&proof_input.candidate_set_hash)?,
        chosen_action_hash: parse_hash(&proof_input.chosen_action_hash)?,
        limits_hash,
        limits_bytes,
        chosen_action_preimage: proof_input
            .chosen_action_preimage_hex
            .as_deref()
            .map(hex::decode)
            .transpose()
            .context("Invalid chosen_action_preimage_hex")?
            .unwrap_or_default(),
        risc0_receipt: decode_receipt(&proof_input.risc0_receipt)?,
        attestation_metadata: proof_input.attestation_metadata,
    };

    let token = DecisionToken {
        policy_hash: parse_hash(&token_input.policy_hash)?,
        policy_ref: PolicyRef {
            policy_epoch: token_input.policy_epoch,
            registry_root: parse_hash(&token_input.registry_root)?,
        },
        state_hash: parse_hash(&token_input.state_hash)?,
        state_ref: StateRef {
            state_source_id: token_input
                .state_source_id
                .as_deref()
                .map(parse_hash)
                .transpose()?
                .unwrap_or(Hash32([0u8; 32])),
            state_epoch: token_input.state_epoch.unwrap_or(0),
            state_attestation_hash: token_input
                .state_attestation_hash
                .as_deref()
                .map(parse_hash)
                .transpose()?
                .unwrap_or(Hash32([0u8; 32])),
        },
        chosen_action_hash: parse_hash(&token_input.chosen_action_hash)?,
        nonce_or_tx_hash: parse_hash(&token_input.nonce_or_tx_hash)?,
        timestamp_ms: token_input.timestamp_ms,
        signature: decode_signature_hex(&token_input.signature)?,
    };

    println!("   Proof file: {}", proof_path.display());
    println!("   Token file: {}", token_path.display());
    println!();

    // Create verifier
    let verifier: Box<dyn ZkLocalVerifier> = if let Some(path) = registry_state_path {
        let key_hex = registry_key_hex
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--registry-key-hex is required"))?;
        let registry_vk = mprd_core::TokenVerifyingKey::from_hex(key_hex)
            .context("Invalid --registry-key-hex")?;
        let manifest_vk = match manifest_key_hex.as_deref() {
            None => registry_vk.clone(),
            Some(hex) => {
                mprd_core::TokenVerifyingKey::from_hex(hex).context("Invalid --manifest-key-hex")?
            }
        };
        let json = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read registry_state file: {}", path.display()))?;
        let signed: mprd_zk::registry_state::SignedRegistryStateV1 =
            serde_json::from_str(&json).context("Failed to parse registry_state JSON")?;
        create_production_verifier_from_signed_registry_state_with_manifest_key(
            signed,
            &registry_vk,
            &manifest_vk,
        )
        .context("Failed to create production verifier from registry_state")?
    } else {
        let Some(hex) = image_id_hex else {
            anyhow::bail!("--image-id is required for dev-only verification");
        };
        let bytes = hex::decode(&hex).context("Invalid image ID hex")?;
        if bytes.len() != 32 {
            anyhow::bail!("Image ID must be 32 bytes");
        }
        let mut image_id = [0u8; 32];
        image_id.copy_from_slice(&bytes);
        Box::new(create_risc0_verifier(image_id))
    };

    // Verify
    let status = verifier.verify(&token, &proof);

    match status {
        VerificationStatus::Success => {
            println!("✅ Verification PASSED");
            println!();
            println!("   Policy hash:  {}", token_input.policy_hash);
            println!("   State hash:   {}", token_input.state_hash);
            println!("   Action hash:  {}", token_input.chosen_action_hash);
            println!();
            println!("The proof cryptographically attests that:");
            println!("   1. The selected action was in the candidate set");
            println!("   2. The policy allowed the selected action");
            println!("   3. The selector contract was satisfied");
        }
        VerificationStatus::Failure(reason) => {
            println!("❌ Verification FAILED");
            println!();
            println!("   Reason: {}", reason);
            std::process::exit(1);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_fails_closed_without_registry_state_or_insecure_demo() {
        let err = run(
            PathBuf::from("proof.json"),
            PathBuf::from("token.json"),
            None,
            None,
            None,
            None,
            false,
        )
        .unwrap_err();
        assert_eq!(
            err.downcast_ref::<VerifyCommandError>(),
            Some(&VerifyCommandError::RegistryStateRequired)
        );
    }
}
