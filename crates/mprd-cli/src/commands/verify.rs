//! `mprd verify` command implementation

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::fs;
use std::collections::HashMap;

use mprd_core::{DecisionToken, Hash32, ProofBundle, VerificationStatus, ZkLocalVerifier};
use mprd_zk::{create_risc0_verifier};

pub fn run(
    proof_path: PathBuf,
    token_path: PathBuf,
    image_id_hex: Option<String>,
) -> Result<()> {
    println!("🔍 Verifying proof bundle...");
    println!();
    
    // Load proof
    let proof_json = fs::read_to_string(&proof_path)
        .with_context(|| format!("Failed to read proof file: {}", proof_path.display()))?;
    
    #[derive(serde::Deserialize)]
    struct ProofInput {
        policy_hash: String,
        state_hash: String,
        candidate_set_hash: String,
        chosen_action_hash: String,
        risc0_receipt: String, // base64 or hex
        attestation_metadata: HashMap<String, String>,
    }
    
    let proof_input: ProofInput = serde_json::from_str(&proof_json)
        .context("Failed to parse proof JSON")?;
    
    // Load token
    let token_json = fs::read_to_string(&token_path)
        .with_context(|| format!("Failed to read token file: {}", token_path.display()))?;
    
    #[derive(serde::Deserialize)]
    struct TokenInput {
        policy_hash: String,
        state_hash: String,
        chosen_action_hash: String,
        nonce_or_tx_hash: String,
        timestamp_ms: i64,
        signature: String, // hex
    }
    
    let token_input: TokenInput = serde_json::from_str(&token_json)
        .context("Failed to parse token JSON")?;
    
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
    
    let proof = ProofBundle {
        policy_hash: parse_hash(&proof_input.policy_hash)?,
        state_hash: parse_hash(&proof_input.state_hash)?,
        candidate_set_hash: parse_hash(&proof_input.candidate_set_hash)?,
        chosen_action_hash: parse_hash(&proof_input.chosen_action_hash)?,
        risc0_receipt: hex::decode(&proof_input.risc0_receipt)
            .unwrap_or_else(|_| proof_input.risc0_receipt.as_bytes().to_vec()),
        attestation_metadata: proof_input.attestation_metadata,
    };
    
    let token = DecisionToken {
        policy_hash: parse_hash(&token_input.policy_hash)?,
        state_hash: parse_hash(&token_input.state_hash)?,
        chosen_action_hash: parse_hash(&token_input.chosen_action_hash)?,
        nonce_or_tx_hash: parse_hash(&token_input.nonce_or_tx_hash)?,
        timestamp_ms: token_input.timestamp_ms,
        signature: hex::decode(&token_input.signature).unwrap_or_default(),
    };
    
    println!("   Proof file: {}", proof_path.display());
    println!("   Token file: {}", token_path.display());
    println!();
    
    // Create verifier
    let image_id = if let Some(hex) = image_id_hex {
        let bytes = hex::decode(&hex).context("Invalid image ID hex")?;
        if bytes.len() != 32 {
            anyhow::bail!("Image ID must be 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    } else {
        [0u8; 32] // Default placeholder
    };
    
    let verifier = create_risc0_verifier(image_id);
    
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
