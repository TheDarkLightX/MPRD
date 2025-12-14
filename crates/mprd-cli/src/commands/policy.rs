//! `mprd policy` command implementations

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

use super::load_config;
use mprd_adapters::storage::{LocalPolicyStorage, PolicyStorage};

pub fn add(file: PathBuf, name: Option<String>, config_path: Option<PathBuf>) -> Result<()> {
    let config = load_config(config_path)?;

    // Read policy file
    let policy_bytes = fs::read(&file)
        .with_context(|| format!("Failed to read policy file: {}", file.display()))?;

    // Create storage
    let storage_dir = config
        .policy_storage
        .local_dir
        .unwrap_or_else(|| PathBuf::from(".mprd/policies"));

    let storage =
        LocalPolicyStorage::new(&storage_dir).context("Failed to initialize policy storage")?;

    // Store policy
    let hash = storage
        .store(&policy_bytes)
        .context("Failed to store policy")?;

    let hash_hex = hex::encode(hash.0);

    println!("✅ Policy added successfully");
    println!();
    println!("   Hash: {}", hash_hex);
    println!("   Size: {} bytes", policy_bytes.len());
    if let Some(n) = name {
        println!("   Name: {}", n);
    }
    println!();
    println!("Use this hash with: mprd run --policy {}", hash_hex);

    Ok(())
}

pub fn list(format: String, config_path: Option<PathBuf>) -> Result<()> {
    let config = load_config(config_path)?;

    let storage_dir = config
        .policy_storage
        .local_dir
        .unwrap_or_else(|| PathBuf::from(".mprd/policies"));

    let storage =
        LocalPolicyStorage::new(&storage_dir).context("Failed to initialize policy storage")?;

    let hashes = storage.list().context("Failed to list policies")?;

    if format == "json" {
        let json_hashes: Vec<String> = hashes.iter().map(|h| hex::encode(h.0)).collect();
        println!("{}", serde_json::to_string_pretty(&json_hashes)?);
        return Ok(());
    }

    if hashes.is_empty() {
        println!("No policies found.");
        println!();
        println!("Add a policy with: mprd policy add --file <policy.tau>");
        return Ok(());
    }

    println!("📋 Stored Policies ({} total)", hashes.len());
    println!();
    for hash in &hashes {
        println!("   {}", hex::encode(hash.0));
    }

    Ok(())
}

pub fn get(hash_hex: String, format: String, config_path: Option<PathBuf>) -> Result<()> {
    let config = load_config(config_path)?;

    let storage_dir = config
        .policy_storage
        .local_dir
        .unwrap_or_else(|| PathBuf::from(".mprd/policies"));

    let storage =
        LocalPolicyStorage::new(&storage_dir).context("Failed to initialize policy storage")?;

    // Parse hash
    let hash_bytes = hex::decode(&hash_hex).context("Invalid hash hex")?;

    if hash_bytes.len() != 32 {
        anyhow::bail!("Hash must be 32 bytes (64 hex characters)");
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash_bytes);
    let hash = mprd_core::Hash32(arr);

    // Retrieve policy
    let policy_bytes = storage
        .retrieve(&hash)
        .context("Failed to retrieve policy")?
        .ok_or_else(|| anyhow::anyhow!("Policy not found: {}", hash_hex))?;

    if format == "raw" {
        // Output raw bytes
        std::io::Write::write_all(&mut std::io::stdout(), &policy_bytes)?;
    } else {
        // Try to parse as UTF-8, fallback to base64
        match String::from_utf8(policy_bytes.clone()) {
            Ok(text) => {
                println!(
                    "{}",
                    serde_json::json!({
                        "hash": hash_hex,
                        "size": policy_bytes.len(),
                        "content": text,
                    })
                );
            }
            Err(_) => {
                println!(
                    "{}",
                    serde_json::json!({
                        "hash": hash_hex,
                        "size": policy_bytes.len(),
                        "content_base64": base64_encode(&policy_bytes)?,
                    })
                );
            }
        }
    }

    Ok(())
}

pub fn validate(file: PathBuf) -> Result<()> {
    // Read policy file
    let policy_bytes = fs::read(&file)
        .with_context(|| format!("Failed to read policy file: {}", file.display()))?;

    // Basic validation
    if policy_bytes.is_empty() {
        anyhow::bail!("Policy file is empty");
    }

    // Try to parse as UTF-8
    let policy_text =
        String::from_utf8(policy_bytes.clone()).context("Policy is not valid UTF-8")?;

    // Check for common Tau patterns (basic heuristic)
    let has_tau_keywords = policy_text.contains("forall")
        || policy_text.contains("exists")
        || policy_text.contains("=>")
        || policy_text.contains("&&")
        || policy_text.contains("||");

    println!("📄 Policy Validation");
    println!();
    println!("   File: {}", file.display());
    println!("   Size: {} bytes", policy_bytes.len());
    println!("   UTF-8: ✅");
    println!(
        "   Tau-like syntax: {}",
        if has_tau_keywords {
            "✅"
        } else {
            "⚠️ (no keywords found)"
        }
    );
    println!();

    if !has_tau_keywords {
        println!(
            "⚠️  Warning: No Tau keywords detected. This may not be a valid Tau specification."
        );
        println!("   Expected keywords: forall, exists, =>, &&, ||");
    } else {
        println!("✅ Basic validation passed.");
        println!();
        println!("Note: Full validation requires the Tau binary. Run with --check-tau to verify.");
    }

    Ok(())
}

fn base64_encode(data: &[u8]) -> Result<String> {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut encoder =
            base64::write::EncoderWriter::new(&mut buf, &base64::engine::general_purpose::STANDARD);
        encoder
            .write_all(data)
            .context("Failed to base64-encode policy bytes")?;
    }
    String::from_utf8(buf).context("Base64 output was not valid UTF-8")
}
