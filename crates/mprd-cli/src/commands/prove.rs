//! `mprd prove` command implementation

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use mprd_core::{CandidateAction, Decision, Hash32, RuleVerdict, Score, StateSnapshot, Value};
use mprd_risc0_methods::{MPRD_GUEST_ELF, MPRD_GUEST_ID};
use mprd_zk::create_risc0_attestor;

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

pub fn run(
    decision_path: PathBuf,
    state_path: PathBuf,
    candidates_path: PathBuf,
    output_path: PathBuf,
    insecure_demo: bool,
    _config_path: Option<PathBuf>,
) -> Result<()> {
    if !insecure_demo {
        anyhow::bail!(
            "Refusing to prove: `mprd prove` currently fabricates an allow-all RuleVerdict. Re-run with --insecure-demo to acknowledge demo-only behavior."
        );
    }

    println!("🔐 Generating ZK proof...");
    println!();

    // Load decision
    #[derive(serde::Deserialize)]
    struct DecisionInput {
        chosen_index: usize,
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
        .filter_map(|(key, value)| json_to_value(value).map(|v| (key, v)))
        .collect();

    let state = StateSnapshot {
        fields,
        policy_inputs: HashMap::new(),
        state_hash: Hash32([0u8; 32]),
    };

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
                .filter_map(|(key, value)| json_to_value(value).map(|v| (key, v)))
                .collect();

            CandidateAction {
                action_type: c.action_type,
                params,
                score: Score(c.score),
                candidate_hash: Hash32([0u8; 32]),
            }
        })
        .collect();

    // Parse policy hash
    let policy_bytes =
        hex::decode(&decision_input.policy_hash).context("Invalid policy hash hex")?;
    if policy_bytes.len() != 32 {
        anyhow::bail!("Policy hash must be 32 bytes");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&policy_bytes);
    let policy_hash = Hash32(arr);

    // Build decision
    if decision_input.chosen_index >= candidates.len() {
        anyhow::bail!(
            "chosen_index {} out of range (candidates: {})",
            decision_input.chosen_index,
            candidates.len()
        );
    }

    let chosen_action = candidates[decision_input.chosen_index].clone();

    let decision = Decision {
        chosen_index: decision_input.chosen_index,
        chosen_action,
        policy_hash: policy_hash.clone(),
        decision_commitment: Hash32([0u8; 32]),
    };

    println!(
        "   Decision: index {} -> {}",
        decision_input.chosen_index, decision.chosen_action.action_type
    );
    println!("   Policy:   {}", decision_input.policy_hash);
    println!("   Candidates: {}", candidates.len());
    println!();

    // Create attestor and generate proof
    let mut image_id = [0u8; 32];
    for (i, word) in MPRD_GUEST_ID.iter().enumerate() {
        image_id[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    let attestor = create_risc0_attestor(MPRD_GUEST_ELF, image_id);

    let verdict = RuleVerdict {
        allowed: true,
        reasons: Vec::new(),
        limits: HashMap::new(),
    };

    let proof = attestor
        .attest_with_verdict(&decision, &state, &candidates, &verdict)
        .context("Failed to generate proof")?;

    // Serialize proof to JSON
    let proof_output = serde_json::json!({
        "policy_hash": hex::encode(proof.policy_hash.0),
        "state_hash": hex::encode(proof.state_hash.0),
        "candidate_set_hash": hex::encode(proof.candidate_set_hash.0),
        "chosen_action_hash": hex::encode(proof.chosen_action_hash.0),
        "risc0_receipt": hex::encode(&proof.risc0_receipt),
        "attestation_metadata": proof.attestation_metadata,
    });

    let proof_json = serde_json::to_string_pretty(&proof_output)?;
    fs::write(&output_path, &proof_json)
        .with_context(|| format!("Failed to write proof file: {}", output_path.display()))?;

    println!("✅ Proof generated successfully");
    println!();
    println!("   Output: {}", output_path.display());
    println!("   Receipt size: {} bytes", proof.risc0_receipt.len());
    println!();
    println!(
        "Verify with: mprd verify --proof {} --token <token.json>",
        output_path.display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_fails_closed_without_insecure_demo_flag() {
        let err = run(
            PathBuf::from("missing-decision.json"),
            PathBuf::from("missing-state.json"),
            PathBuf::from("missing-candidates.json"),
            PathBuf::from("missing-output.json"),
            false,
            None,
        )
        .expect_err("should refuse to prove without explicit insecure_demo");

        assert!(err.to_string().contains("Refusing to prove"));
    }
}
