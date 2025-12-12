//! `mprd run` command implementation

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::fs;
use std::collections::HashMap;

use super::load_config;
use mprd_core::{
    CandidateAction, DefaultSelector, Hash32, PolicyEngine, RuleVerdict,
    Score, Selector, StateSnapshot, Value,
};
use mprd_adapters::storage::{LocalPolicyStorage, PolicyStorage};

pub fn run(
    policy_hex: String,
    state_path: PathBuf,
    candidates_path: PathBuf,
    execute: bool,
    format: String,
    config_path: Option<PathBuf>,
) -> Result<()> {
    let config = load_config(config_path)?;
    
    // Parse policy hash
    let hash_bytes = hex::decode(&policy_hex)
        .context("Invalid policy hash hex")?;
    if hash_bytes.len() != 32 {
        anyhow::bail!("Policy hash must be 32 bytes (64 hex characters)");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash_bytes);
    let policy_hash = Hash32(arr);
    
    // Load state
    let state_json = fs::read_to_string(&state_path)
        .with_context(|| format!("Failed to read state file: {}", state_path.display()))?;
    let state_fields: HashMap<String, serde_json::Value> = serde_json::from_str(&state_json)
        .context("Failed to parse state JSON")?;
    
    let fields: HashMap<String, Value> = state_fields.into_iter()
        .filter_map(|(k, v)| {
            let value = match v {
                serde_json::Value::Bool(b) => Some(Value::Bool(b)),
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        Some(Value::Int(i))
                    } else if let Some(u) = n.as_u64() {
                        Some(Value::UInt(u))
                    } else {
                        None
                    }
                }
                serde_json::Value::String(s) => Some(Value::String(s)),
                _ => None,
            };
            value.map(|v| (k, v))
        })
        .collect();
    
    let state = StateSnapshot {
        fields,
        policy_inputs: HashMap::new(),
        state_hash: Hash32([0u8; 32]), // Will be computed
    };
    
    // Load candidates
    let candidates_json = fs::read_to_string(&candidates_path)
        .with_context(|| format!("Failed to read candidates file: {}", candidates_path.display()))?;
    
    #[derive(serde::Deserialize)]
    struct CandidateInput {
        action_type: String,
        params: HashMap<String, serde_json::Value>,
        score: i64,
    }
    
    let candidate_inputs: Vec<CandidateInput> = serde_json::from_str(&candidates_json)
        .context("Failed to parse candidates JSON")?;
    
    let candidates: Vec<CandidateAction> = candidate_inputs.into_iter()
        .map(|c| {
            let params: HashMap<String, Value> = c.params.into_iter()
                .filter_map(|(k, v)| {
                    let value = match v {
                        serde_json::Value::Bool(b) => Some(Value::Bool(b)),
                        serde_json::Value::Number(n) => {
                            if let Some(i) = n.as_i64() {
                                Some(Value::Int(i))
                            } else if let Some(u) = n.as_u64() {
                                Some(Value::UInt(u))
                            } else {
                                None
                            }
                        }
                        serde_json::Value::String(s) => Some(Value::String(s)),
                        _ => None,
                    };
                    value.map(|v| (k, v))
                })
                .collect();
            
            CandidateAction {
                action_type: c.action_type,
                params,
                score: Score(c.score),
                candidate_hash: Hash32([0u8; 32]), // Will be computed
            }
        })
        .collect();
    
    if format == "human" {
        println!("🚀 MPRD Pipeline");
        println!();
        println!("   Policy: {}", policy_hex);
        println!("   State fields: {}", state.fields.len());
        println!("   Candidates: {}", candidates.len());
        println!();
    }
    
    // For now, use a simple allow-all policy engine for demonstration
    // In production, this would use TauPolicyEngine
    let verdicts: Vec<RuleVerdict> = candidates.iter()
        .map(|_| RuleVerdict {
            allowed: true,
            reasons: vec![],
            limits: HashMap::new(),
        })
        .collect();
    
    // Run selector
    let selector = DefaultSelector;
    let decision = selector.select(&policy_hash, &state, &candidates, &verdicts)
        .context("Selector failed")?;
    
    if format == "json" {
        println!("{}", serde_json::json!({
            "chosen_index": decision.chosen_index,
            "chosen_action_type": decision.chosen_action.action_type,
            "chosen_action_score": decision.chosen_action.score.0,
            "policy_hash": policy_hex,
            "execute": execute,
        }));
    } else {
        println!("📊 Decision");
        println!();
        println!("   Chosen: [{}] {} (score: {})", 
            decision.chosen_index,
            decision.chosen_action.action_type,
            decision.chosen_action.score.0);
        println!();
        
        if execute {
            println!("⚡ Executing action...");
            println!();
            println!("   [Would execute in production mode]");
        } else {
            println!("💡 Dry run - use --execute to perform the action");
        }
    }
    
    Ok(())
}
