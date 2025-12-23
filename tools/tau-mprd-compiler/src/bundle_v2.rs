//! Policy Bundle v2 — production-ready output format.
//!
//! Contains everything needed to register and use a compiled policy.

use crate::error::CompileResult;
use crate::ir_v2::CompiledPolicyV2;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Policy Bundle v2 — complete deployment artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundleV2 {
    /// Bundle format version.
    pub bundle_version: u32,
    
    /// Policy source kind identifier (32-byte derived ID).
    #[serde(with = "hex_serde")]
    pub policy_source_kind_id: [u8; 32],

    /// Human-readable descriptor for `policy_source_kind_id`.
    pub policy_source_kind_descriptor: String,
    
    /// Hash of the Tau-MPRD source bytes.
    #[serde(with = "hex_serde")]
    pub policy_source_hash: [u8; 32],
    
    /// Policy execution kind identifier (32-byte derived ID).
    #[serde(with = "hex_serde")]
    pub policy_exec_kind_id: [u8; 32],

    /// Human-readable descriptor for `policy_exec_kind_id`.
    pub policy_exec_kind_descriptor: String,
    
    /// Policy execution version identifier (32-byte derived ID).
    #[serde(with = "hex_serde")]
    pub policy_exec_version_id: [u8; 32],

    /// Human-readable descriptor for `policy_exec_version_id`.
    pub policy_exec_version_descriptor: String,
    
    /// Hash of the compiled artifact (what guest commits).
    #[serde(with = "hex_serde")]
    pub policy_hash: [u8; 32],

    /// Limits bytes committed by the guest (currently empty for tau-compiled v2).
    #[serde(with = "hex_serde_vec")]
    pub limits_bytes: Vec<u8>,

    /// Hash of `limits_bytes` (domain-separated).
    #[serde(with = "hex_serde")]
    pub limits_hash: [u8; 32],
    
    /// Compiled artifact bytes (hex-encoded).
    #[serde(with = "hex_serde_vec")]
    pub compiled_policy_bytes: Vec<u8>,
    
    /// Schema information for input construction.
    pub schema: PolicySchemaV2,
    
    /// Registry entry snippet for authorization.
    pub registry_entry: RegistryEntrySnippetV2,
    
    /// Optional: compiler provenance for audit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_provenance: Option<CompilerProvenanceV2>,
    
    /// Optional: input templates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub templates: Option<InputTemplatesV2>,
}

/// Schema information for constructing valid inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySchemaV2 {
    /// Required state keys (field names).
    pub required_state_keys: Vec<String>,
    
    /// Required candidate keys (field names).
    pub required_candidate_keys: Vec<String>,
    
    /// State key name → hash mapping.
    pub state_key_hashes: BTreeMap<String, String>,
    
    /// Candidate key name → hash mapping.
    pub candidate_key_hashes: BTreeMap<String, String>,
    
    /// Temporal fields with lookback requirements.
    pub temporal_fields: Vec<TemporalFieldSchemaV2>,
}

/// Temporal field schema entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalFieldSchemaV2 {
    /// Base field name.
    pub field_name: String,
    
    /// Maximum lookback (e.g., 2 means t-1 and t-2 needed).
    pub max_lookback: usize,
    
    /// Derived key names (e.g., ["field_t_1", "field_t_2"]).
    pub derived_keys: Vec<String>,
}

/// Registry entry snippet for policy authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntrySnippetV2 {
    #[serde(with = "hex_serde")]
    pub policy_hash: [u8; 32],
    #[serde(with = "hex_serde")]
    pub policy_exec_kind_id: [u8; 32],
    #[serde(with = "hex_serde")]
    pub policy_exec_version_id: [u8; 32],
    #[serde(with = "hex_serde")]
    pub policy_source_kind_id: [u8; 32],
    #[serde(with = "hex_serde")]
    pub policy_source_hash: [u8; 32],
}

/// Compiler provenance for audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerProvenanceV2 {
    /// Compiler version.
    pub compiler_version: String,
    
    /// Git commit hash (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_hash: Option<String>,
    
    /// Build timestamp (ISO 8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_timestamp: Option<String>,
}

/// Input templates for testing/development.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputTemplatesV2 {
    /// State template with placeholder values.
    pub state_template: BTreeMap<String, serde_json::Value>,
    
    /// Candidate template with placeholder values.
    pub candidate_template: BTreeMap<String, serde_json::Value>,
}

/// Build a policy bundle from compilation output.
pub fn build_bundle_v2(
    _source: &str,
    policy_source_hash: [u8; 32],
    policy_hash: [u8; 32],
    artifact: &CompiledPolicyV2,
    artifact_bytes: Vec<u8>,
) -> CompileResult<PolicyBundleV2> {
    // Build schema
    let mut required_state_keys: Vec<String> = artifact.state_keys.keys().cloned().collect();
    required_state_keys.sort();
    
    let mut required_candidate_keys: Vec<String> = artifact.candidate_keys.keys().cloned().collect();
    required_candidate_keys.sort();
    
    let state_key_hashes: BTreeMap<String, String> = artifact.state_keys
        .iter()
        .map(|(k, v)| (k.clone(), hex::encode(v)))
        .collect();
    
    let candidate_key_hashes: BTreeMap<String, String> = artifact.candidate_keys
        .iter()
        .map(|(k, v)| (k.clone(), hex::encode(v)))
        .collect();
    
    let temporal_fields: Vec<TemporalFieldSchemaV2> = artifact.temporal_fields
        .iter()
        .map(|tf| {
            let derived_keys: Vec<String> = (1..=tf.max_lookback)
                .map(|i| format!("{}_t_{}", tf.field_name, i))
                .collect();
            TemporalFieldSchemaV2 {
                field_name: tf.field_name.clone(),
                max_lookback: tf.max_lookback,
                derived_keys,
            }
        })
        .collect();
    
    let schema = PolicySchemaV2 {
        required_state_keys,
        required_candidate_keys,
        state_key_hashes,
        candidate_key_hashes,
        temporal_fields,
    };
    
    let policy_source_kind_descriptor = "mprd.policy_source.tau_v1".to_string();
    let policy_exec_kind_descriptor = "mprd.policy_exec.tau_compiled_v1".to_string();
    let policy_exec_version_descriptor = "v2".to_string();

    let policy_source_kind_id = mprd_risc0_shared::policy_source_kind_tau_id_v1();
    let policy_exec_kind_id = mprd_risc0_shared::policy_exec_kind_tau_compiled_id_v1();
    let policy_exec_version_id =
        mprd_risc0_shared::id(mprd_risc0_shared::domains::ID, policy_exec_version_descriptor.as_bytes());

    // v2: execution limits are not yet standardized; keep empty and bind it explicitly.
    let limits_bytes: Vec<u8> = Vec::new();
    let limits_hash = mprd_risc0_shared::limits_hash(&limits_bytes);

    // Build registry entry snippet
    let registry_entry = RegistryEntrySnippetV2 {
        policy_hash,
        policy_exec_kind_id,
        policy_exec_version_id,
        policy_source_kind_id,
        policy_source_hash,
    };
    
    // Build templates
    let mut state_template = BTreeMap::new();
    for key in &schema.required_state_keys {
        state_template.insert(key.clone(), serde_json::json!(0));
    }
    
    let mut candidate_template = BTreeMap::new();
    for key in &schema.required_candidate_keys {
        candidate_template.insert(key.clone(), serde_json::json!(0));
    }
    
    let templates = InputTemplatesV2 {
        state_template,
        candidate_template,
    };
    
    // Build provenance
    let provenance = CompilerProvenanceV2 {
        compiler_version: env!("CARGO_PKG_VERSION").to_string(),
        git_hash: option_env!("GIT_HASH").map(String::from),
        build_timestamp: None,
    };
    
    Ok(PolicyBundleV2 {
        bundle_version: 2,
        policy_source_kind_id,
        policy_source_kind_descriptor,
        policy_source_hash,
        policy_exec_kind_id,
        policy_exec_kind_descriptor,
        policy_exec_version_id,
        policy_exec_version_descriptor,
        policy_hash,
        limits_bytes,
        limits_hash,
        compiled_policy_bytes: artifact_bytes,
        schema,
        registry_entry,
        compiler_provenance: Some(provenance),
        templates: Some(templates),
    })
}

/// Serialize bundle to JSON.
pub fn bundle_to_json(bundle: &PolicyBundleV2) -> CompileResult<String> {
    serde_json::to_string_pretty(bundle)
        .map_err(|e| crate::error::CompileError::internal(format!("JSON serialization failed: {}", e)))
}

/// Deserialize bundle from JSON.
pub fn bundle_from_json(json: &str) -> CompileResult<PolicyBundleV2> {
    serde_json::from_str(json)
        .map_err(|e| crate::error::CompileError::internal(format!("JSON deserialization failed: {}", e)))
}

// Hex serialization helpers
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    
    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

mod hex_serde_vec {
    use serde::{Deserialize, Deserializer, Serializer};
    
    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile_v2;
    
    #[test]
    fn build_simple_bundle() {
        let source = "always (state.balance >= candidate.amount)";
        let output = compile_v2(source).unwrap();
        
        let bundle = build_bundle_v2(
            source,
            output.policy_source_hash,
            output.policy_hash,
            &output.artifact,
            output.artifact_bytes,
        ).unwrap();
        
        assert_eq!(bundle.bundle_version, 2);
        assert!(bundle.schema.required_state_keys.contains(&"balance".to_string()));
        assert!(bundle.schema.required_candidate_keys.contains(&"amount".to_string()));
    }
    
    #[test]
    fn bundle_roundtrip_json() {
        let source = "always (state.w0 * 2 + state.w1 * 3 >= state.threshold)";
        let output = compile_v2(source).unwrap();
        
        let bundle = build_bundle_v2(
            source,
            output.policy_source_hash,
            output.policy_hash,
            &output.artifact,
            output.artifact_bytes,
        ).unwrap();
        
        let json = bundle_to_json(&bundle).unwrap();
        let restored = bundle_from_json(&json).unwrap();
        
        assert_eq!(bundle.policy_hash, restored.policy_hash);
        assert_eq!(bundle.compiled_policy_bytes, restored.compiled_policy_bytes);
    }
    
    #[test]
    fn bundle_includes_temporal_schema() {
        let source = "always (state.x[t-2] < state.x)";
        let output = compile_v2(source).unwrap();
        
        let bundle = build_bundle_v2(
            source,
            output.policy_source_hash,
            output.policy_hash,
            &output.artifact,
            output.artifact_bytes,
        ).unwrap();
        
        assert_eq!(bundle.schema.temporal_fields.len(), 1);
        assert_eq!(bundle.schema.temporal_fields[0].field_name, "x");
        assert_eq!(bundle.schema.temporal_fields[0].max_lookback, 2);
        assert!(bundle.schema.temporal_fields[0].derived_keys.contains(&"x_t_1".to_string()));
        assert!(bundle.schema.temporal_fields[0].derived_keys.contains(&"x_t_2".to_string()));
    }
}
