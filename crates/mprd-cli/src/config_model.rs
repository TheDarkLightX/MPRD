use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MprdConfigFile {
    /// Deployment mode.
    pub mode: String,

    /// Optional production trust mode (`high_trust` or `low_trust`).
    #[serde(default)]
    pub trust_mode: Option<String>,

    /// Operator HTTP route scope (`all`, `observer`, or `control`).
    #[serde(default = "default_serve_route_scope")]
    pub serve_route_scope: String,

    /// Policy storage configuration.
    pub policy_storage: PolicyStorageConfig,

    /// Tau binary path.
    pub tau_binary: Option<String>,

    /// Risc0 image ID (hex).
    pub risc0_image_id: Option<String>,

    /// Execution configuration.
    pub execution: ExecutionConfig,

    /// Anti-replay configuration.
    pub anti_replay: Option<AntiReplayConfig>,

    /// Low-trust distributed coordination configuration.
    #[serde(default)]
    pub low_trust: Option<LowTrustConfig>,

    /// State provenance enforcement configuration.
    #[serde(default)]
    pub state_provenance: StateProvenanceConfig,

    /// Registry state path.
    pub registry_state_path: Option<PathBuf>,

    /// Registry verifying key (hex).
    pub registry_verifying_key_hex: Option<String>,

    /// Token signing key (hex).
    pub token_signing_key_hex: Option<String>,

    /// Environment variable holding the token signing key (hex).
    pub token_signing_key_env_var: Option<String>,

    /// Policy artifacts directory.
    pub policy_artifacts_dir: Option<PathBuf>,
}

fn default_serve_route_scope() -> String {
    "all".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyStorageConfig {
    /// Storage type: local, ipfs.
    pub storage_type: String,

    /// Local storage directory.
    pub local_dir: Option<PathBuf>,

    /// IPFS API URL.
    pub ipfs_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionConfig {
    /// Executor type: noop, http, file.
    pub executor_type: String,

    /// HTTP executor URL.
    pub http_url: Option<String>,

    /// File executor path.
    pub audit_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AntiReplayConfig {
    /// Optional durable nonce store directory.
    pub nonce_store_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LowTrustConfig {
    /// Distributed nonce backend: redis.
    pub nonce_store_backend: Option<String>,

    /// Redis URL for distributed nonce storage.
    pub redis_url: Option<String>,

    /// Redis key prefix for nonce entries.
    pub redis_key_prefix: Option<String>,

    /// Redis operation timeout in milliseconds.
    pub redis_timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StateProvenanceConfig {
    /// Whether production execution requires state provenance.
    pub require_provenance: bool,

    /// Allowlisted state provenance scheme IDs (hex-encoded 32-byte ids).
    pub allowed_state_source_ids_hex: Vec<String>,
}

impl Default for MprdConfigFile {
    fn default() -> Self {
        Self {
            mode: "trustless".into(),
            trust_mode: None,
            serve_route_scope: default_serve_route_scope(),
            policy_storage: PolicyStorageConfig {
                storage_type: "local".into(),
                local_dir: Some(PathBuf::from(".mprd/policies")),
                ipfs_url: None,
            },
            tau_binary: None,
            risc0_image_id: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".into(),
            ),
            execution: ExecutionConfig {
                executor_type: "noop".into(),
                http_url: None,
                audit_file: Some(PathBuf::from(".mprd/audit.jsonl")),
            },
            anti_replay: Some(AntiReplayConfig {
                nonce_store_dir: Some(PathBuf::from(".mprd/anti_replay")),
            }),
            low_trust: None,
            state_provenance: StateProvenanceConfig::default(),
            registry_state_path: None,
            registry_verifying_key_hex: None,
            token_signing_key_hex: None,
            token_signing_key_env_var: None,
            policy_artifacts_dir: None,
        }
    }
}
