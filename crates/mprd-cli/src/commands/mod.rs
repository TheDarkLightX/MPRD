//! CLI Command Implementations

pub mod deploy;
pub mod doctor;
pub mod fees;
pub mod init;
pub mod markets;
pub mod panel;
pub mod policy;
pub mod policy_algebra;
pub mod policy_test;
pub mod policy_verify;
pub mod prove;
pub mod run;
pub mod serve;
pub mod staking;
pub mod status;
pub mod tokenomics;
pub mod verify;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// MPRD configuration file structure.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MprdConfigFile {
    /// Deployment mode.
    pub mode: String,

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

impl Default for MprdConfigFile {
    fn default() -> Self {
        Self {
            mode: "trustless".into(),
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
        }
    }
}

/// Load config from file or return default.
pub fn load_config(path: Option<PathBuf>) -> Result<MprdConfigFile> {
    let path = path.unwrap_or_else(|| {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("mprd")
            .join("config.json")
    });

    if path.exists() {
        let content = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&content)?)
    } else {
        Ok(MprdConfigFile::default())
    }
}
