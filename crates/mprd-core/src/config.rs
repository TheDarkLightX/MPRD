//! Configuration management for MPRD.
//!
//! Provides structured configuration with validation for all MPRD components.
//!
//! # Configuration Sources
//!
//! Configuration can be loaded from:
//! - Environment variables (prefixed with `MPRD_`)
//! - Configuration files (TOML, JSON)
//! - Programmatic defaults
//!
//! # Example
//!
//! ```rust,ignore
//! use mprd_core::config::MprdConfig;
//!
//! let config = MprdConfig::builder()
//!     .signing_key_hex("0123456789...")
//!     .max_candidates(64)
//!     .build()?;
//! ```

use crate::{MprdError, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

// =============================================================================
// Trust Modes
// =============================================================================

/// Trust mode for MPRD deployments.
///
/// Determines the level of decentralization and fault tolerance required.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    /// High-trust mode (single-operator deployments).
    ///
    /// Suitable for:
    /// - Single-node deployments
    /// - Operator-controlled environments
    /// - Development and testing
    ///
    /// Characteristics:
    /// - Single signer for registry state
    /// - Single signer for state snapshots
    /// - File-based nonce store (single node)
    /// - Single IPFS gateway
    #[default]
    HighTrust,

    /// Low-trust mode (decentralized deployments).
    ///
    /// Required for:
    /// - Multi-node deployments
    /// - Trustless/permissionless environments
    /// - Production deployments with no single point of failure
    ///
    /// Characteristics:
    /// - Quorum signatures (k-of-n) for registry state
    /// - Quorum signatures (k-of-n) for state snapshots
    /// - Distributed nonce store (multi-node)
    /// - Multi-gateway IPFS with failover
    /// - State freshness SLA enforcement
    LowTrust,
}

/// Low-trust mode specific configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LowTrustConfig {
    /// Minimum quorum threshold for registry state signatures.
    /// Must be >= 1 and <= number of trusted signers.
    pub registry_quorum_threshold: u8,

    /// Hex-encoded public keys of trusted registry signers.
    pub registry_trusted_signers_hex: Vec<String>,

    /// Minimum quorum threshold for state attestor signatures.
    pub state_quorum_threshold: u8,

    /// Hex-encoded public keys of trusted state attestors.
    pub state_trusted_attestors_hex: Vec<String>,

    /// Maximum state staleness in milliseconds.
    /// State snapshots older than this are rejected.
    pub max_state_staleness_ms: i64,

    /// IPFS gateway URLs for multi-gateway failover.
    /// Must contain at least 2 gateways for redundancy.
    pub ipfs_gateways: Vec<String>,

    /// Distributed nonce store backend type.
    pub nonce_store_backend: DistributedNonceBackend,

    /// Redis URL for distributed nonce storage (when `nonce_store_backend = "redis"`).
    ///
    /// Supported forms:
    /// - `redis://host:port`
    /// - `redis://:password@host:port`
    /// - `redis://user:password@host:port`
    /// - `rediss://host:port` (TLS)
    ///
    /// Security: non-loopback `redis://` is plaintext and requires
    /// `MPRD_ALLOW_INSECURE_REDIS=1`.
    #[serde(default)]
    pub redis_url: Option<String>,

    /// Redis key prefix for nonce entries.
    #[serde(default = "default_redis_nonce_key_prefix")]
    pub redis_key_prefix: String,

    /// Redis operation timeout in milliseconds (read/write).
    #[serde(default = "default_redis_timeout_ms")]
    pub redis_timeout_ms: u64,
}

fn default_redis_nonce_key_prefix() -> String {
    "mprd:nonce:v1".to_string()
}

fn default_redis_timeout_ms() -> u64 {
    250
}

/// Backend type for distributed nonce storage.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistributedNonceBackend {
    /// Shared filesystem backend (low-friction pre-testnet / cooperative deployments).
    ///
    /// Relies on atomic file creation on a shared filesystem (e.g., NFS with correct semantics)
    /// to coordinate nonces across nodes.
    #[default]
    SharedFs,

    /// Redis backend (recommended for most deployments).
    Redis,

    /// PostgreSQL backend.
    PostgreSql,

    /// etcd backend.
    Etcd,

    /// On-chain nonce tracking (highest assurance).
    OnChain,
}

/// Complete MPRD configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MprdConfig {
    /// Trust mode (high-trust vs low-trust).
    #[serde(default)]
    pub trust_mode: TrustMode,

    /// Low-trust mode specific configuration.
    /// Only used when `trust_mode` is `LowTrust`.
    #[serde(default)]
    pub low_trust: LowTrustConfig,

    /// Cryptographic configuration.
    pub crypto: CryptoConfig,

    /// State provenance configuration.
    pub state_provenance: StateProvenanceConfig,

    /// Anti-replay configuration.
    pub anti_replay: AntiReplayConfig,

    /// Policy evaluation configuration.
    pub policy: PolicyConfig,

    /// Execution configuration.
    pub execution: ExecutionConfig,

    /// Logging configuration.
    pub logging: LoggingConfig,
}

impl MprdConfig {
    /// Create a new configuration builder.
    pub fn builder() -> MprdConfigBuilder {
        MprdConfigBuilder::default()
    }

    /// Load configuration from environment variables.
    ///
    /// Looks for variables prefixed with `MPRD_`:
    /// - `MPRD_SIGNING_KEY_HEX` - Hex-encoded signing key seed
    /// - `MPRD_MAX_TOKEN_AGE_MS` - Maximum token age in milliseconds
    /// - `MPRD_MAX_CANDIDATES` - Maximum candidates per decision
    /// - `MPRD_LOG_LEVEL` - Logging level (trace, debug, info, warn, error)
    pub fn from_env() -> Result<Self> {
        let mut config = Self::default();

        if let Ok(key) = std::env::var("MPRD_SIGNING_KEY_HEX") {
            config.crypto.signing_key_hex = Some(key);
        }

        if let Ok(age) = std::env::var("MPRD_MAX_TOKEN_AGE_MS") {
            config.anti_replay.max_token_age_ms = age.parse().map_err(|e| {
                MprdError::ConfigError(format!("Invalid MPRD_MAX_TOKEN_AGE_MS: {}", e))
            })?;
        }

        if let Ok(max) = std::env::var("MPRD_MAX_CANDIDATES") {
            config.policy.max_candidates = max.parse().map_err(|e| {
                MprdError::ConfigError(format!("Invalid MPRD_MAX_CANDIDATES: {}", e))
            })?;
        }

        if let Ok(level) = std::env::var("MPRD_LOG_LEVEL") {
            config.logging.level = level;
        }

        if let Ok(v) = std::env::var("MPRD_REQUIRE_STATE_PROVENANCE") {
            config.state_provenance.require_provenance =
                matches!(v.as_str(), "1" | "true" | "TRUE");
        }
        if let Ok(v) = std::env::var("MPRD_ALLOWED_STATE_SOURCE_IDS") {
            config.state_provenance.allowed_state_source_ids_hex = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        config.validate()?;
        Ok(config)
    }

    /// Validate configuration.
    pub fn validate(&self) -> Result<()> {
        // Validate signing key if provided
        if let Some(ref key) = self.crypto.signing_key_hex {
            if key.len() != 64 {
                return Err(MprdError::ConfigError(
                    "signing_key_hex must be 64 hex characters (32 bytes)".into(),
                ));
            }
            if hex::decode(key).is_err() {
                return Err(MprdError::ConfigError(
                    "signing_key_hex is not valid hex".into(),
                ));
            }
        }

        // Validate anti-replay
        if self.anti_replay.max_token_age_ms < 1000 {
            return Err(MprdError::ConfigError(
                "max_token_age_ms must be at least 1000ms".into(),
            ));
        }

        let _ = crate::anti_replay::AntiReplayConfig::new(
            self.anti_replay.max_token_age_ms,
            self.anti_replay.nonce_retention_ms,
            self.anti_replay.max_future_skew_ms,
            self.anti_replay.max_tracked_nonces,
        )?;

        if let Some(ref dir) = self.anti_replay.nonce_store_dir {
            if dir.trim().is_empty() {
                return Err(MprdError::ConfigError(
                    "nonce_store_dir must be non-empty when set".into(),
                ));
            }
        }

        // Validate state provenance allowlist if configured.
        if self.state_provenance.require_provenance
            && self
                .state_provenance
                .allowed_state_source_ids_hex
                .is_empty()
        {
            return Err(MprdError::ConfigError(
                "state_provenance.allowed_state_source_ids_hex must be non-empty when require_provenance=true"
                    .into(),
            ));
        }
        for id in &self.state_provenance.allowed_state_source_ids_hex {
            let id = id.trim();
            if id.len() != 64 {
                return Err(MprdError::ConfigError(
                    "allowed_state_source_ids_hex entries must be 64 hex chars".into(),
                ));
            }
            let bytes = hex::decode(id).map_err(|_| {
                MprdError::ConfigError("allowed_state_source_ids_hex contains invalid hex".into())
            })?;
            if bytes.len() != 32 {
                return Err(MprdError::ConfigError(
                    "allowed_state_source_ids_hex entries must be 32 bytes".into(),
                ));
            }
        }

        // Validate policy
        if self.policy.max_candidates == 0 || self.policy.max_candidates > 1000 {
            return Err(MprdError::ConfigError(
                "max_candidates must be between 1 and 1000".into(),
            ));
        }

        if self.policy.max_fuel == 0 {
            return Err(MprdError::ConfigError(
                "max_fuel must be greater than 0".into(),
            ));
        }

        // Validate low-trust mode configuration
        if self.trust_mode == TrustMode::LowTrust {
            self.validate_low_trust()?;
        }

        Ok(())
    }

    /// Validate low-trust mode specific configuration.
    fn validate_low_trust(&self) -> Result<()> {
        let lt = &self.low_trust;

        // Registry quorum validation
        if lt.registry_quorum_threshold == 0 {
            return Err(MprdError::ConfigError(
                "low_trust.registry_quorum_threshold must be >= 1".into(),
            ));
        }
        if lt.registry_trusted_signers_hex.len() < lt.registry_quorum_threshold as usize {
            return Err(MprdError::ConfigError(format!(
                "low_trust.registry_trusted_signers_hex must have at least {} entries (quorum threshold)",
                lt.registry_quorum_threshold
            )));
        }
        for (i, hex) in lt.registry_trusted_signers_hex.iter().enumerate() {
            if hex.len() != 64 || hex::decode(hex).is_err() {
                return Err(MprdError::ConfigError(format!(
                    "low_trust.registry_trusted_signers_hex[{}] must be 64 hex chars",
                    i
                )));
            }
        }

        // State attestor quorum validation
        if lt.state_quorum_threshold == 0 {
            return Err(MprdError::ConfigError(
                "low_trust.state_quorum_threshold must be >= 1".into(),
            ));
        }
        if lt.state_trusted_attestors_hex.len() < lt.state_quorum_threshold as usize {
            return Err(MprdError::ConfigError(format!(
                "low_trust.state_trusted_attestors_hex must have at least {} entries (quorum threshold)",
                lt.state_quorum_threshold
            )));
        }
        for (i, hex) in lt.state_trusted_attestors_hex.iter().enumerate() {
            if hex.len() != 64 || hex::decode(hex).is_err() {
                return Err(MprdError::ConfigError(format!(
                    "low_trust.state_trusted_attestors_hex[{}] must be 64 hex chars",
                    i
                )));
            }
        }

        // State freshness validation
        if lt.max_state_staleness_ms <= 0 {
            return Err(MprdError::ConfigError(
                "low_trust.max_state_staleness_ms must be > 0".into(),
            ));
        }

        // Multi-gateway IPFS validation
        if lt.ipfs_gateways.len() < 2 {
            return Err(MprdError::ConfigError(
                "low_trust.ipfs_gateways must have at least 2 gateways for redundancy".into(),
            ));
        }

        match lt.nonce_store_backend {
            DistributedNonceBackend::SharedFs => {
                if self
                    .anti_replay
                    .nonce_store_dir
                    .as_deref()
                    .map(|s| s.trim().is_empty())
                    .unwrap_or(true)
                {
                    return Err(MprdError::ConfigError(
                        "LowTrust SharedFs requires anti_replay.nonce_store_dir".into(),
                    ));
                }
            }
            DistributedNonceBackend::Redis => {
                if lt
                    .redis_url
                    .as_deref()
                    .map(|s| s.trim().is_empty())
                    .unwrap_or(true)
                {
                    return Err(MprdError::ConfigError(
                        "LowTrust Redis requires low_trust.redis_url".into(),
                    ));
                }
                if lt.redis_timeout_ms == 0 {
                    return Err(MprdError::ConfigError(
                        "low_trust.redis_timeout_ms must be > 0".into(),
                    ));
                }
                if lt.redis_key_prefix.trim().is_empty() {
                    return Err(MprdError::ConfigError(
                        "low_trust.redis_key_prefix must be non-empty".into(),
                    ));
                }
            }
            DistributedNonceBackend::PostgreSql
            | DistributedNonceBackend::Etcd
            | DistributedNonceBackend::OnChain => {}
        }

        Ok(())
    }

    /// Validate production-readiness requirements.
    ///
    /// This is stricter than `validate()` and is intended to enforce checklist MUSTs
    /// around S4/S5 at the execution boundary.
    pub fn validate_production(&self) -> Result<()> {
        self.validate()?;

        if !self.crypto.require_signatures {
            return Err(MprdError::ConfigError(
                "Production requires require_signatures=true".into(),
            ));
        }

        if self
            .crypto
            .signing_key_hex
            .as_deref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(MprdError::ConfigError(
                "Production requires signing_key_hex (do not generate keys at runtime)".into(),
            ));
        }

        match self.trust_mode {
            TrustMode::HighTrust => {
                if self
                    .anti_replay
                    .nonce_store_dir
                    .as_deref()
                    .map(|s| s.trim().is_empty())
                    .unwrap_or(true)
                {
                    return Err(MprdError::ConfigError(
                        "Production requires anti_replay.nonce_store_dir for persistent anti-replay"
                            .into(),
                    ));
                }
            }
            TrustMode::LowTrust => match self.low_trust.nonce_store_backend {
                DistributedNonceBackend::Redis => {
                    if self
                        .low_trust
                        .redis_url
                        .as_deref()
                        .map(|s| s.trim().is_empty())
                        .unwrap_or(true)
                    {
                        return Err(MprdError::ConfigError(
                            "Production requires low_trust.redis_url for distributed anti-replay"
                                .into(),
                        ));
                    }
                }
                DistributedNonceBackend::SharedFs => {
                    return Err(MprdError::ConfigError(
                        "Production requires a real distributed nonce store (redis/postgresql/etcd/on_chain); shared_fs is pre-testnet only"
                            .into(),
                    ));
                }
                DistributedNonceBackend::PostgreSql
                | DistributedNonceBackend::Etcd
                | DistributedNonceBackend::OnChain => {
                    return Err(MprdError::ConfigError(
                        "Production requires a distributed nonce store backend implemented in this build (redis)"
                            .into(),
                    ));
                }
            },
        }

        if !self.state_provenance.require_provenance {
            return Err(MprdError::ConfigError(
                "Production requires state_provenance.require_provenance=true".into(),
            ));
        }

        if self
            .state_provenance
            .allowed_state_source_ids_hex
            .is_empty()
        {
            return Err(MprdError::ConfigError(
                "Production requires non-empty state_provenance.allowed_state_source_ids_hex"
                    .into(),
            ));
        }

        Ok(())
    }
}

/// Cryptographic configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoConfig {
    /// Hex-encoded signing key seed (32 bytes = 64 hex chars).
    /// If None, a random key will be generated.
    pub signing_key_hex: Option<String>,

    /// Whether to require signature verification on execution.
    pub require_signatures: bool,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            signing_key_hex: None,
            require_signatures: true,
        }
    }
}

/// State provenance configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StateProvenanceConfig {
    /// If true, executors must refuse tokens with unknown/unallowlisted state provenance.
    pub require_provenance: bool,
    /// Allowlisted state provenance scheme IDs (hex-encoded 32 bytes).
    pub allowed_state_source_ids_hex: Vec<String>,
}

/// Anti-replay configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AntiReplayConfig {
    /// Maximum age of a decision token in milliseconds.
    pub max_token_age_ms: i64,

    /// Maximum future timestamp skew allowed in milliseconds.
    pub max_future_skew_ms: i64,

    /// How long to retain nonces for replay checking.
    pub nonce_retention_ms: i64,

    /// Maximum number of nonces to track.
    pub max_tracked_nonces: usize,

    /// Optional durable nonce store directory.
    ///
    /// If set, the executor guard uses a persistent on-disk store for nonces.
    /// This is REQUIRED for production anti-replay across process restarts.
    pub nonce_store_dir: Option<String>,
}

impl Default for AntiReplayConfig {
    fn default() -> Self {
        Self {
            max_token_age_ms: 300_000,     // 5 minutes
            max_future_skew_ms: 5_000,     // 5 seconds
            nonce_retention_ms: 3_600_000, // 1 hour
            max_tracked_nonces: 100_000,
            nonce_store_dir: None,
        }
    }
}

/// Policy evaluation configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Maximum number of candidates per decision.
    pub max_candidates: usize,

    /// Maximum fuel for MPB execution.
    pub max_fuel: u32,

    /// Default timeout for policy evaluation in milliseconds.
    pub evaluation_timeout_ms: u64,

    /// Number of spot checks for MPB proofs.
    pub proof_spot_checks: usize,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            max_candidates: 64,
            max_fuel: 10_000,
            evaluation_timeout_ms: 5_000,
            proof_spot_checks: 64,
        }
    }
}

/// Execution configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionConfig {
    /// Whether to enable dry-run mode (log only, no side effects).
    pub dry_run: bool,

    /// Maximum execution retries on transient failures.
    pub max_retries: u32,

    /// Retry backoff in milliseconds.
    pub retry_backoff_ms: u64,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            dry_run: false,
            max_retries: 3,
            retry_backoff_ms: 100,
        }
    }
}

/// Logging configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error).
    pub level: String,

    /// Whether to include timestamps in logs.
    pub include_timestamps: bool,

    /// Whether to include span context in logs.
    pub include_spans: bool,

    /// JSON output format.
    pub json_output: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            include_timestamps: true,
            include_spans: true,
            json_output: false,
        }
    }
}

/// Builder for MprdConfig.
#[derive(Default)]
pub struct MprdConfigBuilder {
    config: MprdConfig,
}

impl MprdConfigBuilder {
    /// Set the signing key from hex.
    pub fn signing_key_hex(mut self, key: impl Into<String>) -> Self {
        self.config.crypto.signing_key_hex = Some(key.into());
        self
    }

    /// Set whether signatures are required.
    pub fn require_signatures(mut self, require: bool) -> Self {
        self.config.crypto.require_signatures = require;
        self
    }

    /// Require state provenance (fail-closed) at the executor boundary.
    pub fn require_state_provenance(mut self, require: bool) -> Self {
        self.config.state_provenance.require_provenance = require;
        self
    }

    /// Allowlist acceptable `state_source_id` values (hex-encoded 32 bytes).
    pub fn allowed_state_source_ids_hex(mut self, ids: Vec<String>) -> Self {
        self.config.state_provenance.allowed_state_source_ids_hex = ids;
        self
    }

    /// Set maximum token age.
    pub fn max_token_age(mut self, duration: Duration) -> Self {
        self.config.anti_replay.max_token_age_ms = duration.as_millis() as i64;
        self
    }

    /// Set nonce retention window.
    pub fn nonce_retention(mut self, duration: Duration) -> Self {
        self.config.anti_replay.nonce_retention_ms = duration.as_millis() as i64;
        self
    }

    /// Set maximum future timestamp skew.
    pub fn max_future_skew(mut self, duration: Duration) -> Self {
        self.config.anti_replay.max_future_skew_ms = duration.as_millis() as i64;
        self
    }

    /// Set maximum number of tracked nonces.
    pub fn max_tracked_nonces(mut self, max: usize) -> Self {
        self.config.anti_replay.max_tracked_nonces = max;
        self
    }

    /// Enable a durable on-disk nonce store (required for production anti-replay).
    pub fn nonce_store_dir(mut self, dir: impl Into<String>) -> Self {
        self.config.anti_replay.nonce_store_dir = Some(dir.into());
        self
    }

    /// Set maximum candidates.
    pub fn max_candidates(mut self, max: usize) -> Self {
        self.config.policy.max_candidates = max;
        self
    }

    /// Set maximum fuel for MPB.
    pub fn max_fuel(mut self, fuel: u32) -> Self {
        self.config.policy.max_fuel = fuel;
        self
    }

    /// Set number of proof spot checks.
    pub fn proof_spot_checks(mut self, checks: usize) -> Self {
        self.config.policy.proof_spot_checks = checks;
        self
    }

    /// Enable dry-run mode.
    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.config.execution.dry_run = dry_run;
        self
    }

    /// Set log level.
    pub fn log_level(mut self, level: impl Into<String>) -> Self {
        self.config.logging.level = level.into();
        self
    }

    /// Enable JSON log output.
    pub fn json_logs(mut self, enabled: bool) -> Self {
        self.config.logging.json_output = enabled;
        self
    }

    /// Build and validate the configuration.
    pub fn build(self) -> Result<MprdConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = MprdConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn builder_creates_valid_config() {
        let config = MprdConfig::builder()
            .max_candidates(32)
            .max_fuel(5000)
            .dry_run(true)
            .log_level("debug")
            .build()
            .expect("should build");

        assert_eq!(config.policy.max_candidates, 32);
        assert_eq!(config.policy.max_fuel, 5000);
        assert!(config.execution.dry_run);
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn production_validation_requires_persistent_nonce_store_and_signing_key() {
        let allowlisted = vec![hex::encode(
            crate::state_provenance::state_source_id_signed_snapshot_v1().0,
        )];

        let cfg = MprdConfig::default();
        assert!(cfg.validate().is_ok());
        assert!(cfg.validate_production().is_err());

        let cfg = MprdConfig::builder()
            .signing_key_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .require_state_provenance(true)
            .allowed_state_source_ids_hex(allowlisted)
            .nonce_store_dir("/tmp/mprd_nonces")
            .build()
            .expect("build");
        assert!(cfg.validate_production().is_ok());
    }

    #[test]
    fn invalid_signing_key_rejected() {
        let result = MprdConfig::builder().signing_key_hex("invalid").build();

        assert!(result.is_err());
    }

    #[test]
    fn valid_signing_key_accepted() {
        let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let result = MprdConfig::builder().signing_key_hex(hex_key).build();

        assert!(result.is_ok());
    }

    #[test]
    fn zero_candidates_rejected() {
        let result = MprdConfig::builder().max_candidates(0).build();

        assert!(result.is_err());
    }

    #[test]
    fn too_many_candidates_rejected() {
        let result = MprdConfig::builder().max_candidates(10000).build();

        assert!(result.is_err());
    }
}
