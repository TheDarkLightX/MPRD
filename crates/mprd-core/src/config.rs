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

use crate::{
    decentralized_executor::ex60_reference::TrustTier,
    tokenomics_v6::{simplex_planner, SimplexCeoConfig, SimplexCeoMaterialization, SimplexCeoMode},
    MprdError, Result,
};
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

        if let Some(ref key) = self.crypto.verifying_key_hex {
            if key.len() != 64 {
                return Err(MprdError::ConfigError(
                    "verifying_key_hex must be 64 hex characters (32 bytes)".into(),
                ));
            }
            if hex::decode(key).is_err() {
                return Err(MprdError::ConfigError(
                    "verifying_key_hex is not valid hex".into(),
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

        // Validate execution circuit breaker.
        if self.execution.circuit_breaker.enabled && self.execution.circuit_breaker.tick_ms == 0 {
            return Err(MprdError::ConfigError(
                "execution.circuit_breaker.tick_ms must be > 0 when enabled".into(),
            ));
        }

        // Validate optional Mode B simplex CEO deployment wiring.
        if self.execution.simplex_ceo.enabled {
            self.execution.simplex_ceo.validate_enabled()?;
        }

        // Validate decentralized dispatch guard (EX-73).
        if self.execution.decentralized_dispatch.enabled {
            self.validate_decentralized_dispatch()?;
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

    fn validate_decentralized_dispatch(&self) -> Result<()> {
        let dd = &self.execution.decentralized_dispatch;

        if dd.local_executor_id.trim().is_empty() {
            return Err(MprdError::ConfigError(
                "execution.decentralized_dispatch.local_executor_id must be non-empty when enabled"
                    .into(),
            ));
        }
        if dd.local_executor_id.trim() != dd.local_executor_id {
            return Err(MprdError::ConfigError(
                "execution.decentralized_dispatch.local_executor_id must be trimmed".into(),
            ));
        }

        if dd.candidates.is_empty() {
            return Err(MprdError::ConfigError(
                "execution.decentralized_dispatch.candidates must be non-empty when enabled".into(),
            ));
        }

        if dd.topk == 0 {
            return Err(MprdError::ConfigError(
                "execution.decentralized_dispatch.topk must be >= 1 when enabled".into(),
            ));
        }
        if dd.topk > dd.candidates.len() {
            return Err(MprdError::ConfigError(
                "execution.decentralized_dispatch.topk must be <= candidates.len()".into(),
            ));
        }

        if dd.max_attempts == 0 {
            return Err(MprdError::ConfigError(
                "execution.decentralized_dispatch.max_attempts must be >= 1 when enabled".into(),
            ));
        }
        if dd.max_attempts > dd.topk {
            return Err(MprdError::ConfigError(
                "execution.decentralized_dispatch.max_attempts must be <= topk".into(),
            ));
        }

        if dd.slot_delay_ms == 0 {
            return Err(MprdError::ConfigError(
                "execution.decentralized_dispatch.slot_delay_ms must be > 0 when enabled".into(),
            ));
        }
        if dd.trust_weight_low_bps > crate::decentralized_executor::ex60_reference::MAX_BPS {
            return Err(MprdError::ConfigError(
                "execution.decentralized_dispatch.trust_weight_low_bps must be <= 10000".into(),
            ));
        }

        let mut seen = std::collections::BTreeSet::<&str>::new();
        let mut local_present = false;
        for cand in &dd.candidates {
            let id = cand.executor_id.trim();
            if id.is_empty() {
                return Err(MprdError::ConfigError(
                    "execution.decentralized_dispatch.candidates[*].executor_id must be non-empty"
                        .into(),
                ));
            }
            if id != cand.executor_id {
                return Err(MprdError::ConfigError(
                    "execution.decentralized_dispatch.candidates[*].executor_id must be trimmed"
                        .into(),
                ));
            }
            if cand.weight == 0 {
                return Err(MprdError::ConfigError(
                    "execution.decentralized_dispatch.candidates[*].weight must be > 0".into(),
                ));
            }
            if !seen.insert(id) {
                return Err(MprdError::ConfigError(
                    "execution.decentralized_dispatch.candidates[*].executor_id must be unique"
                        .into(),
                ));
            }
            if id == dd.local_executor_id {
                local_present = true;
            }
        }
        if !local_present {
            return Err(MprdError::ConfigError(
                "execution.decentralized_dispatch.local_executor_id must appear in candidates"
                    .into(),
            ));
        }

        if let Some(path) = dd.telemetry_jsonl_path.as_deref() {
            if path.trim().is_empty() {
                return Err(MprdError::ConfigError(
                    "execution.decentralized_dispatch.telemetry_jsonl_path must be non-empty when set"
                        .into(),
                ));
            }
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

        let has_signing_key = self
            .crypto
            .signing_key_hex
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        let has_verifying_key = self
            .crypto
            .verifying_key_hex
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        if !has_signing_key && !has_verifying_key {
            return Err(MprdError::ConfigError(
                "Production requires signing_key_hex or verifying_key_hex".into(),
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

    /// Produce a deterministic advisory report for enabled Mode B simplex CEO config.
    ///
    /// Returns `Ok(None)` when `execution.simplex_ceo.enabled=false`.
    pub fn simplex_ceo_advisory_report(&self) -> Result<Option<SimplexCeoAdvisoryReport>> {
        self.execution.simplex_ceo.advisory_report()
    }
}

/// Cryptographic configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoConfig {
    /// Hex-encoded signing key seed (32 bytes = 64 hex chars).
    /// If None, a random key will be generated.
    pub signing_key_hex: Option<String>,

    /// Hex-encoded verifying key (32 bytes = 64 hex chars).
    ///
    /// Verification-only surfaces can use this to avoid retaining private signing
    /// seed material in memory.
    pub verifying_key_hex: Option<String>,

    /// Whether to require signature verification on execution.
    pub require_signatures: bool,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            signing_key_hex: None,
            verifying_key_hex: None,
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

    /// Executor circuit breaker configuration.
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,

    /// Optional Mode B simplex CEO deployment guard.
    ///
    /// Disabled by default. When enabled, config validation calls the crate-owned simplex
    /// planner advisory and fail-closes if explicit full materialization is unsafe or if
    /// the bounded planner budget is exhausted.
    #[serde(default)]
    pub simplex_ceo: SimplexCeoDeploymentConfig,

    /// Decentralized executor dispatch guard (EX-73).
    ///
    /// When enabled, enforces deterministic eligibility at the executor boundary, based on
    /// a TopK shortlist + slot ladder derived from `nonce_or_tx_hash`.
    #[serde(default)]
    pub decentralized_dispatch: DecentralizedDispatchConfig,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            dry_run: false,
            max_retries: 3,
            retry_backoff_ms: 100,
            circuit_breaker: CircuitBreakerConfig::default(),
            simplex_ceo: SimplexCeoDeploymentConfig::default(),
            decentralized_dispatch: DecentralizedDispatchConfig::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimplexCeoPlannerModeConfig {
    TracePor,
    #[default]
    StateSymmetry,
    AmplePorDfsC2,
}

impl From<SimplexCeoPlannerModeConfig> for SimplexCeoMode {
    fn from(value: SimplexCeoPlannerModeConfig) -> Self {
        match value {
            SimplexCeoPlannerModeConfig::TracePor => SimplexCeoMode::TracePor,
            SimplexCeoPlannerModeConfig::StateSymmetry => SimplexCeoMode::StateSymmetry,
            SimplexCeoPlannerModeConfig::AmplePorDfsC2 => SimplexCeoMode::AmplePorDfsC2,
        }
    }
}

impl SimplexCeoPlannerModeConfig {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TracePor => "trace_por",
            Self::StateSymmetry => "state_symmetry",
            Self::AmplePorDfsC2 => "ample_por_dfs_c2",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimplexCeoMaterializationConfig {
    ExplicitFullGraph,
    #[default]
    LazyPlanner,
}

impl From<SimplexCeoMaterializationConfig> for SimplexCeoMaterialization {
    fn from(value: SimplexCeoMaterializationConfig) -> Self {
        match value {
            SimplexCeoMaterializationConfig::ExplicitFullGraph => {
                SimplexCeoMaterialization::ExplicitFullGraph
            }
            SimplexCeoMaterializationConfig::LazyPlanner => SimplexCeoMaterialization::LazyPlanner,
        }
    }
}

impl SimplexCeoMaterializationConfig {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitFullGraph => "explicit_full_graph",
            Self::LazyPlanner => "lazy_planner",
        }
    }
}

fn default_simplex_full_materialization_threshold() -> u64 {
    simplex_planner::DEFAULT_FULL_MATERIALIZATION_THRESHOLD as u64
}

/// Deployment-time guard for future Mode B simplex CEO planning.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SimplexCeoDeploymentConfig {
    /// Enable this config boundary.
    pub enabled: bool,
    /// Planner reduction mode.
    pub mode: SimplexCeoPlannerModeConfig,
    /// Deployment materialization surface requested by the caller.
    pub materialization: SimplexCeoMaterializationConfig,
    /// Bounded planning horizon.
    pub horizon: usize,
    /// Maximum non-terminal frontier expansions for bounded planning.
    pub budget_expanded: usize,
    /// Explicit full graph threshold. Counts above this force quotient/lazy handling.
    pub full_materialization_threshold: u64,
    /// Required constant-sum total for the simplex menu.
    pub require_sum: Option<u32>,
    /// Initial simplex point used for deployment admission.
    pub x0: Vec<u32>,
    /// Per-bucket caps.
    pub caps: Vec<u32>,
    /// Per-bucket role/objective class weights used by symmetry quotienting.
    pub weights_for_symmetry: Vec<u32>,
}

pub const SIMPLEX_CEO_ADVISORY_REPORT_SCHEMA: &str = "mprd/simplex-ceo-advisory/v1";

/// Deterministic, release-report-friendly view of the enabled simplex CEO advisory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimplexCeoAdvisoryReport {
    pub schema: String,
    pub enabled: bool,
    pub mode: String,
    pub materialization: String,
    pub horizon: usize,
    pub budget_expanded: usize,
    pub require_sum: u32,
    pub x0: Vec<u32>,
    pub caps: Vec<u32>,
    pub weights_for_symmetry: Vec<u32>,
    pub full_materialization_threshold: u64,
    pub total_units: u64,
    pub raw_full_states: u128,
    pub quotient_full_states: u128,
    pub expanded: usize,
    pub generated: usize,
    pub reached_states: usize,
    pub budget_exhausted: bool,
    pub recommendation: String,
    pub diagnostic: String,
}

impl Default for SimplexCeoDeploymentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: SimplexCeoPlannerModeConfig::StateSymmetry,
            materialization: SimplexCeoMaterializationConfig::LazyPlanner,
            horizon: 0,
            budget_expanded: 0,
            full_materialization_threshold: default_simplex_full_materialization_threshold(),
            require_sum: None,
            x0: Vec::new(),
            caps: Vec::new(),
            weights_for_symmetry: Vec::new(),
        }
    }
}

impl SimplexCeoDeploymentConfig {
    pub fn validate_enabled(&self) -> Result<simplex_planner::SimplexPlannerAdvisory> {
        if !self.enabled {
            return Err(MprdError::ConfigError(
                "execution.simplex_ceo.validate_enabled called while disabled".into(),
            ));
        }
        if self.full_materialization_threshold == 0 {
            return Err(MprdError::ConfigError(
                "execution.simplex_ceo.full_materialization_threshold must be > 0 when enabled"
                    .into(),
            ));
        }
        let require_sum = self.require_sum.ok_or_else(|| {
            MprdError::ConfigError(
                "execution.simplex_ceo.require_sum must be set when enabled".into(),
            )
        })?;
        let cfg = SimplexCeoConfig {
            mode: self.mode.into(),
            horizon: self.horizon,
            budget_expanded: self.budget_expanded,
            require_sum: Some(require_sum),
        };
        cfg.validate_planner_advisory(
            &self.x0,
            &self.caps,
            &self.weights_for_symmetry,
            self.full_materialization_threshold as u128,
            self.materialization.into(),
        )
        .map_err(|err| {
            MprdError::ConfigError(format!("execution.simplex_ceo advisory rejected: {err}"))
        })
    }

    pub fn advisory_report(&self) -> Result<Option<SimplexCeoAdvisoryReport>> {
        if !self.enabled {
            return Ok(None);
        }
        let require_sum = self.require_sum.ok_or_else(|| {
            MprdError::ConfigError(
                "execution.simplex_ceo.require_sum must be set when enabled".into(),
            )
        })?;
        let advisory = self.validate_enabled()?;
        Ok(Some(SimplexCeoAdvisoryReport {
            schema: SIMPLEX_CEO_ADVISORY_REPORT_SCHEMA.to_string(),
            enabled: true,
            mode: self.mode.as_str().to_string(),
            materialization: self.materialization.as_str().to_string(),
            horizon: self.horizon,
            budget_expanded: self.budget_expanded,
            require_sum,
            x0: self.x0.clone(),
            caps: self.caps.clone(),
            weights_for_symmetry: self.weights_for_symmetry.clone(),
            full_materialization_threshold: self.full_materialization_threshold,
            total_units: advisory.total_units,
            raw_full_states: advisory.raw_full_states,
            quotient_full_states: advisory.quotient_full_states,
            expanded: advisory.expanded,
            generated: advisory.generated,
            reached_states: advisory.reached_states,
            budget_exhausted: advisory.budget_exhausted,
            recommendation: advisory.recommendation.as_str().to_string(),
            diagnostic: advisory.diagnostic(),
        }))
    }
}

fn default_decentralized_dispatch_enforce() -> bool {
    true
}

/// Candidate executor configuration for decentralized dispatch.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecentralizedDispatchCandidate {
    /// Executor identity (human-readable stable ID).
    pub executor_id: String,
    /// Relative weight (stake/reputation; units are deployment-defined but must be positive).
    pub weight: u64,
    /// Trust tier used for trust-weighted effective weights.
    pub trust_tier: TrustTier,
}

/// Executor-boundary decentralized dispatch guard configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecentralizedDispatchConfig {
    /// Enable decentralized dispatch gating.
    #[serde(default)]
    pub enabled: bool,

    /// Enforce eligibility (block ineligible), or run in shadow mode (telemetry-only).
    #[serde(default = "default_decentralized_dispatch_enforce")]
    pub enforce: bool,

    /// This node's executor identity (must match one of `candidates[*].executor_id` when enabled).
    #[serde(default)]
    pub local_executor_id: String,

    /// Candidate executor pool for deterministic TopK+ladder selection.
    #[serde(default)]
    pub candidates: Vec<DecentralizedDispatchCandidate>,

    /// Size of the TopK shortlist (>= 1 and <= candidates.len()).
    #[serde(default)]
    pub topk: usize,

    /// Maximum number of claim attempts / slots to allow (>= 1 and <= topk).
    #[serde(default)]
    pub max_attempts: usize,

    /// Slot delay in milliseconds between ladder attempts (> 0).
    #[serde(default)]
    pub slot_delay_ms: u64,

    /// Trust weight in basis points (bps) applied to Low trust candidates (0..=10000).
    #[serde(default)]
    pub trust_weight_low_bps: u16,

    /// Optional JSONL path to append dispatch telemetry events.
    #[serde(default)]
    pub telemetry_jsonl_path: Option<String>,
}

impl Default for DecentralizedDispatchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            enforce: default_decentralized_dispatch_enforce(),
            local_executor_id: String::new(),
            candidates: Vec::new(),
            topk: 0,
            max_attempts: 0,
            slot_delay_ms: 0,
            trust_weight_low_bps: 0,
            telemetry_jsonl_path: None,
        }
    }
}

/// Circuit breaker configuration for executor-side effects.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    /// Enable circuit breaker at the executor boundary.
    #[serde(default)]
    pub enabled: bool,

    /// Tick size in milliseconds (cooldown duration is expressed in ticks).
    ///
    /// The verified `executor_circuit_breaker` kernel uses a bounded tick counter for cooldown.
    /// The default maps 30 ticks → ~30 seconds.
    #[serde(default = "default_circuit_breaker_tick_ms")]
    pub tick_ms: u64,
}

fn default_circuit_breaker_tick_ms() -> u64 {
    1_000
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tick_ms: default_circuit_breaker_tick_ms(),
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

    /// Set the verifying key from hex.
    pub fn verifying_key_hex(mut self, key: impl Into<String>) -> Self {
        self.config.crypto.verifying_key_hex = Some(key.into());
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

    /// Enable executor circuit breaker.
    pub fn enable_circuit_breaker(mut self, enabled: bool) -> Self {
        self.config.execution.circuit_breaker.enabled = enabled;
        self
    }

    /// Configure circuit breaker tick size (cooldown ticks are in this unit).
    pub fn circuit_breaker_tick(mut self, duration: Duration) -> Self {
        self.config.execution.circuit_breaker.tick_ms = duration.as_millis() as u64;
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

    fn base_config_with_dispatch_enabled() -> MprdConfig {
        let mut config = MprdConfig::default();
        config.execution.decentralized_dispatch.enabled = true;
        config.execution.decentralized_dispatch.enforce = true;
        config.execution.decentralized_dispatch.local_executor_id = "ExecA".to_string();
        config.execution.decentralized_dispatch.candidates = vec![
            DecentralizedDispatchCandidate {
                executor_id: "ExecA".to_string(),
                weight: 10,
                trust_tier: TrustTier::High,
            },
            DecentralizedDispatchCandidate {
                executor_id: "ExecB".to_string(),
                weight: 10,
                trust_tier: TrustTier::Low,
            },
        ];
        config.execution.decentralized_dispatch.topk = 2;
        config.execution.decentralized_dispatch.max_attempts = 2;
        config.execution.decentralized_dispatch.slot_delay_ms = 100;
        config.execution.decentralized_dispatch.trust_weight_low_bps = 500;
        config
    }

    fn small_simplex_ceo_config() -> SimplexCeoDeploymentConfig {
        SimplexCeoDeploymentConfig {
            enabled: true,
            mode: SimplexCeoPlannerModeConfig::StateSymmetry,
            materialization: SimplexCeoMaterializationConfig::ExplicitFullGraph,
            horizon: 6,
            budget_expanded: 1_000,
            full_materialization_threshold: default_simplex_full_materialization_threshold(),
            require_sum: Some(20),
            x0: vec![10, 10, 0, 0],
            caps: vec![10, 10, 10, 10],
            weights_for_symmetry: vec![7, 7, 1, 2],
        }
    }

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
    fn production_validation_requires_persistent_nonce_store_and_signing_or_verifying_key() {
        let allowlisted = vec![hex::encode(
            crate::state_provenance::state_source_id_signed_snapshot_v1().0,
        )];

        let cfg = MprdConfig::default();
        assert!(cfg.validate().is_ok());
        assert!(cfg.validate_production().is_err());

        let cfg = MprdConfig::builder()
            .signing_key_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .require_state_provenance(true)
            .allowed_state_source_ids_hex(allowlisted.clone())
            .nonce_store_dir("/tmp/mprd_nonces")
            .build()
            .expect("build");
        assert!(cfg.validate_production().is_ok());

        let cfg = MprdConfig::builder()
            .verifying_key_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .require_state_provenance(true)
            .allowed_state_source_ids_hex(allowlisted)
            .nonce_store_dir("/tmp/mprd_nonces")
            .build()
            .expect("build");
        assert!(cfg.validate_production().is_ok());
    }

    #[test]
    fn production_validation_rejects_onchain_nonce_backend_until_finality_adapter_exists() {
        let allowlisted = vec![hex::encode(
            crate::state_provenance::state_source_id_signed_snapshot_v1().0,
        )];
        let signer = "11".repeat(32);
        let attestor = "22".repeat(32);

        let mut cfg = MprdConfig::builder()
            .verifying_key_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .require_state_provenance(true)
            .allowed_state_source_ids_hex(allowlisted)
            .nonce_store_dir("/tmp/mprd_nonces")
            .build()
            .expect("build");
        cfg.trust_mode = TrustMode::LowTrust;
        cfg.low_trust.registry_quorum_threshold = 1;
        cfg.low_trust.registry_trusted_signers_hex = vec![signer];
        cfg.low_trust.state_quorum_threshold = 1;
        cfg.low_trust.state_trusted_attestors_hex = vec![attestor];
        cfg.low_trust.max_state_staleness_ms = 30_000;
        cfg.low_trust.ipfs_gateways = vec![
            "https://ipfs-gateway-a.example".into(),
            "https://ipfs-gateway-b.example".into(),
        ];
        cfg.low_trust.nonce_store_backend = DistributedNonceBackend::OnChain;
        cfg.low_trust.redis_key_prefix = "mprd:nonce:v1".into();
        cfg.low_trust.redis_timeout_ms = 250;

        assert!(cfg.validate().is_ok());
        let err = cfg.validate_production().unwrap_err();
        assert!(
            err.to_string()
                .contains("distributed nonce store backend implemented in this build (redis)"),
            "unexpected production rejection: {err}"
        );
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
    fn valid_verifying_key_accepted() {
        let hex_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let result = MprdConfig::builder().verifying_key_hex(hex_key).build();

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

    #[test]
    fn decentralized_dispatch_disabled_partition_allows_stale_invalid_fields() {
        // [Partition] enabled=false => skip decentralized dispatch validation (stale/invalid fields tolerated).
        let mut config = MprdConfig::default();
        config.execution.decentralized_dispatch.enabled = false;
        config.execution.decentralized_dispatch.local_executor_id = "   ".to_string();
        config.execution.decentralized_dispatch.candidates = vec![DecentralizedDispatchCandidate {
            executor_id: "".to_string(),
            weight: 0,
            trust_tier: TrustTier::Low,
        }];
        config.execution.decentralized_dispatch.topk = 0;
        config.execution.decentralized_dispatch.max_attempts = 0;
        config.execution.decentralized_dispatch.slot_delay_ms = 0;
        config.execution.decentralized_dispatch.trust_weight_low_bps = 65_535;
        config.execution.decentralized_dispatch.telemetry_jsonl_path = Some(" ".to_string());

        assert!(
            config.validate().is_ok(),
            "disabled partition should not block config due to stale dispatch fields"
        );
    }

    #[test]
    fn simplex_ceo_disabled_partition_allows_stale_invalid_fields() {
        // [Partition] enabled=false => skip simplex advisory validation (stale/invalid fields tolerated).
        let mut config = MprdConfig::default();
        config.execution.simplex_ceo.enabled = false;
        config.execution.simplex_ceo.mode = SimplexCeoPlannerModeConfig::AmplePorDfsC2;
        config.execution.simplex_ceo.materialization =
            SimplexCeoMaterializationConfig::ExplicitFullGraph;
        config.execution.simplex_ceo.horizon = 0;
        config.execution.simplex_ceo.budget_expanded = 0;
        config.execution.simplex_ceo.full_materialization_threshold = 0;
        config.execution.simplex_ceo.require_sum = None;
        config.execution.simplex_ceo.x0 = vec![11, 9, 0, 0];
        config.execution.simplex_ceo.caps = vec![10, 10, 10, 10];
        config.execution.simplex_ceo.weights_for_symmetry = vec![7, 7, 1, 2];

        assert!(
            config.validate().is_ok(),
            "disabled partition should not block config due to stale simplex fields"
        );
        assert_eq!(
            config
                .simplex_ceo_advisory_report()
                .expect("disabled report should not fail"),
            None
        );
    }

    #[test]
    fn simplex_ceo_config_accepts_small_explicit_materialization() {
        let mut config = MprdConfig::default();
        config.execution.simplex_ceo = small_simplex_ceo_config();

        let advisory = config
            .execution
            .simplex_ceo
            .validate_enabled()
            .expect("small explicit simplex config should validate");
        assert_eq!(advisory.raw_full_states, 891);
        assert_eq!(advisory.quotient_full_states, 476);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn simplex_ceo_advisory_report_is_deterministic_and_complete() {
        let mut config = MprdConfig::default();
        config.execution.simplex_ceo = small_simplex_ceo_config();

        let report = config
            .simplex_ceo_advisory_report()
            .expect("enabled report should validate")
            .expect("enabled report should be present");
        assert_eq!(report.schema, SIMPLEX_CEO_ADVISORY_REPORT_SCHEMA);
        assert!(report.enabled);
        assert_eq!(report.mode, "state_symmetry");
        assert_eq!(report.materialization, "explicit_full_graph");
        assert_eq!(report.horizon, 6);
        assert_eq!(report.budget_expanded, 1_000);
        assert_eq!(report.require_sum, 20);
        assert_eq!(report.x0, vec![10, 10, 0, 0]);
        assert_eq!(report.caps, vec![10, 10, 10, 10]);
        assert_eq!(report.weights_for_symmetry, vec![7, 7, 1, 2]);
        assert_eq!(report.full_materialization_threshold, 100_000_000);
        assert_eq!(report.total_units, 20);
        assert_eq!(report.raw_full_states, 891);
        assert_eq!(report.quotient_full_states, 476);
        assert_eq!(report.expanded, 50);
        assert_eq!(report.generated, 600);
        assert_eq!(report.reached_states, 78);
        assert!(!report.budget_exhausted);
        assert_eq!(
            report.recommendation,
            "materialization_not_blocked_by_count"
        );
        assert!(
            report
                .diagnostic
                .contains("recommendation=materialization_not_blocked_by_count"),
            "{}",
            report.diagnostic
        );

        let json_a = serde_json::to_string(&report).expect("report should serialize");
        let json_b = serde_json::to_string(&report).expect("report should serialize again");
        assert_eq!(json_a, json_b, "report JSON should be deterministic");
        assert!(json_a.contains("\"schema\":\"mprd/simplex-ceo-advisory/v1\""));
        assert!(json_a.contains("\"recommendation\":\"materialization_not_blocked_by_count\""));
    }

    #[test]
    fn simplex_ceo_config_rejects_missing_required_sum() {
        let mut config = MprdConfig::default();
        config.execution.simplex_ceo = small_simplex_ceo_config();
        config.execution.simplex_ceo.require_sum = None;

        let err = config
            .validate()
            .expect_err("enabled simplex config must declare its constant sum");
        assert!(
            err.to_string()
                .contains("execution.simplex_ceo.require_sum must be set"),
            "{err}"
        );
    }

    #[test]
    fn simplex_ceo_config_rejects_zero_materialization_threshold() {
        let mut config = MprdConfig::default();
        config.execution.simplex_ceo = small_simplex_ceo_config();
        config.execution.simplex_ceo.full_materialization_threshold = 0;

        let err = config
            .validate()
            .expect_err("zero threshold should fail closed");
        assert!(
            err.to_string()
                .contains("full_materialization_threshold must be > 0"),
            "{err}"
        );
    }

    #[test]
    fn simplex_ceo_config_rejects_large_explicit_materialization() {
        let mut config = MprdConfig::default();
        config.execution.simplex_ceo = SimplexCeoDeploymentConfig {
            enabled: true,
            mode: SimplexCeoPlannerModeConfig::StateSymmetry,
            materialization: SimplexCeoMaterializationConfig::ExplicitFullGraph,
            horizon: 6,
            budget_expanded: 1_000_000,
            full_materialization_threshold: default_simplex_full_materialization_threshold(),
            require_sum: Some(1000),
            x0: vec![500, 500, 0, 0],
            caps: vec![1000, 1000, 1000, 1000],
            weights_for_symmetry: vec![7, 7, 1, 2],
        };

        let err = config
            .validate()
            .expect_err("large explicit full graph must be rejected");
        assert!(
            err.to_string()
                .contains("explicit full materialization rejected"),
            "{err}"
        );
        assert!(
            err.to_string()
                .contains("recommendation=use_quotient_or_lazy_planner"),
            "{err}"
        );
    }

    #[test]
    fn simplex_ceo_config_allows_large_lazy_planner() {
        let mut config = MprdConfig::default();
        config.execution.simplex_ceo = SimplexCeoDeploymentConfig {
            enabled: true,
            mode: SimplexCeoPlannerModeConfig::StateSymmetry,
            materialization: SimplexCeoMaterializationConfig::LazyPlanner,
            horizon: 6,
            budget_expanded: 1_000_000,
            full_materialization_threshold: default_simplex_full_materialization_threshold(),
            require_sum: Some(1000),
            x0: vec![250, 250, 250, 250],
            caps: vec![1000, 1000, 1000, 1000],
            weights_for_symmetry: vec![7, 7, 7, 7],
        };

        let advisory = config
            .execution
            .simplex_ceo
            .validate_enabled()
            .expect("large lazy planner config should validate");
        assert_eq!(advisory.raw_full_states, 167_668_501);
        assert_eq!(advisory.quotient_full_states, 7_049_112);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn simplex_ceo_config_rejects_budget_exhausted() {
        let mut config = MprdConfig::default();
        config.execution.simplex_ceo = SimplexCeoDeploymentConfig {
            enabled: true,
            mode: SimplexCeoPlannerModeConfig::StateSymmetry,
            materialization: SimplexCeoMaterializationConfig::LazyPlanner,
            horizon: 1,
            budget_expanded: 0,
            full_materialization_threshold: default_simplex_full_materialization_threshold(),
            require_sum: Some(1),
            x0: vec![1, 0],
            caps: vec![1, 1],
            weights_for_symmetry: vec![1, 2],
        };

        let err = config
            .validate()
            .expect_err("budget exhaustion must fail closed");
        assert!(
            err.to_string()
                .contains("planner advisory budget exhausted"),
            "{err}"
        );
        assert!(err.to_string().contains("budget_exhausted=true"), "{err}");
    }

    #[test]
    fn simplex_ceo_config_rejects_unsupported_ample_mode() {
        let mut config = MprdConfig::default();
        config.execution.simplex_ceo = SimplexCeoDeploymentConfig {
            enabled: true,
            mode: SimplexCeoPlannerModeConfig::AmplePorDfsC2,
            materialization: SimplexCeoMaterializationConfig::LazyPlanner,
            horizon: 1,
            budget_expanded: 10,
            full_materialization_threshold: default_simplex_full_materialization_threshold(),
            require_sum: Some(1),
            x0: vec![1, 0],
            caps: vec![1, 1],
            weights_for_symmetry: vec![1, 2],
        };

        let err = config
            .validate()
            .expect_err("ample mode must not claim this advisory path");
        assert!(
            err.to_string().contains("does not support AmplePorDfsC2"),
            "{err}"
        );
    }

    #[test]
    fn simplex_ceo_config_deserialize_rejects_invalid_enum() {
        // [Enum] each declared enum is closed under serde.
        let ok: SimplexCeoDeploymentConfig = serde_json::from_str(
            r#"{
                "enabled": true,
                "mode": "state_symmetry",
                "materialization": "lazy_planner",
                "horizon": 1,
                "budget_expanded": 1,
                "full_materialization_threshold": 100000000,
                "require_sum": 1,
                "x0": [1, 0],
                "caps": [1, 1],
                "weights_for_symmetry": [1, 2]
            }"#,
        )
        .expect("valid enum values should deserialize");
        assert_eq!(ok.mode, SimplexCeoPlannerModeConfig::StateSymmetry);
        assert_eq!(
            ok.materialization,
            SimplexCeoMaterializationConfig::LazyPlanner
        );

        let err = serde_json::from_str::<SimplexCeoDeploymentConfig>(
            r#"{ "enabled": true, "mode": "unknown", "materialization": "lazy_planner" }"#,
        );
        assert!(err.is_err(), "invalid enum value must fail closed");
    }

    #[test]
    fn decentralized_dispatch_trust_weight_low_bps_boundaries() {
        // [Boundary] trust_weight_low_bps ∈ [0,10000]
        for (bps, expect_ok, reason) in [
            (0u16, true, "exactly at minimum"),
            (1u16, true, "just above minimum"),
            (10_000u16, true, "exactly at maximum"),
            (10_001u16, false, "just above maximum"),
        ] {
            let mut config = base_config_with_dispatch_enabled();
            config.execution.decentralized_dispatch.trust_weight_low_bps = bps;
            assert_eq!(
                config.validate().is_ok(),
                expect_ok,
                "trust_weight_low_bps={bps}: {reason}"
            );
        }
    }

    #[test]
    fn decentralized_dispatch_slot_delay_ms_boundaries() {
        // [Boundary] slot_delay_ms ∈ (0, +∞)
        for (slot_delay_ms, expect_ok, reason) in [
            (0u64, false, "exactly at 0 (invalid)"),
            (1u64, true, "just above 0"),
        ] {
            let mut config = base_config_with_dispatch_enabled();
            config.execution.decentralized_dispatch.slot_delay_ms = slot_delay_ms;
            assert_eq!(
                config.validate().is_ok(),
                expect_ok,
                "slot_delay_ms={slot_delay_ms}: {reason}"
            );
        }
    }

    #[test]
    fn decentralized_dispatch_candidates_len_boundaries_vs_topk() {
        // [Boundary] candidates length and topk coupling.
        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.candidates.clear();
        assert!(
            config.validate().is_err(),
            "candidates.len=0 must be rejected when enabled"
        );

        let mut config = base_config_with_dispatch_enabled();
        config
            .execution
            .decentralized_dispatch
            .candidates
            .truncate(1);
        config.execution.decentralized_dispatch.topk = 1;
        config.execution.decentralized_dispatch.max_attempts = 1;
        assert!(
            config.validate().is_ok(),
            "candidates.len=1 with topk=1/max_attempts=1 should be valid"
        );

        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.topk = 3;
        assert!(
            config.validate().is_err(),
            "topk > candidates.len must be rejected"
        );
    }

    #[test]
    fn decentralized_dispatch_topk_and_max_attempts_cross_field_boundaries() {
        // [Boundary] max_attempts ∈ [1, topk]
        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.max_attempts = 0;
        assert!(
            config.validate().is_err(),
            "max_attempts=0 must be rejected when enabled"
        );

        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.max_attempts = 2;
        assert!(
            config.validate().is_ok(),
            "max_attempts=topk should be valid"
        );

        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.max_attempts = 3;
        assert!(
            config.validate().is_err(),
            "max_attempts > topk must be rejected"
        );
    }

    #[test]
    fn decentralized_dispatch_candidate_id_and_weight_boundaries_and_duplicates() {
        // [Boundary] candidate executor_id string validity + weight positivity + duplicates.
        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.candidates[0].executor_id = "".to_string();
        assert!(
            config.validate().is_err(),
            "empty executor_id must be rejected"
        );

        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.candidates[0].executor_id = " ExecA".to_string();
        assert!(
            config.validate().is_err(),
            "untrimmed executor_id must be rejected"
        );

        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.candidates[0].weight = 0;
        assert!(config.validate().is_err(), "weight=0 must be rejected");

        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.candidates[1].executor_id = "ExecA".to_string();
        assert!(
            config.validate().is_err(),
            "duplicate executor_id must be rejected"
        );
    }

    #[test]
    fn decentralized_dispatch_local_executor_id_string_boundaries() {
        // [Boundary] local_executor_id string validity and membership in candidates.
        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.local_executor_id = "".to_string();
        assert!(
            config.validate().is_err(),
            "empty local_executor_id must be rejected when enabled"
        );

        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.local_executor_id = " ExecA".to_string();
        assert!(
            config.validate().is_err(),
            "untrimmed local_executor_id must be rejected"
        );

        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.local_executor_id = "Missing".to_string();
        assert!(
            config.validate().is_err(),
            "local_executor_id must appear in candidates"
        );
    }

    #[test]
    fn decentralized_dispatch_telemetry_path_option_and_string_boundaries() {
        // [Boundary] telemetry_jsonl_path: None or non-empty trimmed string.
        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.telemetry_jsonl_path = None;
        assert!(config.validate().is_ok(), "None is allowed");

        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.telemetry_jsonl_path = Some("".to_string());
        assert!(config.validate().is_err(), "empty string must be rejected");

        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.telemetry_jsonl_path = Some("   ".to_string());
        assert!(
            config.validate().is_err(),
            "whitespace-only must be rejected"
        );

        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.telemetry_jsonl_path =
            Some("/tmp/mprd_dispatch.jsonl".to_string());
        assert!(config.validate().is_ok(), "non-empty should pass");
    }

    #[test]
    fn decentralized_dispatch_trust_tier_invalid_deserialize_rejected() {
        // [Enum] trust_tier: each value + one invalid.
        let ok: DecentralizedDispatchCandidate = serde_json::from_str(
            r#"{ "executor_id": "ExecA", "weight": 1, "trust_tier": "high" }"#,
        )
        .expect("valid enum value");
        assert_eq!(ok.trust_tier, TrustTier::High);

        let err = serde_json::from_str::<DecentralizedDispatchCandidate>(
            r#"{ "executor_id": "ExecA", "weight": 1, "trust_tier": "invalid" }"#,
        );
        assert!(err.is_err(), "invalid enum value must fail closed");
    }

    #[test]
    fn decentralized_dispatch_trust_tier_partitions_validate() {
        // [Partition] trust_tier ∈ {High,Low}
        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.candidates[0].trust_tier = TrustTier::High;
        assert!(config.validate().is_ok(), "High trust should validate");

        let mut config = base_config_with_dispatch_enabled();
        config.execution.decentralized_dispatch.candidates[0].trust_tier = TrustTier::Low;
        assert!(config.validate().is_ok(), "Low trust should validate");
    }
}
