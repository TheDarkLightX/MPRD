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

/// Complete MPRD configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MprdConfig {
    /// Cryptographic configuration.
    pub crypto: CryptoConfig,

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

        Ok(())
    }
}

/// Cryptographic configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// Anti-replay configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AntiReplayConfig {
    /// Maximum age of a decision token in milliseconds.
    pub max_token_age_ms: i64,

    /// Maximum future timestamp skew allowed in milliseconds.
    pub max_future_skew_ms: i64,

    /// Maximum number of nonces to track.
    pub max_tracked_nonces: usize,
}

impl Default for AntiReplayConfig {
    fn default() -> Self {
        Self {
            max_token_age_ms: 300_000, // 5 minutes
            max_future_skew_ms: 5_000, // 5 seconds
            max_tracked_nonces: 100_000,
        }
    }
}

/// Policy evaluation configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

    /// Set maximum token age.
    pub fn max_token_age(mut self, duration: Duration) -> Self {
        self.config.anti_replay.max_token_age_ms = duration.as_millis() as i64;
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
