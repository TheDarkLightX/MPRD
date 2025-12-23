//! Deployment bounds for MPRD Artifact Repository.
//!
//! All algorithms are bounded by these parameters to ensure:
//! - DoS resistance (bounded work per operation)
//! - Predictable resource usage
//! - Fail-closed behavior on bounds exceeded

/// Maximum block size in bytes (recommended ≤ 256 KiB).
pub const MAX_BLOCK_BYTES: usize = 256 * 1024;

/// Maximum entries per MST node (MUST be ≤ 16 for nibble-indexed model).
pub const MAX_NODE_ENTRIES: usize = 16;

/// Maximum key size in bytes.
pub const MAX_KEY_BYTES: usize = 256;

/// Maximum value size in bytes (MUST be ≤ MAX_BLOCK_BYTES).
pub const MAX_VALUE_BYTES: usize = MAX_BLOCK_BYTES;

/// Maximum commits fetched during catch-up operations.
pub const MAX_COMMIT_CHAIN: usize = 10_000;

/// Maximum blocks fetched during a single operation.
pub const MAX_BLOCK_FETCH: usize = 50_000;

/// Maximum parallel fetch requests.
pub const MAX_PARALLEL_FETCH: usize = 16;

/// Maximum retry attempts per source.
pub const MAX_RETRIES: usize = 2;

/// Maximum MST depth (64 nibbles from 32-byte hash).
pub const MAX_MST_DEPTH: usize = 64;

/// Maximum diff entries returned from a single diff operation.
pub const MAX_DIFF_ENTRIES: usize = 100_000;

/// Default hedge delay in milliseconds for hedged requests.
pub const DEFAULT_HEDGE_DELAY_MS: u64 = 50;

/// Default per-source timeout in milliseconds.
pub const DEFAULT_SOURCE_TIMEOUT_MS: u64 = 5_000;

/// Maximum cache size in bytes.
pub const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Negative cache TTL in seconds.
pub const NEGATIVE_CACHE_TTL_SECS: u64 = 30;

/// Domain separation prefix for block hashing.
pub const BLOCK_HASH_PREFIX: &[u8] = b"MPRD_BLOCK_V1";

/// Domain separation prefix for MST key hashing.
pub const MST_KEY_HASH_PREFIX: &[u8] = b"MPRD_MST_KEY_V1";

/// Domain separation prefix for commit signing.
pub const COMMIT_SIGN_PREFIX: &[u8] = b"MPRD_REPO_COMMIT_V1";

/// Domain separation prefix for source shuffle.
pub const SOURCE_SHUFFLE_PREFIX: &[u8] = b"MPRD_SOURCE_SHUFFLE_V1";

/// Domain separation prefix for block source identity.
pub const BLOCK_SOURCE_PREFIX: &[u8] = b"MPRD_BLOCK_SOURCE_V1";

/// Runtime-configurable bounds for deployment flexibility.
#[derive(Debug, Clone)]
pub struct RuntimeBounds {
    pub max_block_bytes: usize,
    pub max_key_bytes: usize,
    pub max_value_bytes: usize,
    pub max_commit_chain: usize,
    pub max_block_fetch: usize,
    pub max_parallel_fetch: usize,
    pub max_retries: usize,
    pub hedge_delay_ms: u64,
    pub source_timeout_ms: u64,
}

impl Default for RuntimeBounds {
    fn default() -> Self {
        Self {
            max_block_bytes: MAX_BLOCK_BYTES,
            max_key_bytes: MAX_KEY_BYTES,
            max_value_bytes: MAX_VALUE_BYTES,
            max_commit_chain: MAX_COMMIT_CHAIN,
            max_block_fetch: MAX_BLOCK_FETCH,
            max_parallel_fetch: MAX_PARALLEL_FETCH,
            max_retries: MAX_RETRIES,
            hedge_delay_ms: DEFAULT_HEDGE_DELAY_MS,
            source_timeout_ms: DEFAULT_SOURCE_TIMEOUT_MS,
        }
    }
}

impl RuntimeBounds {
    /// Validate that bounds are internally consistent.
    ///
    /// # Invariants
    /// - max_value_bytes ≤ max_block_bytes
    /// - max_parallel_fetch > 0
    /// - max_retries > 0
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_value_bytes > self.max_block_bytes {
            return Err("max_value_bytes must be ≤ max_block_bytes");
        }
        if self.max_parallel_fetch == 0 {
            return Err("max_parallel_fetch must be > 0");
        }
        if self.max_retries == 0 {
            return Err("max_retries must be > 0");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bounds_are_valid() {
        let bounds = RuntimeBounds::default();
        assert!(bounds.validate().is_ok());
    }

    #[test]
    fn invalid_value_bytes() {
        let bounds = RuntimeBounds {
            max_value_bytes: MAX_BLOCK_BYTES + 1,
            ..Default::default()
        };
        assert!(bounds.validate().is_err());
    }
}
