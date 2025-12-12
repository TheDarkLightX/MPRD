//! Anti-replay mechanism for decision tokens.
//!
//! Enforces invariant S4: No `DecisionToken` can be validly used more than once.

use crate::{DecisionToken, Hash32, MprdError, NonceHash, PolicyHash, Result};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for anti-replay validation.
#[derive(Clone, Debug)]
pub struct AntiReplayConfig {
    /// Maximum token age in milliseconds.
    pub max_token_age_ms: i64,

    /// How long to retain nonces for replay checking.
    pub nonce_retention_ms: i64,

    /// Maximum allowed clock skew (future timestamps).
    pub max_future_skew_ms: i64,
}

impl Default for AntiReplayConfig {
    fn default() -> Self {
        Self {
            max_token_age_ms: 60_000,       // 1 minute
            nonce_retention_ms: 3_600_000,  // 1 hour
            max_future_skew_ms: 5_000,      // 5 seconds
        }
    }
}

/// Trait for nonce validation.
pub trait NonceValidator: Send + Sync {
    /// Check if a token's nonce is valid (not replayed, not expired).
    fn validate(&self, token: &DecisionToken) -> Result<()>;

    /// Mark a nonce as used after successful execution.
    fn mark_used(&self, token: &DecisionToken) -> Result<()>;

    /// Clean up expired nonces.
    fn cleanup(&self);
}

/// Entry tracking when a nonce was used.
#[derive(Clone, Debug)]
struct NonceEntry {
    used_at_ms: i64,
}

/// In-memory nonce tracker.
pub struct InMemoryNonceTracker {
    /// Map of (policy_hash, nonce) -> usage info.
    used: RwLock<HashMap<(PolicyHash, NonceHash), NonceEntry>>,

    /// Configuration.
    config: AntiReplayConfig,
}

impl InMemoryNonceTracker {
    /// Create a new tracker with default configuration.
    pub fn new() -> Self {
        Self::with_config(AntiReplayConfig::default())
    }

    /// Create a new tracker with custom configuration.
    pub fn with_config(config: AntiReplayConfig) -> Self {
        Self {
            used: RwLock::new(HashMap::new()),
            config,
        }
    }

    fn current_time_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }
}

impl Default for InMemoryNonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceValidator for InMemoryNonceTracker {
    fn validate(&self, token: &DecisionToken) -> Result<()> {
        let now_ms = Self::current_time_ms();
        let age = now_ms - token.timestamp_ms;

        // Check if token is too old
        if age > self.config.max_token_age_ms {
            return Err(MprdError::TokenExpired {
                age_ms: age,
                max_age_ms: self.config.max_token_age_ms,
            });
        }

        // Check if token is from the future (beyond allowed skew)
        if age < -self.config.max_future_skew_ms {
            return Err(MprdError::TokenFromFuture { skew_ms: -age });
        }

        // Check for replay - SECURITY: Handle poisoned lock gracefully
        let key = (token.policy_hash.clone(), token.nonce_or_tx_hash.clone());
        let used = self.used.read()
            .map_err(|_| MprdError::ExecutionError("Nonce tracker lock poisoned".into()))?;
        
        if used.contains_key(&key) {
            return Err(MprdError::NonceReplay {
                nonce: token.nonce_or_tx_hash.clone(),
            });
        }

        Ok(())
    }

    fn mark_used(&self, token: &DecisionToken) -> Result<()> {
        let key = (token.policy_hash.clone(), token.nonce_or_tx_hash.clone());
        let entry = NonceEntry {
            used_at_ms: Self::current_time_ms(),
        };

        // SECURITY: Handle poisoned lock gracefully
        let mut used = self.used.write()
            .map_err(|_| MprdError::ExecutionError("Nonce tracker lock poisoned".into()))?;
        
        used.insert(key, entry);
        Ok(())
    }

    fn cleanup(&self) {
        let now_ms = Self::current_time_ms();
        let cutoff = now_ms - self.config.nonce_retention_ms;

        // Best effort cleanup - if lock is poisoned, skip cleanup
        if let Ok(mut used) = self.used.write() {
            used.retain(|_, entry| entry.used_at_ms > cutoff);
        }
    }
}

/// Executor wrapper that enforces anti-replay.
pub struct AntiReplayExecutor<E, N> {
    inner: E,
    nonce_validator: N,
}

impl<E, N> AntiReplayExecutor<E, N>
where
    E: crate::ExecutorAdapter,
    N: NonceValidator,
{
    /// Create a new anti-replay executor.
    pub fn new(inner: E, nonce_validator: N) -> Self {
        Self {
            inner,
            nonce_validator,
        }
    }
}

impl<E, N> crate::ExecutorAdapter for AntiReplayExecutor<E, N>
where
    E: crate::ExecutorAdapter,
    N: NonceValidator,
{
    fn execute(
        &self,
        token: &DecisionToken,
        proof: &crate::ProofBundle,
    ) -> Result<crate::ExecutionResult> {
        // Pre-condition: validate nonce
        self.nonce_validator.validate(token)?;

        // Execute the action
        let result = self.inner.execute(token, proof)?;

        // Post-condition: mark nonce as used (only on success)
        if result.success {
            self.nonce_validator.mark_used(token)?;
        }

        Ok(result)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_token(nonce_byte: u8, timestamp_ms: i64) -> DecisionToken {
        DecisionToken {
            policy_hash: Hash32([1u8; 32]),
            state_hash: Hash32([2u8; 32]),
            chosen_action_hash: Hash32([3u8; 32]),
            nonce_or_tx_hash: Hash32([nonce_byte; 32]),
            timestamp_ms,
            signature: vec![],
        }
    }

    #[test]
    fn valid_token_passes() {
        let tracker = InMemoryNonceTracker::new();
        let now = InMemoryNonceTracker::current_time_ms();
        let token = dummy_token(1, now);

        assert!(tracker.validate(&token).is_ok());
    }

    #[test]
    fn expired_token_rejected() {
        let config = AntiReplayConfig {
            max_token_age_ms: 100,
            ..Default::default()
        };
        let tracker = InMemoryNonceTracker::with_config(config);

        let old_timestamp = InMemoryNonceTracker::current_time_ms() - 200;
        let token = dummy_token(1, old_timestamp);

        let result = tracker.validate(&token);
        assert!(matches!(result, Err(MprdError::TokenExpired { .. })));
    }

    #[test]
    fn future_token_rejected() {
        let config = AntiReplayConfig {
            max_future_skew_ms: 100,
            ..Default::default()
        };
        let tracker = InMemoryNonceTracker::with_config(config);

        let future_timestamp = InMemoryNonceTracker::current_time_ms() + 200;
        let token = dummy_token(1, future_timestamp);

        let result = tracker.validate(&token);
        assert!(matches!(result, Err(MprdError::TokenFromFuture { .. })));
    }

    #[test]
    fn replay_rejected() {
        let tracker = InMemoryNonceTracker::new();
        let now = InMemoryNonceTracker::current_time_ms();
        let token = dummy_token(1, now);

        // First use succeeds
        assert!(tracker.validate(&token).is_ok());
        tracker.mark_used(&token).unwrap();

        // Replay fails
        let result = tracker.validate(&token);
        assert!(matches!(result, Err(MprdError::NonceReplay { .. })));
    }

    #[test]
    fn different_nonces_allowed() {
        let tracker = InMemoryNonceTracker::new();
        let now = InMemoryNonceTracker::current_time_ms();

        let token1 = dummy_token(1, now);
        let token2 = dummy_token(2, now);

        tracker.validate(&token1).unwrap();
        tracker.mark_used(&token1).unwrap();

        // Different nonce should work
        assert!(tracker.validate(&token2).is_ok());
    }
}
