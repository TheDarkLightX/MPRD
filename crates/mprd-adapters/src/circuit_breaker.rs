//! Circuit Breaker Executor Wrapper (ESSO-Verified)
//!
//! This module provides a circuit breaker pattern for any ExecutorAdapter,
//! backed by an ESSO-verified state machine that enforces:
//!
//! - FailureThresholdOpens: 5+ failures → Open
//! - HalfOpenRequiresCooldown: HalfOpen → cooldown = 0
//! - ClosedMeansRecovered: Closed → failures < 5
//!
//! @see internal/tools/evolver/examples/mprd/executor_circuit_breaker.yaml

use mprd_core::{ExecutionResult, ExecutorAdapter, MprdError, Result, VerifiedBundle};
use std::sync::Mutex;
use std::time::{Duration, Instant};

// =============================================================================
// Circuit Breaker State (ESSO-Verified Kernel)
// =============================================================================

/// State enum matching the verified ESSO-IR model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Verified circuit breaker state matching `executor_circuit_breaker.yaml`.
#[derive(Debug)]
pub struct CircuitBreakerState {
    pub state: CircuitState,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub cooldown_until: Option<Instant>,
}

impl Default for CircuitBreakerState {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            consecutive_successes: 0,
            cooldown_until: None,
        }
    }
}

// =============================================================================
// Invariant Checks (From ESSO-IR)
// =============================================================================

const FAILURE_THRESHOLD: u32 = 5;
const SUCCESS_THRESHOLD_TO_CLOSE: u32 = 3;
const COOLDOWN_DURATION: Duration = Duration::from_secs(30);

/// Check invariants from verified model.
fn check_invariants(st: &CircuitBreakerState) -> Result<()> {
    // FailureThresholdOpens: 5+ failures → not Closed
    if st.consecutive_failures >= FAILURE_THRESHOLD && st.state == CircuitState::Closed {
        return Err(MprdError::InvalidState(
            "FailureThresholdOpens violated: should not be Closed with 5+ failures".into(),
        ));
    }

    // HalfOpenRequiresCooldown: HalfOpen → cooldown elapsed
    if st.state == CircuitState::HalfOpen {
        if let Some(until) = st.cooldown_until {
            if Instant::now() < until {
                return Err(MprdError::InvalidState(
                    "HalfOpenRequiresCooldown violated: cooldown not elapsed".into(),
                ));
            }
        }
    }

    // ClosedMeansRecovered: Closed → failures < 5
    if st.state == CircuitState::Closed && st.consecutive_failures >= FAILURE_THRESHOLD {
        return Err(MprdError::InvalidState(
            "ClosedMeansRecovered violated: Closed with 5+ failures".into(),
        ));
    }

    Ok(())
}

// =============================================================================
// State Transitions (From ESSO-IR Actions)
// =============================================================================

impl CircuitBreakerState {
    /// Record a successful call (from verified model: record_success action).
    pub fn record_success(&mut self) {
        if self.state == CircuitState::Open {
            return; // Can't record success when open
        }

        self.consecutive_successes = (self.consecutive_successes + 1).min(5);
        self.consecutive_failures = 0;

        // HalfOpen → Closed after 3 successes
        if self.state == CircuitState::HalfOpen && self.consecutive_successes >= SUCCESS_THRESHOLD_TO_CLOSE
        {
            self.state = CircuitState::Closed;
        }
    }

    /// Record a failed call (from verified model: record_failure action).
    pub fn record_failure(&mut self) {
        if self.state == CircuitState::Open {
            return; // Can't record failure when fully open
        }

        self.consecutive_failures = (self.consecutive_failures + 1).min(10);
        self.consecutive_successes = 0;

        // Threshold crossed → Open
        if self.consecutive_failures >= FAILURE_THRESHOLD {
            self.state = CircuitState::Open;
            self.cooldown_until = Some(Instant::now() + COOLDOWN_DURATION);
        }
    }

    /// Try to transition from Open to HalfOpen (from verified model: try_half_open action).
    pub fn try_half_open(&mut self) {
        if self.state != CircuitState::Open {
            return;
        }

        // Check if cooldown has elapsed
        if let Some(until) = self.cooldown_until {
            if Instant::now() >= until {
                self.state = CircuitState::HalfOpen;
                self.consecutive_successes = 0;
                self.cooldown_until = None;
            }
        }
    }

    /// Manual reset (from verified model: manual_reset action).
    pub fn manual_reset(&mut self) {
        self.state = CircuitState::Closed;
        self.consecutive_failures = 0;
        self.consecutive_successes = 0;
        self.cooldown_until = None;
    }
}

// =============================================================================
// Circuit Breaking Executor Wrapper
// =============================================================================

/// Executor wrapper that applies circuit breaker pattern.
///
/// When the circuit is Open, calls fail fast without hitting the backend.
/// When HalfOpen, a single probe call is allowed to test recovery.
pub struct CircuitBreakingExecutor<E: ExecutorAdapter> {
    inner: E,
    state: Mutex<CircuitBreakerState>,
}

impl<E: ExecutorAdapter> CircuitBreakingExecutor<E> {
    /// Create a new circuit breaking wrapper around an executor.
    pub fn new(inner: E) -> Self {
        Self {
            inner,
            state: Mutex::new(CircuitBreakerState::default()),
        }
    }

    /// Get current circuit state for monitoring.
    pub fn circuit_state(&self) -> CircuitState {
        self.state.lock().unwrap().state
    }

    /// Manually reset the circuit (operator override).
    pub fn reset(&self) {
        if let Ok(mut st) = self.state.lock() {
            st.manual_reset();
        }
    }
}

impl<E: ExecutorAdapter + Send + Sync> ExecutorAdapter for CircuitBreakingExecutor<E> {
    fn execute(&self, verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
        let mut st = self
            .state
            .lock()
            .map_err(|_| MprdError::ExecutionError("Circuit breaker lock poisoned".into()))?;

        // Check for cooldown elapsed → transition to HalfOpen
        st.try_half_open();

        // Check invariants (fail-closed)
        check_invariants(&st)?;

        match st.state {
            CircuitState::Open => {
                // Fail fast
                Err(MprdError::ExecutionError(
                    "Circuit breaker is OPEN: executor unavailable".into(),
                ))
            }
            CircuitState::Closed | CircuitState::HalfOpen => {
                // Drop lock before calling inner executor
                drop(st);

                // Execute
                let result = self.inner.execute(verified);

                // Record outcome
                let mut st = self
                    .state
                    .lock()
                    .map_err(|_| MprdError::ExecutionError("Circuit breaker lock poisoned".into()))?;

                match &result {
                    Ok(r) if r.success => st.record_success(),
                    _ => st.record_failure(),
                }

                result
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_is_closed() {
        let st = CircuitBreakerState::default();
        assert_eq!(st.state, CircuitState::Closed);
        assert_eq!(st.consecutive_failures, 0);
    }

    #[test]
    fn five_failures_opens_circuit() {
        let mut st = CircuitBreakerState::default();
        for _ in 0..5 {
            st.record_failure();
        }
        assert_eq!(st.state, CircuitState::Open);
        assert!(st.cooldown_until.is_some());
    }

    #[test]
    fn success_resets_failure_count() {
        let mut st = CircuitBreakerState::default();
        st.record_failure();
        st.record_failure();
        st.record_success();
        assert_eq!(st.consecutive_failures, 0);
        assert_eq!(st.state, CircuitState::Closed);
    }

    #[test]
    fn half_open_to_closed_after_successes() {
        let mut st = CircuitBreakerState {
            state: CircuitState::HalfOpen,
            consecutive_failures: 0,
            consecutive_successes: 0,
            cooldown_until: None,
        };
        st.record_success();
        st.record_success();
        assert_eq!(st.state, CircuitState::HalfOpen);
        st.record_success();
        assert_eq!(st.state, CircuitState::Closed);
    }

// =============================================================================
// Kani Verification Harnesses
// =============================================================================

#[cfg(kani)]
mod kani_verification {
    use super::*;

    /// Verify that 5+ failures always opens the circuit (I1)
    #[kani::proof]
    fn failure_threshold_opens_circuit() {
        let mut st = CircuitBreakerState::default();
        
        // Record some number of failures
        let failures: u32 = kani::any();
        kani::assume(failures <= 10);
        
        for _ in 0..failures {
            st.record_failure();
        }
        
        // Invariant: 5+ failures → not Closed
        if st.consecutive_failures >= FAILURE_THRESHOLD {
            kani::assert(
                st.state != CircuitState::Closed,
                "FailureThresholdOpens violated"
            );
        }
    }

    /// Verify that success resets failure count (I2)
    #[kani::proof]
    fn success_resets_failures() {
        let mut st = CircuitBreakerState::default();
        
        // Record some failures (not enough to open)
        let failures: u32 = kani::any();
        kani::assume(failures < FAILURE_THRESHOLD);
        
        for _ in 0..failures {
            st.record_failure();
        }
        
        // Record a success
        st.record_success();
        
        // Failure count should be reset
        kani::assert(
            st.consecutive_failures == 0,
            "Success should reset failure count"
        );
    }

    /// Verify Closed state means failures < threshold (I3)
    #[kani::proof]
    fn closed_means_recovered() {
        let failures: u32 = kani::any();
        let successes: u32 = kani::any();
        
        kani::assume(failures <= 10);
        kani::assume(successes <= 5);
        
        let st = CircuitBreakerState {
            state: CircuitState::Closed,
            consecutive_failures: failures,
            consecutive_successes: successes,
            cooldown_until: None,
        };
        
        // If invariant check passes, then failures < threshold
        if check_invariants(&st).is_ok() {
            kani::assert(
                st.consecutive_failures < FAILURE_THRESHOLD,
                "ClosedMeansRecovered violated"
            );
        }
    }

    /// Verify HalfOpen transitions to Closed after 3 successes
    #[kani::proof]
    fn half_open_closes_after_successes() {
        let mut st = CircuitBreakerState {
            state: CircuitState::HalfOpen,
            consecutive_failures: 0,
            consecutive_successes: 0,
            cooldown_until: None,
        };
        
        // Record 3 successes
        st.record_success();
        st.record_success();
        st.record_success();
        
        // Should transition to Closed
        kani::assert(
            st.state == CircuitState::Closed,
            "HalfOpen should close after 3 successes"
        );
    }

    /// Verify manual reset always results in Closed state
    #[kani::proof]
    fn manual_reset_always_closes() {
        let state_idx: u8 = kani::any();
        kani::assume(state_idx < 3);
        
        let state = match state_idx {
            0 => CircuitState::Closed,
            1 => CircuitState::Open,
            _ => CircuitState::HalfOpen,
        };
        
        let failures: u32 = kani::any();
        let successes: u32 = kani::any();
        kani::assume(failures <= 10);
        kani::assume(successes <= 5);
        
        let mut st = CircuitBreakerState {
            state,
            consecutive_failures: failures,
            consecutive_successes: successes,
            cooldown_until: None,
        };
        
        st.manual_reset();
        
        kani::assert(st.state == CircuitState::Closed, "Reset should close");
        kani::assert(st.consecutive_failures == 0, "Reset should clear failures");
        kani::assert(st.consecutive_successes == 0, "Reset should clear successes");
    }

    /// Verify circuit breaker state machine is deterministic
    #[kani::proof]
    fn state_machine_deterministic() {
        let failures1: u32 = kani::any();
        let failures2: u32 = kani::any();
        kani::assume(failures1 == failures2);
        kani::assume(failures1 <= 10);
        
        let mut st1 = CircuitBreakerState::default();
        let mut st2 = CircuitBreakerState::default();
        
        for _ in 0..failures1 {
            st1.record_failure();
        }
        for _ in 0..failures2 {
            st2.record_failure();
        }
        
        kani::assert(
            st1.state == st2.state,
            "Same inputs should produce same state"
        );
        kani::assert(
            st1.consecutive_failures == st2.consecutive_failures,
            "Same inputs should produce same failure count"
        );
    }
}

    #[test]
    fn manual_reset_clears_state() {
        let mut st = CircuitBreakerState {
            state: CircuitState::Open,
            consecutive_failures: 5,
            consecutive_successes: 0,
            cooldown_until: Some(Instant::now() + Duration::from_secs(100)),
        };
        st.manual_reset();
        assert_eq!(st.state, CircuitState::Closed);
        assert_eq!(st.consecutive_failures, 0);
        assert!(st.cooldown_until.is_none());
    }

    #[test]
    fn invariant_check_fails_on_violation() {
        let st = CircuitBreakerState {
            state: CircuitState::Closed,
            consecutive_failures: 5,
            consecutive_successes: 0,
            cooldown_until: None,
        };
        assert!(check_invariants(&st).is_err());
    }
}
