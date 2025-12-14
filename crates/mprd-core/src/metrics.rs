//! Observability and Metrics for MPRD
//!
//! This module provides instrumentation for monitoring MPRD pipelines:
//!
//! - **Counters**: Track action counts, decisions, rejections
//! - **Histograms**: Measure latencies for each pipeline stage
//! - **Gauges**: Current state like queue depth, active policies
//!
//! # Usage
//!
//! ```rust,ignore
//! use mprd_core::metrics::{MprdMetrics, record_decision};
//!
//! let metrics = MprdMetrics::new();
//! record_decision(&metrics, "policy_hash", true, 42);
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Instant;

// =============================================================================
// Metric Types
// =============================================================================

/// A simple counter that can only increase.
#[derive(Default)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_by(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// A gauge that can go up or down.
#[derive(Default)]
pub struct Gauge {
    value: AtomicU64,
}

impl Gauge {
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    pub fn set(&self, v: u64) {
        self.value.store(v, Ordering::Relaxed);
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// A histogram for tracking distributions.
pub struct Histogram {
    buckets: Vec<AtomicU64>,
    bucket_bounds: Vec<f64>,
    sum: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    /// Create with default buckets suitable for latencies (in milliseconds).
    pub fn new_latency() -> Self {
        Self::new(vec![
            1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0,
        ])
    }

    pub fn new(bucket_bounds: Vec<f64>) -> Self {
        let buckets = (0..=bucket_bounds.len())
            .map(|_| AtomicU64::new(0))
            .collect();

        Self {
            buckets,
            bucket_bounds,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, value: f64) {
        // Find bucket
        let mut bucket_idx = self.bucket_bounds.len();
        for (i, bound) in self.bucket_bounds.iter().enumerate() {
            if value <= *bound {
                bucket_idx = i;
                break;
            }
        }

        self.buckets[bucket_idx].fetch_add(1, Ordering::Relaxed);
        self.sum
            .fetch_add((value * 1000.0) as u64, Ordering::Relaxed); // Store as micros
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn get_sum(&self) -> f64 {
        self.sum.load(Ordering::Relaxed) as f64 / 1000.0
    }

    pub fn get_mean(&self) -> f64 {
        let count = self.get_count();
        if count == 0 {
            0.0
        } else {
            self.get_sum() / count as f64
        }
    }
}

// =============================================================================
// MPRD Metrics Collection
// =============================================================================

/// Central metrics collection for MPRD.
pub struct MprdMetrics {
    // Counters
    pub proposals_total: Counter,
    pub evaluations_total: Counter,
    pub selections_total: Counter,
    pub attestations_total: Counter,
    pub verifications_total: Counter,
    pub executions_total: Counter,

    pub actions_allowed: Counter,
    pub actions_denied: Counter,
    pub selection_failures: Counter,
    pub verification_failures: Counter,
    pub execution_failures: Counter,

    // Gauges
    pub active_policies: Gauge,
    pub pending_executions: Gauge,

    // Histograms (latencies in ms)
    pub proposal_latency: Histogram,
    pub evaluation_latency: Histogram,
    pub selection_latency: Histogram,
    pub attestation_latency: Histogram,
    pub verification_latency: Histogram,
    pub execution_latency: Histogram,
    pub total_pipeline_latency: Histogram,

    // Per-policy counters
    policy_decisions: RwLock<HashMap<String, Counter>>,
}

impl MprdMetrics {
    pub fn new() -> Self {
        Self {
            proposals_total: Counter::new(),
            evaluations_total: Counter::new(),
            selections_total: Counter::new(),
            attestations_total: Counter::new(),
            verifications_total: Counter::new(),
            executions_total: Counter::new(),

            actions_allowed: Counter::new(),
            actions_denied: Counter::new(),
            selection_failures: Counter::new(),
            verification_failures: Counter::new(),
            execution_failures: Counter::new(),

            active_policies: Gauge::new(),
            pending_executions: Gauge::new(),

            proposal_latency: Histogram::new_latency(),
            evaluation_latency: Histogram::new_latency(),
            selection_latency: Histogram::new_latency(),
            attestation_latency: Histogram::new_latency(),
            verification_latency: Histogram::new_latency(),
            execution_latency: Histogram::new_latency(),
            total_pipeline_latency: Histogram::new_latency(),

            policy_decisions: RwLock::new(HashMap::new()),
        }
    }

    /// Record a decision for a specific policy.
    pub fn record_policy_decision(&self, policy_hash: &str) {
        if let Ok(mut map) = self.policy_decisions.write() {
            map.entry(policy_hash.to_string())
                .or_insert_with(Counter::new)
                .inc();
        }
    }

    /// Get decision count for a policy.
    pub fn get_policy_decisions(&self, policy_hash: &str) -> u64 {
        if let Ok(map) = self.policy_decisions.read() {
            map.get(policy_hash).map(|c| c.get()).unwrap_or(0)
        } else {
            0
        }
    }

    /// Export metrics as JSON.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "counters": {
                "proposals_total": self.proposals_total.get(),
                "evaluations_total": self.evaluations_total.get(),
                "selections_total": self.selections_total.get(),
                "attestations_total": self.attestations_total.get(),
                "verifications_total": self.verifications_total.get(),
                "executions_total": self.executions_total.get(),
                "actions_allowed": self.actions_allowed.get(),
                "actions_denied": self.actions_denied.get(),
                "selection_failures": self.selection_failures.get(),
                "verification_failures": self.verification_failures.get(),
                "execution_failures": self.execution_failures.get(),
            },
            "gauges": {
                "active_policies": self.active_policies.get(),
                "pending_executions": self.pending_executions.get(),
            },
            "latencies_ms": {
                "proposal_mean": self.proposal_latency.get_mean(),
                "evaluation_mean": self.evaluation_latency.get_mean(),
                "selection_mean": self.selection_latency.get_mean(),
                "attestation_mean": self.attestation_latency.get_mean(),
                "verification_mean": self.verification_latency.get_mean(),
                "execution_mean": self.execution_latency.get_mean(),
                "total_pipeline_mean": self.total_pipeline_latency.get_mean(),
            },
        })
    }
}

impl Default for MprdMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Instrumented Pipeline Timer
// =============================================================================

/// Timer for measuring pipeline stage latency.
pub struct StageTimer<'a> {
    histogram: &'a Histogram,
    start: Instant,
}

impl<'a> StageTimer<'a> {
    pub fn start(histogram: &'a Histogram) -> Self {
        Self {
            histogram,
            start: Instant::now(),
        }
    }
}

impl<'a> Drop for StageTimer<'a> {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        self.histogram.observe(elapsed.as_secs_f64() * 1000.0);
    }
}

// =============================================================================
// Convenience Functions
// =============================================================================

/// Record a proposal with timing.
pub fn timed_propose<F, T>(metrics: &MprdMetrics, f: F) -> T
where
    F: FnOnce() -> T,
{
    let _timer = StageTimer::start(&metrics.proposal_latency);
    metrics.proposals_total.inc();
    f()
}

/// Record an evaluation with timing.
pub fn timed_evaluate<F, T>(metrics: &MprdMetrics, f: F) -> T
where
    F: FnOnce() -> T,
{
    let _timer = StageTimer::start(&metrics.evaluation_latency);
    metrics.evaluations_total.inc();
    f()
}

/// Record a selection with timing.
pub fn timed_select<F, T>(metrics: &MprdMetrics, f: F) -> T
where
    F: FnOnce() -> T,
{
    let _timer = StageTimer::start(&metrics.selection_latency);
    metrics.selections_total.inc();
    f()
}

/// Record an attestation with timing.
pub fn timed_attest<F, T>(metrics: &MprdMetrics, f: F) -> T
where
    F: FnOnce() -> T,
{
    let _timer = StageTimer::start(&metrics.attestation_latency);
    metrics.attestations_total.inc();
    f()
}

/// Record a verification with timing.
pub fn timed_verify<F, T>(metrics: &MprdMetrics, f: F) -> T
where
    F: FnOnce() -> T,
{
    let _timer = StageTimer::start(&metrics.verification_latency);
    metrics.verifications_total.inc();
    f()
}

/// Record an execution with timing.
pub fn timed_execute<F, T>(metrics: &MprdMetrics, f: F) -> T
where
    F: FnOnce() -> T,
{
    let _timer = StageTimer::start(&metrics.execution_latency);
    metrics.executions_total.inc();
    f()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_increments() {
        let counter = Counter::new();
        assert_eq!(counter.get(), 0);

        counter.inc();
        assert_eq!(counter.get(), 1);

        counter.inc_by(5);
        assert_eq!(counter.get(), 6);
    }

    #[test]
    fn gauge_goes_up_and_down() {
        let gauge = Gauge::new();

        gauge.set(100);
        assert_eq!(gauge.get(), 100);

        gauge.inc();
        assert_eq!(gauge.get(), 101);

        gauge.dec();
        assert_eq!(gauge.get(), 100);
    }

    #[test]
    fn histogram_tracks_distribution() {
        let hist = Histogram::new_latency();

        hist.observe(5.0);
        hist.observe(10.0);
        hist.observe(15.0);

        assert_eq!(hist.get_count(), 3);
        assert!((hist.get_mean() - 10.0).abs() < 0.1);
    }

    #[test]
    fn metrics_export_to_json() {
        let metrics = MprdMetrics::new();

        metrics.proposals_total.inc();
        metrics.evaluations_total.inc();
        metrics.actions_allowed.inc();

        let json = metrics.to_json();

        assert_eq!(json["counters"]["proposals_total"], 1);
        assert_eq!(json["counters"]["evaluations_total"], 1);
        assert_eq!(json["counters"]["actions_allowed"], 1);
    }

    #[test]
    fn timed_functions_record_latency() {
        let metrics = MprdMetrics::new();

        let result = timed_propose(&metrics, || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            42
        });

        assert_eq!(result, 42);
        assert_eq!(metrics.proposals_total.get(), 1);
        assert!(metrics.proposal_latency.get_mean() >= 10.0);
    }
}
