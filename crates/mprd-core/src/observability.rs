//! Prometheus metrics exporter (basic infrastructure).

use crate::metrics::Counter;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Metric exporter interface for observability backends.
pub trait MetricsExporter: Send + Sync {
    /// Render metrics in a backend-specific format.
    fn render(&self) -> String;

    /// Serve metrics over HTTP.
    fn serve(self: Arc<Self>, addr: SocketAddr) -> std::io::Result<MetricsServer>;
}

/// Storage for the core Prometheus metrics.
pub struct PrometheusMetrics {
    decisions_total: Counter,
    decisions_latency_seconds: PrometheusHistogram,
    policy_evaluations_total: Counter,
    proof_verifications_total: Counter,
}

impl PrometheusMetrics {
    pub fn new() -> Self {
        Self {
            decisions_total: Counter::new(),
            decisions_latency_seconds: PrometheusHistogram::new_latency_seconds(),
            policy_evaluations_total: Counter::new(),
            proof_verifications_total: Counter::new(),
        }
    }

    /// Record a decision and its latency.
    pub fn record_decision(&self, latency: Duration) {
        self.decisions_total.inc();
        self.decisions_latency_seconds
            .observe_seconds(latency.as_secs_f64());
    }

    /// Record a policy evaluation.
    pub fn record_policy_evaluation(&self) {
        self.policy_evaluations_total.inc();
    }

    /// Record a proof verification.
    pub fn record_proof_verification(&self) {
        self.proof_verifications_total.inc();
    }
}

impl Default for PrometheusMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Prometheus text-format exporter with a built-in `/metrics` endpoint.
pub struct PrometheusExporter {
    metrics: Arc<PrometheusMetrics>,
}

impl PrometheusExporter {
    pub fn new(metrics: Arc<PrometheusMetrics>) -> Self {
        Self { metrics }
    }

    pub fn metrics(&self) -> Arc<PrometheusMetrics> {
        Arc::clone(&self.metrics)
    }

    fn render_prometheus(&self) -> String {
        let mut out = String::new();

        out.push_str("# HELP decisions_total Total number of decisions.\n");
        out.push_str("# TYPE decisions_total counter\n");
        out.push_str(&format!(
            "decisions_total {}\n",
            self.metrics.decisions_total.get()
        ));

        out.push_str("# HELP decisions_latency_seconds Decision latency in seconds.\n");
        out.push_str("# TYPE decisions_latency_seconds histogram\n");
        let latency = self.metrics.decisions_latency_seconds.snapshot();
        let mut cumulative = 0u64;
        for (idx, bound) in latency.bucket_bounds.iter().enumerate() {
            cumulative = cumulative.saturating_add(latency.bucket_counts[idx]);
            out.push_str(&format!(
                "decisions_latency_seconds_bucket{{le=\"{}\"}} {}\n",
                bound, cumulative
            ));
        }
        cumulative =
            cumulative.saturating_add(latency.bucket_counts.last().copied().unwrap_or_default());
        out.push_str(&format!(
            "decisions_latency_seconds_bucket{{le=\"+Inf\"}} {}\n",
            cumulative
        ));
        out.push_str(&format!(
            "decisions_latency_seconds_sum {}\n",
            latency.sum_seconds
        ));
        out.push_str(&format!(
            "decisions_latency_seconds_count {}\n",
            latency.count
        ));

        out.push_str("# HELP policy_evaluations_total Total policy evaluations.\n");
        out.push_str("# TYPE policy_evaluations_total counter\n");
        out.push_str(&format!(
            "policy_evaluations_total {}\n",
            self.metrics.policy_evaluations_total.get()
        ));

        out.push_str("# HELP proof_verifications_total Total proof verifications.\n");
        out.push_str("# TYPE proof_verifications_total counter\n");
        out.push_str(&format!(
            "proof_verifications_total {}\n",
            self.metrics.proof_verifications_total.get()
        ));

        out
    }
}

impl MetricsExporter for PrometheusExporter {
    fn render(&self) -> String {
        self.render_prometheus()
    }

    fn serve(self: Arc<Self>, addr: SocketAddr) -> std::io::Result<MetricsServer> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_handle = Arc::clone(&stop);
        let exporter = Arc::clone(&self);

        let join = thread::spawn(move || {
            while !stop_handle.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = handle_connection(stream, &exporter.render_prometheus());
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        });

        Ok(MetricsServer {
            stop,
            join: Some(join),
        })
    }
}

/// Handle to a running metrics server.
pub struct MetricsServer {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl MetricsServer {
    /// Signal the server to stop and wait for it to exit.
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for MetricsServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct HistogramSnapshot {
    bucket_bounds: Vec<f64>,
    bucket_counts: Vec<u64>,
    sum_seconds: f64,
    count: u64,
}

struct PrometheusHistogram {
    buckets: Vec<AtomicU64>,
    bucket_bounds: Vec<f64>,
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl PrometheusHistogram {
    fn new_latency_seconds() -> Self {
        Self::new(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0,
        ])
    }

    fn new(bucket_bounds: Vec<f64>) -> Self {
        let buckets = (0..=bucket_bounds.len())
            .map(|_| AtomicU64::new(0))
            .collect();

        Self {
            buckets,
            bucket_bounds,
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    fn observe_seconds(&self, value_seconds: f64) {
        let mut bucket_idx = self.bucket_bounds.len();
        for (i, bound) in self.bucket_bounds.iter().enumerate() {
            if value_seconds <= *bound {
                bucket_idx = i;
                break;
            }
        }

        self.buckets[bucket_idx].fetch_add(1, Ordering::Relaxed);
        let micros = (value_seconds * 1_000_000.0).round() as u64;
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> HistogramSnapshot {
        let bucket_counts = self
            .buckets
            .iter()
            .map(|bucket| bucket.load(Ordering::Relaxed))
            .collect();

        HistogramSnapshot {
            bucket_bounds: self.bucket_bounds.clone(),
            bucket_counts,
            sum_seconds: self.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0,
            count: self.count.load(Ordering::Relaxed),
        }
    }
}

fn handle_connection(mut stream: TcpStream, body: &str) -> std::io::Result<()> {
    let mut buffer = [0u8; 1024];
    let bytes_read = stream.read(&mut buffer)?;
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let is_metrics = request
        .lines()
        .next()
        .map(|line| line.starts_with("GET /metrics "))
        .unwrap_or(false);

    let (status, response_body, content_type) = if is_metrics {
        ("200 OK", body, "text/plain; version=0.0.4")
    } else {
        ("404 Not Found", "not found", "text/plain; charset=utf-8")
    };

    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        content_type,
        response_body.as_bytes().len(),
        response_body
    );

    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}
