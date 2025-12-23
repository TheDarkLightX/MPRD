//! Production Executor Adapters for MPRD
//!
//! This module provides concrete ExecutorAdapter implementations for
//! different deployment scenarios:
//!
//! - **HttpExecutor**: Calls an HTTP endpoint to execute actions
//! - **WebhookExecutor**: Posts action data to a webhook URL
//! - **FileExecutor**: Writes actions to a file (audit trail)
//! - **CompositeExecutor**: Chains multiple executors
//!
//! # Security Model
//!
//! All executors enforce the Execution Guard invariant:
//! - Actions are only executed if accompanied by valid token + proof
//! - The executor is the ONLY component that performs side effects
//!
//! # Design by Contract
//!
//! Preconditions:
//! - Token signature has been verified
//! - ZK proof has been verified
//! - Anti-replay checks have passed
//!
//! Postconditions:
//! - Either the action is executed exactly once, or not at all
//! - Execution result is recorded for audit

use mprd_core::{
    DecisionToken, ExecutionResult, ExecutorAdapter, MprdError, Result, VerifiedBundle,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::egress;

fn require_action_preimage(verified: &VerifiedBundle<'_>) -> Result<Vec<u8>> {
    let token = verified.token();
    let proof = verified.proof();

    // Fail-closed: ensure committed limits bytes match committed limits hash and are understood.
    mprd_core::limits::verify_limits_binding_v1(&proof.limits_hash, &proof.limits_bytes)?;
    let _ = mprd_core::limits::parse_limits_v1(&proof.limits_bytes)?;

    if proof.chosen_action_preimage.is_empty() {
        return Err(MprdError::ExecutionError(
            "missing chosen_action_preimage (executor must derive action from committed transcript)"
                .into(),
        ));
    }

    let h = mprd_core::hash::hash_candidate_preimage_v1(&proof.chosen_action_preimage);
    if h != token.chosen_action_hash || h != proof.chosen_action_hash {
        return Err(MprdError::ExecutionError(
            "chosen_action_preimage hash mismatch".into(),
        ));
    }

    // Fail-closed: ensure the action bytes are well-formed and schema-valid under canonical v1.
    let (action_type, params, _score) =
        mprd_core::validation::decode_candidate_preimage_v1(&proof.chosen_action_preimage)?;
    mprd_core::validation::validate_action_schema_v1(&action_type, &params)?;

    Ok(proof.chosen_action_preimage.clone())
}

// =============================================================================
// HTTP Executor
// =============================================================================

/// Configuration for HTTP executor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpExecutorConfig {
    /// Base URL of the action execution service.
    pub base_url: String,

    /// Timeout in milliseconds.
    pub timeout_ms: u64,

    /// Optional API key header.
    pub api_key: Option<String>,

    /// Retry count on transient failures.
    pub retry_count: u32,
}

impl Default for HttpExecutorConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:8080".into(),
            timeout_ms: 5000,
            api_key: None,
            retry_count: 3,
        }
    }
}

/// Executor that calls an HTTP endpoint to execute actions.
///
/// The action details are POSTed as JSON to `{base_url}/execute`.
/// The response is expected to be a JSON object with `success` and `message`.
pub struct HttpExecutor {
    config: HttpExecutorConfig,
    client: reqwest::blocking::Client,
}

impl HttpExecutor {
    /// Create a new HTTP executor with the given config.
    pub fn new(config: HttpExecutorConfig) -> Result<Self> {
        if config.timeout_ms == 0 {
            return Err(MprdError::ConfigError("timeout_ms must be > 0".into()));
        }
        if config.retry_count > 3 {
            return Err(MprdError::ConfigError(
                "retry_count must be <= 3 for bounded retries".into(),
            ));
        }
        egress::validate_outbound_url(&config.base_url)?;
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|e| {
                MprdError::ExecutionError(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self { config, client })
    }

    /// Create with default config pointing to localhost.
    pub fn localhost() -> Result<Self> {
        Self::new(HttpExecutorConfig::default())
    }
}

/// Payload sent to the execution endpoint.
#[derive(Serialize)]
struct ExecutePayload {
    policy_hash: String,
    policy_epoch: u64,
    registry_root: String,
    state_hash: String,
    action_hash: String,
    action_preimage_hex: String,
    nonce_or_tx_hash: String,
    timestamp_ms: i64,
    token_signature_hex: String,
    proof_receipt_hex: String,
    proof_metadata: HashMap<String, String>,
}

/// Response from the execution endpoint.
#[derive(Deserialize)]
struct ExecuteResponse {
    success: bool,
    message: Option<String>,
}

/// Maximum total retry delay in milliseconds (5 seconds).
const MAX_TOTAL_RETRY_DELAY_MS: u64 = 5000;

/// Base delay for exponential backoff in milliseconds.
const BASE_RETRY_DELAY_MS: u64 = 100;

/// Maximum single retry delay in milliseconds (2 seconds).
const MAX_SINGLE_RETRY_DELAY_MS: u64 = 2000;

impl ExecutorAdapter for HttpExecutor {
    fn execute(&self, verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
        // SECURITY: network execution is an external interaction. Callers should treat the remote
        // endpoint as malicious/unreliable. Retries are enabled here; therefore the remote
        // endpoint must be idempotent with respect to the (policy_hash, state_hash, action_hash,
        // nonce_or_tx_hash) tuple to avoid duplicate side effects.
        let token = verified.token();
        let proof = verified.proof();
        let action_preimage = require_action_preimage(verified)?;

        let payload = ExecutePayload {
            policy_hash: hex::encode(token.policy_hash.0),
            policy_epoch: token.policy_ref.policy_epoch,
            registry_root: hex::encode(token.policy_ref.registry_root.0),
            state_hash: hex::encode(token.state_hash.0),
            action_hash: hex::encode(token.chosen_action_hash.0),
            action_preimage_hex: hex::encode(&action_preimage),
            nonce_or_tx_hash: hex::encode(token.nonce_or_tx_hash.0),
            timestamp_ms: token.timestamp_ms,
            token_signature_hex: hex::encode(&token.signature),
            proof_receipt_hex: hex::encode(&proof.risc0_receipt),
            proof_metadata: proof.attestation_metadata.clone(),
        };

        let url = format!("{}/execute", self.config.base_url);

        let mut last_error = None;
        let mut total_delay: u64 = 0;

        for attempt in 0..=self.config.retry_count {
            let mut request = self.client.post(&url).json(&payload);

            if let Some(ref api_key) = self.config.api_key {
                request = request.header("X-API-Key", api_key);
            }
            request = request.header("Idempotency-Key", hex::encode(token.nonce_or_tx_hash.0));

            match request.send() {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        match response.json::<ExecuteResponse>() {
                            Ok(resp) => {
                                return Ok(ExecutionResult {
                                    success: resp.success,
                                    message: resp.message,
                                });
                            }
                            Err(e) => {
                                return Err(MprdError::ExecutionError(format!(
                                    "Failed to parse response: {}",
                                    e
                                )));
                            }
                        }
                    } else if status.is_client_error() {
                        // SECURITY: 4xx errors are non-retryable client errors
                        // Retrying would cause duplicate submissions on idempotent endpoints
                        return Err(MprdError::ExecutionError(format!(
                            "HTTP client error (non-retryable): {}",
                            status
                        )));
                    } else if status.is_server_error() {
                        // 5xx errors are retryable server errors
                        last_error = Some(format!("HTTP server error: {}", status));
                    } else {
                        return Err(MprdError::ExecutionError(format!(
                            "HTTP non-retryable response: {}",
                            status
                        )));
                    }
                }
                Err(e) => {
                    // Network errors are retryable
                    last_error = Some(format!("Network error: {}", e));
                }
            }

            // Exponential backoff with cap
            if attempt < self.config.retry_count {
                // Calculate delay: base * 2^attempt, capped at MAX_SINGLE_RETRY_DELAY_MS
                let delay = std::cmp::min(
                    BASE_RETRY_DELAY_MS * (1u64 << attempt),
                    MAX_SINGLE_RETRY_DELAY_MS,
                );

                // Check if total delay would exceed cap
                if total_delay + delay > MAX_TOTAL_RETRY_DELAY_MS {
                    break; // Stop retrying to avoid excessive delay
                }

                total_delay += delay;
                std::thread::sleep(std::time::Duration::from_millis(delay));
            }
        }

        Err(MprdError::ExecutionError(format!(
            "All {} attempts failed: {:?}",
            self.config.retry_count + 1,
            last_error
        )))
    }
}

// =============================================================================
// Webhook Executor
// =============================================================================

/// Executor that posts action data to a webhook URL.
///
/// Unlike HttpExecutor, this is fire-and-forget with optional confirmation.
pub struct WebhookExecutor {
    webhook_url: String,
    client: reqwest::blocking::Client,
}

impl WebhookExecutor {
    /// Create a new webhook executor.
    pub fn new(webhook_url: impl Into<String>, timeout_ms: u64) -> Result<Self> {
        let webhook_url: String = webhook_url.into();
        egress::validate_outbound_url(&webhook_url)?;
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .build()
            .map_err(|e| MprdError::ExecutionError(format!("Failed to create client: {}", e)))?;

        Ok(Self {
            webhook_url,
            client,
        })
    }
}

impl ExecutorAdapter for WebhookExecutor {
    fn execute(&self, verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
        // SECURITY: webhook is a best-effort notification channel. A 2xx/202 response is treated
        // as acceptance; callers must not assume the remote service actually performed the side
        // effect unless the service provides stronger guarantees.
        let token = verified.token();
        let proof = verified.proof();
        let action_preimage = require_action_preimage(verified)?;
        let payload = serde_json::json!({
            "event": "mprd_action_executed",
            "policy_hash": hex::encode(token.policy_hash.0),
            "policy_epoch": token.policy_ref.policy_epoch,
            "registry_root": hex::encode(token.policy_ref.registry_root.0),
            "state_hash": hex::encode(token.state_hash.0),
            "action_hash": hex::encode(token.chosen_action_hash.0),
            "action_preimage_hex": hex::encode(&action_preimage),
            "nonce_or_tx_hash": hex::encode(token.nonce_or_tx_hash.0),
            "timestamp_ms": token.timestamp_ms,
            "token_signature_hex": hex::encode(&token.signature),
            "proof": {
                "candidate_set_hash": hex::encode(proof.candidate_set_hash.0),
                "receipt_hex": hex::encode(&proof.risc0_receipt),
                "metadata": proof.attestation_metadata,
            }
        });

        match self.client.post(&self.webhook_url).json(&payload).send() {
            Ok(response) => {
                if response.status().is_success() || response.status().as_u16() == 202 {
                    Ok(ExecutionResult {
                        success: true,
                        message: Some(format!("Webhook accepted ({})", response.status())),
                    })
                } else {
                    Ok(ExecutionResult {
                        success: false,
                        message: Some(format!("Webhook rejected ({})", response.status())),
                    })
                }
            }
            Err(e) => Err(MprdError::ExecutionError(format!("Webhook failed: {}", e))),
        }
    }
}

// =============================================================================
// File Executor (Audit Trail)
// =============================================================================

/// Executor that writes actions to a file for audit purposes.
///
/// Each action is appended as a JSON line to the specified file.
/// This is useful for creating immutable audit trails.
pub struct FileExecutor {
    path: PathBuf,
    file: Arc<Mutex<File>>,
}

impl FileExecutor {
    /// Create a new file executor writing to the given path.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| MprdError::ExecutionError(format!("Failed to open file: {}", e)))?;

        Ok(Self {
            path,
            file: Arc::new(Mutex::new(file)),
        })
    }
}

/// Record written to the audit file.
#[derive(Serialize)]
struct AuditRecord {
    timestamp: String,
    policy_hash: String,
    state_hash: String,
    action_hash: String,
    action_preimage_hex: Option<String>,
    nonce_or_tx_hash: String,
    token_timestamp_ms: i64,
    proof_metadata: HashMap<String, String>,
}

impl ExecutorAdapter for FileExecutor {
    fn execute(&self, verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
        // SECURITY: this executor writes an append-only audit line. The file is a side-effecting
        // sink and should be treated as untrusted storage; callers should provide a path on a
        // durable filesystem with appropriate permissions.
        let token = verified.token();
        let proof = verified.proof();
        let action_preimage = require_action_preimage(verified)?;
        let record = AuditRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            policy_hash: hex::encode(token.policy_hash.0),
            state_hash: hex::encode(token.state_hash.0),
            action_hash: hex::encode(token.chosen_action_hash.0),
            action_preimage_hex: Some(hex::encode(action_preimage)),
            nonce_or_tx_hash: hex::encode(token.nonce_or_tx_hash.0),
            token_timestamp_ms: token.timestamp_ms,
            proof_metadata: proof.attestation_metadata.clone(),
        };

        let json = serde_json::to_string(&record)
            .map_err(|e| MprdError::ExecutionError(format!("Failed to serialize record: {}", e)))?;

        let mut file = self
            .file
            .lock()
            .map_err(|_| MprdError::ExecutionError("File lock poisoned".into()))?;

        writeln!(file, "{}", json)
            .map_err(|e| MprdError::ExecutionError(format!("Failed to write to file: {}", e)))?;

        file.flush()
            .map_err(|e| MprdError::ExecutionError(format!("Failed to flush file: {}", e)))?;

        Ok(ExecutionResult {
            success: true,
            message: Some(format!("Recorded to {}", self.path.display())),
        })
    }
}

// =============================================================================
// Idempotent File Executor (per-nonce audit records)
// =============================================================================

/// Executor that writes exactly one audit record per nonce.
///
/// This is useful when the downstream effect must be idempotent across retries
/// and across process restarts.
///
/// Record path:
/// `root/<policy_hash_hex>/<nonce_hex>.json`
pub struct IdempotentFileExecutor {
    root: PathBuf,
}

impl IdempotentFileExecutor {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)
            .map_err(|e| MprdError::ExecutionError(format!("Failed to create audit dir: {}", e)))?;
        Ok(Self { root })
    }

    fn record_path(&self, token: &DecisionToken) -> PathBuf {
        let policy = hex::encode(token.policy_hash.0);
        let nonce = hex::encode(token.nonce_or_tx_hash.0);
        self.root.join(policy).join(format!("{}.json", nonce))
    }
}

impl ExecutorAdapter for IdempotentFileExecutor {
    fn execute(&self, verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
        let token = verified.token();
        let proof = verified.proof();
        let action_preimage = require_action_preimage(verified)?;
        let record = AuditRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            policy_hash: hex::encode(token.policy_hash.0),
            state_hash: hex::encode(token.state_hash.0),
            action_hash: hex::encode(token.chosen_action_hash.0),
            action_preimage_hex: Some(hex::encode(action_preimage)),
            nonce_or_tx_hash: hex::encode(token.nonce_or_tx_hash.0),
            token_timestamp_ms: token.timestamp_ms,
            proof_metadata: proof.attestation_metadata.clone(),
        };

        let path = self.record_path(token);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                MprdError::ExecutionError(format!("Failed to create audit dir: {}", e))
            })?;
        }

        // Fail-closed on IO errors; succeed idempotently if already recorded.
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Ok(ExecutionResult {
                    success: true,
                    message: Some(format!("Already recorded: {}", path.display())),
                });
            }
            Err(e) => {
                return Err(MprdError::ExecutionError(format!(
                    "Failed to create audit record: {}",
                    e
                )));
            }
        };

        let json = serde_json::to_vec(&record)
            .map_err(|e| MprdError::ExecutionError(format!("Failed to serialize record: {}", e)))?;
        file.write_all(&json)
            .map_err(|e| MprdError::ExecutionError(format!("Failed to write: {}", e)))?;
        file.write_all(b"\n")
            .map_err(|e| MprdError::ExecutionError(format!("Failed to write: {}", e)))?;
        file.flush()
            .map_err(|e| MprdError::ExecutionError(format!("Failed to flush: {}", e)))?;

        Ok(ExecutionResult {
            success: true,
            message: Some(format!("Recorded to {}", path.display())),
        })
    }
}

// =============================================================================
// Composite Executor
// =============================================================================

/// Executor that chains multiple executors together.
///
/// All child executors are called in sequence. If any fails, the composite
/// fails. This is useful for executing an action AND logging it.
pub struct CompositeExecutor {
    executors: Vec<Box<dyn ExecutorAdapter + Send + Sync>>,
    /// If true, continue even if one executor fails.
    best_effort: bool,
}

impl CompositeExecutor {
    /// Create a new composite executor with strict mode (fail on any error).
    pub fn new(executors: Vec<Box<dyn ExecutorAdapter + Send + Sync>>) -> Self {
        Self {
            executors,
            best_effort: false,
        }
    }

    /// Create with best-effort mode (continue on errors).
    pub fn best_effort(executors: Vec<Box<dyn ExecutorAdapter + Send + Sync>>) -> Self {
        Self {
            executors,
            best_effort: true,
        }
    }
}

impl ExecutorAdapter for CompositeExecutor {
    fn execute(&self, verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
        let mut messages = Vec::new();
        let mut all_success = true;

        for (i, executor) in self.executors.iter().enumerate() {
            match executor.execute(verified) {
                Ok(result) => {
                    if !result.success {
                        all_success = false;
                    }
                    if let Some(msg) = result.message {
                        messages.push(format!("[{}] {}", i, msg));
                    }
                }
                Err(e) => {
                    all_success = false;
                    messages.push(format!("[{}] ERROR: {}", i, e));

                    if !self.best_effort {
                        return Err(e);
                    }
                }
            }
        }

        Ok(ExecutionResult {
            success: all_success,
            message: Some(messages.join("; ")),
        })
    }
}

// =============================================================================
// No-Op Executor (Testing)
// =============================================================================

/// Executor that does nothing (for testing).
pub struct NoOpExecutor;

impl ExecutorAdapter for NoOpExecutor {
    fn execute(&self, _verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
        Ok(ExecutionResult {
            success: true,
            message: Some("no-op".into()),
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use mprd_core::{verify_for_execution, CandidateAction, Hash32, ProofBundle, Score, Value};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn dummy_hash(b: u8) -> Hash32 {
        Hash32([b; 32])
    }

    fn dummy_http_call_action_preimage() -> Vec<u8> {
        let c = CandidateAction {
            action_type: "http_call".into(),
            params: HashMap::from([
                ("http_method".into(), Value::String("POST".into())),
                (
                    "http_url".into(),
                    Value::String("http://localhost:8080/execute".into()),
                ),
            ]),
            score: Score(0),
            candidate_hash: dummy_hash(1),
        };
        mprd_core::hash::candidate_hash_preimage(&c)
    }

    fn dummy_http_call_action_hash(preimage: &[u8]) -> Hash32 {
        mprd_core::hash::hash_candidate_preimage_v1(preimage)
    }

    fn dummy_token() -> DecisionToken {
        let preimage = dummy_http_call_action_preimage();
        let action_hash = dummy_http_call_action_hash(&preimage);
        DecisionToken {
            policy_hash: dummy_hash(1),
            policy_ref: mprd_core::PolicyRef {
                policy_epoch: 1,
                registry_root: dummy_hash(99),
            },
            state_hash: dummy_hash(2),
            state_ref: mprd_core::StateRef::unknown(),
            chosen_action_hash: action_hash,
            nonce_or_tx_hash: dummy_hash(4),
            timestamp_ms: 12345,
            signature: vec![1, 2, 3],
        }
    }

    fn dummy_proof() -> ProofBundle {
        let preimage = dummy_http_call_action_preimage();
        let action_hash = dummy_http_call_action_hash(&preimage);
        let limits_bytes = Vec::new();
        let limits_hash = mprd_core::limits::limits_hash_v1(&limits_bytes);
        ProofBundle {
            policy_hash: dummy_hash(1),
            state_hash: dummy_hash(2),
            candidate_set_hash: dummy_hash(5),
            chosen_action_hash: action_hash,
            limits_hash,
            limits_bytes,
            chosen_action_preimage: preimage,
            risc0_receipt: vec![1, 2, 3],
            attestation_metadata: HashMap::from([("test".into(), "value".into())]),
        }
    }

    struct AcceptAllVerifier;

    impl mprd_core::ZkLocalVerifier for AcceptAllVerifier {
        fn verify(
            &self,
            _token: &DecisionToken,
            _proof: &ProofBundle,
        ) -> mprd_core::VerificationStatus {
            mprd_core::VerificationStatus::Success
        }
    }

    fn verified<'a>(
        token: &'a DecisionToken,
        proof: &'a ProofBundle,
    ) -> mprd_core::VerifiedBundle<'a> {
        verify_for_execution(&AcceptAllVerifier, token, proof).expect("verify_for_execution")
    }

    struct CountingExecutor {
        calls: Arc<AtomicUsize>,
    }

    impl ExecutorAdapter for CountingExecutor {
        fn execute(&self, _verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ExecutionResult {
                success: true,
                message: Some("counting".into()),
            })
        }
    }

    struct FailingExecutor;

    impl ExecutorAdapter for FailingExecutor {
        fn execute(&self, _verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
            Err(MprdError::ExecutionError("boom".into()))
        }
    }

    #[test]
    fn noop_executor_succeeds() {
        let executor = NoOpExecutor;
        let token = dummy_token();
        let proof = dummy_proof();
        let result = executor.execute(&verified(&token, &proof)).unwrap();
        assert!(result.success);
    }

    #[test]
    fn file_executor_creates_audit_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mprd_test.jsonl");

        let executor = FileExecutor::new(&path).unwrap();
        let token = dummy_token();
        let proof = dummy_proof();
        let result = executor.execute(&verified(&token, &proof)).unwrap();

        assert!(result.success);
        assert!(path.exists());
    }

    #[test]
    fn composite_executor_chains_multiple() {
        let executors: Vec<Box<dyn ExecutorAdapter + Send + Sync>> =
            vec![Box::new(NoOpExecutor), Box::new(NoOpExecutor)];

        let composite = CompositeExecutor::new(executors);
        let token = dummy_token();
        let proof = dummy_proof();
        let result = composite.execute(&verified(&token, &proof)).unwrap();

        assert!(result.success);
    }

    #[test]
    fn composite_executor_strict_fails_closed_and_stops_on_first_error() {
        let c1 = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::new(AtomicUsize::new(0));
        let executors: Vec<Box<dyn ExecutorAdapter + Send + Sync>> = vec![
            Box::new(CountingExecutor { calls: c1.clone() }),
            Box::new(FailingExecutor),
            Box::new(CountingExecutor { calls: c2.clone() }),
        ];

        let composite = CompositeExecutor::new(executors);
        let token = dummy_token();
        let proof = dummy_proof();
        let err = composite.execute(&verified(&token, &proof)).unwrap_err();
        assert!(matches!(err, MprdError::ExecutionError(_)));

        assert_eq!(c1.load(Ordering::SeqCst), 1);
        assert_eq!(c2.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn composite_executor_best_effort_continues_after_error() {
        let c1 = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::new(AtomicUsize::new(0));
        let executors: Vec<Box<dyn ExecutorAdapter + Send + Sync>> = vec![
            Box::new(CountingExecutor { calls: c1.clone() }),
            Box::new(FailingExecutor),
            Box::new(CountingExecutor { calls: c2.clone() }),
        ];

        let composite = CompositeExecutor::best_effort(executors);
        let token = dummy_token();
        let proof = dummy_proof();
        let result = composite.execute(&verified(&token, &proof)).unwrap();
        assert!(!result.success);
        assert!(result.message.unwrap_or_default().contains("ERROR"));

        assert_eq!(c1.load(Ordering::SeqCst), 1);
        assert_eq!(c2.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn file_executor_rejects_limits_bytes_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mprd_test_limits_mismatch.jsonl");

        let executor = FileExecutor::new(&path).unwrap();
        let token = dummy_token();
        let mut proof = dummy_proof();

        // Tamper: change limits_bytes without updating limits_hash.
        proof.limits_bytes = vec![mprd_core::limits::tags::MPB_FUEL_LIMIT, 0, 0, 0, 0];

        let result = executor.execute(&verified(&token, &proof));
        assert!(result.is_err());
    }

    #[test]
    fn idempotent_file_executor_writes_once_per_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let exec = IdempotentFileExecutor::new(dir.path()).expect("new");
        let token = dummy_token();
        let proof = dummy_proof();
        let verified = verified(&token, &proof);

        let r1 = exec.execute(&verified).expect("exec1");
        assert!(r1.success);
        let r2 = exec.execute(&verified).expect("exec2");
        assert!(r2.success);

        let policy_dir = dir.path().join(hex::encode(token.policy_hash.0));
        let entries: Vec<_> = std::fs::read_dir(policy_dir).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }
}
