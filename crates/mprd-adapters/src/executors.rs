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
    DecisionToken, ExecutionResult, ExecutorAdapter, MprdError, ProofBundle, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|e| MprdError::ExecutionError(format!("Failed to create HTTP client: {}", e)))?;
        
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
    state_hash: String,
    action_hash: String,
    timestamp_ms: i64,
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
    fn execute(&self, token: &DecisionToken, proof: &ProofBundle) -> Result<ExecutionResult> {
        let payload = ExecutePayload {
            policy_hash: hex::encode(&token.policy_hash.0),
            state_hash: hex::encode(&token.state_hash.0),
            action_hash: hex::encode(&token.chosen_action_hash.0),
            timestamp_ms: token.timestamp_ms,
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
            
            match request.send() {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<ExecuteResponse>() {
                            Ok(resp) => {
                                return Ok(ExecutionResult {
                                    success: resp.success,
                                    message: resp.message,
                                });
                            }
                            Err(e) => {
                                return Err(MprdError::ExecutionError(
                                    format!("Failed to parse response: {}", e)
                                ));
                            }
                        }
                    } else {
                        last_error = Some(format!("HTTP {}", response.status()));
                    }
                }
                Err(e) => {
                    last_error = Some(format!("Request failed: {}", e));
                }
            }
            
            // Exponential backoff with cap
            if attempt < self.config.retry_count {
                // Calculate delay: base * 2^attempt, capped at MAX_SINGLE_RETRY_DELAY_MS
                let delay = std::cmp::min(
                    BASE_RETRY_DELAY_MS * (1u64 << attempt),
                    MAX_SINGLE_RETRY_DELAY_MS
                );
                
                // Check if total delay would exceed cap
                if total_delay + delay > MAX_TOTAL_RETRY_DELAY_MS {
                    break; // Stop retrying to avoid excessive delay
                }
                
                total_delay += delay;
                std::thread::sleep(std::time::Duration::from_millis(delay));
            }
        }
        
        Err(MprdError::ExecutionError(
            format!("All {} attempts failed: {:?}", self.config.retry_count + 1, last_error)
        ))
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
    timeout_ms: u64,
    client: reqwest::blocking::Client,
}

impl WebhookExecutor {
    /// Create a new webhook executor.
    pub fn new(webhook_url: impl Into<String>, timeout_ms: u64) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .build()
            .map_err(|e| MprdError::ExecutionError(format!("Failed to create client: {}", e)))?;
        
        Ok(Self {
            webhook_url: webhook_url.into(),
            timeout_ms,
            client,
        })
    }
}

impl ExecutorAdapter for WebhookExecutor {
    fn execute(&self, token: &DecisionToken, proof: &ProofBundle) -> Result<ExecutionResult> {
        let payload = serde_json::json!({
            "event": "mprd_action_executed",
            "policy_hash": hex::encode(&token.policy_hash.0),
            "state_hash": hex::encode(&token.state_hash.0),
            "action_hash": hex::encode(&token.chosen_action_hash.0),
            "timestamp_ms": token.timestamp_ms,
            "proof": {
                "candidate_set_hash": hex::encode(&proof.candidate_set_hash.0),
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
    token_timestamp_ms: i64,
    proof_metadata: HashMap<String, String>,
}

impl ExecutorAdapter for FileExecutor {
    fn execute(&self, token: &DecisionToken, proof: &ProofBundle) -> Result<ExecutionResult> {
        let record = AuditRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            policy_hash: hex::encode(&token.policy_hash.0),
            state_hash: hex::encode(&token.state_hash.0),
            action_hash: hex::encode(&token.chosen_action_hash.0),
            token_timestamp_ms: token.timestamp_ms,
            proof_metadata: proof.attestation_metadata.clone(),
        };
        
        let json = serde_json::to_string(&record)
            .map_err(|e| MprdError::ExecutionError(format!("Failed to serialize record: {}", e)))?;
        
        let mut file = self.file.lock()
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
    fn execute(&self, token: &DecisionToken, proof: &ProofBundle) -> Result<ExecutionResult> {
        let mut messages = Vec::new();
        let mut all_success = true;
        
        for (i, executor) in self.executors.iter().enumerate() {
            match executor.execute(token, proof) {
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
    fn execute(&self, _token: &DecisionToken, _proof: &ProofBundle) -> Result<ExecutionResult> {
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
    use mprd_core::Hash32;
    
    fn dummy_hash(b: u8) -> Hash32 {
        Hash32([b; 32])
    }
    
    fn dummy_token() -> DecisionToken {
        DecisionToken {
            policy_hash: dummy_hash(1),
            state_hash: dummy_hash(2),
            chosen_action_hash: dummy_hash(3),
            nonce_or_tx_hash: dummy_hash(4),
            timestamp_ms: 12345,
            signature: vec![1, 2, 3],
        }
    }
    
    fn dummy_proof() -> ProofBundle {
        ProofBundle {
            policy_hash: dummy_hash(1),
            state_hash: dummy_hash(2),
            candidate_set_hash: dummy_hash(5),
            chosen_action_hash: dummy_hash(3),
            risc0_receipt: vec![1, 2, 3],
            attestation_metadata: HashMap::from([("test".into(), "value".into())]),
        }
    }
    
    #[test]
    fn noop_executor_succeeds() {
        let executor = NoOpExecutor;
        let result = executor.execute(&dummy_token(), &dummy_proof()).unwrap();
        assert!(result.success);
    }
    
    #[test]
    fn file_executor_creates_audit_record() {
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join(format!("mprd_test_{}.jsonl", std::process::id()));
        
        let executor = FileExecutor::new(&path).unwrap();
        let result = executor.execute(&dummy_token(), &dummy_proof()).unwrap();
        
        assert!(result.success);
        assert!(path.exists());
        
        // Clean up
        let _ = std::fs::remove_file(&path);
    }
    
    #[test]
    fn composite_executor_chains_multiple() {
        let executors: Vec<Box<dyn ExecutorAdapter + Send + Sync>> = vec![
            Box::new(NoOpExecutor),
            Box::new(NoOpExecutor),
        ];
        
        let composite = CompositeExecutor::new(executors);
        let result = composite.execute(&dummy_token(), &dummy_proof()).unwrap();
        
        assert!(result.success);
    }
}
