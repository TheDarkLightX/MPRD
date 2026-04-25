//! Production Executor Adapters for MPRD
//!
//! This module provides concrete ExecutorAdapter implementations for
//! different deployment scenarios:
//!
//! - **HttpExecutor**: Calls an HTTP endpoint to execute actions
//! - **IdempotentHttpExecutor**: HTTP executor with a local pending/committed barrier
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
    DecisionToken, ExecutionReadyBundle, ExecutionResult, ExecutorAdapter, MprdError, ProofBundle,
    Result, VerifiedBundle,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::egress;

fn require_action_preimage(verified: &VerifiedBundle<'_>) -> Result<Vec<u8>> {
    Ok(mprd_core::execution_boundary_witness_v1(verified)?
        .chosen_action_preimage()
        .to_vec())
}

fn require_ready_action_preimage(ready: &ExecutionReadyBundle<'_>) -> Vec<u8> {
    ready.boundary().chosen_action_preimage().to_vec()
}

const EXECUTION_IDEMPOTENCY_KEY_DOMAIN_V1: &[u8] = b"mprd-execution-idempotency-v1";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EffectJournalSummary {
    pub pending_entries: usize,
    pub committed_entries: usize,
    pub committed_automatic_entries: usize,
    pub committed_manual_promote_entries: usize,
    pub committed_legacy_entries: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingHttpEffectBarrier {
    pub barrier_path: PathBuf,
    pub policy_hash_hex: String,
    pub idempotency_key_v1: String,
    pub state_hash_hex: String,
    pub action_hash_hex: String,
    pub nonce_or_tx_hash_hex: String,
    pub timestamp_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedHttpEffectBarrier {
    pub barrier_path: PathBuf,
    pub policy_hash_hex: String,
    pub idempotency_key_v1: String,
    pub state_hash_hex: String,
    pub action_hash_hex: String,
    pub nonce_or_tx_hash_hex: String,
    pub timestamp_ms: i64,
    pub resolution_kind: Option<CommittedHttpEffectBarrierResolutionKind>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingHttpEffectBarrierResolution {
    Clear,
    PromoteToCommitted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommittedHttpEffectBarrierResolutionKind {
    Automatic,
    ManualPromote,
}

impl CommittedHttpEffectBarrierResolutionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::ManualPromote => "manual_promote",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPendingHttpEffectBarrier {
    pub barrier: PendingHttpEffectBarrier,
    pub committed_barrier_path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct PendingHttpEffectBarrierPayload {
    idempotency_key_v1: String,
    policy_hash: String,
    state_hash: String,
    action_hash: String,
    nonce_or_tx_hash: String,
    timestamp_ms: i64,
    #[serde(default)]
    effect_barrier_resolution_kind: Option<CommittedHttpEffectBarrierResolutionKind>,
}

struct ParsedHttpEffectBarrier {
    barrier_path: PathBuf,
    policy_hash_hex: String,
    idempotency_key_v1: String,
    state_hash_hex: String,
    action_hash_hex: String,
    nonce_or_tx_hash_hex: String,
    timestamp_ms: i64,
    resolution_kind: Option<CommittedHttpEffectBarrierResolutionKind>,
}

const MAX_HTTP_EFFECT_BARRIER_BYTES: u64 = 64 * 1024;

fn parse_http_effect_barrier(
    path: &Path,
    suffix: &str,
    kind: &str,
) -> Result<ParsedHttpEffectBarrier> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            MprdError::ExecutionError(format!(
                "{} {} has a non-UTF8 filename",
                kind,
                path.display()
            ))
        })?;
    if !name.ends_with(suffix) {
        return Err(MprdError::ExecutionError(format!(
            "{} {} does not end with {}",
            kind,
            path.display(),
            suffix
        )));
    }

    let metadata = fs::symlink_metadata(path).map_err(|e| {
        MprdError::ExecutionError(format!(
            "Failed to inspect {} {}: {}",
            kind,
            path.display(),
            e
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(MprdError::ExecutionError(format!(
            "{} {} is not a regular file",
            kind,
            path.display()
        )));
    }
    if metadata.len() > MAX_HTTP_EFFECT_BARRIER_BYTES {
        return Err(MprdError::ExecutionError(format!(
            "{} {} exceeds maximum size {} bytes",
            kind,
            path.display(),
            MAX_HTTP_EFFECT_BARRIER_BYTES
        )));
    }

    let mut file = File::open(path).map_err(|e| {
        MprdError::ExecutionError(format!("Failed to read {} {}: {}", kind, path.display(), e))
    })?;
    let mut bytes = Vec::new();
    let mut limited_reader = (&mut file).take(MAX_HTTP_EFFECT_BARRIER_BYTES + 1);
    limited_reader.read_to_end(&mut bytes).map_err(|e| {
        MprdError::ExecutionError(format!("Failed to read {} {}: {}", kind, path.display(), e))
    })?;
    if bytes.len() as u64 > MAX_HTTP_EFFECT_BARRIER_BYTES {
        return Err(MprdError::ExecutionError(format!(
            "{} {} exceeds maximum size {} bytes",
            kind,
            path.display(),
            MAX_HTTP_EFFECT_BARRIER_BYTES
        )));
    }
    let payload: PendingHttpEffectBarrierPayload = serde_json::from_slice(&bytes).map_err(|e| {
        MprdError::ExecutionError(format!(
            "Failed to parse {} {}: {}",
            kind,
            path.display(),
            e
        ))
    })?;

    let expected_idempotency_key = name.trim_end_matches(suffix);
    if payload.idempotency_key_v1 != expected_idempotency_key {
        return Err(MprdError::ExecutionError(format!(
            "{} {} has idempotency key drift: file={}, payload={}",
            kind,
            path.display(),
            expected_idempotency_key,
            payload.idempotency_key_v1
        )));
    }

    let policy_dir = path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            MprdError::ExecutionError(format!(
                "{} {} is missing a policy-hash directory",
                kind,
                path.display()
            ))
        })?;
    if payload.policy_hash != policy_dir {
        return Err(MprdError::ExecutionError(format!(
            "{} {} has policy hash drift: dir={}, payload={}",
            kind,
            path.display(),
            policy_dir,
            payload.policy_hash
        )));
    }

    Ok(ParsedHttpEffectBarrier {
        barrier_path: path.to_path_buf(),
        policy_hash_hex: payload.policy_hash,
        idempotency_key_v1: payload.idempotency_key_v1,
        state_hash_hex: payload.state_hash,
        action_hash_hex: payload.action_hash,
        nonce_or_tx_hash_hex: payload.nonce_or_tx_hash,
        timestamp_ms: payload.timestamp_ms,
        resolution_kind: payload.effect_barrier_resolution_kind,
    })
}

fn parse_pending_http_effect_barrier(path: &Path) -> Result<PendingHttpEffectBarrier> {
    let parsed = parse_http_effect_barrier(path, ".pending.json", "Pending HTTP effect barrier")?;
    if parsed.resolution_kind.is_some() {
        return Err(MprdError::ExecutionError(format!(
            "Pending HTTP effect barrier {} unexpectedly carries a committed resolution kind",
            path.display()
        )));
    }
    Ok(PendingHttpEffectBarrier {
        barrier_path: parsed.barrier_path,
        policy_hash_hex: parsed.policy_hash_hex,
        idempotency_key_v1: parsed.idempotency_key_v1,
        state_hash_hex: parsed.state_hash_hex,
        action_hash_hex: parsed.action_hash_hex,
        nonce_or_tx_hash_hex: parsed.nonce_or_tx_hash_hex,
        timestamp_ms: parsed.timestamp_ms,
    })
}

fn parse_committed_http_effect_barrier(path: &Path) -> Result<CommittedHttpEffectBarrier> {
    let parsed =
        parse_http_effect_barrier(path, ".committed.json", "Committed HTTP effect barrier")?;
    Ok(CommittedHttpEffectBarrier {
        barrier_path: parsed.barrier_path,
        policy_hash_hex: parsed.policy_hash_hex,
        idempotency_key_v1: parsed.idempotency_key_v1,
        state_hash_hex: parsed.state_hash_hex,
        action_hash_hex: parsed.action_hash_hex,
        nonce_or_tx_hash_hex: parsed.nonce_or_tx_hash_hex,
        timestamp_ms: parsed.timestamp_ms,
        resolution_kind: parsed.resolution_kind,
    })
}

pub fn summarize_http_effect_journal_root(root: &Path) -> Result<EffectJournalSummary> {
    if !root.exists() {
        return Ok(EffectJournalSummary::default());
    }
    if !root.is_dir() {
        return Err(MprdError::ConfigError(format!(
            "HTTP effect journal root is not a directory: {}",
            root.display()
        )));
    }

    let mut summary = EffectJournalSummary::default();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let mut entries = fs::read_dir(&dir)
            .map_err(|e| {
                MprdError::ExecutionError(format!(
                    "Failed to inspect HTTP effect journal dir {}: {}",
                    dir.display(),
                    e
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                MprdError::ExecutionError(format!(
                    "Failed to inspect HTTP effect journal dir {}: {}",
                    dir.display(),
                    e
                ))
            })?;
        entries.sort_by_key(|entry| entry.path());

        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type().map_err(|e| {
                MprdError::ExecutionError(format!(
                    "Failed to inspect HTTP effect journal entry {}: {}",
                    path.display(),
                    e
                ))
            })?;
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }

            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name.ends_with(".pending.json") {
                summary.pending_entries += 1;
            } else if name.ends_with(".committed.json") {
                summary.committed_entries += 1;
                match parse_committed_http_effect_barrier(&path)?.resolution_kind {
                    Some(CommittedHttpEffectBarrierResolutionKind::Automatic) => {
                        summary.committed_automatic_entries += 1;
                    }
                    Some(CommittedHttpEffectBarrierResolutionKind::ManualPromote) => {
                        summary.committed_manual_promote_entries += 1;
                    }
                    None => {
                        summary.committed_legacy_entries += 1;
                    }
                }
            }
        }
    }

    Ok(summary)
}

pub fn list_pending_http_effect_barriers(root: &Path) -> Result<Vec<PendingHttpEffectBarrier>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    if !root.is_dir() {
        return Err(MprdError::ConfigError(format!(
            "HTTP effect journal root is not a directory: {}",
            root.display()
        )));
    }

    let mut barriers = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let mut entries = fs::read_dir(&dir)
            .map_err(|e| {
                MprdError::ExecutionError(format!(
                    "Failed to inspect HTTP effect journal dir {}: {}",
                    dir.display(),
                    e
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                MprdError::ExecutionError(format!(
                    "Failed to inspect HTTP effect journal dir {}: {}",
                    dir.display(),
                    e
                ))
            })?;
        entries.sort_by_key(|entry| entry.path());

        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type().map_err(|e| {
                MprdError::ExecutionError(format!(
                    "Failed to inspect HTTP effect journal entry {}: {}",
                    path.display(),
                    e
                ))
            })?;
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }

            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if !name.ends_with(".pending.json") {
                continue;
            }

            barriers.push(parse_pending_http_effect_barrier(&path)?);
        }
    }

    barriers.sort_by(|a, b| a.barrier_path.cmp(&b.barrier_path));
    Ok(barriers)
}

pub fn list_committed_http_effect_barriers(root: &Path) -> Result<Vec<CommittedHttpEffectBarrier>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    if !root.is_dir() {
        return Err(MprdError::ConfigError(format!(
            "HTTP effect journal root is not a directory: {}",
            root.display()
        )));
    }

    let mut barriers = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let mut entries = fs::read_dir(&dir)
            .map_err(|e| {
                MprdError::ExecutionError(format!(
                    "Failed to inspect HTTP effect journal dir {}: {}",
                    dir.display(),
                    e
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                MprdError::ExecutionError(format!(
                    "Failed to inspect HTTP effect journal dir {}: {}",
                    dir.display(),
                    e
                ))
            })?;
        entries.sort_by_key(|entry| entry.path());

        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type().map_err(|e| {
                MprdError::ExecutionError(format!(
                    "Failed to inspect HTTP effect journal entry {}: {}",
                    path.display(),
                    e
                ))
            })?;
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }

            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name.ends_with(".committed.json") {
                barriers.push(parse_committed_http_effect_barrier(&path)?);
            }
        }
    }

    Ok(barriers)
}

pub fn get_pending_http_effect_barrier(
    root: &Path,
    policy_hash_hex: &str,
    idempotency_key_v1: &str,
) -> Result<PendingHttpEffectBarrier> {
    let path = root
        .join(policy_hash_hex)
        .join(format!("{idempotency_key_v1}.pending.json"));
    if !path.exists() {
        return Err(MprdError::ExecutionError(format!(
            "Pending HTTP effect barrier not found: {}",
            path.display()
        )));
    }
    let barrier = parse_pending_http_effect_barrier(&path)?;
    if barrier.policy_hash_hex != policy_hash_hex {
        return Err(MprdError::ExecutionError(format!(
            "Pending HTTP effect barrier {} resolved to unexpected policy hash {}",
            path.display(),
            barrier.policy_hash_hex
        )));
    }
    if barrier.idempotency_key_v1 != idempotency_key_v1 {
        return Err(MprdError::ExecutionError(format!(
            "Pending HTTP effect barrier {} resolved to unexpected idempotency key {}",
            path.display(),
            barrier.idempotency_key_v1
        )));
    }
    Ok(barrier)
}

pub fn resolve_pending_http_effect_barrier(
    root: &Path,
    policy_hash_hex: &str,
    idempotency_key_v1: &str,
    resolution: PendingHttpEffectBarrierResolution,
) -> Result<ResolvedPendingHttpEffectBarrier> {
    let barrier = get_pending_http_effect_barrier(root, policy_hash_hex, idempotency_key_v1)?;
    match resolution {
        PendingHttpEffectBarrierResolution::Clear => {
            fs::remove_file(&barrier.barrier_path).map_err(|e| {
                MprdError::ExecutionError(format!(
                    "Failed to clear pending HTTP effect barrier {}: {}",
                    barrier.barrier_path.display(),
                    e
                ))
            })?;
            Ok(ResolvedPendingHttpEffectBarrier {
                barrier,
                committed_barrier_path: None,
            })
        }
        PendingHttpEffectBarrierResolution::PromoteToCommitted => {
            let committed = barrier
                .barrier_path
                .with_file_name(format!("{}.committed.json", barrier.idempotency_key_v1));
            if committed.exists() {
                return Err(MprdError::ExecutionError(format!(
                    "Committed HTTP effect barrier already exists: {}",
                    committed.display()
                )));
            }
            let document = IdempotentHttpExecutor::load_barrier_document(&barrier.barrier_path)?;
            IdempotentHttpExecutor::write_committed_barrier_document(
                &barrier.barrier_path,
                &committed,
                document,
                CommittedHttpEffectBarrierResolutionKind::ManualPromote,
            )?;
            Ok(ResolvedPendingHttpEffectBarrier {
                barrier,
                committed_barrier_path: Some(committed),
            })
        }
    }
}

fn execution_idempotency_key_v1(token: &DecisionToken) -> String {
    let mut hasher = Sha256::new();
    hasher.update(EXECUTION_IDEMPOTENCY_KEY_DOMAIN_V1);
    hasher.update(token.policy_hash.0);
    hasher.update(token.state_hash.0);
    hasher.update(token.chosen_action_hash.0);
    hasher.update(token.nonce_or_tx_hash.0);
    hex::encode(hasher.finalize())
}

fn execute_payload_from_parts(
    token: &DecisionToken,
    proof: &ProofBundle,
    action_preimage: &[u8],
    governance: Option<&mprd_core::GovernanceAdmissionWitnessV1>,
    bridge: Option<&mprd_core::ExecutionRegistryBridgeWitnessV1>,
) -> ExecutePayload {
    ExecutePayload {
        idempotency_key_v1: execution_idempotency_key_v1(token),
        policy_hash: hex::encode(token.policy_hash.0),
        policy_epoch: token.policy_ref.policy_epoch,
        registry_root: hex::encode(token.policy_ref.registry_root.0),
        state_hash: hex::encode(token.state_hash.0),
        state_source_id: hex::encode(token.state_ref.state_source_id.0),
        state_epoch: token.state_ref.state_epoch,
        state_attestation_hash: hex::encode(token.state_ref.state_attestation_hash.0),
        action_hash: hex::encode(token.chosen_action_hash.0),
        action_preimage_hex: hex::encode(action_preimage),
        nonce_or_tx_hash: hex::encode(token.nonce_or_tx_hash.0),
        timestamp_ms: token.timestamp_ms,
        token_signature_hex: hex::encode(&token.signature),
        proof_receipt_hex: hex::encode(&proof.risc0_receipt),
        proof_metadata: proof.attestation_metadata.clone(),
        registry_authorization_hash: bridge.map(|b| hex::encode(b.registry_authorization_hash().0)),
        registry_checkpoint_attestation_hash: bridge.and_then(|b| {
            b.registry_checkpoint_attestation_hash()
                .map(|hash| hex::encode(hash.0))
        }),
        governance_update_kind: governance.map(|g| g.update_kind().as_str().to_string()),
        governance_profile_app_ok: governance.map(|g| g.profile_app_ok()),
        governance_profile_safety_ok: governance.map(|g| g.profile_safety_ok()),
        governance_link_ok: governance.map(|g| g.link_ok()),
        effect_barrier_resolution_kind: None,
    }
}

fn webhook_payload_from_parts(
    token: &DecisionToken,
    proof: &ProofBundle,
    action_preimage: &[u8],
    governance: Option<&mprd_core::GovernanceAdmissionWitnessV1>,
    bridge: Option<&mprd_core::ExecutionRegistryBridgeWitnessV1>,
) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "event": "mprd_action_executed",
        "idempotency_key_v1": execution_idempotency_key_v1(token),
        "policy_hash": hex::encode(token.policy_hash.0),
        "policy_epoch": token.policy_ref.policy_epoch,
        "registry_root": hex::encode(token.policy_ref.registry_root.0),
        "state_hash": hex::encode(token.state_hash.0),
        "state_source_id": hex::encode(token.state_ref.state_source_id.0),
        "state_epoch": token.state_ref.state_epoch,
        "state_attestation_hash": hex::encode(token.state_ref.state_attestation_hash.0),
        "action_hash": hex::encode(token.chosen_action_hash.0),
        "action_preimage_hex": hex::encode(action_preimage),
        "nonce_or_tx_hash": hex::encode(token.nonce_or_tx_hash.0),
        "timestamp_ms": token.timestamp_ms,
        "token_signature_hex": hex::encode(&token.signature),
        "proof": {
            "candidate_set_hash": hex::encode(proof.candidate_set_hash.0),
            "receipt_hex": hex::encode(&proof.risc0_receipt),
            "metadata": proof.attestation_metadata.clone(),
        }
    });

    if let Some(governance) = governance {
        let object = payload
            .as_object_mut()
            .expect("webhook payload should remain an object");
        object.insert(
            "governance_update_kind".into(),
            serde_json::Value::String(governance.update_kind().as_str().into()),
        );
        object.insert(
            "governance_profile_app_ok".into(),
            serde_json::Value::Bool(governance.profile_app_ok()),
        );
        object.insert(
            "governance_profile_safety_ok".into(),
            serde_json::Value::Bool(governance.profile_safety_ok()),
        );
        object.insert(
            "governance_link_ok".into(),
            serde_json::Value::Bool(governance.link_ok()),
        );
    }

    if let Some(bridge) = bridge {
        let object = payload
            .as_object_mut()
            .expect("webhook payload should remain an object");
        object.insert(
            "registry_authorization_hash".into(),
            serde_json::Value::String(hex::encode(bridge.registry_authorization_hash().0)),
        );
        if let Some(checkpoint_hash) = bridge.registry_checkpoint_attestation_hash() {
            object.insert(
                "registry_checkpoint_attestation_hash".into(),
                serde_json::Value::String(hex::encode(checkpoint_hash.0)),
            );
        }
    }

    payload
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

    /// Optional local barrier journal root for idempotent HTTP execution.
    pub effect_journal_root: Option<PathBuf>,
}

impl Default for HttpExecutorConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:8080".into(),
            timeout_ms: 5000,
            api_key: None,
            retry_count: 3,
            effect_journal_root: None,
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

    fn execute_payload(
        &self,
        token: &DecisionToken,
        payload: &ExecutePayload,
    ) -> Result<ExecutionResult> {
        let url = format!("{}/execute", self.config.base_url);
        let idempotency_key = execution_idempotency_key_v1(token);

        let mut last_error = None;
        let mut total_delay: u64 = 0;

        for attempt in 0..=self.config.retry_count {
            let mut request = self.client.post(&url).json(payload);

            if let Some(ref api_key) = self.config.api_key {
                request = request.header("X-API-Key", api_key);
            }
            request = request.header("Idempotency-Key", &idempotency_key);

            match request.send() {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        if let Some(content_length) = response.content_length() {
                            if content_length > MAX_RESPONSE_BYTES as u64 {
                                return Err(MprdError::BoundedValueExceeded(format!(
                                    "executor response too large: {} bytes (max {})",
                                    content_length, MAX_RESPONSE_BYTES
                                )));
                            }
                        }

                        let mut limited_reader = response.take((MAX_RESPONSE_BYTES + 1) as u64);
                        let mut buf = Vec::with_capacity(MAX_RESPONSE_BYTES);
                        limited_reader.read_to_end(&mut buf).map_err(|e| {
                            MprdError::ExecutionError(format!(
                                "Failed to read executor response: {}",
                                e
                            ))
                        })?;

                        if buf.len() > MAX_RESPONSE_BYTES {
                            return Err(MprdError::BoundedValueExceeded(format!(
                                "executor response too large: >{} bytes (max {})",
                                MAX_RESPONSE_BYTES, MAX_RESPONSE_BYTES
                            )));
                        }

                        let resp: ExecuteResponse = serde_json::from_slice(&buf).map_err(|e| {
                            MprdError::ExecutionError(format!("Failed to parse response: {}", e))
                        })?;

                        return Ok(ExecutionResult {
                            success: resp.success,
                            message: resp.message,
                        });
                    } else if status.is_client_error() {
                        return Err(MprdError::ExecutionError(format!(
                            "HTTP client error (non-retryable): {}",
                            status
                        )));
                    } else if status.is_server_error() {
                        last_error = Some(format!("HTTP server error: {}", status));
                    } else {
                        return Err(MprdError::ExecutionError(format!(
                            "HTTP non-retryable response: {}",
                            status
                        )));
                    }
                }
                Err(e) => {
                    last_error = Some(format!("Network error: {}", e));
                }
            }

            if attempt < self.config.retry_count {
                let delay = std::cmp::min(
                    BASE_RETRY_DELAY_MS * (1u64 << attempt),
                    MAX_SINGLE_RETRY_DELAY_MS,
                );

                if total_delay + delay > MAX_TOTAL_RETRY_DELAY_MS {
                    break;
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

/// HTTP executor with a local fail-closed pending/committed barrier.
///
/// The barrier uses:
/// `root/<policy_hash_hex>/<execution_idempotency_key_v1>.pending.json`
/// `root/<policy_hash_hex>/<execution_idempotency_key_v1>.committed.json`
///
/// If the process loses certainty after creating the pending marker, subsequent retries reject
/// until an operator resolves the pending barrier manually. This narrows duplicate remote effects
/// without claiming global exactly-once semantics.
pub struct IdempotentHttpExecutor {
    inner: HttpExecutor,
    effect_journal_root: PathBuf,
}

impl IdempotentHttpExecutor {
    /// Create a new idempotent HTTP executor.
    pub fn new(config: HttpExecutorConfig) -> Result<Self> {
        let effect_journal_root = config.effect_journal_root.clone().ok_or_else(|| {
            MprdError::ConfigError("idempotent_http requires effect_journal_root".into())
        })?;
        fs::create_dir_all(&effect_journal_root).map_err(|e| {
            MprdError::ExecutionError(format!("Failed to create HTTP effect journal dir: {}", e))
        })?;
        let inner = HttpExecutor::new(config)?;
        Ok(Self {
            inner,
            effect_journal_root,
        })
    }

    fn journal_base_dir(&self, token: &DecisionToken) -> PathBuf {
        self.effect_journal_root
            .join(hex::encode(token.policy_hash.0))
    }

    fn pending_path(&self, token: &DecisionToken) -> PathBuf {
        self.journal_base_dir(token).join(format!(
            "{}.pending.json",
            execution_idempotency_key_v1(token)
        ))
    }

    fn committed_path(&self, token: &DecisionToken) -> PathBuf {
        self.journal_base_dir(token).join(format!(
            "{}.committed.json",
            execution_idempotency_key_v1(token)
        ))
    }

    fn persist_barrier_payload<T: Serialize>(
        mut file: File,
        path: &Path,
        payload: &T,
    ) -> Result<()> {
        let json = serde_json::to_vec(payload).map_err(|e| {
            MprdError::ExecutionError(format!("Failed to serialize HTTP effect barrier: {}", e))
        })?;
        file.write_all(&json).map_err(|e| {
            MprdError::ExecutionError(format!(
                "Failed to write HTTP effect barrier {}: {}",
                path.display(),
                e
            ))
        })?;
        file.write_all(b"\n").map_err(|e| {
            MprdError::ExecutionError(format!(
                "Failed to write HTTP effect barrier {}: {}",
                path.display(),
                e
            ))
        })?;
        file.flush().map_err(|e| {
            MprdError::ExecutionError(format!(
                "Failed to flush HTTP effect barrier {}: {}",
                path.display(),
                e
            ))
        })
    }

    fn clear_pending(path: &PathBuf) -> Result<()> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(MprdError::ExecutionError(format!(
                "Failed to clear pending HTTP effect barrier {}: {}",
                path.display(),
                e
            ))),
        }
    }

    fn load_barrier_document(path: &Path) -> Result<serde_json::Map<String, serde_json::Value>> {
        let bytes = fs::read(path).map_err(|e| {
            MprdError::ExecutionError(format!(
                "Failed to read HTTP effect barrier {}: {}",
                path.display(),
                e
            ))
        })?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
            MprdError::ExecutionError(format!(
                "Failed to parse HTTP effect barrier {}: {}",
                path.display(),
                e
            ))
        })?;
        value.as_object().cloned().ok_or_else(|| {
            MprdError::ExecutionError(format!(
                "HTTP effect barrier {} is not a JSON object",
                path.display()
            ))
        })
    }

    fn write_committed_barrier_document(
        pending: &PathBuf,
        committed: &PathBuf,
        mut document: serde_json::Map<String, serde_json::Value>,
        resolution_kind: CommittedHttpEffectBarrierResolutionKind,
    ) -> Result<()> {
        document.insert(
            "effect_barrier_resolution_kind".into(),
            serde_json::Value::String(resolution_kind.as_str().to_string()),
        );
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(committed)
            .map_err(|e| {
                MprdError::ExecutionError(format!(
                    "Failed to create committed HTTP effect barrier {}: {}",
                    committed.display(),
                    e
                ))
            })?;
        Self::persist_barrier_payload(file, committed, &document)?;
        Self::clear_pending(pending)
    }

    fn prepare_pending_barrier(
        &self,
        token: &DecisionToken,
        payload: &ExecutePayload,
    ) -> Result<EffectBarrierState> {
        let base_dir = self.journal_base_dir(token);
        fs::create_dir_all(&base_dir).map_err(|e| {
            MprdError::ExecutionError(format!(
                "Failed to create HTTP effect journal dir {}: {}",
                base_dir.display(),
                e
            ))
        })?;

        let committed = self.committed_path(token);
        if committed.exists() {
            return Ok(EffectBarrierState::Committed(committed));
        }

        let pending = self.pending_path(token);
        let file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Ok(EffectBarrierState::BlockedPending(pending));
            }
            Err(e) => {
                return Err(MprdError::ExecutionError(format!(
                    "Failed to create HTTP effect barrier {}: {}",
                    pending.display(),
                    e
                )));
            }
        };
        match Self::persist_barrier_payload(file, &pending, payload) {
            Ok(()) => Ok(EffectBarrierState::Pending { pending, committed }),
            Err(err) => {
                let _ = Self::clear_pending(&pending);
                Err(err)
            }
        }
    }

    fn execute_payload_idempotent(
        &self,
        token: &DecisionToken,
        payload: &ExecutePayload,
    ) -> Result<ExecutionResult> {
        match self.prepare_pending_barrier(token, payload)? {
            EffectBarrierState::Committed(path) => Ok(ExecutionResult {
                success: true,
                message: Some(format!(
                    "Already committed remote effect barrier: {}",
                    path.display()
                )),
            }),
            EffectBarrierState::BlockedPending(path) => Err(MprdError::ExecutionError(format!(
                "HTTP effect barrier pending at {}; manual resolution required before retry",
                path.display()
            ))),
            EffectBarrierState::Pending { pending, committed } => {
                let result = self.inner.execute_payload(token, payload);
                match result {
                    Ok(result) if result.success => {
                        if committed.exists() {
                            Self::clear_pending(&pending)?;
                        } else {
                            let document =
                                serde_json::to_value(payload).map_err(|e| {
                                    MprdError::ExecutionError(format!(
                                        "Failed to serialize committed HTTP effect barrier payload: {}",
                                        e
                                    ))
                                })?
                                .as_object()
                                .cloned()
                                .ok_or_else(|| {
                                    MprdError::ExecutionError(
                                        "Committed HTTP effect barrier payload is not a JSON object"
                                            .into(),
                                    )
                                })?;
                            Self::write_committed_barrier_document(
                                &pending,
                                &committed,
                                document,
                                CommittedHttpEffectBarrierResolutionKind::Automatic,
                            )?;
                        }
                        Ok(ExecutionResult {
                            success: true,
                            message: Some(match result.message {
                                Some(message) => {
                                    format!("{message}; committed barrier: {}", committed.display())
                                }
                                None => format!("committed barrier: {}", committed.display()),
                            }),
                        })
                    }
                    Ok(result) => {
                        Self::clear_pending(&pending)?;
                        Ok(result)
                    }
                    Err(err) => Err(MprdError::ExecutionError(format!(
                        "HTTP effect barrier pending at {} after uncertain remote outcome: {}",
                        pending.display(),
                        err
                    ))),
                }
            }
        }
    }
}

enum EffectBarrierState {
    Committed(PathBuf),
    BlockedPending(PathBuf),
    Pending {
        pending: PathBuf,
        committed: PathBuf,
    },
}

impl ExecutorAdapter for IdempotentHttpExecutor {
    fn execute(&self, verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
        let token = verified.token();
        let proof = verified.proof();
        let action_preimage = require_action_preimage(verified)?;
        let payload = execute_payload_from_parts(token, proof, &action_preimage, None, None);
        self.execute_payload_idempotent(token, &payload)
    }

    fn execute_ready(&self, ready: &ExecutionReadyBundle<'_>) -> Result<ExecutionResult> {
        let token = ready.token();
        let proof = ready.proof();
        let action_preimage = require_ready_action_preimage(ready);
        let payload = execute_payload_from_parts(
            token,
            proof,
            &action_preimage,
            ready.authorization().and_then(|a| a.governance()),
            ready.bridge(),
        );
        self.execute_payload_idempotent(token, &payload)
    }
}

/// Payload sent to the execution endpoint.
#[derive(Clone, Serialize)]
struct ExecutePayload {
    idempotency_key_v1: String,
    policy_hash: String,
    policy_epoch: u64,
    registry_root: String,
    state_hash: String,
    state_source_id: String,
    state_epoch: u64,
    state_attestation_hash: String,
    action_hash: String,
    action_preimage_hex: String,
    nonce_or_tx_hash: String,
    timestamp_ms: i64,
    token_signature_hex: String,
    proof_receipt_hex: String,
    proof_metadata: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_authorization_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_checkpoint_attestation_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    governance_update_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    governance_profile_app_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    governance_profile_safety_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    governance_link_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    effect_barrier_resolution_kind: Option<CommittedHttpEffectBarrierResolutionKind>,
}

/// Response from the execution endpoint.
#[derive(Deserialize)]
struct ExecuteResponse {
    success: bool,
    message: Option<String>,
}

/// Maximum response body size from executor endpoints (DoS prevention).
const MAX_RESPONSE_BYTES: usize = 1024 * 1024; // 1 MiB

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

        let payload = execute_payload_from_parts(token, proof, &action_preimage, None, None);
        self.execute_payload(token, &payload)
    }

    fn execute_ready(&self, ready: &ExecutionReadyBundle<'_>) -> Result<ExecutionResult> {
        let token = ready.token();
        let proof = ready.proof();
        let action_preimage = require_ready_action_preimage(ready);
        let payload = execute_payload_from_parts(
            token,
            proof,
            &action_preimage,
            ready.authorization().and_then(|a| a.governance()),
            ready.bridge(),
        );
        self.execute_payload(token, &payload)
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
        let payload = webhook_payload_from_parts(token, proof, &action_preimage, None, None);
        let idempotency_key = execution_idempotency_key_v1(token);

        match self
            .client
            .post(&self.webhook_url)
            .header("Idempotency-Key", &idempotency_key)
            .json(&payload)
            .send()
        {
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

    fn execute_ready(&self, ready: &ExecutionReadyBundle<'_>) -> Result<ExecutionResult> {
        let token = ready.token();
        let proof = ready.proof();
        let action_preimage = require_ready_action_preimage(ready);
        let payload = webhook_payload_from_parts(
            token,
            proof,
            &action_preimage,
            ready.authorization().and_then(|a| a.governance()),
            ready.bridge(),
        );
        let idempotency_key = execution_idempotency_key_v1(token);

        match self
            .client
            .post(&self.webhook_url)
            .header("Idempotency-Key", &idempotency_key)
            .json(&payload)
            .send()
        {
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
    idempotency_key_v1: String,
    policy_hash: String,
    state_hash: String,
    state_source_id: String,
    state_epoch: u64,
    state_attestation_hash: String,
    action_hash: String,
    action_preimage_hex: Option<String>,
    nonce_or_tx_hash: String,
    token_timestamp_ms: i64,
    proof_metadata: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_authorization_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_checkpoint_attestation_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    governance_update_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    governance_profile_app_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    governance_profile_safety_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    governance_link_ok: Option<bool>,
}

fn audit_record_from_parts(
    token: &DecisionToken,
    proof: &ProofBundle,
    action_preimage: &[u8],
    governance: Option<&mprd_core::GovernanceAdmissionWitnessV1>,
    bridge: Option<&mprd_core::ExecutionRegistryBridgeWitnessV1>,
) -> AuditRecord {
    AuditRecord {
        timestamp: chrono::Utc::now().to_rfc3339(),
        idempotency_key_v1: execution_idempotency_key_v1(token),
        policy_hash: hex::encode(token.policy_hash.0),
        state_hash: hex::encode(token.state_hash.0),
        state_source_id: hex::encode(token.state_ref.state_source_id.0),
        state_epoch: token.state_ref.state_epoch,
        state_attestation_hash: hex::encode(token.state_ref.state_attestation_hash.0),
        action_hash: hex::encode(token.chosen_action_hash.0),
        action_preimage_hex: Some(hex::encode(action_preimage)),
        nonce_or_tx_hash: hex::encode(token.nonce_or_tx_hash.0),
        token_timestamp_ms: token.timestamp_ms,
        proof_metadata: proof.attestation_metadata.clone(),
        registry_authorization_hash: bridge.map(|b| hex::encode(b.registry_authorization_hash().0)),
        registry_checkpoint_attestation_hash: bridge.and_then(|b| {
            b.registry_checkpoint_attestation_hash()
                .map(|hash| hex::encode(hash.0))
        }),
        governance_update_kind: governance.map(|g| g.update_kind().as_str().to_string()),
        governance_profile_app_ok: governance.map(|g| g.profile_app_ok()),
        governance_profile_safety_ok: governance.map(|g| g.profile_safety_ok()),
        governance_link_ok: governance.map(|g| g.link_ok()),
    }
}

impl ExecutorAdapter for FileExecutor {
    fn execute(&self, verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
        // SECURITY: this executor writes an append-only audit line. The file is a side-effecting
        // sink and should be treated as untrusted storage; callers should provide a path on a
        // durable filesystem with appropriate permissions.
        let token = verified.token();
        let proof = verified.proof();
        let action_preimage = require_action_preimage(verified)?;
        let record = audit_record_from_parts(token, proof, &action_preimage, None, None);

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

    fn execute_ready(&self, ready: &ExecutionReadyBundle<'_>) -> Result<ExecutionResult> {
        let token = ready.token();
        let proof = ready.proof();
        let action_preimage = require_ready_action_preimage(ready);
        let record = audit_record_from_parts(
            token,
            proof,
            &action_preimage,
            ready.authorization().and_then(|a| a.governance()),
            ready.bridge(),
        );

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
/// `root/<policy_hash_hex>/<execution_idempotency_key_v1>.json`
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
        let idempotency_key = execution_idempotency_key_v1(token);
        self.root
            .join(policy)
            .join(format!("{}.json", idempotency_key))
    }
}

impl ExecutorAdapter for IdempotentFileExecutor {
    fn execute(&self, verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
        let token = verified.token();
        let proof = verified.proof();
        let action_preimage = require_action_preimage(verified)?;
        let record = audit_record_from_parts(token, proof, &action_preimage, None, None);

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

    fn execute_ready(&self, ready: &ExecutionReadyBundle<'_>) -> Result<ExecutionResult> {
        let token = ready.token();
        let proof = ready.proof();
        let action_preimage = require_ready_action_preimage(ready);
        let record = audit_record_from_parts(
            token,
            proof,
            &action_preimage,
            ready.authorization().and_then(|a| a.governance()),
            ready.bridge(),
        );

        let path = self.record_path(token);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                MprdError::ExecutionError(format!("Failed to create audit dir: {}", e))
            })?;
        }

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

    fn execute_ready(&self, ready: &ExecutionReadyBundle<'_>) -> Result<ExecutionResult> {
        let mut messages = Vec::new();
        let mut all_success = true;

        for (i, executor) in self.executors.iter().enumerate() {
            match executor.execute_ready(ready) {
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

    fn execute_ready(&self, _ready: &ExecutionReadyBundle<'_>) -> Result<ExecutionResult> {
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
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

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

    fn spawn_fixed_http_server(
        expected_requests: usize,
        body: &'static str,
    ) -> (String, Arc<AtomicUsize>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = hits.clone();
        let handle = thread::spawn(move || {
            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                hits_clone.fetch_add(1, Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write response");
                stream.flush().expect("flush response");
            }
        });
        (format!("http://{}", addr), hits, handle)
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

    fn ready<'a>(
        token: &'a DecisionToken,
        proof: &'a ProofBundle,
    ) -> mprd_core::ExecutionReadyBundle<'a> {
        mprd_core::prepare_execution_ready(verified(token, proof)).expect("prepare_execution_ready")
    }

    fn ready_with_governance<'a>(
        token: &'a DecisionToken,
        proof: &'a mut ProofBundle,
    ) -> mprd_core::ExecutionReadyBundle<'a> {
        let governance = mprd_core::governance_admission_witness_from_fields_v1(
            mprd_core::GovernanceUpdateKindV1::PolicyTweak,
            true,
            false,
            true,
        )
        .expect("governance witness");
        mprd_core::insert_governance_attestation_metadata_v1(
            &mut proof.attestation_metadata,
            &governance,
        );
        let state = mprd_core::StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: token.state_hash,
            state_ref: token.state_ref.clone(),
        };
        mprd_core::insert_execution_authorization_attestation_metadata_v1(
            &mut proof.attestation_metadata,
            token,
            &state,
            Some(&governance),
        );
        let authority =
            mprd_core::policy_authority_witness_v1(&token.policy_hash, &token.policy_ref)
                .expect("policy authority");
        let state_binding = mprd_core::state_provenance::state_binding_witness_v1(&state);
        mprd_core::prepare_execution_ready_with_authorization(
            verified(token, proof),
            &authority,
            &state_binding,
            Some(governance),
        )
        .expect("prepare_execution_ready_with_authorization")
    }

    fn ready_with_governance_and_bridge<'a>(
        token: &'a DecisionToken,
        proof: &'a mut ProofBundle,
    ) -> mprd_core::ExecutionReadyBundle<'a> {
        let ready = ready_with_governance(token, proof);
        let resolution_hash = mprd_core::registry_authorization_attestation_hash_from_fields_v1(
            &token.policy_hash,
            &mprd_core::artifact_repo::Id32([0xAA; 32]),
            &mprd_core::artifact_repo::Id32([0xAB; 32]),
            &mprd_core::artifact_repo::Id32([0xAC; 32]),
            Some(&mprd_core::artifact_repo::Id32([0xAD; 32])),
            Some(&Hash32([0xAE; 32])),
        )
        .expect("resolution hash");
        let registry_authorization = mprd_core::registry_authorization_witness_v1(
            resolution_hash,
            mprd_core::artifact_repo::Id32([0xAA; 32]),
            mprd_core::artifact_repo::Id32([0xAB; 32]),
            mprd_core::artifact_repo::Id32([0xAC; 32]),
            Some(mprd_core::artifact_repo::Id32([0xAD; 32])),
            Some(Hash32([0xAE; 32])),
        )
        .expect("registry authorization");
        let bridge = mprd_core::execution_registry_bridge_witness_v1(
            &token.policy_hash,
            registry_authorization,
            Some(Hash32([0xBB; 32])),
        )
        .expect("registry bridge witness");
        mprd_core::prepare_execution_ready_with_registry_bridge(&ready, bridge)
            .expect("prepare_execution_ready_with_registry_bridge")
    }

    struct CountingExecutor {
        raw_calls: Arc<AtomicUsize>,
        ready_calls: Arc<AtomicUsize>,
    }

    impl ExecutorAdapter for CountingExecutor {
        fn execute(&self, _verified: &VerifiedBundle<'_>) -> Result<ExecutionResult> {
            self.raw_calls.fetch_add(1, Ordering::SeqCst);
            Ok(ExecutionResult {
                success: true,
                message: Some("counting".into()),
            })
        }

        fn execute_ready(&self, _ready: &ExecutionReadyBundle<'_>) -> Result<ExecutionResult> {
            self.ready_calls.fetch_add(1, Ordering::SeqCst);
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
    fn execute_payload_includes_state_ref_provenance() {
        let token = dummy_token();
        let proof = dummy_proof();
        let action_preimage = dummy_http_call_action_preimage();
        let expected_idempotency_key = execution_idempotency_key_v1(&token);

        let payload = execute_payload_from_parts(&token, &proof, &action_preimage, None, None);
        assert_eq!(payload.idempotency_key_v1, expected_idempotency_key);
        assert_eq!(
            payload.state_source_id,
            hex::encode(token.state_ref.state_source_id.0)
        );
        assert_eq!(payload.state_epoch, token.state_ref.state_epoch);
        assert_eq!(
            payload.state_attestation_hash,
            hex::encode(token.state_ref.state_attestation_hash.0)
        );
    }

    #[test]
    fn webhook_payload_includes_state_ref_provenance() {
        let token = dummy_token();
        let proof = dummy_proof();
        let action_preimage = dummy_http_call_action_preimage();
        let expected_idempotency_key = execution_idempotency_key_v1(&token);
        let expected_state_source_id = hex::encode(token.state_ref.state_source_id.0);
        let expected_state_attestation_hash = hex::encode(token.state_ref.state_attestation_hash.0);

        let payload = webhook_payload_from_parts(&token, &proof, &action_preimage, None, None);
        assert_eq!(
            payload
                .get("idempotency_key_v1")
                .and_then(serde_json::Value::as_str),
            Some(expected_idempotency_key.as_str())
        );
        assert_eq!(
            payload
                .get("state_source_id")
                .and_then(serde_json::Value::as_str),
            Some(expected_state_source_id.as_str())
        );
        assert_eq!(
            payload
                .get("state_epoch")
                .and_then(serde_json::Value::as_u64),
            Some(token.state_ref.state_epoch)
        );
        assert_eq!(
            payload
                .get("state_attestation_hash")
                .and_then(serde_json::Value::as_str),
            Some(expected_state_attestation_hash.as_str())
        );
    }

    #[test]
    fn file_executor_execute_ready_creates_audit_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mprd_test_ready.jsonl");

        let executor = FileExecutor::new(&path).unwrap();
        let token = dummy_token();
        let proof = dummy_proof();
        let result = executor.execute_ready(&ready(&token, &proof)).unwrap();

        assert!(result.success);
        assert!(path.exists());
    }

    #[test]
    fn file_executor_record_includes_state_ref_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mprd_test_state_ref.jsonl");

        let executor = FileExecutor::new(&path).unwrap();
        let token = dummy_token();
        let proof = dummy_proof();
        let expected_idempotency_key = execution_idempotency_key_v1(&token);
        let expected_state_source_id = hex::encode(token.state_ref.state_source_id.0);
        let expected_state_attestation_hash = hex::encode(token.state_ref.state_attestation_hash.0);
        let result = executor.execute_ready(&ready(&token, &proof)).unwrap();

        assert!(result.success);
        let line = std::fs::read_to_string(&path).expect("read audit file");
        let record: serde_json::Value = serde_json::from_str(line.trim()).expect("json record");
        assert_eq!(
            record
                .get("idempotency_key_v1")
                .and_then(serde_json::Value::as_str),
            Some(expected_idempotency_key.as_str())
        );
        assert_eq!(
            record
                .get("state_source_id")
                .and_then(serde_json::Value::as_str),
            Some(expected_state_source_id.as_str())
        );
        assert_eq!(
            record
                .get("state_epoch")
                .and_then(serde_json::Value::as_u64),
            Some(token.state_ref.state_epoch)
        );
        assert_eq!(
            record
                .get("state_attestation_hash")
                .and_then(serde_json::Value::as_str),
            Some(expected_state_attestation_hash.as_str())
        );
    }

    #[test]
    fn execute_ready_payload_includes_governance_provenance() {
        let token = dummy_token();
        let mut proof = dummy_proof();
        let ready = ready_with_governance_and_bridge(&token, &mut proof);
        let action_preimage = require_ready_action_preimage(&ready);
        let expected_registry_authorization_hash = hex::encode(
            ready
                .bridge()
                .expect("bridge")
                .registry_authorization_hash()
                .0,
        );

        let payload = execute_payload_from_parts(
            ready.token(),
            ready.proof(),
            &action_preimage,
            ready.authorization().and_then(|a| a.governance()),
            ready.bridge(),
        );
        assert_eq!(
            payload.governance_update_kind.as_deref(),
            Some("policy_tweak")
        );
        assert_eq!(payload.governance_profile_app_ok, Some(true));
        assert_eq!(payload.governance_profile_safety_ok, Some(false));
        assert_eq!(payload.governance_link_ok, Some(true));
        assert_eq!(
            payload.registry_authorization_hash.as_deref(),
            Some(expected_registry_authorization_hash.as_str())
        );
        assert_eq!(
            payload.registry_checkpoint_attestation_hash.as_deref(),
            Some(hex::encode([0xBB; 32]).as_str())
        );
    }

    #[test]
    fn webhook_ready_payload_includes_governance_provenance() {
        let token = dummy_token();
        let mut proof = dummy_proof();
        let ready = ready_with_governance_and_bridge(&token, &mut proof);
        let action_preimage = require_ready_action_preimage(&ready);
        let expected_registry_authorization_hash = hex::encode(
            ready
                .bridge()
                .expect("bridge")
                .registry_authorization_hash()
                .0,
        );

        let payload = webhook_payload_from_parts(
            ready.token(),
            ready.proof(),
            &action_preimage,
            ready.authorization().and_then(|a| a.governance()),
            ready.bridge(),
        );
        assert_eq!(
            payload
                .get("governance_update_kind")
                .and_then(serde_json::Value::as_str),
            Some("policy_tweak")
        );
        assert_eq!(
            payload
                .get("governance_profile_app_ok")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            payload
                .get("governance_profile_safety_ok")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            payload
                .get("governance_link_ok")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            payload
                .get("registry_authorization_hash")
                .and_then(serde_json::Value::as_str),
            Some(expected_registry_authorization_hash.as_str())
        );
        assert_eq!(
            payload
                .get("registry_checkpoint_attestation_hash")
                .and_then(serde_json::Value::as_str),
            Some(hex::encode([0xBB; 32]).as_str())
        );
    }

    #[test]
    fn file_executor_record_includes_governance_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mprd_test_governance.jsonl");

        let executor = FileExecutor::new(&path).unwrap();
        let token = dummy_token();
        let mut proof = dummy_proof();
        let ready = ready_with_governance_and_bridge(&token, &mut proof);
        let expected_registry_authorization_hash = hex::encode(
            ready
                .bridge()
                .expect("bridge")
                .registry_authorization_hash()
                .0,
        );
        let result = executor.execute_ready(&ready).unwrap();

        assert!(result.success);
        let line = std::fs::read_to_string(&path).expect("read audit file");
        let record: serde_json::Value = serde_json::from_str(line.trim()).expect("json record");
        assert_eq!(
            record
                .get("governance_update_kind")
                .and_then(serde_json::Value::as_str),
            Some("policy_tweak")
        );
        assert_eq!(
            record
                .get("governance_profile_app_ok")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            record
                .get("governance_profile_safety_ok")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            record
                .get("governance_link_ok")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            record
                .get("registry_authorization_hash")
                .and_then(serde_json::Value::as_str),
            Some(expected_registry_authorization_hash.as_str())
        );
        assert_eq!(
            record
                .get("registry_checkpoint_attestation_hash")
                .and_then(serde_json::Value::as_str),
            Some(hex::encode([0xBB; 32]).as_str())
        );
    }

    #[test]
    fn execution_idempotency_key_v1_is_deterministic_and_tuple_bound() {
        let token = dummy_token();
        let baseline = execution_idempotency_key_v1(&token);
        assert_eq!(baseline, execution_idempotency_key_v1(&token));

        let mut policy_drift = token.clone();
        policy_drift.policy_hash = Hash32([9u8; 32]);
        assert_ne!(baseline, execution_idempotency_key_v1(&policy_drift));

        let mut state_drift = token.clone();
        state_drift.state_hash = Hash32([8u8; 32]);
        assert_ne!(baseline, execution_idempotency_key_v1(&state_drift));

        let mut action_drift = token.clone();
        action_drift.chosen_action_hash = Hash32([7u8; 32]);
        assert_ne!(baseline, execution_idempotency_key_v1(&action_drift));

        let mut nonce_drift = token.clone();
        nonce_drift.nonce_or_tx_hash = Hash32([6u8; 32]);
        assert_ne!(baseline, execution_idempotency_key_v1(&nonce_drift));
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
        let c1_raw = Arc::new(AtomicUsize::new(0));
        let c1_ready = Arc::new(AtomicUsize::new(0));
        let c2_raw = Arc::new(AtomicUsize::new(0));
        let c2_ready = Arc::new(AtomicUsize::new(0));
        let executors: Vec<Box<dyn ExecutorAdapter + Send + Sync>> = vec![
            Box::new(CountingExecutor {
                raw_calls: c1_raw.clone(),
                ready_calls: c1_ready.clone(),
            }),
            Box::new(FailingExecutor),
            Box::new(CountingExecutor {
                raw_calls: c2_raw.clone(),
                ready_calls: c2_ready.clone(),
            }),
        ];

        let composite = CompositeExecutor::new(executors);
        let token = dummy_token();
        let proof = dummy_proof();
        let err = composite.execute(&verified(&token, &proof)).unwrap_err();
        assert!(matches!(err, MprdError::ExecutionError(_)));

        assert_eq!(c1_raw.load(Ordering::SeqCst), 1);
        assert_eq!(c1_ready.load(Ordering::SeqCst), 0);
        assert_eq!(c2_raw.load(Ordering::SeqCst), 0);
        assert_eq!(c2_ready.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn composite_executor_best_effort_continues_after_error() {
        let c1_raw = Arc::new(AtomicUsize::new(0));
        let c1_ready = Arc::new(AtomicUsize::new(0));
        let c2_raw = Arc::new(AtomicUsize::new(0));
        let c2_ready = Arc::new(AtomicUsize::new(0));
        let executors: Vec<Box<dyn ExecutorAdapter + Send + Sync>> = vec![
            Box::new(CountingExecutor {
                raw_calls: c1_raw.clone(),
                ready_calls: c1_ready.clone(),
            }),
            Box::new(FailingExecutor),
            Box::new(CountingExecutor {
                raw_calls: c2_raw.clone(),
                ready_calls: c2_ready.clone(),
            }),
        ];

        let composite = CompositeExecutor::best_effort(executors);
        let token = dummy_token();
        let proof = dummy_proof();
        let result = composite.execute(&verified(&token, &proof)).unwrap();
        assert!(!result.success);
        assert!(result.message.unwrap_or_default().contains("ERROR"));

        assert_eq!(c1_raw.load(Ordering::SeqCst), 1);
        assert_eq!(c1_ready.load(Ordering::SeqCst), 0);
        assert_eq!(c2_raw.load(Ordering::SeqCst), 1);
        assert_eq!(c2_ready.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn composite_executor_execute_ready_uses_child_ready_path() {
        let c1_raw = Arc::new(AtomicUsize::new(0));
        let c1_ready = Arc::new(AtomicUsize::new(0));
        let c2_raw = Arc::new(AtomicUsize::new(0));
        let c2_ready = Arc::new(AtomicUsize::new(0));
        let executors: Vec<Box<dyn ExecutorAdapter + Send + Sync>> = vec![
            Box::new(CountingExecutor {
                raw_calls: c1_raw.clone(),
                ready_calls: c1_ready.clone(),
            }),
            Box::new(CountingExecutor {
                raw_calls: c2_raw.clone(),
                ready_calls: c2_ready.clone(),
            }),
        ];

        let composite = CompositeExecutor::new(executors);
        let token = dummy_token();
        let proof = dummy_proof();
        let result = composite.execute_ready(&ready(&token, &proof)).unwrap();

        assert!(result.success);
        assert_eq!(c1_raw.load(Ordering::SeqCst), 0);
        assert_eq!(c1_ready.load(Ordering::SeqCst), 1);
        assert_eq!(c2_raw.load(Ordering::SeqCst), 0);
        assert_eq!(c2_ready.load(Ordering::SeqCst), 1);
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

    #[test]
    fn idempotent_http_executor_writes_once_per_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let (base_url, hits, handle) =
            spawn_fixed_http_server(1, r#"{"success":true,"message":"ok"}"#);
        let exec = IdempotentHttpExecutor::new(HttpExecutorConfig {
            base_url,
            effect_journal_root: Some(dir.path().join("http_effects")),
            ..Default::default()
        })
        .expect("new");
        let token = dummy_token();
        let proof = dummy_proof();
        let verified = verified(&token, &proof);

        let r1 = exec.execute(&verified).expect("exec1");
        assert!(r1.success);
        let r2 = exec.execute(&verified).expect("exec2");
        assert!(r2.success);
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        handle.join().expect("join");

        let policy_dir = dir
            .path()
            .join("http_effects")
            .join(hex::encode(token.policy_hash.0));
        let entries: Vec<_> = std::fs::read_dir(policy_dir).unwrap().collect();
        assert_eq!(entries.len(), 1);
        let file_name = entries[0]
            .as_ref()
            .expect("entry")
            .file_name()
            .into_string()
            .expect("filename");
        assert!(file_name.ends_with(".committed.json"));
    }

    #[test]
    fn idempotent_http_executor_blocks_when_pending_barrier_exists() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("http_effects");
        let exec = IdempotentHttpExecutor::new(HttpExecutorConfig {
            base_url: "http://127.0.0.1:1".into(),
            effect_journal_root: Some(root.clone()),
            ..Default::default()
        })
        .expect("new");
        let token = dummy_token();
        let proof = dummy_proof();
        let verified = verified(&token, &proof);

        let policy_dir = root.join(hex::encode(token.policy_hash.0));
        std::fs::create_dir_all(&policy_dir).expect("policy dir");
        let pending = policy_dir.join(format!(
            "{}.pending.json",
            execution_idempotency_key_v1(&token)
        ));
        std::fs::write(&pending, b"{}\n").expect("pending marker");

        let err = exec
            .execute(&verified)
            .expect_err("pending barrier must block");
        assert!(
            err.to_string()
                .contains("manual resolution required before retry"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn summarize_http_effect_journal_root_counts_pending_and_committed_markers() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("http_effects");
        let policy_dir = root.join("deadbeef");
        std::fs::create_dir_all(&policy_dir).unwrap();
        std::fs::write(policy_dir.join("a.pending.json"), b"{}\n").unwrap();
        std::fs::write(
            policy_dir.join("b.committed.json"),
            serde_json::to_vec(&serde_json::json!({
                "idempotency_key_v1": "b",
                "policy_hash": "deadbeef",
                "state_hash": format!("{:064x}", 0x11),
                "action_hash": format!("{:064x}", 0x22),
                "nonce_or_tx_hash": format!("{:064x}", 0x33),
                "timestamp_ms": 1,
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(policy_dir.join("ignored.txt"), b"noop\n").unwrap();

        let summary = summarize_http_effect_journal_root(&root).expect("summary");
        assert_eq!(
            summary,
            EffectJournalSummary {
                pending_entries: 1,
                committed_entries: 1,
                committed_automatic_entries: 0,
                committed_manual_promote_entries: 0,
                committed_legacy_entries: 1,
            }
        );
    }

    #[test]
    fn summarize_http_effect_journal_root_treats_missing_root_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("missing");
        let summary = summarize_http_effect_journal_root(&root).expect("summary");
        assert_eq!(summary, EffectJournalSummary::default());
    }

    #[test]
    fn summarize_http_effect_journal_root_counts_committed_resolution_kinds() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("http_effects");
        let policy_dir = root.join("deadbeef");
        std::fs::create_dir_all(&policy_dir).unwrap();
        std::fs::write(
            policy_dir.join("legacy.committed.json"),
            serde_json::to_vec(&serde_json::json!({
                "idempotency_key_v1": "legacy",
                "policy_hash": "deadbeef",
                "state_hash": format!("{:064x}", 0x11),
                "action_hash": format!("{:064x}", 0x22),
                "nonce_or_tx_hash": format!("{:064x}", 0x33),
                "timestamp_ms": 1,
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            policy_dir.join("auto.committed.json"),
            serde_json::to_vec(&serde_json::json!({
                "idempotency_key_v1": "auto",
                "policy_hash": "deadbeef",
                "state_hash": format!("{:064x}", 0x44),
                "action_hash": format!("{:064x}", 0x55),
                "nonce_or_tx_hash": format!("{:064x}", 0x66),
                "timestamp_ms": 2,
                "effect_barrier_resolution_kind": "automatic",
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            policy_dir.join("manual.committed.json"),
            serde_json::to_vec(&serde_json::json!({
                "idempotency_key_v1": "manual",
                "policy_hash": "deadbeef",
                "state_hash": format!("{:064x}", 0x77),
                "action_hash": format!("{:064x}", 0x88),
                "nonce_or_tx_hash": format!("{:064x}", 0x99),
                "timestamp_ms": 3,
                "effect_barrier_resolution_kind": "manual_promote",
            }))
            .unwrap(),
        )
        .unwrap();

        let summary = summarize_http_effect_journal_root(&root).expect("summary");
        assert_eq!(
            summary,
            EffectJournalSummary {
                pending_entries: 0,
                committed_entries: 3,
                committed_automatic_entries: 1,
                committed_manual_promote_entries: 1,
                committed_legacy_entries: 1,
            }
        );
    }

    #[test]
    fn list_pending_http_effect_barriers_returns_sorted_validated_entries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("http_effects");

        let mut token_a = dummy_token();
        token_a.policy_hash = Hash32([0x11; 32]);
        token_a.state_hash = Hash32([0x21; 32]);
        token_a.chosen_action_hash = Hash32([0x31; 32]);
        token_a.nonce_or_tx_hash = Hash32([0x41; 32]);
        token_a.timestamp_ms = 111;

        let mut token_b = dummy_token();
        token_b.policy_hash = Hash32([0x12; 32]);
        token_b.state_hash = Hash32([0x22; 32]);
        token_b.chosen_action_hash = Hash32([0x32; 32]);
        token_b.nonce_or_tx_hash = Hash32([0x42; 32]);
        token_b.timestamp_ms = 222;

        for token in [&token_b, &token_a] {
            let policy_dir = root.join(hex::encode(token.policy_hash.0));
            std::fs::create_dir_all(&policy_dir).unwrap();
            let key = execution_idempotency_key_v1(token);
            let payload = serde_json::json!({
                "idempotency_key_v1": key,
                "policy_hash": hex::encode(token.policy_hash.0),
                "state_hash": hex::encode(token.state_hash.0),
                "action_hash": hex::encode(token.chosen_action_hash.0),
                "nonce_or_tx_hash": hex::encode(token.nonce_or_tx_hash.0),
                "timestamp_ms": token.timestamp_ms,
            });
            std::fs::write(
                policy_dir.join(format!("{}.pending.json", key)),
                serde_json::to_vec(&payload).unwrap(),
            )
            .unwrap();
        }

        let barriers = list_pending_http_effect_barriers(&root).expect("barriers");
        assert_eq!(barriers.len(), 2);
        assert_eq!(
            barriers[0].policy_hash_hex,
            hex::encode(token_a.policy_hash.0)
        );
        assert_eq!(
            barriers[0].idempotency_key_v1,
            execution_idempotency_key_v1(&token_a)
        );
        assert_eq!(barriers[0].timestamp_ms, token_a.timestamp_ms);
        assert_eq!(
            barriers[1].policy_hash_hex,
            hex::encode(token_b.policy_hash.0)
        );
        assert_eq!(
            barriers[1].idempotency_key_v1,
            execution_idempotency_key_v1(&token_b)
        );
        assert_eq!(barriers[1].timestamp_ms, token_b.timestamp_ms);
    }

    #[test]
    fn list_pending_http_effect_barriers_rejects_oversized_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("http_effects");
        let token = dummy_token();
        let policy_dir = root.join(hex::encode(token.policy_hash.0));
        std::fs::create_dir_all(&policy_dir).unwrap();
        let path = policy_dir.join(format!(
            "{}.pending.json",
            execution_idempotency_key_v1(&token)
        ));
        std::fs::write(
            &path,
            vec![b'{'; (MAX_HTTP_EFFECT_BARRIER_BYTES as usize) + 1],
        )
        .unwrap();

        let err = list_pending_http_effect_barriers(&root).expect_err("oversize must fail closed");
        assert!(
            err.to_string().contains("exceeds maximum size"),
            "unexpected error: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn list_pending_http_effect_barriers_ignores_symlink_entries() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("http_effects");
        std::fs::create_dir_all(&root).unwrap();
        symlink("/dev/zero", root.join("attack.pending.json")).unwrap();

        let barriers = list_pending_http_effect_barriers(&root).expect("barriers");
        assert!(barriers.is_empty());
    }

    #[test]
    fn list_pending_http_effect_barriers_rejects_filename_payload_drift() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("http_effects");
        let token = dummy_token();
        let policy_dir = root.join(hex::encode(token.policy_hash.0));
        std::fs::create_dir_all(&policy_dir).unwrap();
        let payload = serde_json::json!({
            "idempotency_key_v1": "deadbeef",
            "policy_hash": hex::encode(token.policy_hash.0),
            "state_hash": hex::encode(token.state_hash.0),
            "action_hash": hex::encode(token.chosen_action_hash.0),
            "nonce_or_tx_hash": hex::encode(token.nonce_or_tx_hash.0),
            "timestamp_ms": token.timestamp_ms,
        });
        let path = policy_dir.join(format!(
            "{}.pending.json",
            execution_idempotency_key_v1(&token)
        ));
        std::fs::write(&path, serde_json::to_vec(&payload).unwrap()).unwrap();

        let err = list_pending_http_effect_barriers(&root).expect_err("drift must fail closed");
        assert!(
            err.to_string().contains("idempotency key drift"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn list_pending_http_effect_barriers_rejects_committed_resolution_kind() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("http_effects");
        let token = dummy_token();
        let policy_hash_hex = hex::encode(token.policy_hash.0);
        let idempotency_key = execution_idempotency_key_v1(&token);
        let policy_dir = root.join(&policy_hash_hex);
        std::fs::create_dir_all(&policy_dir).unwrap();
        let payload = serde_json::json!({
            "idempotency_key_v1": idempotency_key,
            "policy_hash": policy_hash_hex,
            "state_hash": hex::encode(token.state_hash.0),
            "action_hash": hex::encode(token.chosen_action_hash.0),
            "nonce_or_tx_hash": hex::encode(token.nonce_or_tx_hash.0),
            "timestamp_ms": token.timestamp_ms,
            "effect_barrier_resolution_kind": "automatic",
        });
        let path = policy_dir.join(format!("{}.pending.json", idempotency_key));
        std::fs::write(&path, serde_json::to_vec(&payload).unwrap()).unwrap();

        let err = list_pending_http_effect_barriers(&root).expect_err("must fail closed");
        assert!(
            err.to_string()
                .contains("unexpectedly carries a committed resolution kind"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn list_committed_http_effect_barriers_returns_sorted_validated_entries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("http_effects");

        let mut token_a = dummy_token();
        token_a.policy_hash = Hash32([0x51; 32]);
        token_a.state_hash = Hash32([0x61; 32]);
        token_a.chosen_action_hash = Hash32([0x71; 32]);
        token_a.nonce_or_tx_hash = Hash32([0x81; 32]);
        token_a.timestamp_ms = 333;

        let mut token_b = dummy_token();
        token_b.policy_hash = Hash32([0x52; 32]);
        token_b.state_hash = Hash32([0x62; 32]);
        token_b.chosen_action_hash = Hash32([0x72; 32]);
        token_b.nonce_or_tx_hash = Hash32([0x82; 32]);
        token_b.timestamp_ms = 444;

        for token in [&token_b, &token_a] {
            let policy_dir = root.join(hex::encode(token.policy_hash.0));
            std::fs::create_dir_all(&policy_dir).unwrap();
            let key = execution_idempotency_key_v1(token);
            let payload = serde_json::json!({
                "idempotency_key_v1": key,
                "policy_hash": hex::encode(token.policy_hash.0),
                "state_hash": hex::encode(token.state_hash.0),
                "action_hash": hex::encode(token.chosen_action_hash.0),
                "nonce_or_tx_hash": hex::encode(token.nonce_or_tx_hash.0),
                "timestamp_ms": token.timestamp_ms,
            });
            std::fs::write(
                policy_dir.join(format!("{}.committed.json", key)),
                serde_json::to_vec(&payload).unwrap(),
            )
            .unwrap();
        }

        let mut barriers = list_committed_http_effect_barriers(&root).expect("barriers");
        barriers.sort_by(|a, b| a.barrier_path.cmp(&b.barrier_path));
        assert_eq!(barriers.len(), 2);
        assert_eq!(
            barriers[0].policy_hash_hex,
            hex::encode(token_a.policy_hash.0)
        );
        assert_eq!(
            barriers[0].idempotency_key_v1,
            execution_idempotency_key_v1(&token_a)
        );
        assert_eq!(barriers[0].timestamp_ms, token_a.timestamp_ms);
        assert_eq!(
            barriers[1].policy_hash_hex,
            hex::encode(token_b.policy_hash.0)
        );
        assert_eq!(
            barriers[1].idempotency_key_v1,
            execution_idempotency_key_v1(&token_b)
        );
        assert_eq!(barriers[1].timestamp_ms, token_b.timestamp_ms);
    }

    #[test]
    fn list_committed_http_effect_barriers_rejects_filename_payload_drift() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("http_effects");
        let token = dummy_token();
        let policy_dir = root.join(hex::encode(token.policy_hash.0));
        std::fs::create_dir_all(&policy_dir).unwrap();
        let payload = serde_json::json!({
            "idempotency_key_v1": "badc0ffee",
            "policy_hash": hex::encode(token.policy_hash.0),
            "state_hash": hex::encode(token.state_hash.0),
            "action_hash": hex::encode(token.chosen_action_hash.0),
            "nonce_or_tx_hash": hex::encode(token.nonce_or_tx_hash.0),
            "timestamp_ms": token.timestamp_ms,
        });
        let path = policy_dir.join(format!(
            "{}.committed.json",
            execution_idempotency_key_v1(&token)
        ));
        std::fs::write(&path, serde_json::to_vec(&payload).unwrap()).unwrap();

        let err = list_committed_http_effect_barriers(&root).expect_err("drift must fail closed");
        assert!(
            err.to_string().contains("idempotency key drift"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_pending_http_effect_barrier_clear_removes_pending_marker() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("http_effects");
        let token = dummy_token();
        let policy_hash_hex = hex::encode(token.policy_hash.0);
        let idempotency_key = execution_idempotency_key_v1(&token);
        let policy_dir = root.join(&policy_hash_hex);
        std::fs::create_dir_all(&policy_dir).unwrap();
        let payload = serde_json::json!({
            "idempotency_key_v1": idempotency_key,
            "policy_hash": policy_hash_hex,
            "state_hash": hex::encode(token.state_hash.0),
            "action_hash": hex::encode(token.chosen_action_hash.0),
            "nonce_or_tx_hash": hex::encode(token.nonce_or_tx_hash.0),
            "timestamp_ms": token.timestamp_ms,
        });
        let pending = policy_dir.join(format!("{}.pending.json", idempotency_key));
        std::fs::write(&pending, serde_json::to_vec(&payload).unwrap()).unwrap();

        let resolved = resolve_pending_http_effect_barrier(
            &root,
            &hex::encode(token.policy_hash.0),
            &execution_idempotency_key_v1(&token),
            PendingHttpEffectBarrierResolution::Clear,
        )
        .expect("resolved");
        assert_eq!(resolved.committed_barrier_path, None);
        assert!(!pending.exists());
    }

    #[test]
    fn resolve_pending_http_effect_barrier_promote_renames_to_committed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("http_effects");
        let token = dummy_token();
        let policy_hash_hex = hex::encode(token.policy_hash.0);
        let idempotency_key = execution_idempotency_key_v1(&token);
        let policy_dir = root.join(&policy_hash_hex);
        std::fs::create_dir_all(&policy_dir).unwrap();
        let payload = serde_json::json!({
            "idempotency_key_v1": idempotency_key,
            "policy_hash": policy_hash_hex,
            "state_hash": hex::encode(token.state_hash.0),
            "action_hash": hex::encode(token.chosen_action_hash.0),
            "nonce_or_tx_hash": hex::encode(token.nonce_or_tx_hash.0),
            "timestamp_ms": token.timestamp_ms,
        });
        let pending = policy_dir.join(format!("{}.pending.json", idempotency_key));
        std::fs::write(&pending, serde_json::to_vec(&payload).unwrap()).unwrap();

        let resolved = resolve_pending_http_effect_barrier(
            &root,
            &hex::encode(token.policy_hash.0),
            &execution_idempotency_key_v1(&token),
            PendingHttpEffectBarrierResolution::PromoteToCommitted,
        )
        .expect("resolved");
        let committed = resolved.committed_barrier_path.expect("committed path");
        assert!(!pending.exists());
        assert!(committed.exists());
        assert!(committed.ends_with(format!("{}.committed.json", idempotency_key)));
        let barriers = list_committed_http_effect_barriers(&root).expect("committed barriers");
        assert_eq!(barriers.len(), 1);
        assert_eq!(
            barriers[0].resolution_kind,
            Some(CommittedHttpEffectBarrierResolutionKind::ManualPromote)
        );
    }

    #[test]
    fn idempotent_http_executor_committed_barrier_records_automatic_resolution_kind() {
        let dir = tempfile::tempdir().unwrap();
        let (base_url, _hits, handle) =
            spawn_fixed_http_server(1, r#"{"success":true,"message":"ok"}"#);
        let exec = IdempotentHttpExecutor::new(HttpExecutorConfig {
            base_url,
            effect_journal_root: Some(dir.path().join("http_effects")),
            ..Default::default()
        })
        .expect("new");
        let token = dummy_token();
        let proof = dummy_proof();
        let verified = verified(&token, &proof);

        let result = exec.execute(&verified).expect("exec");
        assert!(result.success);
        handle.join().expect("join");

        let barriers = list_committed_http_effect_barriers(&dir.path().join("http_effects"))
            .expect("barriers");
        assert_eq!(barriers.len(), 1);
        assert_eq!(
            barriers[0].resolution_kind,
            Some(CommittedHttpEffectBarrierResolutionKind::Automatic)
        );
    }
}
