use crate::operator::api;
use anyhow::Context;
use mprd_core::crypto::sha256;
use mprd_core::wire::{self, WireKind};
use mprd_core::{
    CandidateAction, Decision, DecisionToken, Hash32, ProofBundle, RuleVerdict, StateSnapshot,
};
use mprd_zk::bounded_deser::MAX_RECEIPT_BYTES;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const OPERATOR_DECISION_ID_DOMAIN_V1: &[u8] = b"MPRD_OPERATOR_DECISION_ID_V1";
const DEFAULT_DECISION_RETENTION_DAYS: u64 = 30;
const DEFAULT_MAX_DECISIONS: u64 = 10_000;
const SETTINGS_VERSION_V1: u32 = 1;
const AUTOPILOT_STATE_VERSION_V1: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AutopilotStateFileV1 {
    pub version: u32,
    pub mode: api::AutopilotMode,
    pub last_human_ack: i64,
    pub pending_review_count: u32,
    pub auto_handled_24h: u32,
}

impl AutopilotStateFileV1 {
    fn default_now(now_ms: i64) -> Self {
        Self {
            version: AUTOPILOT_STATE_VERSION_V1,
            mode: api::AutopilotMode::Manual,
            last_human_ack: now_ms,
            pending_review_count: 0,
            auto_handled_24h: 0,
        }
    }
}

fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn now_ms() -> i64 {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_millis(0))
        .as_millis();
    i64::try_from(ms).unwrap_or(0)
}

fn hash_hex(h: &Hash32) -> String {
    hex::encode(h.0)
}

fn bytes_hex(b: &[u8]) -> String {
    hex::encode(b)
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<u64>().ok())
}

fn days_to_ms(days: u64) -> Option<i64> {
    let ms = (days as u128).checked_mul(24 * 60 * 60 * 1000)?;
    i64::try_from(ms).ok()
}

fn normalize_retention_days(days: u64) -> anyhow::Result<u64> {
    if days == 0 {
        return Ok(0);
    }
    days_to_ms(days).ok_or_else(|| anyhow::anyhow!("decision_retention_days overflow"))?;
    Ok(days)
}

fn normalize_max_decisions(max: u64) -> anyhow::Result<u64> {
    if max == 0 {
        return Ok(0);
    }
    if max > (usize::MAX as u64) {
        return Err(anyhow::anyhow!("decision_max exceeds platform limit"));
    }
    Ok(max)
}

pub fn decision_id_v1(token: &DecisionToken) -> Hash32 {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(OPERATOR_DECISION_ID_DOMAIN_V1);
    bytes.extend_from_slice(&token.policy_hash.0);
    bytes.extend_from_slice(&token.state_hash.0);
    bytes.extend_from_slice(&token.chosen_action_hash.0);
    bytes.extend_from_slice(&token.nonce_or_tx_hash.0);
    bytes.extend_from_slice(&token.timestamp_ms.to_le_bytes());
    bytes.extend_from_slice(&token.signature);
    sha256(&bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorDecisionRecordV1 {
    pub record_version: u32,
    pub recorded_at_ms: i64,
    pub decision_id_hex: String,

    pub token: OperatorTokenV1,
    pub proof: OperatorProofV1,
    pub state: OperatorStateV1,
    pub candidates: Vec<OperatorCandidateV1>,

    pub summary: OperatorSummaryV1,
    pub execution: Option<OperatorExecutionV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorSummaryV1 {
    pub verdict: api::Verdict,
    pub proof_status: api::ProofStatus,
    pub execution_status: api::ExecutionStatus,
    pub latency_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorTokenV1 {
    pub policy_hash: String,
    pub policy_epoch: u64,
    pub registry_root: String,
    pub state_hash: String,
    pub state_source_id: String,
    pub state_epoch: u64,
    pub state_attestation_hash: String,
    pub chosen_action_hash: String,
    pub nonce_or_tx_hash: String,
    pub timestamp_ms: i64,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorProofV1 {
    pub policy_hash: String,
    pub state_hash: String,
    pub candidate_set_hash: String,
    pub chosen_action_hash: String,
    pub limits_hash: String,
    pub verified_at_ms: i64,
    pub receipt_size: u64,

    pub receipt_path: String,
    pub limits_bytes_path: String,
    pub chosen_action_preimage_path: String,

    pub attestation_metadata: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorStateV1 {
    pub state_hash: String,
    pub fields_json: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorCandidateV1 {
    pub index: u32,
    pub action_type: String,
    pub params_json: serde_json::Value,
    pub score: i64,
    pub candidate_hash: String,
    pub verdict: api::Verdict,
    pub selected: bool,
    pub reasons: Vec<String>,
    pub limits_json: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorExecutionV1 {
    pub success: bool,
    pub message: Option<String>,
    pub executor: String,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorProofStatusUpdateV1 {
    pub proof_status: api::ProofStatus,
    pub verified_at_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorExecutionUpdateV1 {
    pub success: bool,
    pub message: Option<String>,
    pub executor: String,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OperatorRetentionSettingsV1 {
    pub version: u32,
    pub decision_retention_days: u64,
    pub decision_max: u64,
}

#[derive(Clone)]
pub struct OperatorStore {
    root: PathBuf,
    cache: std::sync::Arc<RwLock<Cache>>,
    store_sensitive: bool,
    retention: std::sync::Arc<RwLock<OperatorRetentionSettingsV1>>,
    autopilot: std::sync::Arc<RwLock<AutopilotStateFileV1>>,
}

#[derive(Default)]
struct Cache {
    last_scan_ms: i64,
    summaries: Vec<api::DecisionSummary>,
}

impl OperatorStore {
    const MAX_LIMITS_BYTES: u64 = 4 * 1024;
    const MAX_CHOSEN_ACTION_PREIMAGE_BYTES: u64 =
        mprd_core::validation::MAX_CANDIDATE_PREIMAGE_BYTES_V1 as u64;

    fn read_bounded_file(path: &Path, max_payload_bytes: u64) -> anyhow::Result<Vec<u8>> {
        let max_total_bytes = max_payload_bytes.saturating_add(wire::MAX_HEADER_BYTES as u64);
        let meta =
            fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
        let len = meta.len();
        if len > max_total_bytes {
            anyhow::bail!(
                "refusing to read {} ({} bytes exceeds max {} bytes)",
                path.display(),
                len,
                max_total_bytes
            );
        }

        let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        if (bytes.len() as u64) > max_total_bytes {
            anyhow::bail!(
                "refusing to read {} ({} bytes exceeds max {} bytes)",
                path.display(),
                bytes.len(),
                max_total_bytes
            );
        }
        Ok(bytes)
    }

    fn retention_settings_path(root: &std::path::Path) -> PathBuf {
        root.join("settings.json")
    }

    fn load_retention_settings(
        root: &std::path::Path,
    ) -> anyhow::Result<Option<OperatorRetentionSettingsV1>> {
        let path = Self::retention_settings_path(root);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };
        let settings: OperatorRetentionSettingsV1 = match serde_json::from_slice(&bytes) {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };
        if settings.version != SETTINGS_VERSION_V1 {
            return Ok(None);
        }
        if normalize_retention_days(settings.decision_retention_days).is_err()
            || normalize_max_decisions(settings.decision_max).is_err()
        {
            return Ok(None);
        }
        Ok(Some(settings))
    }

    fn save_retention_settings(
        root: &std::path::Path,
        settings: &OperatorRetentionSettingsV1,
    ) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec_pretty(settings)?;
        atomic_write(&Self::retention_settings_path(root), &bytes)?;
        Ok(())
    }

    pub fn new(root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("decisions"))?;
        fs::create_dir_all(root.join("alerts"))?;
        fs::create_dir_all(root.join("incidents"))?;
        fs::create_dir_all(root.join("autopilot"))?;
        let store_sensitive = std::env::var("MPRD_OPERATOR_STORE_SENSITIVE")
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
            .is_some_and(|s| s == "1" || s == "true" || s == "yes");
        let retention_days = env_u64("MPRD_OPERATOR_DECISION_RETENTION_DAYS")
            .unwrap_or(DEFAULT_DECISION_RETENTION_DAYS);
        let max_decisions = env_u64("MPRD_OPERATOR_DECISION_MAX").unwrap_or(DEFAULT_MAX_DECISIONS);

        let retention =
            Self::load_retention_settings(&root)?.unwrap_or(OperatorRetentionSettingsV1 {
                version: SETTINGS_VERSION_V1,
                decision_retention_days: retention_days,
                decision_max: max_decisions,
            });
        let autopilot = Self::load_autopilot_state(&root)?
            .unwrap_or_else(|| AutopilotStateFileV1::default_now(now_ms()));
        Ok(Self {
            root,
            cache: std::sync::Arc::new(RwLock::new(Cache::default())),
            store_sensitive,
            retention: std::sync::Arc::new(RwLock::new(retention)),
            autopilot: std::sync::Arc::new(RwLock::new(autopilot)),
        })
    }

    fn autopilot_state_path(root: &std::path::Path) -> PathBuf {
        root.join("autopilot").join("state.json")
    }

    fn autopilot_actions_path(root: &std::path::Path) -> PathBuf {
        root.join("autopilot").join("actions.json")
    }

    fn load_autopilot_state(
        root: &std::path::Path,
    ) -> anyhow::Result<Option<AutopilotStateFileV1>> {
        let path = Self::autopilot_state_path(root);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let Ok(state) = serde_json::from_slice::<AutopilotStateFileV1>(&bytes) else {
            return Ok(None);
        };
        if state.version != AUTOPILOT_STATE_VERSION_V1 {
            return Ok(None);
        }
        Ok(Some(state))
    }

    fn save_autopilot_state(
        root: &std::path::Path,
        state: &AutopilotStateFileV1,
    ) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec_pretty(state)?;
        atomic_write(&Self::autopilot_state_path(root), &bytes)?;
        Ok(())
    }

    pub(crate) fn read_autopilot_state(&self) -> AutopilotStateFileV1 {
        self.autopilot
            .read()
            .map(|s| s.clone())
            .unwrap_or_else(|_| AutopilotStateFileV1::default_now(now_ms()))
    }

    pub(crate) fn set_autopilot_mode(
        &self,
        mode: api::AutopilotMode,
    ) -> anyhow::Result<AutopilotStateFileV1> {
        let mut state = self
            .autopilot
            .write()
            .map_err(|_| anyhow::anyhow!("autopilot state lock poisoned"))?;
        state.mode = mode;
        Self::save_autopilot_state(&self.root, &state)?;
        Ok(state.clone())
    }

    pub(crate) fn autopilot_ack(&self) -> anyhow::Result<AutopilotStateFileV1> {
        let mut state = self
            .autopilot
            .write()
            .map_err(|_| anyhow::anyhow!("autopilot state lock poisoned"))?;
        state.last_human_ack = now_ms();
        Self::save_autopilot_state(&self.root, &state)?;
        Ok(state.clone())
    }

    pub(crate) fn list_autopilot_actions(
        &self,
        limit: usize,
    ) -> anyhow::Result<Vec<api::AutoAction>> {
        let limit = limit.clamp(1, 200);
        let path = Self::autopilot_actions_path(&self.root);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut items: Vec<api::AutoAction> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => Vec::new(),
        };
        if items.len() > limit {
            items.truncate(limit);
        }
        Ok(items)
    }

    pub(crate) fn append_autopilot_action(&self, action: api::AutoAction) -> anyhow::Result<()> {
        let path = Self::autopilot_actions_path(&self.root);
        let mut items: Vec<api::AutoAction> = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        items.insert(0, action);
        if items.len() > 200 {
            items.truncate(200);
        }
        let bytes = serde_json::to_vec_pretty(&items)?;
        atomic_write(&path, &bytes)?;
        Ok(())
    }

    pub fn decision_dir(&self, decision_id_hex: &str) -> PathBuf {
        self.root.join("decisions").join(decision_id_hex)
    }

    pub fn store_sensitive_enabled(&self) -> bool {
        self.store_sensitive
    }

    pub fn decision_retention_days(&self) -> u64 {
        self.retention
            .read()
            .map(|r| r.decision_retention_days)
            .unwrap_or(0)
    }

    pub fn decision_max(&self) -> u64 {
        self.retention.read().map(|r| r.decision_max).unwrap_or(0)
    }

    pub fn decision_retention_ms(&self) -> Option<i64> {
        let days = self.decision_retention_days();
        if days == 0 {
            None
        } else {
            days_to_ms(days)
        }
    }

    pub fn max_decisions(&self) -> Option<usize> {
        let max = self.decision_max();
        if max == 0 {
            None
        } else {
            Some(max as usize)
        }
    }

    pub fn update_retention_settings(
        &self,
        decision_retention_days: Option<u64>,
        decision_max: Option<u64>,
    ) -> anyhow::Result<()> {
        let mut settings = self
            .retention
            .write()
            .map_err(|_| anyhow::anyhow!("retention settings lock poisoned"))?;

        if let Some(days) = decision_retention_days {
            settings.decision_retention_days = normalize_retention_days(days)?;
        }
        if let Some(max) = decision_max {
            settings.decision_max = normalize_max_decisions(max)?;
        }

        Self::save_retention_settings(&self.root, &settings)?;
        Ok(())
    }

    pub fn write_verified_decision(
        &self,
        token: &DecisionToken,
        proof: &ProofBundle,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
        verdicts: &[RuleVerdict],
        decision: &Decision,
    ) -> anyhow::Result<String> {
        let decision_id = decision_id_v1(token);
        let decision_id_hex = hash_hex(&decision_id);
        let dir = self.decision_dir(&decision_id_hex);
        fs::create_dir_all(&dir)?;

        let receipt_path = dir.join("receipt.bin");
        let limits_bytes_path = dir.join("limits.bin");
        let action_preimage_path = dir.join("chosen_action_preimage.bin");

        // Store receipts as MPRDPACK v1 (kind-tagged + integrity). Readers accept legacy bytes too.
        let receipt_bytes = wire::wrap_v1(WireKind::ZkReceiptBincode, 0, &proof.risc0_receipt);
        atomic_write(&receipt_path, &receipt_bytes)?;
        atomic_write(&limits_bytes_path, &proof.limits_bytes)?;
        if self.store_sensitive {
            atomic_write(&action_preimage_path, &proof.chosen_action_preimage)?;
        }

        let chosen_verdict = verdicts
            .get(decision.chosen_index)
            .map(|v| v.allowed)
            .unwrap_or(false);

        let summary = OperatorSummaryV1 {
            verdict: if chosen_verdict {
                api::Verdict::Allowed
            } else {
                api::Verdict::Denied
            },
            proof_status: api::ProofStatus::Verified,
            execution_status: api::ExecutionStatus::Skipped,
            latency_ms: 0,
        };

        let record = OperatorDecisionRecordV1 {
            record_version: 1,
            recorded_at_ms: now_ms(),
            decision_id_hex: decision_id_hex.clone(),
            summary,
            token: OperatorTokenV1 {
                policy_hash: hash_hex(&token.policy_hash),
                policy_epoch: token.policy_ref.policy_epoch,
                registry_root: hash_hex(&token.policy_ref.registry_root),
                state_hash: hash_hex(&token.state_hash),
                state_source_id: hash_hex(&token.state_ref.state_source_id),
                state_epoch: token.state_ref.state_epoch,
                state_attestation_hash: hash_hex(&token.state_ref.state_attestation_hash),
                chosen_action_hash: hash_hex(&token.chosen_action_hash),
                nonce_or_tx_hash: hash_hex(&token.nonce_or_tx_hash),
                timestamp_ms: token.timestamp_ms,
                signature_hex: bytes_hex(&token.signature),
            },
            proof: OperatorProofV1 {
                policy_hash: hash_hex(&proof.policy_hash),
                state_hash: hash_hex(&proof.state_hash),
                candidate_set_hash: hash_hex(&proof.candidate_set_hash),
                chosen_action_hash: hash_hex(&proof.chosen_action_hash),
                limits_hash: hash_hex(&proof.limits_hash),
                verified_at_ms: now_ms(),
                receipt_size: proof.risc0_receipt.len() as u64,
                receipt_path: receipt_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("receipt.bin")
                    .to_string(),
                limits_bytes_path: limits_bytes_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("limits.bin")
                    .to_string(),
                chosen_action_preimage_path: if self.store_sensitive {
                    action_preimage_path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("chosen_action_preimage.bin")
                        .to_string()
                } else {
                    String::new()
                },
                attestation_metadata: proof.attestation_metadata.clone(),
            },
            state: OperatorStateV1 {
                state_hash: hash_hex(&state.state_hash),
                fields_json: if self.store_sensitive {
                    serde_json::to_value(&state.fields)?
                } else {
                    serde_json::json!({ "_redacted": true })
                },
            },
            candidates: candidates
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    let v = verdicts.get(i).cloned().unwrap_or_else(|| RuleVerdict {
                        allowed: false,
                        reasons: vec!["missing verdict".into()],
                        limits: HashMap::new(),
                    });
                    OperatorCandidateV1 {
                        index: i as u32,
                        action_type: c.action_type.clone(),
                        params_json: if self.store_sensitive {
                            serde_json::to_value(&c.params).unwrap_or(serde_json::Value::Null)
                        } else {
                            serde_json::json!({ "_redacted": true })
                        },
                        score: c.score.0,
                        candidate_hash: hash_hex(&c.candidate_hash),
                        verdict: if v.allowed {
                            api::Verdict::Allowed
                        } else {
                            api::Verdict::Denied
                        },
                        selected: decision.chosen_index == i,
                        reasons: v.reasons,
                        limits_json: if self.store_sensitive {
                            serde_json::to_value(&v.limits).unwrap_or(serde_json::Value::Null)
                        } else {
                            serde_json::json!({ "_redacted": true })
                        },
                    }
                })
                .collect(),
            execution: None,
        };

        let record_json = serde_json::to_vec_pretty(&record)?;
        atomic_write(&dir.join("record.json"), &record_json)?;

        self.invalidate_cache();
        Ok(decision_id_hex)
    }

    fn proof_status_path(&self, decision_id_hex: &str) -> PathBuf {
        self.decision_dir(decision_id_hex).join("proof_status.json")
    }

    fn execution_path(&self, decision_id_hex: &str) -> PathBuf {
        self.decision_dir(decision_id_hex).join("execution.json")
    }

    pub fn write_proof_status(
        &self,
        decision_id_hex: &str,
        proof_status: api::ProofStatus,
        verified_at_ms: i64,
    ) -> anyhow::Result<()> {
        let update = OperatorProofStatusUpdateV1 {
            proof_status,
            verified_at_ms,
        };
        let bytes = serde_json::to_vec_pretty(&update)?;
        atomic_write(&self.proof_status_path(decision_id_hex), &bytes)?;
        self.invalidate_cache();
        Ok(())
    }

    pub fn write_execution_result(
        &self,
        decision_id_hex: &str,
        success: bool,
        message: Option<String>,
        executor: String,
        duration_ms: u64,
    ) -> anyhow::Result<()> {
        let update = OperatorExecutionUpdateV1 {
            success,
            message,
            executor,
            duration_ms,
        };
        let bytes = serde_json::to_vec_pretty(&update)?;
        atomic_write(&self.execution_path(decision_id_hex), &bytes)?;
        self.invalidate_cache();
        Ok(())
    }

    pub fn read_record(&self, decision_id_hex: &str) -> anyhow::Result<OperatorDecisionRecordV1> {
        let bytes = fs::read(self.decision_dir(decision_id_hex).join("record.json"))?;
        let mut record: OperatorDecisionRecordV1 = serde_json::from_slice(&bytes)?;
        self.apply_status_updates(decision_id_hex, &mut record);
        Ok(record)
    }

    fn apply_status_updates(&self, decision_id_hex: &str, record: &mut OperatorDecisionRecordV1) {
        if let Ok(bytes) = fs::read(self.proof_status_path(decision_id_hex)) {
            if let Ok(update) = serde_json::from_slice::<OperatorProofStatusUpdateV1>(&bytes) {
                record.summary.proof_status = update.proof_status;
                record.proof.verified_at_ms = update.verified_at_ms;
            }
        }

        if let Ok(bytes) = fs::read(self.execution_path(decision_id_hex)) {
            if let Ok(update) = serde_json::from_slice::<OperatorExecutionUpdateV1>(&bytes) {
                record.execution = Some(OperatorExecutionV1 {
                    success: update.success,
                    message: update.message,
                    executor: update.executor,
                    duration_ms: update.duration_ms,
                });
                record.summary.execution_status =
                    if record.execution.as_ref().is_some_and(|e| e.success) {
                        api::ExecutionStatus::Success
                    } else {
                        api::ExecutionStatus::Failed
                    };
            }
        }
    }

    pub fn list_summaries(
        &self,
        refresh_if_older_than: Duration,
    ) -> anyhow::Result<Vec<api::DecisionSummary>> {
        self.refresh_cache(refresh_if_older_than)?;
        Ok(self.cache.read().expect("lock poisoned").summaries.clone())
    }

    fn invalidate_cache(&self) {
        if let Ok(mut guard) = self.cache.write() {
            guard.last_scan_ms = 0;
        }
    }

    fn refresh_cache(&self, refresh_if_older_than: Duration) -> anyhow::Result<()> {
        let now = now_ms();
        {
            let guard = self.cache.read().expect("lock poisoned");
            if guard.last_scan_ms != 0
                && (now - guard.last_scan_ms) < refresh_if_older_than.as_millis() as i64
            {
                return Ok(());
            }
        }

        let decisions_dir = self.root.join("decisions");
        let mut summaries = Vec::new();
        for entry in fs::read_dir(&decisions_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let id = entry.file_name().to_string_lossy().to_string();
            let record = match self.read_record(&id) {
                Ok(r) => r,
                Err(_) => continue,
            };
            summaries.push(api::DecisionSummary {
                id: id.clone(),
                timestamp: record.token.timestamp_ms,
                policy_hash: record.token.policy_hash.clone(),
                action_type: record
                    .candidates
                    .iter()
                    .find(|c| c.selected)
                    .map(|c| c.action_type.clone())
                    .unwrap_or_else(|| "UNKNOWN".into()),
                verdict: record.summary.verdict.clone(),
                proof_status: record.summary.proof_status.clone(),
                execution_status: record.summary.execution_status.clone(),
                latency_ms: record.summary.latency_ms,
            });
        }
        summaries.sort_by_key(|s| std::cmp::Reverse(s.timestamp));

        let mut guard = self.cache.write().expect("lock poisoned");
        guard.last_scan_ms = now;
        guard.summaries = summaries;
        Ok(())
    }

    pub fn prune_decisions(&self) -> anyhow::Result<usize> {
        let retention_ms = self.decision_retention_ms();
        let max_decisions = self.max_decisions();
        if retention_ms.is_none() && max_decisions.is_none() {
            return Ok(0);
        }

        let decisions_dir = self.root.join("decisions");
        let mut entries: Vec<(String, i64)> = Vec::new();
        for entry in fs::read_dir(&decisions_dir)? {
            let entry = match entry {
                Ok(v) => v,
                Err(_) => continue,
            };
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let id = entry.file_name().to_string_lossy().to_string();
            let record_path = entry.path().join("record.json");
            let ts = match fs::read(&record_path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<OperatorDecisionRecordV1>(&bytes).ok())
            {
                Some(record) => record.token.timestamp_ms,
                None => record_path
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as i64)
                    .or_else(|| {
                        entry
                            .path()
                            .metadata()
                            .and_then(|m| m.modified())
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_millis() as i64)
                    })
                    .unwrap_or(0),
            };
            entries.push((id, ts));
        }

        if entries.is_empty() {
            return Ok(0);
        }

        entries.sort_by_key(|(_, ts)| std::cmp::Reverse(*ts));
        let now = now_ms();
        let cutoff = retention_ms.map(|ms| now - ms);

        let mut removed = 0usize;
        let mut keep: HashSet<String> = HashSet::new();
        let mut remove_ids: Vec<String> = Vec::new();
        for (idx, (id, ts)) in entries.iter().enumerate() {
            let too_old = cutoff.map(|c| *ts < c).unwrap_or(false);
            let over_max = max_decisions.map(|m| idx >= m).unwrap_or(false);
            if too_old || over_max {
                remove_ids.push(id.clone());
            } else {
                keep.insert(id.clone());
            }
        }

        for id in &remove_ids {
            let dir = self.decision_dir(id);
            if fs::remove_dir_all(&dir).is_ok() {
                removed += 1;
            }
        }

        if removed > 0 {
            self.invalidate_cache();
            let _ = self.prune_alert_acknowledgements(&keep);
        }
        let _ = self.prune_incident_snoozes();
        Ok(removed)
    }

    fn prune_alert_acknowledgements(&self, keep_decisions: &HashSet<String>) -> anyhow::Result<()> {
        let path = self.alert_ack_path();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(()),
        };
        let mut acks: HashMap<String, i64> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        let before = acks.len();
        acks.retain(|id, _| {
            let (prefix, decision_id) = match id.split_once(':') {
                Some(v) => v,
                None => return true,
            };
            match prefix {
                "verification_failure" | "execution_error" => keep_decisions.contains(decision_id),
                _ => true,
            }
        });
        if acks.len() != before {
            let bytes = serde_json::to_vec_pretty(&acks)?;
            atomic_write(&path, &bytes)?;
        }
        Ok(())
    }

    fn prune_incident_snoozes(&self) -> anyhow::Result<()> {
        let path = self.incident_snooze_path();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(()),
        };
        let mut snoozes: HashMap<String, i64> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        let before = snoozes.len();
        let now = now_ms();
        snoozes.retain(|_, until| *until > now);
        if snoozes.len() != before {
            let bytes = serde_json::to_vec_pretty(&snoozes)?;
            atomic_write(&path, &bytes)?;
        }
        Ok(())
    }

    pub fn blobs_for_proof(
        &self,
        decision_id_hex: &str,
        record: &OperatorDecisionRecordV1,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let dir = self.decision_dir(decision_id_hex);
        let receipt =
            Self::read_bounded_file(&dir.join(&record.proof.receipt_path), MAX_RECEIPT_BYTES)?;
        let limits = Self::read_bounded_file(
            &dir.join(&record.proof.limits_bytes_path),
            Self::MAX_LIMITS_BYTES,
        )?;
        if record.proof.chosen_action_preimage_path.trim().is_empty() {
            anyhow::bail!(
                "chosen_action_preimage is not stored (set MPRD_OPERATOR_STORE_SENSITIVE=1 to enable)"
            );
        }
        let preimage = Self::read_bounded_file(
            &dir.join(&record.proof.chosen_action_preimage_path),
            Self::MAX_CHOSEN_ACTION_PREIMAGE_BYTES,
        )?;
        Ok((receipt, limits, preimage))
    }

    fn alert_ack_path(&self) -> PathBuf {
        self.root.join("alerts").join("ack.json")
    }

    fn incident_snooze_path(&self) -> PathBuf {
        self.root.join("incidents").join("snooze.json")
    }

    pub fn snooze_incident(&self, incident_id: &str, snoozed_until_ms: i64) -> anyhow::Result<()> {
        let path = self.incident_snooze_path();
        let mut snoozes: HashMap<String, i64> = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => HashMap::new(),
        };
        snoozes.insert(incident_id.to_string(), snoozed_until_ms);
        let bytes = serde_json::to_vec_pretty(&snoozes)?;
        atomic_write(&path, &bytes)?;
        Ok(())
    }

    pub fn clear_incident_snooze(&self, incident_id: &str) -> anyhow::Result<()> {
        let path = self.incident_snooze_path();
        let mut snoozes: HashMap<String, i64> = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => HashMap::new(),
        };
        if snoozes.remove(incident_id).is_some() {
            let bytes = serde_json::to_vec_pretty(&snoozes)?;
            atomic_write(&path, &bytes)?;
        }
        Ok(())
    }

    pub fn incident_snoozed_until(&self, incident_id: &str) -> Option<i64> {
        let path = self.incident_snooze_path();
        let Ok(bytes) = fs::read(&path) else {
            return None;
        };
        let Ok(snoozes) = serde_json::from_slice::<HashMap<String, i64>>(&bytes) else {
            return None;
        };
        snoozes.get(incident_id).copied()
    }

    pub fn acknowledge_alert(&self, id: &str) -> anyhow::Result<()> {
        let path = self.alert_ack_path();
        let mut acks: HashMap<String, i64> = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => HashMap::new(),
        };
        acks.insert(id.to_string(), now_ms());
        let bytes = serde_json::to_vec_pretty(&acks)?;
        atomic_write(&path, &bytes)?;
        Ok(())
    }

    pub fn is_alert_acknowledged(&self, id: &str) -> bool {
        let path = self.alert_ack_path();
        let Ok(bytes) = fs::read(&path) else {
            return false;
        };
        let Ok(acks) = serde_json::from_slice::<HashMap<String, i64>>(&bytes) else {
            return false;
        };
        acks.contains_key(id)
    }
}

#[cfg(test)]
mod tests {
    use super::OperatorStore;
    use crate::operator::api as op_api;
    use mprd_core::{
        CandidateAction, Decision, DecisionToken, Hash32, PolicyRef, ProofBundle, RuleVerdict,
        Score, StateRef, StateSnapshot,
    };
    use proptest::prelude::*;
    use std::collections::HashMap;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::TempDir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        prev: Vec<(&'static str, Option<String>)>,
        _lock: MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn set_many(vars: &[(&'static str, &str)]) -> Self {
            let lock = ENV_LOCK.lock().expect("env lock");
            let mut prev = Vec::with_capacity(vars.len());
            for (key, value) in vars {
                prev.push((*key, std::env::var(key).ok()));
                std::env::set_var(key, value);
            }
            Self { prev, _lock: lock }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, prev) in self.prev.drain(..) {
                if let Some(prev) = prev {
                    std::env::set_var(key, prev);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }

    #[test]
    fn incident_snooze_roundtrips_and_clears() {
        let tmp = TempDir::new().expect("tempdir");
        let store = OperatorStore::new(tmp.path()).expect("store");

        store.snooze_incident("inc_1", 123).expect("snooze");
        assert_eq!(store.incident_snoozed_until("inc_1"), Some(123));

        store.clear_incident_snooze("inc_1").expect("clear");
        assert_eq!(store.incident_snoozed_until("inc_1"), None);
    }

    #[test]
    fn incident_snooze_recovers_from_corrupt_json() {
        let tmp = TempDir::new().expect("tempdir");
        let store = OperatorStore::new(tmp.path()).expect("store");

        let path = tmp.path().join("incidents").join("snooze.json");
        std::fs::write(&path, b"not-json").expect("write corrupt");

        store.snooze_incident("inc_2", 999).expect("snooze");
        assert_eq!(store.incident_snoozed_until("inc_2"), Some(999));
    }

    #[test]
    fn clearing_snooze_is_idempotent_and_preserves_others() {
        let tmp = TempDir::new().expect("tempdir");
        let store = OperatorStore::new(tmp.path()).expect("store");

        store.snooze_incident("inc_a", 1).expect("snooze");
        store.snooze_incident("inc_b", 2).expect("snooze");

        store.clear_incident_snooze("inc_a").expect("clear");
        store.clear_incident_snooze("inc_a").expect("clear again");

        assert_eq!(store.incident_snoozed_until("inc_a"), None);
        assert_eq!(store.incident_snoozed_until("inc_b"), Some(2));
    }

    #[test]
    fn retention_settings_persist_and_reload() {
        let _g = EnvGuard::set_many(&[
            ("MPRD_OPERATOR_DECISION_RETENTION_DAYS", "1"),
            ("MPRD_OPERATOR_DECISION_MAX", "10"),
        ]);

        let tmp = TempDir::new().expect("tempdir");
        let store = OperatorStore::new(tmp.path()).expect("store");
        store
            .update_retention_settings(Some(7), Some(77))
            .expect("update");

        drop(store);
        std::env::set_var("MPRD_OPERATOR_DECISION_RETENTION_DAYS", "30");
        std::env::set_var("MPRD_OPERATOR_DECISION_MAX", "1000");

        let store2 = OperatorStore::new(tmp.path()).expect("store2");
        assert_eq!(store2.decision_retention_days(), 7);
        assert_eq!(store2.decision_max(), 77);
    }

    #[test]
    fn autopilot_state_persists_and_recovers_from_corrupt_json() {
        let tmp = TempDir::new().expect("tempdir");
        let store = OperatorStore::new(tmp.path()).expect("store");

        let s1 = store
            .set_autopilot_mode(op_api::AutopilotMode::Assisted)
            .expect("set mode");
        assert!(matches!(s1.mode, op_api::AutopilotMode::Assisted));

        drop(store);
        let store2 = OperatorStore::new(tmp.path()).expect("store2");
        let s2 = store2.read_autopilot_state();
        assert!(matches!(s2.mode, op_api::AutopilotMode::Assisted));

        let path = tmp.path().join("autopilot").join("state.json");
        std::fs::write(&path, b"not-json").expect("write corrupt");

        drop(store2);
        let store3 = OperatorStore::new(tmp.path()).expect("store3");
        let s3 = store3.read_autopilot_state();
        assert!(matches!(s3.mode, op_api::AutopilotMode::Manual));
        assert!(s3.last_human_ack > 0);
    }

    #[test]
    fn autopilot_actions_append_and_list_is_bounded_and_ordered() {
        let tmp = TempDir::new().expect("tempdir");
        let store = OperatorStore::new(tmp.path()).expect("store");

        let mk_action = |id: &str, ts: i64| op_api::AutoAction {
            id: id.to_string(),
            action_type: op_api::AutoActionType::AutoDismiss,
            target: "x".into(),
            timestamp: ts,
            reversible: false,
            explanation: op_api::Explanation {
                summary: "s".into(),
                evidence: "e".into(),
                confidence: 1.0,
                counterfactual: "c".into(),
                audit_id: format!("audit_{id}"),
                timestamp: ts,
                operator_can_override: false,
            },
        };

        store
            .append_autopilot_action(mk_action("a1", 10))
            .expect("append 1");
        store
            .append_autopilot_action(mk_action("a2", 20))
            .expect("append 2");

        let items = store.list_autopilot_actions(10).expect("list");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].id, "a2");
        assert_eq!(items[1].id, "a1");

        let items = store.list_autopilot_actions(1).expect("list 1");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "a2");
    }

    #[test]
    fn prune_decisions_removes_old_and_cleans_metadata() {
        let _g = EnvGuard::set_many(&[
            ("MPRD_OPERATOR_DECISION_RETENTION_DAYS", "1"),
            ("MPRD_OPERATOR_DECISION_MAX", "100"),
        ]);

        let tmp = TempDir::new().expect("tempdir");
        let store = OperatorStore::new(tmp.path()).expect("store");
        store
            .update_retention_settings(Some(1), Some(100))
            .expect("update retention");

        let policy_hash = Hash32([1u8; 32]);
        let state_hash = Hash32([2u8; 32]);
        let now = super::now_ms();
        let old_ts = now - (2 * 24 * 60 * 60 * 1000);

        let candidate = CandidateAction {
            action_type: "X".into(),
            params: HashMap::new(),
            score: Score(0),
            candidate_hash: Hash32([3u8; 32]),
        };
        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate.clone(),
            policy_hash: policy_hash.clone(),
            decision_commitment: Hash32([4u8; 32]),
        };
        let verdicts = vec![RuleVerdict {
            allowed: true,
            reasons: vec![],
            limits: HashMap::new(),
        }];
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: state_hash.clone(),
            state_ref: StateRef::unknown(),
        };
        let proof = ProofBundle {
            policy_hash: policy_hash.clone(),
            state_hash: state_hash.clone(),
            candidate_set_hash: Hash32([5u8; 32]),
            chosen_action_hash: Hash32([6u8; 32]),
            limits_hash: Hash32([7u8; 32]),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![],
            attestation_metadata: HashMap::new(),
        };

        let old_token = DecisionToken {
            policy_hash: policy_hash.clone(),
            policy_ref: PolicyRef {
                policy_epoch: 1,
                registry_root: Hash32([9u8; 32]),
            },
            state_hash: state_hash.clone(),
            state_ref: StateRef::unknown(),
            chosen_action_hash: Hash32([6u8; 32]),
            nonce_or_tx_hash: Hash32([10u8; 32]),
            timestamp_ms: old_ts,
            signature: vec![1, 2, 3],
        };

        let new_token = DecisionToken {
            policy_hash: policy_hash.clone(),
            policy_ref: PolicyRef {
                policy_epoch: 1,
                registry_root: Hash32([9u8; 32]),
            },
            state_hash: state_hash.clone(),
            state_ref: StateRef::unknown(),
            chosen_action_hash: Hash32([6u8; 32]),
            nonce_or_tx_hash: Hash32([11u8; 32]),
            timestamp_ms: now,
            signature: vec![4, 5, 6],
        };

        let old_id = store
            .write_verified_decision(
                &old_token,
                &proof,
                &state,
                &[candidate.clone()],
                &verdicts,
                &decision,
            )
            .expect("old decision");
        let new_id = store
            .write_verified_decision(
                &new_token,
                &proof,
                &state,
                &[candidate],
                &verdicts,
                &decision,
            )
            .expect("new decision");

        let old_alert = format!("verification_failure:{old_id}");
        let new_alert = format!("verification_failure:{new_id}");
        store.acknowledge_alert(&old_alert).expect("ack");
        store.acknowledge_alert(&new_alert).expect("ack");
        store.snooze_incident("inc_old", now - 1).expect("snooze");

        let removed = store.prune_decisions().expect("prune");
        assert!(removed >= 1);
        assert!(!store.decision_dir(&old_id).exists());
        assert!(store.decision_dir(&new_id).exists());
        assert!(!store.is_alert_acknowledged(&old_alert));
        assert!(store.is_alert_acknowledged(&new_alert));
        assert_eq!(store.incident_snoozed_until("inc_old"), None);
    }

    #[test]
    fn blobs_for_proof_are_bounded_and_receipt_is_enveloped() {
        let _g = EnvGuard::set_many(&[("MPRD_OPERATOR_STORE_SENSITIVE", "1")]);

        let tmp = TempDir::new().expect("tempdir");
        let store = OperatorStore::new(tmp.path()).expect("store");

        let policy_hash = Hash32([1u8; 32]);
        let state_hash = Hash32([2u8; 32]);

        let candidate = CandidateAction {
            action_type: "X".into(),
            params: HashMap::new(),
            score: Score(1),
            candidate_hash: Hash32([3u8; 32]),
        };
        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate.clone(),
            policy_hash: policy_hash.clone(),
            decision_commitment: Hash32([4u8; 32]),
        };
        let verdicts = vec![RuleVerdict {
            allowed: true,
            reasons: vec![],
            limits: HashMap::new(),
        }];
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: state_hash.clone(),
            state_ref: StateRef::unknown(),
        };
        let proof = ProofBundle {
            policy_hash: policy_hash.clone(),
            state_hash: state_hash.clone(),
            candidate_set_hash: Hash32([5u8; 32]),
            chosen_action_hash: Hash32([6u8; 32]),
            limits_hash: Hash32([7u8; 32]),
            limits_bytes: vec![1, 2, 3],
            chosen_action_preimage: vec![9, 9, 9],
            risc0_receipt: vec![8, 8, 8],
            attestation_metadata: HashMap::new(),
        };

        let token = DecisionToken {
            policy_hash: policy_hash.clone(),
            policy_ref: PolicyRef {
                policy_epoch: 1,
                registry_root: Hash32([9u8; 32]),
            },
            state_hash: state_hash.clone(),
            state_ref: StateRef::unknown(),
            chosen_action_hash: Hash32([6u8; 32]),
            nonce_or_tx_hash: Hash32([10u8; 32]),
            timestamp_ms: super::now_ms(),
            signature: vec![1, 2, 3],
        };

        let id = store
            .write_verified_decision(&token, &proof, &state, &[candidate], &verdicts, &decision)
            .expect("write decision");
        let record = store.read_record(&id).expect("read record");

        let (receipt, limits, preimage) = store.blobs_for_proof(&id, &record).expect("blobs");
        assert!(receipt.starts_with(&mprd_core::wire::MAGIC));
        assert_eq!(limits, proof.limits_bytes);
        assert_eq!(preimage, proof.chosen_action_preimage);
    }

    #[test]
    fn blobs_for_proof_rejects_oversized_limits_file() {
        let _g = EnvGuard::set_many(&[("MPRD_OPERATOR_STORE_SENSITIVE", "1")]);

        let tmp = TempDir::new().expect("tempdir");
        let store = OperatorStore::new(tmp.path()).expect("store");

        let policy_hash = Hash32([1u8; 32]);
        let state_hash = Hash32([2u8; 32]);

        let candidate = CandidateAction {
            action_type: "X".into(),
            params: HashMap::new(),
            score: Score(1),
            candidate_hash: Hash32([3u8; 32]),
        };
        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate.clone(),
            policy_hash: policy_hash.clone(),
            decision_commitment: Hash32([4u8; 32]),
        };
        let verdicts = vec![RuleVerdict {
            allowed: true,
            reasons: vec![],
            limits: HashMap::new(),
        }];
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: state_hash.clone(),
            state_ref: StateRef::unknown(),
        };
        let proof = ProofBundle {
            policy_hash: policy_hash.clone(),
            state_hash: state_hash.clone(),
            candidate_set_hash: Hash32([5u8; 32]),
            chosen_action_hash: Hash32([6u8; 32]),
            limits_hash: Hash32([7u8; 32]),
            limits_bytes: vec![1, 2, 3],
            chosen_action_preimage: vec![9, 9, 9],
            risc0_receipt: vec![8, 8, 8],
            attestation_metadata: HashMap::new(),
        };

        let token = DecisionToken {
            policy_hash: policy_hash.clone(),
            policy_ref: PolicyRef {
                policy_epoch: 1,
                registry_root: Hash32([9u8; 32]),
            },
            state_hash: state_hash.clone(),
            state_ref: StateRef::unknown(),
            chosen_action_hash: Hash32([6u8; 32]),
            nonce_or_tx_hash: Hash32([10u8; 32]),
            timestamp_ms: super::now_ms(),
            signature: vec![1, 2, 3],
        };

        let id = store
            .write_verified_decision(&token, &proof, &state, &[candidate], &verdicts, &decision)
            .expect("write decision");
        let record = store.read_record(&id).expect("read record");

        let limits_path = store
            .decision_dir(&id)
            .join(&record.proof.limits_bytes_path);
        let max_total = OperatorStore::MAX_LIMITS_BYTES + mprd_core::wire::MAX_HEADER_BYTES as u64;
        let f = std::fs::File::create(&limits_path).expect("create limits");
        f.set_len(max_total + 1).expect("set_len oversize");

        let err = store
            .blobs_for_proof(&id, &record)
            .expect_err("should reject oversized limits");
        assert!(err.to_string().contains("refusing to read"));
    }

    #[test]
    fn blobs_for_proof_rejects_oversized_preimage_file() {
        let _g = EnvGuard::set_many(&[("MPRD_OPERATOR_STORE_SENSITIVE", "1")]);

        let tmp = TempDir::new().expect("tempdir");
        let store = OperatorStore::new(tmp.path()).expect("store");

        let policy_hash = Hash32([1u8; 32]);
        let state_hash = Hash32([2u8; 32]);

        let candidate = CandidateAction {
            action_type: "X".into(),
            params: HashMap::new(),
            score: Score(1),
            candidate_hash: Hash32([3u8; 32]),
        };
        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate.clone(),
            policy_hash: policy_hash.clone(),
            decision_commitment: Hash32([4u8; 32]),
        };
        let verdicts = vec![RuleVerdict {
            allowed: true,
            reasons: vec![],
            limits: HashMap::new(),
        }];
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: state_hash.clone(),
            state_ref: StateRef::unknown(),
        };
        let proof = ProofBundle {
            policy_hash: policy_hash.clone(),
            state_hash: state_hash.clone(),
            candidate_set_hash: Hash32([5u8; 32]),
            chosen_action_hash: Hash32([6u8; 32]),
            limits_hash: Hash32([7u8; 32]),
            limits_bytes: vec![1, 2, 3],
            chosen_action_preimage: vec![9, 9, 9],
            risc0_receipt: vec![8, 8, 8],
            attestation_metadata: HashMap::new(),
        };

        let token = DecisionToken {
            policy_hash: policy_hash.clone(),
            policy_ref: PolicyRef {
                policy_epoch: 1,
                registry_root: Hash32([9u8; 32]),
            },
            state_hash: state_hash.clone(),
            state_ref: StateRef::unknown(),
            chosen_action_hash: Hash32([6u8; 32]),
            nonce_or_tx_hash: Hash32([10u8; 32]),
            timestamp_ms: super::now_ms(),
            signature: vec![1, 2, 3],
        };

        let id = store
            .write_verified_decision(&token, &proof, &state, &[candidate], &verdicts, &decision)
            .expect("write decision");
        let record = store.read_record(&id).expect("read record");

        let preimage_path = store
            .decision_dir(&id)
            .join(&record.proof.chosen_action_preimage_path);
        let max_total = OperatorStore::MAX_CHOSEN_ACTION_PREIMAGE_BYTES
            + mprd_core::wire::MAX_HEADER_BYTES as u64;
        let f = std::fs::File::create(&preimage_path).expect("create preimage");
        f.set_len(max_total + 1).expect("set_len oversize");

        let err = store
            .blobs_for_proof(&id, &record)
            .expect_err("should reject oversized preimage");
        assert!(err.to_string().contains("refusing to read"));
    }

    #[test]
    fn blobs_for_proof_rejects_oversized_receipt_file() {
        let _g = EnvGuard::set_many(&[("MPRD_OPERATOR_STORE_SENSITIVE", "1")]);

        let tmp = TempDir::new().expect("tempdir");
        let store = OperatorStore::new(tmp.path()).expect("store");

        let policy_hash = Hash32([1u8; 32]);
        let state_hash = Hash32([2u8; 32]);

        let candidate = CandidateAction {
            action_type: "X".into(),
            params: HashMap::new(),
            score: Score(1),
            candidate_hash: Hash32([3u8; 32]),
        };
        let decision = Decision {
            chosen_index: 0,
            chosen_action: candidate.clone(),
            policy_hash: policy_hash.clone(),
            decision_commitment: Hash32([4u8; 32]),
        };
        let verdicts = vec![RuleVerdict {
            allowed: true,
            reasons: vec![],
            limits: HashMap::new(),
        }];
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: state_hash.clone(),
            state_ref: StateRef::unknown(),
        };
        let proof = ProofBundle {
            policy_hash: policy_hash.clone(),
            state_hash: state_hash.clone(),
            candidate_set_hash: Hash32([5u8; 32]),
            chosen_action_hash: Hash32([6u8; 32]),
            limits_hash: Hash32([7u8; 32]),
            limits_bytes: vec![1, 2, 3],
            chosen_action_preimage: vec![9, 9, 9],
            risc0_receipt: vec![8, 8, 8],
            attestation_metadata: HashMap::new(),
        };

        let token = DecisionToken {
            policy_hash: policy_hash.clone(),
            policy_ref: PolicyRef {
                policy_epoch: 1,
                registry_root: Hash32([9u8; 32]),
            },
            state_hash: state_hash.clone(),
            state_ref: StateRef::unknown(),
            chosen_action_hash: Hash32([6u8; 32]),
            nonce_or_tx_hash: Hash32([10u8; 32]),
            timestamp_ms: super::now_ms(),
            signature: vec![1, 2, 3],
        };

        let id = store
            .write_verified_decision(&token, &proof, &state, &[candidate], &verdicts, &decision)
            .expect("write decision");
        let record = store.read_record(&id).expect("read record");

        let receipt_path = store.decision_dir(&id).join(&record.proof.receipt_path);
        let max_total =
            mprd_zk::bounded_deser::MAX_RECEIPT_BYTES + mprd_core::wire::MAX_HEADER_BYTES as u64;
        let f = std::fs::File::create(&receipt_path).expect("create receipt");
        f.set_len(max_total + 1).expect("set_len oversize");

        let err = store
            .blobs_for_proof(&id, &record)
            .expect_err("should reject oversized receipt");
        assert!(err.to_string().contains("refusing to read"));
    }

    #[derive(Debug, Clone, Copy)]
    enum OpKind {
        Snooze,
        ClearSnooze,
        AckAlert,
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            max_shrink_iters: 10_000,
            .. ProptestConfig::default()
        })]

        /// Stateful/model-based test for OperatorStore incident snoozes + alert acknowledgements.
        ///
        /// Contract:
        /// - `snooze_incident(id, until)` sets `incident_snoozed_until(id) == Some(until)`.
        /// - `clear_incident_snooze(id)` makes `incident_snoozed_until(id) == None` and is idempotent.
        /// - `acknowledge_alert(id)` makes `is_alert_acknowledged(id) == true` and is idempotent.
        #[test]
        fn operator_store_stateful_snooze_and_ack_model_test(
            ops in proptest::collection::vec(
                (
                    prop_oneof![Just(OpKind::Snooze), Just(OpKind::ClearSnooze), Just(OpKind::AckAlert)],
                    0usize..8usize,
                    0i64..(14i64 * 24 * 60 * 60 * 1000),
                ),
                1..50
            )
        ) {
            let tmp = TempDir::new().expect("tempdir");
            let store = OperatorStore::new(tmp.path()).expect("store");

            let incident_ids: [&str; 8] = ["inc0","inc1","inc2","inc3","inc4","inc5","inc6","inc7"];
            let alert_ids: [&str; 8] = ["a0","a1","a2","a3","a4","a5","a6","a7"];

            // Reference model
            let mut model_snoozes: HashMap<String, i64> = HashMap::new();
            let mut model_acks: std::collections::HashSet<String> = std::collections::HashSet::new();

            for (op, idx, val) in ops {
                let incident_id = incident_ids[idx % incident_ids.len()];
                let alert_id = alert_ids[idx % alert_ids.len()];

                match op {
                    OpKind::Snooze => {
                        store.snooze_incident(incident_id, val).expect("snooze");
                        model_snoozes.insert(incident_id.to_string(), val);
                    }
                    OpKind::ClearSnooze => {
                        store.clear_incident_snooze(incident_id).expect("clear");
                        model_snoozes.remove(incident_id);
                    }
                    OpKind::AckAlert => {
                        store.acknowledge_alert(alert_id).expect("ack");
                        model_acks.insert(alert_id.to_string());
                    }
                }

                // After every step, verify SUT matches model for all tracked IDs.
                for id in incident_ids {
                    let got = store.incident_snoozed_until(id);
                    let want = model_snoozes.get(id).copied();
                    prop_assert_eq!(got, want, "incident snooze mismatch for {}", id);
                }

                for id in alert_ids {
                    let got = store.is_alert_acknowledged(id);
                    let want = model_acks.contains(id);
                    prop_assert_eq!(got, want, "alert ack mismatch for {}", id);
                }
            }
        }
    }
}
