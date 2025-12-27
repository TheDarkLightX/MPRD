//! Proof publication / transparency log (pre-testnet, off-chain first).
//!
//! This module provides a minimal append-only decision log for publishing proofs and token
//! bindings. It is intended as a low-friction "Option A" publication strategy:
//! - append-only JSONL file,
//! - hash-chained records (anti-equivocation within the log),
//! - deterministic record hash domain separation.
//!
//! Later (Option B), the log head hash can be anchored on Tau Net or another chain without
//! changing the record hash format.

use crate::crypto::sha256;
use crate::orchestrator::DecisionRecorder;
use crate::{DecisionToken, Hash32, MprdError, ProofBundle, Result};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DECISION_LOG_RECORD_DOMAIN_V1: &[u8] = b"MPRD_DECISION_LOG_RECORD_V1";
pub const DECISION_LOG_RECORD_DOMAIN_V2: &[u8] = b"MPRD_DECISION_LOG_RECORD_V2";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionLogRecordV1 {
    pub record_version: u32,
    pub published_at_ms: i64,
    pub prev_record_hash: Hash32,
    pub record_hash: Hash32,

    pub policy_hash: Hash32,
    pub policy_epoch: u64,
    pub registry_root: Hash32,

    pub state_hash: Hash32,
    pub state_source_id: Hash32,
    pub state_epoch: u64,
    pub state_attestation_hash: Hash32,

    pub chosen_action_hash: Hash32,
    pub nonce_or_tx_hash: Hash32,

    pub limits_hash: Hash32,
    pub limits_bytes_hash: Hash32,
    pub chosen_action_preimage_hash: Hash32,
    pub risc0_receipt_hash: Hash32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionLogRecordV2 {
    pub record_version: u32,
    pub published_at_ms: i64,
    pub prev_record_hash: Hash32,
    pub record_hash: Hash32,

    pub policy_hash: Hash32,
    pub policy_epoch: u64,
    pub registry_root: Hash32,

    pub state_hash: Hash32,
    pub state_source_id: Hash32,
    pub state_epoch: u64,
    pub state_attestation_hash: Hash32,

    pub chosen_action_hash: Hash32,
    pub nonce_or_tx_hash: Hash32,

    pub limits_hash: Hash32,
    pub limits_bytes_hash: Hash32,
    pub chosen_action_preimage_hash: Hash32,
    pub risc0_receipt_hash: Hash32,
}

fn now_ms() -> Result<i64> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| MprdError::ExecutionError("system clock error".into()))?
        .as_millis();
    i64::try_from(ms).map_err(|_| MprdError::ExecutionError("system clock overflow".into()))
}

pub fn record_hash_v1(
    prev_record_hash: &Hash32,
    published_at_ms: i64,
    token: &DecisionToken,
    proof: &ProofBundle,
) -> Hash32 {
    let limits_bytes_hash = sha256(&proof.limits_bytes);
    let chosen_action_preimage_hash = sha256(&proof.chosen_action_preimage);
    let risc0_receipt_hash = sha256(&proof.risc0_receipt);

    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(DECISION_LOG_RECORD_DOMAIN_V1);
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&published_at_ms.to_le_bytes());
    bytes.extend_from_slice(&prev_record_hash.0);

    bytes.extend_from_slice(&token.policy_hash.0);
    bytes.extend_from_slice(&token.policy_ref.policy_epoch.to_le_bytes());
    bytes.extend_from_slice(&token.policy_ref.registry_root.0);
    bytes.extend_from_slice(&token.state_hash.0);
    bytes.extend_from_slice(&token.state_ref.state_source_id.0);
    bytes.extend_from_slice(&token.state_ref.state_epoch.to_le_bytes());
    bytes.extend_from_slice(&token.state_ref.state_attestation_hash.0);
    bytes.extend_from_slice(&token.chosen_action_hash.0);
    bytes.extend_from_slice(&token.nonce_or_tx_hash.0);

    bytes.extend_from_slice(&proof.limits_hash.0);
    bytes.extend_from_slice(&limits_bytes_hash.0);
    bytes.extend_from_slice(&chosen_action_preimage_hash.0);
    bytes.extend_from_slice(&risc0_receipt_hash.0);

    sha256(&bytes)
}

fn record_hash_v2_fields(
    prev_record_hash: &Hash32,
    published_at_ms: i64,
    token: &DecisionToken,
    limits_hash: &Hash32,
    limits_bytes_hash: &Hash32,
    chosen_action_preimage_hash: &Hash32,
    risc0_receipt_hash: &Hash32,
) -> Hash32 {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(DECISION_LOG_RECORD_DOMAIN_V2);
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&published_at_ms.to_le_bytes());
    bytes.extend_from_slice(&prev_record_hash.0);

    bytes.extend_from_slice(&token.policy_hash.0);
    bytes.extend_from_slice(&token.policy_ref.policy_epoch.to_le_bytes());
    bytes.extend_from_slice(&token.policy_ref.registry_root.0);
    bytes.extend_from_slice(&token.state_hash.0);
    bytes.extend_from_slice(&token.state_ref.state_source_id.0);
    bytes.extend_from_slice(&token.state_ref.state_epoch.to_le_bytes());
    bytes.extend_from_slice(&token.state_ref.state_attestation_hash.0);
    bytes.extend_from_slice(&token.chosen_action_hash.0);
    bytes.extend_from_slice(&token.nonce_or_tx_hash.0);

    bytes.extend_from_slice(&limits_hash.0);
    bytes.extend_from_slice(&limits_bytes_hash.0);
    bytes.extend_from_slice(&chosen_action_preimage_hash.0);
    bytes.extend_from_slice(&risc0_receipt_hash.0);

    sha256(&bytes)
}

pub fn record_hash_v2(
    prev_record_hash: &Hash32,
    published_at_ms: i64,
    token: &DecisionToken,
    proof: &ProofBundle,
) -> Hash32 {
    let limits_bytes_hash = sha256(&proof.limits_bytes);
    let chosen_action_preimage_hash = sha256(&proof.chosen_action_preimage);
    let risc0_receipt_hash = sha256(&proof.risc0_receipt);

    record_hash_v2_fields(
        prev_record_hash,
        published_at_ms,
        token,
        &proof.limits_hash,
        &limits_bytes_hash,
        &chosen_action_preimage_hash,
        &risc0_receipt_hash,
    )
}

pub fn record_hash_v2_from_record(record: &DecisionLogRecordV2) -> Hash32 {
    let token = DecisionToken {
        policy_hash: record.policy_hash,
        policy_ref: crate::PolicyRef {
            policy_epoch: record.policy_epoch,
            registry_root: record.registry_root,
        },
        state_hash: record.state_hash,
        state_ref: crate::StateRef {
            state_source_id: record.state_source_id,
            state_epoch: record.state_epoch,
            state_attestation_hash: record.state_attestation_hash,
        },
        chosen_action_hash: record.chosen_action_hash,
        nonce_or_tx_hash: record.nonce_or_tx_hash,
        timestamp_ms: 0,
        signature: Vec::new(),
    };

    record_hash_v2_fields(
        &record.prev_record_hash,
        record.published_at_ms,
        &token,
        &record.limits_hash,
        &record.limits_bytes_hash,
        &record.chosen_action_preimage_hash,
        &record.risc0_receipt_hash,
    )
}

/// Append-only file recorder for decision publication.
///
/// Each line is one JSON-encoded `DecisionLogRecordV1`.
pub struct FileDecisionRecorder {
    path: PathBuf,
    /// Best-effort per-process serialization of writes.
    lock: Mutex<()>,
    /// Hash of last record appended by this process (genesis is zero).
    last_hash: Mutex<Hash32>,
}

impl FileDecisionRecorder {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
            last_hash: Mutex::new(Hash32([0u8; 32])),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn last_record_hash(&self) -> Hash32 {
        self.last_hash.lock().expect("lock poisoned").clone()
    }
}

impl DecisionRecorder for FileDecisionRecorder {
    fn record(&self, token: &DecisionToken, proof: &ProofBundle) -> Result<()> {
        let _guard = self.lock.lock().expect("lock poisoned");
        let published_at_ms = now_ms()?;
        let prev_hash = self.last_hash.lock().expect("lock poisoned").clone();
        let record_hash = record_hash_v2(&prev_hash, published_at_ms, token, proof);

        let record = DecisionLogRecordV2 {
            record_version: 2,
            published_at_ms,
            prev_record_hash: prev_hash,
            record_hash: record_hash.clone(),

            policy_hash: token.policy_hash.clone(),
            policy_epoch: token.policy_ref.policy_epoch,
            registry_root: token.policy_ref.registry_root.clone(),

            state_hash: token.state_hash.clone(),
            state_source_id: token.state_ref.state_source_id.clone(),
            state_epoch: token.state_ref.state_epoch,
            state_attestation_hash: token.state_ref.state_attestation_hash.clone(),

            chosen_action_hash: token.chosen_action_hash.clone(),
            nonce_or_tx_hash: token.nonce_or_tx_hash.clone(),

            limits_hash: proof.limits_hash.clone(),
            limits_bytes_hash: sha256(&proof.limits_bytes),
            chosen_action_preimage_hash: sha256(&proof.chosen_action_preimage),
            risc0_receipt_hash: sha256(&proof.risc0_receipt),
        };

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| MprdError::ExecutionError(format!("failed to open decision log: {e}")))?;

        let line = serde_json::to_vec(&record).map_err(|e| {
            MprdError::ExecutionError(format!("failed to serialize decision log record: {e}"))
        })?;
        file.write_all(&line).map_err(|e| {
            MprdError::ExecutionError(format!("failed to write decision log record: {e}"))
        })?;
        file.write_all(b"\n").map_err(|e| {
            MprdError::ExecutionError(format!("failed to write decision log newline: {e}"))
        })?;
        file.sync_all()
            .map_err(|e| MprdError::ExecutionError(format!("failed to sync decision log: {e}")))?;

        *self.last_hash.lock().expect("lock poisoned") = record_hash;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum DecisionLogRecord {
    V1(DecisionLogRecordV1),
    V2(DecisionLogRecordV2),
}

impl DecisionLogRecord {
    fn prev_hash(&self) -> Hash32 {
        match self {
            DecisionLogRecord::V1(r) => r.prev_record_hash,
            DecisionLogRecord::V2(r) => r.prev_record_hash,
        }
    }

    fn record_hash(&self) -> Hash32 {
        match self {
            DecisionLogRecord::V1(r) => r.record_hash,
            DecisionLogRecord::V2(r) => r.record_hash,
        }
    }
}

/// Verified append-only decision log.
///
/// This type is only constructible by verifying the existing log chain.
pub struct VerifiedDecisionLog {
    path: PathBuf,
    lock: Mutex<()>,
    last_hash: Mutex<Hash32>,
    saw_unverified_v1: bool,
}

impl VerifiedDecisionLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let (last_hash, saw_unverified_v1) = verify_chain(&path)?;
        Ok(Self {
            path,
            lock: Mutex::new(()),
            last_hash: Mutex::new(last_hash),
            saw_unverified_v1,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn last_record_hash(&self) -> Hash32 {
        self.last_hash.lock().expect("lock poisoned").clone()
    }

    pub fn saw_unverified_v1(&self) -> bool {
        self.saw_unverified_v1
    }
}

impl DecisionRecorder for VerifiedDecisionLog {
    fn record(&self, token: &DecisionToken, proof: &ProofBundle) -> Result<()> {
        let _guard = self.lock.lock().expect("lock poisoned");
        let published_at_ms = now_ms()?;
        let prev_hash = self.last_hash.lock().expect("lock poisoned").clone();
        let record_hash = record_hash_v2(&prev_hash, published_at_ms, token, proof);

        let record = DecisionLogRecordV2 {
            record_version: 2,
            published_at_ms,
            prev_record_hash: prev_hash,
            record_hash: record_hash.clone(),

            policy_hash: token.policy_hash,
            policy_epoch: token.policy_ref.policy_epoch,
            registry_root: token.policy_ref.registry_root,

            state_hash: token.state_hash,
            state_source_id: token.state_ref.state_source_id,
            state_epoch: token.state_ref.state_epoch,
            state_attestation_hash: token.state_ref.state_attestation_hash,

            chosen_action_hash: token.chosen_action_hash,
            nonce_or_tx_hash: token.nonce_or_tx_hash,

            limits_hash: proof.limits_hash,
            limits_bytes_hash: sha256(&proof.limits_bytes),
            chosen_action_preimage_hash: sha256(&proof.chosen_action_preimage),
            risc0_receipt_hash: sha256(&proof.risc0_receipt),
        };

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| MprdError::ExecutionError(format!("failed to open decision log: {e}")))?;

        let line = serde_json::to_vec(&record).map_err(|e| {
            MprdError::ExecutionError(format!("failed to serialize decision log record: {e}"))
        })?;
        file.write_all(&line).map_err(|e| {
            MprdError::ExecutionError(format!("failed to write decision log record: {e}"))
        })?;
        file.write_all(b"\n").map_err(|e| {
            MprdError::ExecutionError(format!("failed to write decision log newline: {e}"))
        })?;
        file.sync_all()
            .map_err(|e| MprdError::ExecutionError(format!("failed to sync decision log: {e}")))?;

        *self.last_hash.lock().expect("lock poisoned") = record_hash;
        Ok(())
    }
}

fn parse_decision_log_record(line: &str) -> Result<DecisionLogRecord> {
    let value: serde_json::Value = serde_json::from_str(line).map_err(|e| {
        MprdError::ExecutionError(format!("failed to parse decision log JSON: {e}"))
    })?;
    let version = value
        .get("record_version")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            MprdError::ExecutionError("decision log record missing record_version".into())
        })?;
    match version {
        1 => {
            let record: DecisionLogRecordV1 = serde_json::from_value(value).map_err(|e| {
                MprdError::ExecutionError(format!("failed to decode v1 decision log record: {e}"))
            })?;
            Ok(DecisionLogRecord::V1(record))
        }
        2 => {
            let record: DecisionLogRecordV2 = serde_json::from_value(value).map_err(|e| {
                MprdError::ExecutionError(format!("failed to decode v2 decision log record: {e}"))
            })?;
            Ok(DecisionLogRecord::V2(record))
        }
        _ => Err(MprdError::ExecutionError(format!(
            "unsupported decision log record_version={version}"
        ))),
    }
}

fn verify_chain(path: &Path) -> Result<(Hash32, bool)> {
    if !path.exists() {
        return Ok((Hash32([0u8; 32]), false));
    }

    let contents = std::fs::read_to_string(path).map_err(|e| {
        MprdError::ExecutionError(format!("failed to read decision log: {e}"))
    })?;

    let mut prev_hash = Hash32([0u8; 32]);
    let mut saw_unverified_v1 = false;

    for (idx, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record = parse_decision_log_record(line).map_err(|e| {
            MprdError::ExecutionError(format!("decision log line {} invalid: {e}", idx + 1))
        })?;

        if record.prev_hash() != prev_hash {
            return Err(MprdError::ExecutionError(format!(
                "decision log chain break at line {}",
                idx + 1
            )));
        }

        match &record {
            DecisionLogRecord::V1(_) => {
                saw_unverified_v1 = true;
            }
            DecisionLogRecord::V2(r) => {
                let expected = record_hash_v2_from_record(r);
                if expected != r.record_hash {
                    return Err(MprdError::ExecutionError(format!(
                        "decision log hash mismatch at line {}",
                        idx + 1
                    )));
                }
            }
        }

        prev_hash = record.record_hash();
    }

    Ok((prev_hash, saw_unverified_v1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::limits_hash_v1;
    use crate::{PolicyRef, StateRef};
    use std::fs;
    use std::io::Write;

    fn dummy_hash(b: u8) -> Hash32 {
        Hash32([b; 32])
    }

    fn sample_token_and_proof() -> (DecisionToken, ProofBundle) {
        let token = DecisionToken {
            policy_hash: dummy_hash(1),
            policy_ref: PolicyRef {
                policy_epoch: 1,
                registry_root: dummy_hash(2),
            },
            state_hash: dummy_hash(3),
            state_ref: StateRef {
                state_source_id: dummy_hash(4),
                state_epoch: 9,
                state_attestation_hash: dummy_hash(5),
            },
            chosen_action_hash: dummy_hash(6),
            nonce_or_tx_hash: dummy_hash(7),
            timestamp_ms: 0,
            signature: vec![],
        };
        let proof = ProofBundle {
            policy_hash: token.policy_hash,
            state_hash: token.state_hash,
            candidate_set_hash: dummy_hash(8),
            chosen_action_hash: token.chosen_action_hash,
            limits_hash: limits_hash_v1(&[]),
            limits_bytes: vec![1, 2, 3],
            chosen_action_preimage: vec![4, 5],
            risc0_receipt: vec![6, 7, 8],
            attestation_metadata: Default::default(),
        };
        (token, proof)
    }

    #[test]
    fn file_decision_recorder_hash_chains_records() {
        let dir = std::env::temp_dir().join(format!(
            "mprd_decision_log_test_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("decisions.jsonl");

        let rec = FileDecisionRecorder::new(&path);
        let (token, proof) = sample_token_and_proof();

        rec.record(&token, &proof).unwrap();
        let h1 = rec.last_record_hash();
        rec.record(&token, &proof).unwrap();
        let h2 = rec.last_record_hash();
        assert_ne!(h1, h2);

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        let r1: DecisionLogRecordV2 = serde_json::from_str(lines[0]).unwrap();
        let r2: DecisionLogRecordV2 = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(r1.record_hash, r2.prev_record_hash);
    }

    #[test]
    fn verified_decision_log_accepts_valid_chain() {
        let dir = std::env::temp_dir().join(format!(
            "mprd_decision_log_verified_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("decisions.jsonl");

        let (token, proof) = sample_token_and_proof();
        let log = VerifiedDecisionLog::open(&path).expect("open");
        log.record(&token, &proof).expect("record");
        log.record(&token, &proof).expect("record");

        let reopened = VerifiedDecisionLog::open(&path).expect("reopen");
        assert_eq!(reopened.last_record_hash(), log.last_record_hash());
    }

    #[test]
    fn verified_decision_log_rejects_hash_mismatch() {
        let dir = std::env::temp_dir().join(format!(
            "mprd_decision_log_bad_hash_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("decisions.jsonl");

        let (token, proof) = sample_token_and_proof();
        let log = VerifiedDecisionLog::open(&path).expect("open");
        log.record(&token, &proof).expect("record");

        let contents = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<_> = contents.lines().map(|l| l.to_string()).collect();
        let mut record: DecisionLogRecordV2 = serde_json::from_str(&lines[0]).unwrap();
        record.record_hash = Hash32([9u8; 32]);
        lines[0] = serde_json::to_string(&record).unwrap();
        let mut file = fs::File::create(&path).unwrap();
        for line in lines {
            writeln!(file, "{}", line).unwrap();
        }

        assert!(VerifiedDecisionLog::open(&path).is_err());
    }

    #[test]
    fn verified_decision_log_rejects_chain_break() {
        let dir = std::env::temp_dir().join(format!(
            "mprd_decision_log_bad_chain_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("decisions.jsonl");

        let (token, proof) = sample_token_and_proof();
        let log = VerifiedDecisionLog::open(&path).expect("open");
        log.record(&token, &proof).expect("record");
        log.record(&token, &proof).expect("record");

        let contents = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<_> = contents.lines().map(|l| l.to_string()).collect();
        let mut record: DecisionLogRecordV2 = serde_json::from_str(&lines[1]).unwrap();
        record.prev_record_hash = Hash32([1u8; 32]);
        lines[1] = serde_json::to_string(&record).unwrap();
        let mut file = fs::File::create(&path).unwrap();
        for line in lines {
            writeln!(file, "{}", line).unwrap();
        }

        assert!(VerifiedDecisionLog::open(&path).is_err());
    }
}
