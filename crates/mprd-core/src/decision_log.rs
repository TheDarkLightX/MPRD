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
        let record_hash = record_hash_v1(&prev_hash, published_at_ms, token, proof);

        let record = DecisionLogRecordV1 {
            record_version: 1,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::limits_hash_v1;
    use crate::{PolicyRef, StateRef};
    use std::fs;

    fn dummy_hash(b: u8) -> Hash32 {
        Hash32([b; 32])
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
            policy_hash: token.policy_hash.clone(),
            state_hash: token.state_hash.clone(),
            candidate_set_hash: dummy_hash(8),
            chosen_action_hash: token.chosen_action_hash.clone(),
            limits_hash: limits_hash_v1(&[]),
            limits_bytes: vec![1, 2, 3],
            chosen_action_preimage: vec![4, 5],
            risc0_receipt: vec![6, 7, 8],
            attestation_metadata: Default::default(),
        };

        rec.record(&token, &proof).unwrap();
        let h1 = rec.last_record_hash();
        rec.record(&token, &proof).unwrap();
        let h2 = rec.last_record_hash();
        assert_ne!(h1, h2);

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        let r1: DecisionLogRecordV1 = serde_json::from_str(lines[0]).unwrap();
        let r2: DecisionLogRecordV1 = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(r1.record_hash, r2.prev_record_hash);
    }
}
