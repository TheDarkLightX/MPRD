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
pub const DECISION_LOG_RECORD_DOMAIN_V3: &[u8] = b"MPRD_DECISION_LOG_RECORD_V3";
pub const DECISION_LOG_RECORD_DOMAIN_V4: &[u8] = b"MPRD_DECISION_LOG_RECORD_V4";
pub const DECISION_LOG_ATTESTATION_METADATA_HASH_DOMAIN_V1: &[u8] =
    b"MPRD_DECISION_LOG_ATTESTATION_METADATA_HASH_V1";

#[derive(Clone, Debug, Default)]
struct GovernanceMetadataFields {
    update_kind: Option<String>,
    profile_app_ok: Option<bool>,
    profile_safety_ok: Option<bool>,
    link_ok: Option<bool>,
}

struct RecordHashV3Inputs<'a> {
    limits_hash: &'a Hash32,
    limits_bytes_hash: &'a Hash32,
    chosen_action_preimage_hash: &'a Hash32,
    risc0_receipt_hash: &'a Hash32,
    attestation_metadata_hash: &'a Hash32,
    governance: &'a GovernanceMetadataFields,
}

struct RecordHashV4Inputs<'a> {
    limits_hash: &'a Hash32,
    limits_bytes_hash: &'a Hash32,
    chosen_action_preimage_hash: &'a Hash32,
    risc0_receipt_hash: &'a Hash32,
    attestation_metadata_hash: &'a Hash32,
    execution_authorization_hash: Option<&'a Hash32>,
    governance: &'a GovernanceMetadataFields,
}

struct PreparedDecisionLogRecordV4Inputs {
    limits_bytes_hash: Hash32,
    chosen_action_preimage_hash: Hash32,
    risc0_receipt_hash: Hash32,
    attestation_metadata_hash: Hash32,
    execution_authorization_hash: Option<Hash32>,
    governance: GovernanceMetadataFields,
}

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionLogRecordV3 {
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
    pub attestation_metadata_hash: Hash32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_update_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_profile_app_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_profile_safety_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_link_ok: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionLogRecordV4 {
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
    pub attestation_metadata_hash: Hash32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_authorization_hash: Option<Hash32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_update_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_profile_app_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_profile_safety_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_link_ok: Option<bool>,
}

fn now_ms() -> Result<i64> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| MprdError::ExecutionError("system clock error".into()))?
        .as_millis();
    i64::try_from(ms).map_err(|_| MprdError::ExecutionError("system clock overflow".into()))
}

pub fn attestation_metadata_hash_v1(
    metadata: &std::collections::HashMap<String, String>,
) -> Hash32 {
    let mut entries: Vec<_> = metadata.iter().collect();
    entries.sort_by(|(ka, va), (kb, vb)| ka.cmp(kb).then_with(|| va.cmp(vb)));

    let mut bytes = Vec::new();
    bytes.extend_from_slice(DECISION_LOG_ATTESTATION_METADATA_HASH_DOMAIN_V1);
    bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (key, value) in entries {
        bytes.extend_from_slice(&(key.len() as u32).to_le_bytes());
        bytes.extend_from_slice(key.as_bytes());
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    sha256(&bytes)
}

fn governance_metadata_fields_from_proof(proof: &ProofBundle) -> Result<GovernanceMetadataFields> {
    let governance = crate::governance_admission_witness_from_attestation_metadata_v1(
        &proof.attestation_metadata,
    )
    .map_err(|e| MprdError::ExecutionError(e.to_string()))?;

    Ok(match governance {
        None => GovernanceMetadataFields::default(),
        Some(governance) => GovernanceMetadataFields {
            update_kind: Some(governance.update_kind().as_str().into()),
            profile_app_ok: Some(governance.profile_app_ok()),
            profile_safety_ok: Some(governance.profile_safety_ok()),
            link_ok: Some(governance.link_ok()),
        },
    })
}

fn attestation_metadata_hash32_v1(
    metadata: &std::collections::HashMap<String, String>,
    key: &'static str,
) -> Result<Option<Hash32>> {
    let Some(value) = metadata.get(key) else {
        return Ok(None);
    };
    let bytes = hex::decode(value).map_err(|_| {
        MprdError::ExecutionError(format!("invalid {key} attestation metadata hash hex"))
    })?;
    if bytes.len() != 32 {
        return Err(MprdError::ExecutionError(format!(
            "invalid {key} attestation metadata hash length"
        )));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(Some(Hash32(hash)))
}

fn execution_authorization_hash_from_proof(proof: &ProofBundle) -> Result<Option<Hash32>> {
    attestation_metadata_hash32_v1(
        &proof.attestation_metadata,
        crate::EXECUTION_AUTH_ATTESTATION_METADATA_HASH_V1,
    )
}

fn prepare_decision_log_record_v4_inputs(
    proof: &ProofBundle,
) -> Result<PreparedDecisionLogRecordV4Inputs> {
    Ok(PreparedDecisionLogRecordV4Inputs {
        limits_bytes_hash: sha256(&proof.limits_bytes),
        chosen_action_preimage_hash: sha256(&proof.chosen_action_preimage),
        risc0_receipt_hash: sha256(&proof.risc0_receipt),
        attestation_metadata_hash: attestation_metadata_hash_v1(&proof.attestation_metadata),
        execution_authorization_hash: execution_authorization_hash_from_proof(proof)?,
        governance: governance_metadata_fields_from_proof(proof)?,
    })
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

fn record_hash_v3_fields(
    prev_record_hash: &Hash32,
    published_at_ms: i64,
    token: &DecisionToken,
    inputs: RecordHashV3Inputs<'_>,
) -> Hash32 {
    let mut bytes = Vec::with_capacity(640);
    bytes.extend_from_slice(DECISION_LOG_RECORD_DOMAIN_V3);
    bytes.extend_from_slice(&3u32.to_le_bytes());
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

    bytes.extend_from_slice(&inputs.limits_hash.0);
    bytes.extend_from_slice(&inputs.limits_bytes_hash.0);
    bytes.extend_from_slice(&inputs.chosen_action_preimage_hash.0);
    bytes.extend_from_slice(&inputs.risc0_receipt_hash.0);
    bytes.extend_from_slice(&inputs.attestation_metadata_hash.0);

    match inputs.governance.update_kind.as_deref() {
        Some(kind) => {
            bytes.push(1);
            bytes.extend_from_slice(&(kind.len() as u32).to_le_bytes());
            bytes.extend_from_slice(kind.as_bytes());
        }
        None => bytes.push(0),
    }
    match inputs.governance.profile_app_ok {
        Some(value) => {
            bytes.push(1);
            bytes.push(u8::from(value));
        }
        None => bytes.push(0),
    }
    match inputs.governance.profile_safety_ok {
        Some(value) => {
            bytes.push(1);
            bytes.push(u8::from(value));
        }
        None => bytes.push(0),
    }
    match inputs.governance.link_ok {
        Some(value) => {
            bytes.push(1);
            bytes.push(u8::from(value));
        }
        None => bytes.push(0),
    }

    sha256(&bytes)
}

fn record_hash_v4_fields(
    prev_record_hash: &Hash32,
    published_at_ms: i64,
    token: &DecisionToken,
    inputs: RecordHashV4Inputs<'_>,
) -> Hash32 {
    let mut bytes = Vec::with_capacity(704);
    bytes.extend_from_slice(DECISION_LOG_RECORD_DOMAIN_V4);
    bytes.extend_from_slice(&4u32.to_le_bytes());
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

    bytes.extend_from_slice(&inputs.limits_hash.0);
    bytes.extend_from_slice(&inputs.limits_bytes_hash.0);
    bytes.extend_from_slice(&inputs.chosen_action_preimage_hash.0);
    bytes.extend_from_slice(&inputs.risc0_receipt_hash.0);
    bytes.extend_from_slice(&inputs.attestation_metadata_hash.0);

    match inputs.execution_authorization_hash {
        Some(hash) => {
            bytes.push(1);
            bytes.extend_from_slice(&hash.0);
        }
        None => bytes.push(0),
    }

    match inputs.governance.update_kind.as_deref() {
        Some(kind) => {
            bytes.push(1);
            bytes.extend_from_slice(&(kind.len() as u32).to_le_bytes());
            bytes.extend_from_slice(kind.as_bytes());
        }
        None => bytes.push(0),
    }
    match inputs.governance.profile_app_ok {
        Some(value) => {
            bytes.push(1);
            bytes.push(u8::from(value));
        }
        None => bytes.push(0),
    }
    match inputs.governance.profile_safety_ok {
        Some(value) => {
            bytes.push(1);
            bytes.push(u8::from(value));
        }
        None => bytes.push(0),
    }
    match inputs.governance.link_ok {
        Some(value) => {
            bytes.push(1);
            bytes.push(u8::from(value));
        }
        None => bytes.push(0),
    }

    sha256(&bytes)
}

pub fn record_hash_v3(
    prev_record_hash: &Hash32,
    published_at_ms: i64,
    token: &DecisionToken,
    proof: &ProofBundle,
) -> Result<Hash32> {
    let limits_bytes_hash = sha256(&proof.limits_bytes);
    let chosen_action_preimage_hash = sha256(&proof.chosen_action_preimage);
    let risc0_receipt_hash = sha256(&proof.risc0_receipt);
    let attestation_metadata_hash = attestation_metadata_hash_v1(&proof.attestation_metadata);
    let governance = governance_metadata_fields_from_proof(proof)?;

    Ok(record_hash_v3_fields(
        prev_record_hash,
        published_at_ms,
        token,
        RecordHashV3Inputs {
            limits_hash: &proof.limits_hash,
            limits_bytes_hash: &limits_bytes_hash,
            chosen_action_preimage_hash: &chosen_action_preimage_hash,
            risc0_receipt_hash: &risc0_receipt_hash,
            attestation_metadata_hash: &attestation_metadata_hash,
            governance: &governance,
        },
    ))
}

pub fn record_hash_v4(
    prev_record_hash: &Hash32,
    published_at_ms: i64,
    token: &DecisionToken,
    proof: &ProofBundle,
) -> Result<Hash32> {
    let prepared = prepare_decision_log_record_v4_inputs(proof)?;

    Ok(record_hash_v4_fields(
        prev_record_hash,
        published_at_ms,
        token,
        RecordHashV4Inputs {
            limits_hash: &proof.limits_hash,
            limits_bytes_hash: &prepared.limits_bytes_hash,
            chosen_action_preimage_hash: &prepared.chosen_action_preimage_hash,
            risc0_receipt_hash: &prepared.risc0_receipt_hash,
            attestation_metadata_hash: &prepared.attestation_metadata_hash,
            execution_authorization_hash: prepared.execution_authorization_hash.as_ref(),
            governance: &prepared.governance,
        },
    ))
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

fn record_hash_v1_from_record(record: &DecisionLogRecordV1) -> Hash32 {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(DECISION_LOG_RECORD_DOMAIN_V1);
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&record.published_at_ms.to_le_bytes());
    bytes.extend_from_slice(&record.prev_record_hash.0);

    bytes.extend_from_slice(&record.policy_hash.0);
    bytes.extend_from_slice(&record.policy_epoch.to_le_bytes());
    bytes.extend_from_slice(&record.registry_root.0);
    bytes.extend_from_slice(&record.state_hash.0);
    bytes.extend_from_slice(&record.state_source_id.0);
    bytes.extend_from_slice(&record.state_epoch.to_le_bytes());
    bytes.extend_from_slice(&record.state_attestation_hash.0);
    bytes.extend_from_slice(&record.chosen_action_hash.0);
    bytes.extend_from_slice(&record.nonce_or_tx_hash.0);

    bytes.extend_from_slice(&record.limits_hash.0);
    bytes.extend_from_slice(&record.limits_bytes_hash.0);
    bytes.extend_from_slice(&record.chosen_action_preimage_hash.0);
    bytes.extend_from_slice(&record.risc0_receipt_hash.0);

    sha256(&bytes)
}

pub fn record_hash_v3_from_record(record: &DecisionLogRecordV3) -> Hash32 {
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

    record_hash_v3_fields(
        &record.prev_record_hash,
        record.published_at_ms,
        &token,
        RecordHashV3Inputs {
            limits_hash: &record.limits_hash,
            limits_bytes_hash: &record.limits_bytes_hash,
            chosen_action_preimage_hash: &record.chosen_action_preimage_hash,
            risc0_receipt_hash: &record.risc0_receipt_hash,
            attestation_metadata_hash: &record.attestation_metadata_hash,
            governance: &GovernanceMetadataFields {
                update_kind: record.governance_update_kind.clone(),
                profile_app_ok: record.governance_profile_app_ok,
                profile_safety_ok: record.governance_profile_safety_ok,
                link_ok: record.governance_link_ok,
            },
        },
    )
}

pub fn record_hash_v4_from_record(record: &DecisionLogRecordV4) -> Hash32 {
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

    record_hash_v4_fields(
        &record.prev_record_hash,
        record.published_at_ms,
        &token,
        RecordHashV4Inputs {
            limits_hash: &record.limits_hash,
            limits_bytes_hash: &record.limits_bytes_hash,
            chosen_action_preimage_hash: &record.chosen_action_preimage_hash,
            risc0_receipt_hash: &record.risc0_receipt_hash,
            attestation_metadata_hash: &record.attestation_metadata_hash,
            execution_authorization_hash: record.execution_authorization_hash.as_ref(),
            governance: &GovernanceMetadataFields {
                update_kind: record.governance_update_kind.clone(),
                profile_app_ok: record.governance_profile_app_ok,
                profile_safety_ok: record.governance_profile_safety_ok,
                link_ok: record.governance_link_ok,
            },
        },
    )
}

/// Append-only file recorder for decision publication.
///
/// Each line is one JSON-encoded decision-log record. New writes use V4.
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
        *self.last_hash.lock().expect("lock poisoned")
    }
}

impl DecisionRecorder for FileDecisionRecorder {
    fn record(&self, token: &DecisionToken, proof: &ProofBundle) -> Result<()> {
        let _guard = self.lock.lock().expect("lock poisoned");
        let published_at_ms = now_ms()?;
        let prev_hash = *self.last_hash.lock().expect("lock poisoned");
        let record = decision_log_record_v4(prev_hash, published_at_ms, token, proof)?;

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

        *self.last_hash.lock().expect("lock poisoned") = record.record_hash;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum DecisionLogRecord {
    V1(DecisionLogRecordV1),
    V2(DecisionLogRecordV2),
    V3(DecisionLogRecordV3),
    V4(DecisionLogRecordV4),
}

impl DecisionLogRecord {
    fn prev_hash(&self) -> Hash32 {
        match self {
            DecisionLogRecord::V1(r) => r.prev_record_hash,
            DecisionLogRecord::V2(r) => r.prev_record_hash,
            DecisionLogRecord::V3(r) => r.prev_record_hash,
            DecisionLogRecord::V4(r) => r.prev_record_hash,
        }
    }

    fn record_hash(&self) -> Hash32 {
        match self {
            DecisionLogRecord::V1(r) => r.record_hash,
            DecisionLogRecord::V2(r) => r.record_hash,
            DecisionLogRecord::V3(r) => r.record_hash,
            DecisionLogRecord::V4(r) => r.record_hash,
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
        *self.last_hash.lock().expect("lock poisoned")
    }

    pub fn saw_unverified_v1(&self) -> bool {
        self.saw_unverified_v1
    }
}

impl DecisionRecorder for VerifiedDecisionLog {
    fn record(&self, token: &DecisionToken, proof: &ProofBundle) -> Result<()> {
        let _guard = self.lock.lock().expect("lock poisoned");
        let published_at_ms = now_ms()?;
        let prev_hash = *self.last_hash.lock().expect("lock poisoned");
        let record = decision_log_record_v4(prev_hash, published_at_ms, token, proof)?;

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

        *self.last_hash.lock().expect("lock poisoned") = record.record_hash;
        Ok(())
    }
}

#[cfg(test)]
fn decision_log_record_v3(
    prev_hash: Hash32,
    published_at_ms: i64,
    token: &DecisionToken,
    proof: &ProofBundle,
) -> Result<DecisionLogRecordV3> {
    let record_hash = record_hash_v3(&prev_hash, published_at_ms, token, proof)?;
    let governance = governance_metadata_fields_from_proof(proof)?;

    Ok(DecisionLogRecordV3 {
        record_version: 3,
        published_at_ms,
        prev_record_hash: prev_hash,
        record_hash,

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
        attestation_metadata_hash: attestation_metadata_hash_v1(&proof.attestation_metadata),
        governance_update_kind: governance.update_kind,
        governance_profile_app_ok: governance.profile_app_ok,
        governance_profile_safety_ok: governance.profile_safety_ok,
        governance_link_ok: governance.link_ok,
    })
}

fn decision_log_record_v4(
    prev_hash: Hash32,
    published_at_ms: i64,
    token: &DecisionToken,
    proof: &ProofBundle,
) -> Result<DecisionLogRecordV4> {
    let prepared = prepare_decision_log_record_v4_inputs(proof)?;
    let record_hash = record_hash_v4_fields(
        &prev_hash,
        published_at_ms,
        token,
        RecordHashV4Inputs {
            limits_hash: &proof.limits_hash,
            limits_bytes_hash: &prepared.limits_bytes_hash,
            chosen_action_preimage_hash: &prepared.chosen_action_preimage_hash,
            risc0_receipt_hash: &prepared.risc0_receipt_hash,
            attestation_metadata_hash: &prepared.attestation_metadata_hash,
            execution_authorization_hash: prepared.execution_authorization_hash.as_ref(),
            governance: &prepared.governance,
        },
    );

    Ok(DecisionLogRecordV4 {
        record_version: 4,
        published_at_ms,
        prev_record_hash: prev_hash,
        record_hash,

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
        limits_bytes_hash: prepared.limits_bytes_hash,
        chosen_action_preimage_hash: prepared.chosen_action_preimage_hash,
        risc0_receipt_hash: prepared.risc0_receipt_hash,
        attestation_metadata_hash: prepared.attestation_metadata_hash,
        execution_authorization_hash: prepared.execution_authorization_hash,
        governance_update_kind: prepared.governance.update_kind,
        governance_profile_app_ok: prepared.governance.profile_app_ok,
        governance_profile_safety_ok: prepared.governance.profile_safety_ok,
        governance_link_ok: prepared.governance.link_ok,
    })
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
        3 => {
            let record: DecisionLogRecordV3 = serde_json::from_value(value).map_err(|e| {
                MprdError::ExecutionError(format!("failed to decode v3 decision log record: {e}"))
            })?;
            Ok(DecisionLogRecord::V3(record))
        }
        4 => {
            let record: DecisionLogRecordV4 = serde_json::from_value(value).map_err(|e| {
                MprdError::ExecutionError(format!("failed to decode v4 decision log record: {e}"))
            })?;
            Ok(DecisionLogRecord::V4(record))
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

    let contents = std::fs::read_to_string(path)
        .map_err(|e| MprdError::ExecutionError(format!("failed to read decision log: {e}")))?;

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
            DecisionLogRecord::V1(r) => {
                saw_unverified_v1 = true;
                let expected = record_hash_v1_from_record(r);
                if expected != r.record_hash {
                    return Err(MprdError::ExecutionError(format!(
                        "decision log hash mismatch at line {}",
                        idx + 1
                    )));
                }
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
            DecisionLogRecord::V3(r) => {
                let expected = record_hash_v3_from_record(r);
                if expected != r.record_hash {
                    return Err(MprdError::ExecutionError(format!(
                        "decision log hash mismatch at line {}",
                        idx + 1
                    )));
                }
            }
            DecisionLogRecord::V4(r) => {
                let expected = record_hash_v4_from_record(r);
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

    fn sample_v1_record(prev_record_hash: Hash32, published_at_ms: i64) -> DecisionLogRecordV1 {
        let (token, proof) = sample_token_and_proof();
        DecisionLogRecordV1 {
            record_version: 1,
            published_at_ms,
            prev_record_hash,
            record_hash: record_hash_v1(&prev_record_hash, published_at_ms, &token, &proof),
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
        }
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

        let r1: DecisionLogRecordV4 = serde_json::from_str(lines[0]).unwrap();
        let r2: DecisionLogRecordV4 = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(r1.record_hash, r2.prev_record_hash);
        assert_eq!(r1.record_version, 4);
        assert_eq!(
            r1.attestation_metadata_hash,
            attestation_metadata_hash_v1(&proof.attestation_metadata)
        );
        assert_eq!(r1.execution_authorization_hash, None);
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
        let mut record: DecisionLogRecordV4 = serde_json::from_str(&lines[0]).unwrap();
        record.record_hash = Hash32([9u8; 32]);
        lines[0] = serde_json::to_string(&record).unwrap();
        let mut file = fs::File::create(&path).unwrap();
        for line in lines {
            writeln!(file, "{}", line).unwrap();
        }

        assert!(VerifiedDecisionLog::open(&path).is_err());
    }

    #[test]
    fn verified_decision_log_rejects_v1_hash_mismatch() {
        let dir = std::env::temp_dir().join(format!(
            "mprd_decision_log_bad_v1_hash_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("decisions.jsonl");

        let mut record = sample_v1_record(Hash32([0u8; 32]), 1_700_000_000_000);
        record.record_hash = Hash32([9u8; 32]);

        let mut file = fs::File::create(&path).unwrap();
        writeln!(file, "{}", serde_json::to_string(&record).unwrap()).unwrap();

        assert!(VerifiedDecisionLog::open(&path).is_err());
    }

    #[test]
    fn verified_decision_log_accepts_valid_v1_chain_and_marks_legacy() {
        let dir = std::env::temp_dir().join(format!(
            "mprd_decision_log_valid_v1_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("decisions.jsonl");

        let record = sample_v1_record(Hash32([0u8; 32]), 1_700_000_000_000);
        let mut file = fs::File::create(&path).unwrap();
        writeln!(file, "{}", serde_json::to_string(&record).unwrap()).unwrap();

        let verified = VerifiedDecisionLog::open(&path).expect("open");
        assert!(verified.saw_unverified_v1());
        assert_eq!(verified.last_record_hash(), record.record_hash);
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
        let mut record: DecisionLogRecordV4 = serde_json::from_str(&lines[1]).unwrap();
        record.prev_record_hash = Hash32([1u8; 32]);
        lines[1] = serde_json::to_string(&record).unwrap();
        let mut file = fs::File::create(&path).unwrap();
        for line in lines {
            writeln!(file, "{}", line).unwrap();
        }

        assert!(VerifiedDecisionLog::open(&path).is_err());
    }

    #[test]
    fn record_hash_v3_governance_metadata_boundary_cases() {
        let (token, proof) = sample_token_and_proof();
        let prev_hash = Hash32([0u8; 32]);
        let published_at_ms = 17;

        let cases = [
            (
                "no governance metadata stays valid",
                Vec::<(&'static str, &'static str)>::new(),
                true,
            ),
            (
                "partial governance metadata is rejected",
                vec![(
                    crate::GOVERNANCE_ATTESTATION_METADATA_UPDATE_KIND_V1,
                    "SafetyRuleChange",
                )],
                false,
            ),
            (
                "invalid governance bool is rejected",
                vec![
                    (
                        crate::GOVERNANCE_ATTESTATION_METADATA_UPDATE_KIND_V1,
                        "SafetyRuleChange",
                    ),
                    (
                        crate::GOVERNANCE_ATTESTATION_METADATA_PROFILE_APP_OK_V1,
                        "maybe",
                    ),
                    (
                        crate::GOVERNANCE_ATTESTATION_METADATA_PROFILE_SAFETY_OK_V1,
                        "true",
                    ),
                    (crate::GOVERNANCE_ATTESTATION_METADATA_LINK_OK_V1, "true"),
                ],
                false,
            ),
            (
                "complete governance metadata stays valid",
                vec![
                    (
                        crate::GOVERNANCE_ATTESTATION_METADATA_UPDATE_KIND_V1,
                        "safety_rule_change",
                    ),
                    (
                        crate::GOVERNANCE_ATTESTATION_METADATA_PROFILE_APP_OK_V1,
                        "true",
                    ),
                    (
                        crate::GOVERNANCE_ATTESTATION_METADATA_PROFILE_SAFETY_OK_V1,
                        "true",
                    ),
                    (crate::GOVERNANCE_ATTESTATION_METADATA_LINK_OK_V1, "true"),
                ],
                true,
            ),
        ];

        for (reason, entries, expect_ok) in cases {
            let mut case_proof = proof.clone();
            case_proof.attestation_metadata = entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let result = record_hash_v3(&prev_hash, published_at_ms, &token, &case_proof);
            assert_eq!(result.is_ok(), expect_ok, "{reason}");
        }
    }

    #[test]
    fn record_hash_v4_execution_authorization_metadata_boundary_cases() {
        let (token, proof) = sample_token_and_proof();
        let prev_hash = Hash32([0u8; 32]);
        let published_at_ms = 23;

        let cases = [
            (
                "no execution authorization metadata stays valid",
                None,
                true,
            ),
            (
                "valid execution authorization hash stays valid",
                Some(hex::encode([0xabu8; 32])),
                true,
            ),
            (
                "invalid execution authorization hex is rejected",
                Some("zz".into()),
                false,
            ),
            (
                "short execution authorization hash is rejected",
                Some(hex::encode([0xabu8; 31])),
                false,
            ),
        ];

        for (reason, value, expect_ok) in cases {
            let mut case_proof = proof.clone();
            if let Some(value) = value {
                case_proof.attestation_metadata.insert(
                    crate::EXECUTION_AUTH_ATTESTATION_METADATA_HASH_V1.into(),
                    value,
                );
            }
            let result = record_hash_v4(&prev_hash, published_at_ms, &token, &case_proof);
            assert_eq!(result.is_ok(), expect_ok, "{reason}");
        }
    }

    #[test]
    fn verified_decision_log_accepts_legacy_v2_chain_and_appends_v4() {
        let dir = std::env::temp_dir().join(format!(
            "mprd_decision_log_legacy_v2_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("decisions.jsonl");

        let (token, proof) = sample_token_and_proof();
        let published_at_ms = 42;
        let prev_hash = Hash32([0u8; 32]);
        let record_hash = record_hash_v2(&prev_hash, published_at_ms, &token, &proof);
        let legacy = DecisionLogRecordV2 {
            record_version: 2,
            published_at_ms,
            prev_record_hash: prev_hash,
            record_hash,
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
        let mut file = fs::File::create(&path).unwrap();
        writeln!(file, "{}", serde_json::to_string(&legacy).unwrap()).unwrap();

        let log = VerifiedDecisionLog::open(&path).expect("open");
        log.record(&token, &proof).expect("append v4");

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        let legacy_record: DecisionLogRecordV2 = serde_json::from_str(lines[0]).unwrap();
        let v4_record: DecisionLogRecordV4 = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(legacy_record.record_hash, v4_record.prev_record_hash);
        assert_eq!(v4_record.record_version, 4);
    }

    #[test]
    fn verified_decision_log_accepts_legacy_v3_chain_and_appends_v4() {
        let dir = std::env::temp_dir().join(format!(
            "mprd_decision_log_legacy_v3_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("decisions.jsonl");

        let (token, mut proof) = sample_token_and_proof();
        proof.attestation_metadata.insert(
            crate::GOVERNANCE_ATTESTATION_METADATA_UPDATE_KIND_V1.into(),
            crate::GovernanceUpdateKindV1::PolicyTweak.as_str().into(),
        );
        proof.attestation_metadata.insert(
            crate::GOVERNANCE_ATTESTATION_METADATA_PROFILE_APP_OK_V1.into(),
            "true".into(),
        );
        proof.attestation_metadata.insert(
            crate::GOVERNANCE_ATTESTATION_METADATA_PROFILE_SAFETY_OK_V1.into(),
            "false".into(),
        );
        proof.attestation_metadata.insert(
            crate::GOVERNANCE_ATTESTATION_METADATA_LINK_OK_V1.into(),
            "true".into(),
        );

        let published_at_ms = 42;
        let prev_hash = Hash32([0u8; 32]);
        let legacy =
            decision_log_record_v3(prev_hash, published_at_ms, &token, &proof).expect("v3 record");
        let mut file = fs::File::create(&path).unwrap();
        writeln!(file, "{}", serde_json::to_string(&legacy).unwrap()).unwrap();

        let log = VerifiedDecisionLog::open(&path).expect("open");
        log.record(&token, &proof).expect("append v4");

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        let legacy_record: DecisionLogRecordV3 = serde_json::from_str(lines[0]).unwrap();
        let v4_record: DecisionLogRecordV4 = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(legacy_record.record_hash, v4_record.prev_record_hash);
        assert_eq!(legacy_record.record_version, 3);
        assert_eq!(v4_record.record_version, 4);
    }
}
