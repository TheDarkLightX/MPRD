// Copyright (c) 2026 TheDarkLightX
// SPDX-License-Identifier: MIT

//! Constructor-gated, fail-closed governance for model-proposed memories.
//!
//! An observer, reflector, LLM, or heuristic may produce a
//! [`MemoryMutationProposal`]. Only [`admit_memory_mutation`] can construct an
//! [`AdmittedMemoryMutation`]. Persistence belongs in an imperative shell that
//! accepts the admitted type rather than raw model output.
//!
//! This module binds a mutation to its evidence, prior revision, content, scope,
//! expiry, and exact admission policy. It does not prove that the proposed
//! memory is semantically true; higher-assurance deployments can require human,
//! cryptographic, or ZK-backed evidence before admission.

use crate::Hash32;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

const CONTENT_HASH_DOMAIN_V1: &[u8] = b"mprd:memory-content:v1";
const POLICY_HASH_DOMAIN_V1: &[u8] = b"mprd:memory-policy:v1";
const MUTATION_COMMITMENT_DOMAIN_V1: &[u8] = b"mprd:memory-mutation:v1";
const MAX_POLICY_IDENTIFIER_BYTES: usize = 1024;
const MAX_POLICY_CONTENT_BYTES: usize = 1024 * 1024;
const MAX_POLICY_EVIDENCE_ITEMS: usize = 256;
const ZERO_HASH: Hash32 = Hash32([0u8; 32]);

/// Scope of a proposed memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryScope {
    Workspace,
    Global,
}

impl MemoryScope {
    fn tag(self) -> u8 {
        match self {
            Self::Workspace => 0,
            Self::Global => 1,
        }
    }
}

/// Supported mutation kinds for the initial governed-memory kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryMutationKind {
    Create,
    Update,
}

impl MemoryMutationKind {
    fn tag(self) -> u8 {
        match self {
            Self::Create => 0,
            Self::Update => 1,
        }
    }
}

/// Minimal committed identity of an already-persisted memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRecordRef {
    pub memory_id: String,
    pub subject_id: String,
    pub workspace_id: Option<String>,
    pub scope: MemoryScope,
    pub revision: u64,
    pub content_hash: Hash32,
}

/// Untrusted proposal emitted by an observer, reflector, LLM, or heuristic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryMutationProposal {
    pub proposal_id: String,
    pub memory_id: String,
    pub subject_id: String,
    pub workspace_id: Option<String>,
    pub scope: MemoryScope,
    pub kind: MemoryMutationKind,
    pub expected_revision: Option<u64>,
    pub content: String,
    pub evidence_hashes: Vec<Hash32>,
    pub observed_at_ms: i64,
    pub expires_at_ms: Option<i64>,
}

/// Explicit limits and scope policy used by the pure admission function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryAdmissionPolicy {
    pub max_identifier_bytes: usize,
    pub max_content_bytes: usize,
    pub min_evidence_items: usize,
    pub max_evidence_items: usize,
    pub allow_global: bool,
    pub require_global_expiry: bool,
    pub max_ttl_ms: Option<i64>,
}

impl Default for MemoryAdmissionPolicy {
    fn default() -> Self {
        Self {
            max_identifier_bytes: 128,
            max_content_bytes: 4 * 1024,
            min_evidence_items: 1,
            max_evidence_items: 32,
            allow_global: false,
            require_global_expiry: true,
            max_ttl_ms: Some(365_i64 * 24 * 60 * 60 * 1000),
        }
    }
}

/// Constructor-gated packet that an imperative persistence shell may consume.
///
/// The fields are private and this type deliberately does not implement
/// `Deserialize`, so callers cannot bypass admission by decoding arbitrary
/// bytes into an admitted value.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdmittedMemoryMutation {
    proposal: MemoryMutationProposal,
    next_revision: u64,
    previous_content_hash: Option<Hash32>,
    content_hash: Hash32,
    policy_hash: Hash32,
    mutation_commitment: Hash32,
}

impl AdmittedMemoryMutation {
    /// Return the canonicalized proposal admitted by the kernel.
    pub fn proposal(&self) -> &MemoryMutationProposal {
        &self.proposal
    }

    /// Return the revision the persistence shell must write.
    pub fn next_revision(&self) -> u64 {
        self.next_revision
    }

    /// Return the prior content commitment for updates, or `None` for creates.
    pub fn previous_content_hash(&self) -> Option<&Hash32> {
        self.previous_content_hash.as_ref()
    }

    /// Return the domain-separated commitment to the new content.
    pub fn content_hash(&self) -> &Hash32 {
        &self.content_hash
    }

    /// Return the commitment to the exact admission policy.
    pub fn policy_hash(&self) -> &Hash32 {
        &self.policy_hash
    }

    /// Return the commitment binding the complete admitted mutation.
    pub fn mutation_commitment(&self) -> &Hash32 {
        &self.mutation_commitment
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MemoryAdmissionError {
    #[error("invalid memory admission policy: {0}")]
    InvalidPolicy(String),
    #[error("{field} must not be empty")]
    EmptyIdentifier { field: &'static str },
    #[error("{field} must be canonical visible ASCII without surrounding whitespace")]
    NonCanonicalIdentifier { field: &'static str },
    #[error("{field} is {actual} bytes; maximum is {max}")]
    IdentifierTooLong {
        field: &'static str,
        actual: usize,
        max: usize,
    },
    #[error("memory content must not be empty")]
    EmptyContent,
    #[error("memory content is {actual} bytes; maximum is {max}")]
    ContentTooLarge { actual: usize, max: usize },
    #[error("proposal has {actual} evidence items; minimum is {min}")]
    TooFewEvidenceItems { actual: usize, min: usize },
    #[error("proposal has {actual} evidence items; maximum is {max}")]
    TooManyEvidenceItems { actual: usize, max: usize },
    #[error("evidence hash at index {index} is the all-zero sentinel")]
    ZeroEvidenceHash { index: usize },
    #[error("duplicate evidence hash")]
    DuplicateEvidenceHash,
    #[error("observed_at_ms must be non-negative")]
    NegativeObservedAt,
    #[error("workspace-scoped memory requires workspace_id")]
    WorkspaceScopeMissingWorkspace,
    #[error("global-scoped memory must not carry workspace_id")]
    GlobalScopeHasWorkspace,
    #[error("global memories are disabled by policy")]
    GlobalScopeDenied,
    #[error("global memory requires an explicit expiry")]
    GlobalExpiryRequired,
    #[error("expires_at_ms must be greater than observed_at_ms")]
    InvalidExpiry,
    #[error("memory TTL is {actual_ms} ms; policy maximum is {max_ms} ms")]
    TtlTooLong { actual_ms: i64, max_ms: i64 },
    #[error("create proposal must not reference an existing record")]
    CreateHasExistingRecord,
    #[error("create proposal must not set expected_revision")]
    CreateHasExpectedRevision,
    #[error("update proposal requires an existing record")]
    UpdateMissingExistingRecord,
    #[error("update proposal requires expected_revision")]
    UpdateMissingExpectedRevision,
    #[error("existing record revision must be at least 1")]
    InvalidExistingRevision,
    #[error("existing record content hash is the all-zero sentinel")]
    ZeroExistingContentHash,
    #[error("existing record does not match proposal field {field}")]
    ExistingRecordMismatch { field: &'static str },
    #[error("stale update revision: proposal expected {expected}, existing record is {actual}")]
    StaleRevision { expected: u64, actual: u64 },
    #[error("memory revision overflow")]
    RevisionOverflow,
}

/// Admit a raw memory proposal under an explicit policy and optional prior state.
///
/// The function has no clock, I/O, randomness, mutable global state, or model
/// call. Its output is fully determined by `policy`, `existing`, and `proposal`.
pub fn admit_memory_mutation(
    policy: &MemoryAdmissionPolicy,
    existing: Option<&MemoryRecordRef>,
    mut proposal: MemoryMutationProposal,
) -> Result<AdmittedMemoryMutation, MemoryAdmissionError> {
    validate_policy(policy)?;
    validate_identifier(
        "proposal_id",
        &proposal.proposal_id,
        policy.max_identifier_bytes,
    )?;
    validate_identifier(
        "memory_id",
        &proposal.memory_id,
        policy.max_identifier_bytes,
    )?;
    validate_identifier(
        "subject_id",
        &proposal.subject_id,
        policy.max_identifier_bytes,
    )?;
    validate_scope(
        proposal.scope,
        proposal.workspace_id.as_deref(),
        policy.max_identifier_bytes,
    )?;

    if proposal.scope == MemoryScope::Global && !policy.allow_global {
        return Err(MemoryAdmissionError::GlobalScopeDenied);
    }
    if proposal.scope == MemoryScope::Global
        && policy.require_global_expiry
        && proposal.expires_at_ms.is_none()
    {
        return Err(MemoryAdmissionError::GlobalExpiryRequired);
    }
    if proposal.observed_at_ms < 0 {
        return Err(MemoryAdmissionError::NegativeObservedAt);
    }
    validate_expiry(policy, proposal.observed_at_ms, proposal.expires_at_ms)?;

    if proposal.content.trim().is_empty() {
        return Err(MemoryAdmissionError::EmptyContent);
    }
    if proposal.content.len() > policy.max_content_bytes {
        return Err(MemoryAdmissionError::ContentTooLarge {
            actual: proposal.content.len(),
            max: policy.max_content_bytes,
        });
    }

    proposal.evidence_hashes = canonical_evidence(policy, &proposal.evidence_hashes)?;

    if let Some(record) = existing {
        validate_existing_record(policy, record)?;
    }

    let (next_revision, previous_content_hash) = match proposal.kind {
        MemoryMutationKind::Create => {
            if existing.is_some() {
                return Err(MemoryAdmissionError::CreateHasExistingRecord);
            }
            if proposal.expected_revision.is_some() {
                return Err(MemoryAdmissionError::CreateHasExpectedRevision);
            }
            (1, None)
        }
        MemoryMutationKind::Update => {
            let record = existing.ok_or(MemoryAdmissionError::UpdateMissingExistingRecord)?;
            let expected = proposal
                .expected_revision
                .ok_or(MemoryAdmissionError::UpdateMissingExpectedRevision)?;
            validate_record_identity(record, &proposal)?;
            if expected != record.revision {
                return Err(MemoryAdmissionError::StaleRevision {
                    expected,
                    actual: record.revision,
                });
            }
            let next_revision = record
                .revision
                .checked_add(1)
                .ok_or(MemoryAdmissionError::RevisionOverflow)?;
            (next_revision, Some(record.content_hash))
        }
    };

    let content_hash = memory_content_hash(&proposal.content);
    let policy_hash = memory_policy_hash(policy)?;
    let mutation_commitment = mutation_commitment(
        &proposal,
        next_revision,
        previous_content_hash.as_ref(),
        &content_hash,
        &policy_hash,
    );

    Ok(AdmittedMemoryMutation {
        proposal,
        next_revision,
        previous_content_hash,
        content_hash,
        policy_hash,
        mutation_commitment,
    })
}

/// Hash exact memory content with domain separation and a length prefix.
#[must_use]
pub fn memory_content_hash(content: &str) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(CONTENT_HASH_DOMAIN_V1);
    hash_field(&mut hasher, content.as_bytes());
    Hash32(hasher.finalize().into())
}

/// Hash an admission policy after validating its hard resource bounds.
pub fn memory_policy_hash(policy: &MemoryAdmissionPolicy) -> Result<Hash32, MemoryAdmissionError> {
    validate_policy(policy)?;
    let mut hasher = Sha256::new();
    hasher.update(POLICY_HASH_DOMAIN_V1);
    hasher.update((policy.max_identifier_bytes as u64).to_le_bytes());
    hasher.update((policy.max_content_bytes as u64).to_le_bytes());
    hasher.update((policy.min_evidence_items as u64).to_le_bytes());
    hasher.update((policy.max_evidence_items as u64).to_le_bytes());
    hasher.update([u8::from(policy.allow_global)]);
    hasher.update([u8::from(policy.require_global_expiry)]);
    hash_optional_i64(&mut hasher, policy.max_ttl_ms);
    Ok(Hash32(hasher.finalize().into()))
}

fn validate_policy(policy: &MemoryAdmissionPolicy) -> Result<(), MemoryAdmissionError> {
    if policy.max_identifier_bytes == 0 || policy.max_identifier_bytes > MAX_POLICY_IDENTIFIER_BYTES
    {
        return Err(MemoryAdmissionError::InvalidPolicy(format!(
            "max_identifier_bytes must be between 1 and {MAX_POLICY_IDENTIFIER_BYTES}"
        )));
    }
    if policy.max_content_bytes == 0 || policy.max_content_bytes > MAX_POLICY_CONTENT_BYTES {
        return Err(MemoryAdmissionError::InvalidPolicy(format!(
            "max_content_bytes must be between 1 and {MAX_POLICY_CONTENT_BYTES}"
        )));
    }
    if policy.max_evidence_items == 0 || policy.max_evidence_items > MAX_POLICY_EVIDENCE_ITEMS {
        return Err(MemoryAdmissionError::InvalidPolicy(format!(
            "max_evidence_items must be between 1 and {MAX_POLICY_EVIDENCE_ITEMS}"
        )));
    }
    if policy.min_evidence_items > policy.max_evidence_items {
        return Err(MemoryAdmissionError::InvalidPolicy(
            "min_evidence_items must not exceed max_evidence_items".to_string(),
        ));
    }
    if policy.max_ttl_ms.is_some_and(|ttl| ttl <= 0) {
        return Err(MemoryAdmissionError::InvalidPolicy(
            "max_ttl_ms must be positive when present".to_string(),
        ));
    }
    Ok(())
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), MemoryAdmissionError> {
    if value.is_empty() {
        return Err(MemoryAdmissionError::EmptyIdentifier { field });
    }
    if value.trim() != value
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\x7f')
    {
        return Err(MemoryAdmissionError::NonCanonicalIdentifier { field });
    }
    if value.len() > max_bytes {
        return Err(MemoryAdmissionError::IdentifierTooLong {
            field,
            actual: value.len(),
            max: max_bytes,
        });
    }
    Ok(())
}

fn validate_scope(
    scope: MemoryScope,
    workspace_id: Option<&str>,
    max_identifier_bytes: usize,
) -> Result<(), MemoryAdmissionError> {
    match (scope, workspace_id) {
        (MemoryScope::Workspace, Some(workspace_id)) => {
            validate_identifier("workspace_id", workspace_id, max_identifier_bytes)
        }
        (MemoryScope::Workspace, None) => Err(MemoryAdmissionError::WorkspaceScopeMissingWorkspace),
        (MemoryScope::Global, Some(_)) => Err(MemoryAdmissionError::GlobalScopeHasWorkspace),
        (MemoryScope::Global, None) => Ok(()),
    }
}

fn validate_expiry(
    policy: &MemoryAdmissionPolicy,
    observed_at_ms: i64,
    expires_at_ms: Option<i64>,
) -> Result<(), MemoryAdmissionError> {
    let Some(expires_at_ms) = expires_at_ms else {
        return Ok(());
    };
    let ttl = expires_at_ms
        .checked_sub(observed_at_ms)
        .ok_or(MemoryAdmissionError::InvalidExpiry)?;
    if ttl <= 0 {
        return Err(MemoryAdmissionError::InvalidExpiry);
    }
    if let Some(max_ttl_ms) = policy.max_ttl_ms {
        if ttl > max_ttl_ms {
            return Err(MemoryAdmissionError::TtlTooLong {
                actual_ms: ttl,
                max_ms: max_ttl_ms,
            });
        }
    }
    Ok(())
}

fn canonical_evidence(
    policy: &MemoryAdmissionPolicy,
    evidence_hashes: &[Hash32],
) -> Result<Vec<Hash32>, MemoryAdmissionError> {
    if evidence_hashes.len() < policy.min_evidence_items {
        return Err(MemoryAdmissionError::TooFewEvidenceItems {
            actual: evidence_hashes.len(),
            min: policy.min_evidence_items,
        });
    }
    if evidence_hashes.len() > policy.max_evidence_items {
        return Err(MemoryAdmissionError::TooManyEvidenceItems {
            actual: evidence_hashes.len(),
            max: policy.max_evidence_items,
        });
    }

    let mut canonical = BTreeSet::new();
    for (index, evidence_hash) in evidence_hashes.iter().copied().enumerate() {
        if evidence_hash == ZERO_HASH {
            return Err(MemoryAdmissionError::ZeroEvidenceHash { index });
        }
        if !canonical.insert(evidence_hash) {
            return Err(MemoryAdmissionError::DuplicateEvidenceHash);
        }
    }
    Ok(canonical.into_iter().collect())
}

fn validate_existing_record(
    policy: &MemoryAdmissionPolicy,
    record: &MemoryRecordRef,
) -> Result<(), MemoryAdmissionError> {
    validate_identifier(
        "existing.memory_id",
        &record.memory_id,
        policy.max_identifier_bytes,
    )?;
    validate_identifier(
        "existing.subject_id",
        &record.subject_id,
        policy.max_identifier_bytes,
    )?;
    validate_scope(
        record.scope,
        record.workspace_id.as_deref(),
        policy.max_identifier_bytes,
    )?;
    if record.revision == 0 {
        return Err(MemoryAdmissionError::InvalidExistingRevision);
    }
    if record.content_hash == ZERO_HASH {
        return Err(MemoryAdmissionError::ZeroExistingContentHash);
    }
    Ok(())
}

fn validate_record_identity(
    record: &MemoryRecordRef,
    proposal: &MemoryMutationProposal,
) -> Result<(), MemoryAdmissionError> {
    if record.memory_id != proposal.memory_id {
        return Err(MemoryAdmissionError::ExistingRecordMismatch { field: "memory_id" });
    }
    if record.subject_id != proposal.subject_id {
        return Err(MemoryAdmissionError::ExistingRecordMismatch {
            field: "subject_id",
        });
    }
    if record.scope != proposal.scope {
        return Err(MemoryAdmissionError::ExistingRecordMismatch { field: "scope" });
    }
    if record.workspace_id != proposal.workspace_id {
        return Err(MemoryAdmissionError::ExistingRecordMismatch {
            field: "workspace_id",
        });
    }
    Ok(())
}

fn mutation_commitment(
    proposal: &MemoryMutationProposal,
    next_revision: u64,
    previous_content_hash: Option<&Hash32>,
    content_hash: &Hash32,
    policy_hash: &Hash32,
) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(MUTATION_COMMITMENT_DOMAIN_V1);
    hasher.update(policy_hash.0);
    hash_field(&mut hasher, proposal.proposal_id.as_bytes());
    hash_field(&mut hasher, proposal.memory_id.as_bytes());
    hash_field(&mut hasher, proposal.subject_id.as_bytes());
    hasher.update([proposal.scope.tag()]);
    hash_optional_string(&mut hasher, proposal.workspace_id.as_deref());
    hasher.update([proposal.kind.tag()]);
    hash_optional_u64(&mut hasher, proposal.expected_revision);
    hasher.update(next_revision.to_le_bytes());
    hash_optional_hash(&mut hasher, previous_content_hash);
    hasher.update(content_hash.0);
    hasher.update(proposal.observed_at_ms.to_le_bytes());
    hash_optional_i64(&mut hasher, proposal.expires_at_ms);
    hasher.update((proposal.evidence_hashes.len() as u64).to_le_bytes());
    for evidence_hash in &proposal.evidence_hashes {
        hasher.update(evidence_hash.0);
    }
    Hash32(hasher.finalize().into())
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hash_optional_string(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1u8]);
            hash_field(hasher, value.as_bytes());
        }
        None => hasher.update([0u8]),
    }
}

fn hash_optional_u64(hasher: &mut Sha256, value: Option<u64>) {
    match value {
        Some(value) => {
            hasher.update([1u8]);
            hasher.update(value.to_le_bytes());
        }
        None => hasher.update([0u8]),
    }
}

fn hash_optional_i64(hasher: &mut Sha256, value: Option<i64>) {
    match value {
        Some(value) => {
            hasher.update([1u8]);
            hasher.update(value.to_le_bytes());
        }
        None => hasher.update([0u8]),
    }
}

fn hash_optional_hash(hasher: &mut Sha256, value: Option<&Hash32>) {
    match value {
        Some(value) => {
            hasher.update([1u8]);
            hasher.update(value.0);
        }
        None => hasher.update([0u8]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn create_proposal() -> MemoryMutationProposal {
        MemoryMutationProposal {
            proposal_id: "proposal-1".to_string(),
            memory_id: "memory-1".to_string(),
            subject_id: "user-1".to_string(),
            workspace_id: Some("workspace-1".to_string()),
            scope: MemoryScope::Workspace,
            kind: MemoryMutationKind::Create,
            expected_revision: None,
            content: "The user requires deterministic functional cores.".to_string(),
            evidence_hashes: vec![hash(2), hash(1)],
            observed_at_ms: 1_000,
            expires_at_ms: None,
        }
    }

    fn existing_record(revision: u64) -> MemoryRecordRef {
        MemoryRecordRef {
            memory_id: "memory-1".to_string(),
            subject_id: "user-1".to_string(),
            workspace_id: Some("workspace-1".to_string()),
            scope: MemoryScope::Workspace,
            revision,
            content_hash: hash(9),
        }
    }

    #[test]
    fn valid_workspace_create_is_admitted_and_canonicalized() {
        let admitted =
            admit_memory_mutation(&MemoryAdmissionPolicy::default(), None, create_proposal())
                .expect("admitted create");
        assert_eq!(admitted.next_revision(), 1);
        assert_eq!(admitted.previous_content_hash(), None);
        assert_eq!(admitted.proposal().evidence_hashes, vec![hash(1), hash(2)]);
        assert_eq!(
            admitted.content_hash(),
            &memory_content_hash(&admitted.proposal().content)
        );
    }

    #[test]
    fn missing_evidence_fails_closed() {
        let mut proposal = create_proposal();
        proposal.evidence_hashes.clear();
        assert!(matches!(
            admit_memory_mutation(&MemoryAdmissionPolicy::default(), None, proposal),
            Err(MemoryAdmissionError::TooFewEvidenceItems { actual: 0, min: 1 })
        ));
    }

    #[test]
    fn global_memory_is_denied_by_default() {
        let mut proposal = create_proposal();
        proposal.scope = MemoryScope::Global;
        proposal.workspace_id = None;
        proposal.expires_at_ms = Some(2_000);
        assert_eq!(
            admit_memory_mutation(&MemoryAdmissionPolicy::default(), None, proposal),
            Err(MemoryAdmissionError::GlobalScopeDenied)
        );
    }

    #[test]
    fn enabled_global_memory_still_requires_expiry() {
        let policy = MemoryAdmissionPolicy {
            allow_global: true,
            ..MemoryAdmissionPolicy::default()
        };
        let mut proposal = create_proposal();
        proposal.scope = MemoryScope::Global;
        proposal.workspace_id = None;
        proposal.expires_at_ms = None;
        assert_eq!(
            admit_memory_mutation(&policy, None, proposal),
            Err(MemoryAdmissionError::GlobalExpiryRequired)
        );
    }

    #[test]
    fn stale_update_revision_is_rejected() {
        let record = existing_record(3);
        let mut proposal = create_proposal();
        proposal.kind = MemoryMutationKind::Update;
        proposal.expected_revision = Some(2);
        assert_eq!(
            admit_memory_mutation(&MemoryAdmissionPolicy::default(), Some(&record), proposal,),
            Err(MemoryAdmissionError::StaleRevision {
                expected: 2,
                actual: 3
            })
        );
    }

    #[test]
    fn update_identity_drift_is_rejected() {
        let record = existing_record(3);
        let mut proposal = create_proposal();
        proposal.kind = MemoryMutationKind::Update;
        proposal.expected_revision = Some(3);
        proposal.subject_id = "other-user".to_string();
        assert_eq!(
            admit_memory_mutation(&MemoryAdmissionPolicy::default(), Some(&record), proposal,),
            Err(MemoryAdmissionError::ExistingRecordMismatch {
                field: "subject_id"
            })
        );
    }

    #[test]
    fn evidence_order_does_not_change_commitment() {
        let left = create_proposal();
        let mut right = left.clone();
        right.evidence_hashes.reverse();
        let left = admit_memory_mutation(&MemoryAdmissionPolicy::default(), None, left)
            .expect("left admission");
        let right = admit_memory_mutation(&MemoryAdmissionPolicy::default(), None, right)
            .expect("right admission");
        assert_eq!(left.mutation_commitment(), right.mutation_commitment());
    }

    #[test]
    fn content_change_changes_commitment() {
        let left = create_proposal();
        let mut right = left.clone();
        right.content.push_str(" Strictly.");
        let left = admit_memory_mutation(&MemoryAdmissionPolicy::default(), None, left)
            .expect("left admission");
        let right = admit_memory_mutation(&MemoryAdmissionPolicy::default(), None, right)
            .expect("right admission");
        assert_ne!(left.mutation_commitment(), right.mutation_commitment());
    }

    #[test]
    fn duplicate_evidence_is_rejected() {
        let mut proposal = create_proposal();
        proposal.evidence_hashes = vec![hash(1), hash(1)];
        assert_eq!(
            admit_memory_mutation(&MemoryAdmissionPolicy::default(), None, proposal),
            Err(MemoryAdmissionError::DuplicateEvidenceHash)
        );
    }

    #[test]
    fn ttl_above_policy_maximum_is_rejected() {
        let mut proposal = create_proposal();
        proposal.expires_at_ms = Some(2_001);
        let policy = MemoryAdmissionPolicy {
            max_ttl_ms: Some(1_000),
            ..MemoryAdmissionPolicy::default()
        };
        assert_eq!(
            admit_memory_mutation(&policy, None, proposal),
            Err(MemoryAdmissionError::TtlTooLong {
                actual_ms: 1_001,
                max_ms: 1_000
            })
        );
    }

    #[test]
    fn valid_update_binds_previous_content_and_increments_revision() {
        let record = existing_record(3);
        let mut proposal = create_proposal();
        proposal.kind = MemoryMutationKind::Update;
        proposal.expected_revision = Some(3);
        let admitted =
            admit_memory_mutation(&MemoryAdmissionPolicy::default(), Some(&record), proposal)
                .expect("admitted update");
        assert_eq!(admitted.next_revision(), 4);
        assert_eq!(admitted.previous_content_hash(), Some(&record.content_hash));
    }
}
