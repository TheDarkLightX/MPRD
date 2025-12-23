//! Tau Net output attestation (trustless signal integration).
//!
//! This module implements the core, verifier-checkable attestation structure described in:
//! `internal/specs/tau_net_output_attestation.md`.
//!
//! The attestation is intended to be consumed by a verifier-trusted state source adapter that
//! produces a canonical `StateSnapshot` + `StateRef` for the MPRD pipeline.

use crate::crypto::sha256;
use crate::hash::hash_value;
use crate::validation::{
    canonicalize_state_snapshot_v1, MAX_KEY_BYTES_V1, MAX_STATE_FIELDS_V1, MAX_STRING_BYTES_V1,
    MAX_VALUE_BYTES_V1,
};
use crate::{
    Hash32, MprdError, Result, StateProvider, StateRef, StateSnapshot, TokenVerifyingKey, Value,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

pub const TAU_OUTPUT_ATTESTATION_DOMAIN_V1: &[u8] = b"TAU_OUTPUT_ATTESTATION_V1";
pub const TAU_OUTPUT_ATTESTATION_ENVELOPE_DOMAIN_V1: &[u8] = b"TAU_OUTPUT_ATTESTATION_ENVELOPE_V1";
pub const TAU_OUTPUT_SCHEMA_DOMAIN_V1: &[u8] = b"TAU_OUTPUT_SCHEMA_V1";
pub const TAU_NET_STATE_SOURCE_DOMAIN_V1: &[u8] = b"TAU_NET_V1";

/// Maximum number of outputs permitted in a single attestation (DoS resistance).
///
/// This is aligned with the core state field bound.
pub const MAX_TAU_OUTPUTS_V1: usize = MAX_STATE_FIELDS_V1;

/// Maximum number of signatures carried by an attestation (DoS resistance).
pub const MAX_TAU_SIGNATURES_V1: usize = 64;

/// Content-addressed store for attestation envelopes.
///
/// For `Publication-by-hash (MUST)`, a verifier/auditor should be able to retrieve an envelope
/// given the `state_attestation_hash` and recompute/validate its fields (fail-closed).
pub trait TauOutputAttestationStore: Send + Sync {
    fn get(&self, attestation_hash: &Hash32) -> Result<Option<Vec<u8>>>;
}

/// In-memory attestation store (development/testing only).
pub struct InMemoryTauOutputAttestationStore {
    inner: RwLock<HashMap<Hash32, Vec<u8>>>,
}

impl InMemoryTauOutputAttestationStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn insert(&self, bytes: Vec<u8>) -> Result<Hash32> {
        let att = TauOutputAttestationV1::from_envelope_bytes_v1(&bytes)?;
        let h = att.attestation_hash_v1()?;
        let mut g = self
            .inner
            .write()
            .map_err(|_| MprdError::ExecutionError("attestation store poisoned".into()))?;
        g.insert(h.clone(), bytes);
        Ok(h)
    }
}

impl Default for InMemoryTauOutputAttestationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TauOutputAttestationStore for InMemoryTauOutputAttestationStore {
    fn get(&self, attestation_hash: &Hash32) -> Result<Option<Vec<u8>>> {
        let g = self
            .inner
            .read()
            .map_err(|_| MprdError::ExecutionError("attestation store poisoned".into()))?;
        Ok(g.get(attestation_hash).cloned())
    }
}

/// Replay/continuity guard for an output stream `(tau_instance_id, spec_id)`.
///
/// This is a boundary primitive: it lets a state provider enforce monotonicity and hash-chain
/// continuity without trusting the caller to "remember last time".
pub trait TauOutputReplayGuard: Send + Sync {
    fn check_and_record(
        &self,
        tau_instance_id: &[u8; 32],
        spec_id: &[u8; 32],
        output_epoch: u64,
        prev_attestation_hash: &Hash32,
        attestation_hash: &Hash32,
    ) -> Result<()>;
}

/// In-memory replay guard (development/testing only).
///
/// Production deployments should back this with durable storage to prevent replay after restarts.
type TauOutputStreamKey = ([u8; 32], [u8; 32]);
type TauOutputCheckpoint = (u64, Hash32);

pub struct InMemoryTauOutputReplayGuard {
    inner: RwLock<HashMap<TauOutputStreamKey, TauOutputCheckpoint>>,
}

impl InMemoryTauOutputReplayGuard {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Seed a stream checkpoint so a process can start mid-stream (e.g., from a trusted snapshot).
    pub fn seed_stream(
        &self,
        tau_instance_id: [u8; 32],
        spec_id: [u8; 32],
        last_output_epoch: u64,
        last_attestation_hash: Hash32,
    ) -> Result<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| MprdError::ExecutionError("replay guard poisoned".into()))?;
        g.insert(
            (tau_instance_id, spec_id),
            (last_output_epoch, last_attestation_hash),
        );
        Ok(())
    }
}

impl Default for InMemoryTauOutputReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl TauOutputReplayGuard for InMemoryTauOutputReplayGuard {
    fn check_and_record(
        &self,
        tau_instance_id: &[u8; 32],
        spec_id: &[u8; 32],
        output_epoch: u64,
        prev_attestation_hash: &Hash32,
        attestation_hash: &Hash32,
    ) -> Result<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| MprdError::ExecutionError("replay guard poisoned".into()))?;

        match g.get(&(*tau_instance_id, *spec_id)) {
            None => {
                // Fail-closed bootstrap: if no checkpoint is configured, only accept genesis.
                if prev_attestation_hash.0 != [0u8; 32] {
                    return Err(MprdError::ExecutionError(
                        "missing replay checkpoint for non-genesis attestation".into(),
                    ));
                }
            }
            Some((last_epoch, last_hash)) => {
                if output_epoch <= *last_epoch {
                    return Err(MprdError::ExecutionError(format!(
                        "attestation epoch replay: {output_epoch} <= {last_epoch}"
                    )));
                }
                if prev_attestation_hash != last_hash {
                    return Err(MprdError::ExecutionError(
                        "attestation prev_attestation_hash mismatch".into(),
                    ));
                }
            }
        }

        g.insert(
            (*tau_instance_id, *spec_id),
            (output_epoch, attestation_hash.clone()),
        );
        Ok(())
    }
}

/// A stable identifier for the provenance scheme used by Tau Net attested outputs.
///
/// Matches the spec: `H("TAU_NET_V1" || tau_instance_id || spec_id)`.
pub fn state_source_id_tau_net_output_v1(tau_instance_id: &[u8; 32], spec_id: &[u8; 32]) -> Hash32 {
    let mut bytes = Vec::with_capacity(
        TAU_NET_STATE_SOURCE_DOMAIN_V1.len() + tau_instance_id.len() + spec_id.len(),
    );
    bytes.extend_from_slice(TAU_NET_STATE_SOURCE_DOMAIN_V1);
    bytes.extend_from_slice(tau_instance_id);
    bytes.extend_from_slice(spec_id);
    sha256(&bytes)
}

fn is_reserved_temporal_suffix_key(name: &str) -> bool {
    let Some((_, suffix)) = name.rsplit_once("_t_") else {
        return false;
    };
    !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
}

fn validate_key_name(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(MprdError::InvalidInput("empty output key".into()));
    }
    if key.len() > MAX_KEY_BYTES_V1 {
        return Err(MprdError::BoundedValueExceeded(format!(
            "output key too long ({} > {})",
            key.len(),
            MAX_KEY_BYTES_V1
        )));
    }

    // Stable subset: lowercase snake_case ([a-z][a-z0-9_]*).
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return Err(MprdError::InvalidInput("empty output key".into()));
    };
    if !first.is_ascii_lowercase() {
        return Err(MprdError::InvalidInput(format!(
            "invalid output key (expected lowercase snake_case): {key}"
        )));
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return Err(MprdError::InvalidInput(format!(
                "invalid output key (expected lowercase snake_case): {key}"
            )));
        }
    }

    if is_reserved_temporal_suffix_key(key) {
        return Err(MprdError::InvalidInput(format!(
            "output key uses reserved temporal suffix pattern: {key}"
        )));
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TauOutputValueTypeV1 {
    Bool = 0,
    Int = 1,
    UInt = 2,
    String = 3,
    Bytes = 4,
}

fn value_type_of(v: &Value) -> TauOutputValueTypeV1 {
    match v {
        Value::Bool(_) => TauOutputValueTypeV1::Bool,
        Value::Int(_) => TauOutputValueTypeV1::Int,
        Value::UInt(_) => TauOutputValueTypeV1::UInt,
        Value::String(_) => TauOutputValueTypeV1::String,
        Value::Bytes(_) => TauOutputValueTypeV1::Bytes,
    }
}

#[derive(Clone, Debug)]
pub struct TauOutputFieldV1 {
    pub key: String,
    pub value_type: TauOutputValueTypeV1,
    pub required: bool,
}

#[derive(Clone, Debug)]
pub struct TauOutputSchemaV1 {
    pub spec_id: [u8; 32],
    pub output_schema_hash: Hash32,
    /// Canonical schema fields, sorted by `key` bytes.
    pub outputs: Vec<TauOutputFieldV1>,
}

impl TauOutputSchemaV1 {
    pub fn new(spec_id: [u8; 32], outputs: Vec<TauOutputFieldV1>) -> Result<Self> {
        let mut schema = Self {
            spec_id,
            output_schema_hash: Hash32([0u8; 32]),
            outputs,
        };
        schema.output_schema_hash = schema.compute_hash_v1()?;
        Ok(schema)
    }

    pub fn compute_hash_v1(&self) -> Result<Hash32> {
        if self.outputs.is_empty() {
            return Err(MprdError::InvalidInput(
                "output schema cannot be empty".into(),
            ));
        }
        if self.outputs.len() > MAX_TAU_OUTPUTS_V1 {
            return Err(MprdError::BoundedValueExceeded(format!(
                "too many schema fields ({} > {})",
                self.outputs.len(),
                MAX_TAU_OUTPUTS_V1
            )));
        }

        // Fail-closed: schema must already be sorted and unique.
        let mut seen = HashSet::<String>::new();
        let mut last: Option<&str> = None;
        for f in &self.outputs {
            validate_key_name(&f.key)?;
            if !seen.insert(f.key.clone()) {
                return Err(MprdError::InvalidInput(format!(
                    "duplicate schema key: {}",
                    f.key
                )));
            }
            if let Some(prev) = last {
                if f.key.as_bytes() <= prev.as_bytes() {
                    return Err(MprdError::InvalidInput(
                        "schema keys must be strictly sorted by key bytes".into(),
                    ));
                }
            }
            last = Some(&f.key);
        }

        let mut preimage = Vec::with_capacity(64 + self.outputs.len() * 80);
        preimage.extend_from_slice(TAU_OUTPUT_SCHEMA_DOMAIN_V1);
        preimage.extend_from_slice(&self.spec_id);
        preimage.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for f in &self.outputs {
            preimage.extend_from_slice(&(f.key.len() as u32).to_le_bytes());
            preimage.extend_from_slice(f.key.as_bytes());
            preimage.push(f.value_type as u8);
            preimage.push(if f.required { 1 } else { 0 });
        }
        Ok(sha256(&preimage))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TauCommitteeSignatureV1 {
    /// Ed25519 public key (32 bytes).
    pub signer_pubkey: [u8; 32],
    /// Ed25519 signature bytes (64 bytes).
    pub signature: [u8; 64],
}

#[derive(Clone, Debug)]
pub struct TauOutputAttestationV1 {
    pub tau_instance_id: [u8; 32],
    pub spec_id: [u8; 32],
    pub committee_epoch: u64,
    pub output_epoch: u64,
    pub prev_attestation_hash: Hash32,
    /// Unix seconds.
    pub timestamp: u64,
    pub output_schema_hash: Hash32,
    /// Canonical key/value outputs, sorted by key bytes.
    pub outputs: Vec<(String, Value)>,
    pub signatures: Vec<TauCommitteeSignatureV1>,
}

// =============================================================================
// Canonical envelope encoding (publication-by-hash)
// =============================================================================

#[derive(Clone, Copy)]
struct Cursor<'a> {
    bytes: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, i: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.i.checked_add(n).is_none() || self.i + n > self.bytes.len() {
            return Err(MprdError::InvalidInput(
                "unexpected end of envelope bytes".into(),
            ));
        }
        let out = &self.bytes[self.i..self.i + n];
        self.i += n;
        Ok(out)
    }

    fn take_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn take_u32_le(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn take_u64_le(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn finish(self) -> Result<()> {
        if self.i != self.bytes.len() {
            return Err(MprdError::InvalidInput("trailing bytes in envelope".into()));
        }
        Ok(())
    }
}

fn decode_value_v1(cur: &mut Cursor<'_>) -> Result<Value> {
    let tag = cur.take_u8()?;
    match tag {
        0x00 => {
            let b = cur.take_u8()?;
            match b {
                0 => Ok(Value::Bool(false)),
                1 => Ok(Value::Bool(true)),
                _ => Err(MprdError::InvalidInput("invalid bool encoding".into())),
            }
        }
        0x01 => {
            let b = cur.take(8)?;
            Ok(Value::Int(i64::from_le_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ])))
        }
        0x02 => {
            let b = cur.take(8)?;
            Ok(Value::UInt(u64::from_le_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ])))
        }
        0x03 => {
            let len = cur.take_u32_le()? as usize;
            if len > MAX_STRING_BYTES_V1 {
                return Err(MprdError::BoundedValueExceeded(format!(
                    "string value too long ({} > {})",
                    len, MAX_STRING_BYTES_V1
                )));
            }
            let b = cur.take(len)?;
            let s = std::str::from_utf8(b)
                .map_err(|_| MprdError::InvalidInput("invalid utf8 string".into()))?
                .to_string();
            Ok(Value::String(s))
        }
        0x04 => {
            let len = cur.take_u32_le()? as usize;
            if len > MAX_VALUE_BYTES_V1 {
                return Err(MprdError::BoundedValueExceeded(format!(
                    "bytes value too long ({} > {})",
                    len, MAX_VALUE_BYTES_V1
                )));
            }
            let b = cur.take(len)?;
            Ok(Value::Bytes(b.to_vec()))
        }
        _ => Err(MprdError::InvalidInput("invalid value tag".into())),
    }
}

impl TauOutputAttestationV1 {
    /// Encode an envelope including signatures for content-addressed publication.
    ///
    /// Fail-closed: the attestation must already be canonical (sorted keys, unique keys, bounded).
    pub fn envelope_bytes_v1(&self) -> Result<Vec<u8>> {
        // Also enforces output/sig bounds and canonical ordering.
        let _ = self.signing_bytes_v1()?;

        let mut out =
            Vec::with_capacity(256 + self.outputs.len() * 64 + self.signatures.len() * 96);
        out.extend_from_slice(TAU_OUTPUT_ATTESTATION_ENVELOPE_DOMAIN_V1);
        out.extend_from_slice(&self.tau_instance_id);
        out.extend_from_slice(&self.spec_id);
        out.extend_from_slice(&self.committee_epoch.to_le_bytes());
        out.extend_from_slice(&self.output_epoch.to_le_bytes());
        out.extend_from_slice(&self.prev_attestation_hash.0);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.output_schema_hash.0);
        out.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for (k, v) in &self.outputs {
            out.extend_from_slice(&(k.len() as u32).to_le_bytes());
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(&hash_value(v));
        }
        out.extend_from_slice(&(self.signatures.len() as u32).to_le_bytes());
        for s in &self.signatures {
            out.extend_from_slice(&s.signer_pubkey);
            out.extend_from_slice(&s.signature);
        }
        Ok(out)
    }

    /// Decode an attestation envelope.
    ///
    /// Fail-closed: requires canonical ordering (sorted unique keys) and bounded sizes.
    pub fn from_envelope_bytes_v1(bytes: &[u8]) -> Result<Self> {
        let mut cur = Cursor::new(bytes);
        let domain = cur.take(TAU_OUTPUT_ATTESTATION_ENVELOPE_DOMAIN_V1.len())?;
        if domain != TAU_OUTPUT_ATTESTATION_ENVELOPE_DOMAIN_V1 {
            return Err(MprdError::InvalidInput("invalid envelope domain".into()));
        }

        let tau_instance_id: [u8; 32] = cur.take(32)?.try_into().unwrap();
        let spec_id: [u8; 32] = cur.take(32)?.try_into().unwrap();
        let committee_epoch = cur.take_u64_le()?;
        let output_epoch = cur.take_u64_le()?;
        let prev_attestation_hash = Hash32(cur.take(32)?.try_into().unwrap());
        let timestamp = cur.take_u64_le()?;
        let output_schema_hash = Hash32(cur.take(32)?.try_into().unwrap());

        let num_outputs = cur.take_u32_le()? as usize;
        if num_outputs == 0 {
            return Err(MprdError::InvalidInput("outputs cannot be empty".into()));
        }
        if num_outputs > MAX_TAU_OUTPUTS_V1 {
            return Err(MprdError::BoundedValueExceeded(format!(
                "too many outputs ({} > {})",
                num_outputs, MAX_TAU_OUTPUTS_V1
            )));
        }
        let mut outputs: Vec<(String, Value)> = Vec::with_capacity(num_outputs);
        for _ in 0..num_outputs {
            let k_len = cur.take_u32_le()? as usize;
            if k_len == 0 {
                return Err(MprdError::InvalidInput("empty output key".into()));
            }
            if k_len > MAX_KEY_BYTES_V1 {
                return Err(MprdError::BoundedValueExceeded(format!(
                    "output key too long ({} > {})",
                    k_len, MAX_KEY_BYTES_V1
                )));
            }
            let key = std::str::from_utf8(cur.take(k_len)?)
                .map_err(|_| MprdError::InvalidInput("invalid utf8 key".into()))?
                .to_string();
            validate_key_name(&key)?;
            let value = decode_value_v1(&mut cur)?;
            outputs.push((key, value));
        }

        let num_sigs = cur.take_u32_le()? as usize;
        if num_sigs > MAX_TAU_SIGNATURES_V1 {
            return Err(MprdError::BoundedValueExceeded(format!(
                "too many signatures ({} > {})",
                num_sigs, MAX_TAU_SIGNATURES_V1
            )));
        }
        let mut signatures = Vec::with_capacity(num_sigs);
        for _ in 0..num_sigs {
            let signer_pubkey: [u8; 32] = cur.take(32)?.try_into().unwrap();
            let signature: [u8; 64] = cur.take(64)?.try_into().unwrap();
            signatures.push(TauCommitteeSignatureV1 {
                signer_pubkey,
                signature,
            });
        }

        cur.finish()?;

        let att = Self {
            tau_instance_id,
            spec_id,
            committee_epoch,
            output_epoch,
            prev_attestation_hash,
            timestamp,
            output_schema_hash,
            outputs,
            signatures,
        };

        // Enforce canonical order for signing bytes (fail-closed).
        let _ = att.signing_bytes_v1()?;
        Ok(att)
    }
}

impl TauOutputAttestationV1 {
    /// Compute canonical signing bytes for this attestation.
    ///
    /// Fail-closed: the attestation must already be canonical (sorted keys, unique keys, bounded).
    pub fn signing_bytes_v1(&self) -> Result<Vec<u8>> {
        if self.outputs.is_empty() {
            return Err(MprdError::InvalidInput("outputs cannot be empty".into()));
        }
        if self.outputs.len() > MAX_TAU_OUTPUTS_V1 {
            return Err(MprdError::BoundedValueExceeded(format!(
                "too many outputs ({} > {})",
                self.outputs.len(),
                MAX_TAU_OUTPUTS_V1
            )));
        }
        if self.signatures.len() > MAX_TAU_SIGNATURES_V1 {
            return Err(MprdError::BoundedValueExceeded(format!(
                "too many signatures ({} > {})",
                self.signatures.len(),
                MAX_TAU_SIGNATURES_V1
            )));
        }

        let mut seen = HashSet::<String>::new();
        let mut last: Option<&str> = None;
        for (k, _) in &self.outputs {
            validate_key_name(k)?;
            if !seen.insert(k.clone()) {
                return Err(MprdError::InvalidInput(format!(
                    "duplicate output key: {k}"
                )));
            }
            if let Some(prev) = last {
                if k.as_bytes() <= prev.as_bytes() {
                    return Err(MprdError::InvalidInput(
                        "outputs must be strictly sorted by key bytes".into(),
                    ));
                }
            }
            last = Some(k);
        }

        let mut out = Vec::with_capacity(128 + self.outputs.len() * 64);
        out.extend_from_slice(TAU_OUTPUT_ATTESTATION_DOMAIN_V1);
        out.extend_from_slice(&self.tau_instance_id);
        out.extend_from_slice(&self.spec_id);
        out.extend_from_slice(&self.committee_epoch.to_le_bytes());
        out.extend_from_slice(&self.output_epoch.to_le_bytes());
        out.extend_from_slice(&self.prev_attestation_hash.0);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.output_schema_hash.0);
        out.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for (k, v) in &self.outputs {
            out.extend_from_slice(&(k.len() as u32).to_le_bytes());
            out.extend_from_slice(k.as_bytes());
            // Reuse the exact Value encoding tags used by MPRD canonical hashing.
            out.extend_from_slice(&hash_value(v));
        }
        Ok(out)
    }

    /// Compute `attestation_hash = SHA256(attestation_preimage)`.
    pub fn attestation_hash_v1(&self) -> Result<Hash32> {
        Ok(sha256(&self.signing_bytes_v1()?))
    }

    /// Verify that this attestation matches a schema (fail-closed).
    pub fn verify_schema_v1(&self, schema: &TauOutputSchemaV1) -> Result<()> {
        if self.spec_id != schema.spec_id {
            return Err(MprdError::InvalidInput("spec_id mismatch vs schema".into()));
        }
        if self.output_schema_hash != schema.output_schema_hash {
            return Err(MprdError::InvalidInput(
                "output_schema_hash mismatch".into(),
            ));
        }

        // Build schema map (small, bounded).
        let mut schema_map: HashMap<&str, (&TauOutputFieldV1, bool)> = HashMap::new();
        for f in &schema.outputs {
            schema_map.insert(f.key.as_str(), (f, f.required));
        }

        // Track seen keys and enforce types.
        let mut present = HashSet::<&str>::new();
        for (k, v) in &self.outputs {
            let Some((field, _)) = schema_map.get(k.as_str()) else {
                return Err(MprdError::InvalidInput(format!(
                    "unexpected output field not present in schema: {k}"
                )));
            };
            if !present.insert(k.as_str()) {
                return Err(MprdError::InvalidInput(format!(
                    "duplicate output key: {k}"
                )));
            }
            let got = value_type_of(v);
            if got != field.value_type {
                return Err(MprdError::InvalidInput(format!(
                    "output type mismatch for {k}: expected {:?}, got {:?}",
                    field.value_type, got
                )));
            }
        }

        for f in &schema.outputs {
            if f.required && !present.contains(f.key.as_str()) {
                return Err(MprdError::InvalidInput(format!(
                    "missing required output field: {}",
                    f.key
                )));
            }
        }

        Ok(())
    }

    /// Verify committee signatures (k-of-n), signing over the `attestation_hash` bytes.
    pub fn verify_signatures_v1(&self, trusted_members: &[[u8; 32]], threshold: u32) -> Result<()> {
        if threshold == 0 {
            return Err(MprdError::InvalidInput(
                "threshold must be at least 1".into(),
            ));
        }
        if trusted_members.is_empty() {
            return Err(MprdError::InvalidInput(
                "trusted_members must be non-empty".into(),
            ));
        }

        let att_hash = self.attestation_hash_v1()?;
        let msg = att_hash.0;

        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut valid: u32 = 0;

        for s in &self.signatures {
            if !trusted_members.contains(&s.signer_pubkey) {
                continue;
            }
            if !seen.insert(s.signer_pubkey) {
                continue;
            }

            let vk = TokenVerifyingKey::from_bytes(&s.signer_pubkey)?;
            if vk.verify_bytes(&msg, &s.signature).is_ok() {
                valid = valid.saturating_add(1);
                if valid >= threshold {
                    return Ok(());
                }
            }
        }

        Err(MprdError::SignatureInvalid(format!(
            "insufficient signatures: {valid} valid, {threshold} required"
        )))
    }
}

#[derive(Clone, Debug)]
pub struct TauNetCommitteeConfigV1 {
    pub tau_instance_id: [u8; 32],
    pub spec_id: [u8; 32],
    pub members: Vec<[u8; 32]>,
    pub threshold: u32,
    pub max_staleness_seconds: u64,
    pub max_future_skew_seconds: u64,
    pub committee_epoch: u64,
}

impl TauNetCommitteeConfigV1 {
    pub fn validate(&self) -> Result<()> {
        if self.members.is_empty() {
            return Err(MprdError::InvalidInput("committee has no members".into()));
        }
        if self.threshold == 0 {
            return Err(MprdError::InvalidInput(
                "committee threshold must be at least 1".into(),
            ));
        }
        if (self.threshold as usize) > self.members.len() {
            return Err(MprdError::InvalidInput(
                "committee threshold exceeds member count".into(),
            ));
        }
        Ok(())
    }
}

/// A verifier-trusted state provider that converts a Tau Net output attestation into a `StateSnapshot`.
///
/// This is the boundary adapter: it enforces signatures + schema + freshness, then emits canonical
/// MPRD state bytes with provenance bound in `StateRef`.
pub struct TauNetAttestedOutputStateProvider {
    pub attestation: TauOutputAttestationV1,
    pub committee: TauNetCommitteeConfigV1,
    pub schema: TauOutputSchemaV1,
    /// Optional replay/continuity guard (recommended for production).
    pub replay_guard: Option<Arc<dyn TauOutputReplayGuard>>,
}

impl TauNetAttestedOutputStateProvider {
    pub fn from_store_v1(
        store: &dyn TauOutputAttestationStore,
        expected_attestation_hash: &Hash32,
        committee: TauNetCommitteeConfigV1,
        schema: TauOutputSchemaV1,
        replay_guard: Option<Arc<dyn TauOutputReplayGuard>>,
    ) -> Result<Self> {
        let bytes = store
            .get(expected_attestation_hash)?
            .ok_or_else(|| MprdError::InvalidInput("attestation not found in store".into()))?;
        let attestation = TauOutputAttestationV1::from_envelope_bytes_v1(&bytes)?;
        let got = attestation.attestation_hash_v1()?;
        if &got != expected_attestation_hash {
            return Err(MprdError::InvalidInput(
                "attestation hash mismatch vs expected".into(),
            ));
        }
        Ok(Self {
            attestation,
            committee,
            schema,
            replay_guard,
        })
    }

    fn now_unix_seconds() -> Result<u64> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MprdError::ExecutionError("system clock error".into()))?;
        Ok(now.as_secs())
    }

    fn verify(&self, now_secs: u64) -> Result<Hash32> {
        self.committee.validate()?;

        if self.attestation.tau_instance_id != self.committee.tau_instance_id {
            return Err(MprdError::InvalidInput(
                "tau_instance_id mismatch vs committee config".into(),
            ));
        }
        if self.attestation.spec_id != self.committee.spec_id {
            return Err(MprdError::InvalidInput(
                "spec_id mismatch vs committee config".into(),
            ));
        }
        if self.attestation.committee_epoch != self.committee.committee_epoch {
            return Err(MprdError::InvalidInput(
                "committee_epoch mismatch vs committee config".into(),
            ));
        }

        self.attestation.verify_schema_v1(&self.schema)?;
        self.attestation
            .verify_signatures_v1(&self.committee.members, self.committee.threshold)?;

        // Freshness checks.
        if self.attestation.timestamp
            > now_secs.saturating_add(self.committee.max_future_skew_seconds)
        {
            return Err(MprdError::ExecutionError("attestation from future".into()));
        }
        let age = now_secs.saturating_sub(self.attestation.timestamp);
        if age > self.committee.max_staleness_seconds {
            return Err(MprdError::ExecutionError(format!(
                "attestation too stale: {}s > {}s max",
                age, self.committee.max_staleness_seconds
            )));
        }

        let att_hash = self.attestation.attestation_hash_v1()?;
        if let Some(g) = &self.replay_guard {
            g.check_and_record(
                &self.attestation.tau_instance_id,
                &self.attestation.spec_id,
                self.attestation.output_epoch,
                &self.attestation.prev_attestation_hash,
                &att_hash,
            )?;
        }
        Ok(att_hash)
    }

    /// Produce a canonical `StateSnapshot` using an explicit timestamp for freshness checks.
    ///
    /// This is useful for deterministic tests and for deployments where "current time" is sourced
    /// from a trusted clock (e.g., L1 block time) rather than local wall-clock time.
    pub fn snapshot_with_now(&self, now_secs: u64) -> Result<StateSnapshot> {
        let att_hash = self.verify(now_secs)?;

        let mut fields: HashMap<String, Value> =
            HashMap::with_capacity(self.attestation.outputs.len());
        for (k, v) in &self.attestation.outputs {
            fields.insert(k.clone(), v.clone());
        }

        let state_ref = StateRef {
            state_source_id: state_source_id_tau_net_output_v1(
                &self.attestation.tau_instance_id,
                &self.attestation.spec_id,
            ),
            state_epoch: self.attestation.output_epoch,
            state_attestation_hash: att_hash,
        };

        let state = StateSnapshot {
            fields,
            policy_inputs: HashMap::new(),
            state_hash: Hash32([0u8; 32]),
            state_ref,
        };

        canonicalize_state_snapshot_v1(state)
    }
}

impl StateProvider for TauNetAttestedOutputStateProvider {
    fn snapshot(&self) -> Result<StateSnapshot> {
        let now_secs = Self::now_unix_seconds()?;
        self.snapshot_with_now(now_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TokenSigningKey;
    use proptest::prelude::*;

    fn dummy_id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn schema_for_outputs(
        spec_id: [u8; 32],
        keys: &[(&str, TauOutputValueTypeV1)],
    ) -> TauOutputSchemaV1 {
        let mut fields = Vec::new();
        for (k, t) in keys {
            fields.push(TauOutputFieldV1 {
                key: (*k).to_string(),
                value_type: *t,
                required: true,
            });
        }
        // Canonical ordering required by schema hash.
        fields.sort_by(|a, b| a.key.as_bytes().cmp(b.key.as_bytes()));
        TauOutputSchemaV1::new(spec_id, fields).expect("schema")
    }

    fn attestation(
        tau_instance_id: [u8; 32],
        spec_id: [u8; 32],
        committee_epoch: u64,
        output_epoch: u64,
        schema_hash: Hash32,
        outputs: Vec<(String, Value)>,
    ) -> TauOutputAttestationV1 {
        TauOutputAttestationV1 {
            tau_instance_id,
            spec_id,
            committee_epoch,
            output_epoch,
            prev_attestation_hash: Hash32([0u8; 32]),
            timestamp: 100,
            output_schema_hash: schema_hash,
            outputs,
            signatures: vec![],
        }
    }

    #[test]
    fn schema_hash_is_deterministic() {
        let spec_id = dummy_id(2);
        let schema1 = schema_for_outputs(
            spec_id,
            &[
                ("a", TauOutputValueTypeV1::UInt),
                ("b", TauOutputValueTypeV1::Bool),
            ],
        );
        let schema2 = schema_for_outputs(
            spec_id,
            &[
                ("a", TauOutputValueTypeV1::UInt),
                ("b", TauOutputValueTypeV1::Bool),
            ],
        );
        assert_eq!(schema1.output_schema_hash, schema2.output_schema_hash);
    }

    #[test]
    fn attestation_signing_bytes_require_sorted_unique_keys() {
        let spec_id = dummy_id(2);
        let schema = schema_for_outputs(
            spec_id,
            &[
                ("a", TauOutputValueTypeV1::UInt),
                ("b", TauOutputValueTypeV1::UInt),
            ],
        );

        let bad = attestation(
            dummy_id(1),
            spec_id,
            1,
            1,
            schema.output_schema_hash.clone(),
            vec![
                ("b".to_string(), Value::UInt(2)),
                ("a".to_string(), Value::UInt(1)),
            ],
        );
        assert!(bad.signing_bytes_v1().is_err());

        let dup = attestation(
            dummy_id(1),
            spec_id,
            1,
            1,
            schema.output_schema_hash.clone(),
            vec![
                ("a".to_string(), Value::UInt(1)),
                ("a".to_string(), Value::UInt(2)),
            ],
        );
        assert!(dup.signing_bytes_v1().is_err());
    }

    #[test]
    fn verify_signatures_k_of_n() {
        let k1 = TokenSigningKey::from_seed(&[1u8; 32]);
        let k2 = TokenSigningKey::from_seed(&[2u8; 32]);
        let k3 = TokenSigningKey::from_seed(&[3u8; 32]);
        let trusted = vec![
            k1.verifying_key().to_bytes(),
            k2.verifying_key().to_bytes(),
            k3.verifying_key().to_bytes(),
        ];

        let spec_id = dummy_id(2);
        let schema = schema_for_outputs(spec_id, &[("x", TauOutputValueTypeV1::UInt)]);
        let mut a = attestation(
            dummy_id(1),
            spec_id,
            7,
            42,
            schema.output_schema_hash.clone(),
            vec![("x".to_string(), Value::UInt(5))],
        );
        let h = a.attestation_hash_v1().expect("hash");

        // 2-of-3 signatures.
        a.signatures = vec![
            TauCommitteeSignatureV1 {
                signer_pubkey: trusted[0],
                signature: k1.sign_bytes(&h.0),
            },
            TauCommitteeSignatureV1 {
                signer_pubkey: trusted[1],
                signature: k2.sign_bytes(&h.0),
            },
        ];

        a.verify_signatures_v1(&trusted, 2).expect("verify");
        assert!(a.verify_signatures_v1(&trusted, 3).is_err());
    }

    #[test]
    fn provider_emits_canonical_state_snapshot_with_provenance() {
        let signer1 = TokenSigningKey::from_seed(&[4u8; 32]);
        let signer2 = TokenSigningKey::from_seed(&[5u8; 32]);
        let members = vec![
            signer1.verifying_key().to_bytes(),
            signer2.verifying_key().to_bytes(),
        ];

        let spec_id = dummy_id(2);
        let schema = schema_for_outputs(
            spec_id,
            &[
                ("confidence_score", TauOutputValueTypeV1::UInt),
                ("recommendation_value", TauOutputValueTypeV1::UInt),
            ],
        );

        let mut a = attestation(
            dummy_id(1),
            spec_id,
            9,
            10,
            schema.output_schema_hash.clone(),
            vec![
                ("confidence_score".to_string(), Value::UInt(95)),
                ("recommendation_value".to_string(), Value::UInt(100)),
            ],
        );

        let h = a.attestation_hash_v1().expect("hash");
        a.signatures = vec![
            TauCommitteeSignatureV1 {
                signer_pubkey: members[0],
                signature: signer1.sign_bytes(&h.0),
            },
            TauCommitteeSignatureV1 {
                signer_pubkey: members[1],
                signature: signer2.sign_bytes(&h.0),
            },
        ];

        let provider = TauNetAttestedOutputStateProvider {
            attestation: a,
            committee: TauNetCommitteeConfigV1 {
                tau_instance_id: dummy_id(1),
                spec_id,
                members,
                threshold: 2,
                max_staleness_seconds: 1_000_000,
                max_future_skew_seconds: 0,
                committee_epoch: 9,
            },
            schema,
            replay_guard: None,
        };

        let state = provider.snapshot_with_now(100).expect("state");
        assert_ne!(state.state_hash, Hash32([0u8; 32]));
        assert_ne!(state.state_ref.state_source_id, Hash32([0u8; 32]));
        assert_ne!(state.state_ref.state_attestation_hash, Hash32([0u8; 32]));
        assert_eq!(state.state_ref.state_epoch, 10);
        assert!(state.policy_inputs.is_empty());
    }

    #[test]
    fn envelope_roundtrip_and_store_lookup() {
        let signer = TokenSigningKey::from_seed(&[6u8; 32]);
        let members = vec![signer.verifying_key().to_bytes()];

        let spec_id = dummy_id(7);
        let schema = schema_for_outputs(spec_id, &[("x", TauOutputValueTypeV1::UInt)]);
        let mut a = attestation(
            dummy_id(1),
            spec_id,
            1,
            1,
            schema.output_schema_hash.clone(),
            vec![("x".to_string(), Value::UInt(5))],
        );
        let h = a.attestation_hash_v1().expect("hash");
        a.signatures = vec![TauCommitteeSignatureV1 {
            signer_pubkey: members[0],
            signature: signer.sign_bytes(&h.0),
        }];

        let bytes = a.envelope_bytes_v1().expect("encode");
        let decoded = TauOutputAttestationV1::from_envelope_bytes_v1(&bytes).expect("decode");
        assert_eq!(decoded.attestation_hash_v1().unwrap(), h);

        let store = InMemoryTauOutputAttestationStore::new();
        let stored_hash = store.insert(bytes).expect("insert");
        assert_eq!(stored_hash, h);

        let provider = TauNetAttestedOutputStateProvider::from_store_v1(
            &store,
            &h,
            TauNetCommitteeConfigV1 {
                tau_instance_id: dummy_id(1),
                spec_id,
                members,
                threshold: 1,
                max_staleness_seconds: 1_000_000,
                max_future_skew_seconds: 0,
                committee_epoch: 1,
            },
            schema,
            None,
        )
        .expect("provider");

        let state = provider.snapshot_with_now(100).expect("state");
        assert_eq!(state.state_ref.state_attestation_hash, h);
    }

    proptest! {
        #[test]
        fn replay_guard_accepts_monotonic_hash_chain(
            tau_instance_id in any::<[u8; 32]>(),
            spec_id in any::<[u8; 32]>(),
            epochs in proptest::collection::vec(1u64..1000, 1..32),
            hashes in proptest::collection::vec(any::<[u8; 32]>(), 1..32),
        ) {
            let guard = InMemoryTauOutputReplayGuard::new();

            // Ensure we have matching lengths.
            let n = epochs.len().min(hashes.len());
            let epochs = &epochs[..n];
            let hashes = &hashes[..n];

            let mut prev = Hash32([0u8; 32]);
            let mut last_epoch = 0u64;

            for (epoch, h) in epochs.iter().zip(hashes.iter()) {
                let epoch = *epoch;
                // Make epochs strictly increasing.
                let epoch = if epoch <= last_epoch { last_epoch + 1 } else { epoch };
                let h = Hash32(*h);

                guard.check_and_record(&tau_instance_id, &spec_id, epoch, &prev, &h).expect("ok");
                prev = h;
                last_epoch = epoch;
            }
        }

        #[test]
        fn replay_guard_fails_closed_on_prev_hash_mismatch(
            tau_instance_id in any::<[u8; 32]>(),
            spec_id in any::<[u8; 32]>(),
            h1 in any::<[u8; 32]>(),
            h2 in any::<[u8; 32]>(),
        ) {
            let guard = InMemoryTauOutputReplayGuard::new();
            let h1 = Hash32(h1);
            let h2 = Hash32(h2);
            guard.check_and_record(&tau_instance_id, &spec_id, 1, &Hash32([0u8; 32]), &h1).expect("genesis ok");

            // Wrong prev hash for next epoch must fail.
            prop_assume!(h2 != h1);
            prop_assert!(guard.check_and_record(&tau_instance_id, &spec_id, 2, &h2, &Hash32([9u8; 32])).is_err());
        }

        #[test]
        fn replay_guard_fails_closed_on_epoch_replay(
            tau_instance_id in any::<[u8; 32]>(),
            spec_id in any::<[u8; 32]>(),
            h1 in any::<[u8; 32]>(),
        ) {
            let guard = InMemoryTauOutputReplayGuard::new();
            let h1 = Hash32(h1);
            guard.check_and_record(&tau_instance_id, &spec_id, 5, &Hash32([0u8; 32]), &h1).expect("ok");
            prop_assert!(guard.check_and_record(&tau_instance_id, &spec_id, 5, &h1, &Hash32([1u8; 32])).is_err());
            prop_assert!(guard.check_and_record(&tau_instance_id, &spec_id, 4, &h1, &Hash32([1u8; 32])).is_err());
        }

        #[test]
        fn validate_key_name_rejects_reserved_temporal_suffix(n in 0u64..1_000_000) {
            let key = format!("score_t_{n}");
            prop_assert!(validate_key_name(&key).is_err());
        }

        #[test]
        fn validate_key_name_accepts_lower_snake_case(key in "[a-z][a-z0-9_]{0,31}") {
            prop_assume!(!key.contains("_t_") || !key.rsplit_once("_t_").is_some_and(|(_, s)| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())));
            prop_assert!(validate_key_name(&key).is_ok());
        }
    }
}
