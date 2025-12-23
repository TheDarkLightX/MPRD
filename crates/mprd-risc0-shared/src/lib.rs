#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type Id32 = [u8; 32];

/// Journal ABI version; verifiers must reject unknown versions (fail-closed).
pub const JOURNAL_VERSION_V1: u32 = 1;
pub const JOURNAL_VERSION_V2: u32 = 2;
pub const JOURNAL_VERSION_V3: u32 = 3;
pub const JOURNAL_VERSION: u32 = JOURNAL_VERSION_V3;

/// mpb-v1 fuel semantics are pinned: the guest enforces this constant fuel limit per candidate.
pub const MPB_FUEL_LIMIT_V1: u32 = 10_000;

/// mpb-v1 input bounds (DoS resistance).
pub const MAX_POLICY_BYTECODE_BYTES_V1: usize = 64 * 1024;
pub const MAX_STATE_PREIMAGE_BYTES_V1: usize = 64 * 1024;
pub const MAX_CANDIDATE_PREIMAGE_BYTES_V1: usize = 16 * 1024;
pub const MAX_CANDIDATES_V1: usize = 64;
pub const MAX_POLICY_VARIABLES_V1: usize = 32;
/// tau_compiled_v1 compiled artifact bounds (DoS resistance).
pub const MAX_TCV_COMPILED_POLICY_BYTES_V1: usize = 64 * 1024;
pub const MAX_TCV_PREDICATES_V1: usize = 32;
pub const MAX_TCV_GATES_V1: usize = 4096;
pub const MAX_TCV_TEMPORAL_FIELDS_V1: usize = 16;
pub const MAX_TCV_TEMPORAL_LOOKBACK_V1: usize = 8;
pub const MAX_TCV_WIRES_V1: usize = MAX_TCV_GATES_V1 + 256;

/// Domain separation tags used in MPRD decision receipts.
pub mod domains {
    /// Domain for deriving fixed-size IDs from ASCII descriptors.
    pub const ID: &[u8] = b"MPRD_ID_V1";

    /// Domain for hashing canonical v1 state preimage bytes.
    pub const STATE_HASH_V1: &[u8] = b"MPRD_STATE_HASH_V1";

    /// Domain for hashing canonical v1 candidate preimage bytes.
    pub const CANDIDATE_HASH_V1: &[u8] = b"MPRD_CANDIDATE_HASH_V1";

    /// Domain for hashing canonical v1 candidate-set preimage bytes.
    pub const CANDIDATE_SET_HASH_V1: &[u8] = b"MPRD_CANDIDATE_SET_HASH_V1";

    /// Domain for hashing (possibly-empty) limits bytes into `limits_hash`.
    pub const LIMITS: &[u8] = b"MPRD_LIMITS_V1";

    /// Domain for the overall decision commitment.
    pub const DECISION_COMMITMENT: &[u8] = b"MPRD_DECISION_COMMITMENT_V1";
    pub const DECISION_COMMITMENT_V2: &[u8] = b"MPRD_DECISION_COMMITMENT_V2";
    pub const DECISION_COMMITMENT_V3: &[u8] = b"MPRD_DECISION_COMMITMENT_V3";

    /// Domain for hashing Tau-compiled policy artifact bytes into `policy_hash`.
    pub const TAU_COMPILED_POLICY_V1: &[u8] = b"MPRD_TAU_COMPILED_POLICY_V1";

    /// Domain for hashing operand key bytes in Tau-compiled policies.
    pub const KEY_V1: &[u8] = b"MPRD_KEY_V1";
}

/// Canonical limits encoding for v1.
pub mod limits {
    /// Tag for the mpb-v1 per-candidate fuel limit.
    pub const TAG_MPB_FUEL_LIMIT: u8 = 1;
}

/// Canonical ASCII descriptors (v1) for encoding and execution IDs.
///
/// These are used to derive fixed-size IDs via `id(domains::ID, descriptor)`.
pub mod descriptors {
    pub const STATE_ENCODING_V1: &[u8] = b"mprd.state.canonical_v1";
    pub const ACTION_ENCODING_V1: &[u8] = b"mprd.action.canonical_v1";

    pub const POLICY_EXEC_KIND_HOST_TRUSTED_V0: &[u8] = b"mprd.policy_exec.host_trusted_v0";
    pub const POLICY_EXEC_KIND_TAU_CLI_WFF: &[u8] = b"mprd.policy_exec.tau_cli_wff";
    pub const POLICY_EXEC_KIND_MPB_V1: &[u8] = b"mprd.policy_exec.mpb_v1";
    pub const POLICY_EXEC_KIND_TAU_COMPILED_V1: &[u8] = b"mprd.policy_exec.tau_compiled_v1";

    pub const POLICY_EXEC_VERSION_V1: &[u8] = b"v1";

    /// Canonical mapping from MPRD state/action encodings to MPB registers.
    pub const MPB_REGISTER_MAPPING_V1: &[u8] = b"mprd.mpb.register_mapping.v1";

    /// Policy source kind ID for Tau source bytes (audit-only mapping).
    pub const POLICY_SOURCE_KIND_TAU_V1: &[u8] = b"mprd.policy_source.tau_v1";
}

/// Compute SHA-256 over a byte slice.
pub fn sha256(data: &[u8]) -> Id32 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute domain-separated SHA-256: `H(domain || data)`.
pub fn sha256_domain(domain: &[u8], data: &[u8]) -> Id32 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(data);
    hasher.finalize().into()
}

/// Derive a fixed-size ID for a descriptor (domain-separated).
pub fn id(domain: &[u8], descriptor: &[u8]) -> Id32 {
    sha256_domain(domain, descriptor)
}

pub fn state_encoding_id_v1() -> Id32 {
    id(domains::ID, descriptors::STATE_ENCODING_V1)
}

pub fn action_encoding_id_v1() -> Id32 {
    id(domains::ID, descriptors::ACTION_ENCODING_V1)
}

pub fn policy_exec_kind_tau_cli_wff_id_v1() -> Id32 {
    id(domains::ID, descriptors::POLICY_EXEC_KIND_TAU_CLI_WFF)
}

pub fn policy_exec_kind_host_trusted_id_v0() -> Id32 {
    id(domains::ID, descriptors::POLICY_EXEC_KIND_HOST_TRUSTED_V0)
}

pub fn policy_exec_kind_mpb_id_v1() -> Id32 {
    id(domains::ID, descriptors::POLICY_EXEC_KIND_MPB_V1)
}

pub fn policy_exec_kind_tau_compiled_id_v1() -> Id32 {
    id(domains::ID, descriptors::POLICY_EXEC_KIND_TAU_COMPILED_V1)
}

pub fn policy_exec_version_id_v1() -> Id32 {
    id(domains::ID, descriptors::POLICY_EXEC_VERSION_V1)
}

pub fn mpb_register_mapping_id_v1() -> Id32 {
    id(domains::ID, descriptors::MPB_REGISTER_MAPPING_V1)
}

pub fn policy_source_kind_tau_id_v1() -> Id32 {
    id(domains::ID, descriptors::POLICY_SOURCE_KIND_TAU_V1)
}

pub fn limits_hash(limits_bytes: &[u8]) -> Id32 {
    sha256_domain(domains::LIMITS, limits_bytes)
}

pub fn tau_compiled_policy_hash_v1(compiled_policy_bytes: &[u8]) -> Id32 {
    sha256_domain(domains::TAU_COMPILED_POLICY_V1, compiled_policy_bytes)
}

pub fn tcv_key_hash_v1(key_bytes: &[u8]) -> Id32 {
    sha256_domain(domains::KEY_V1, key_bytes)
}

/// Hash canonical v1 state preimage bytes into `state_hash` (domain-separated).
pub fn hash_state_preimage_v1(state_preimage: &[u8]) -> Id32 {
    sha256_domain(domains::STATE_HASH_V1, state_preimage)
}

/// Hash canonical v1 candidate preimage bytes into `chosen_action_hash` / candidate hashes (domain-separated).
pub fn hash_candidate_preimage_v1(candidate_preimage: &[u8]) -> Id32 {
    sha256_domain(domains::CANDIDATE_HASH_V1, candidate_preimage)
}

/// Hash canonical v1 candidate-set preimage bytes into `candidate_set_hash` (domain-separated).
pub fn hash_candidate_set_preimage_v1(candidate_set_preimage: &[u8]) -> Id32 {
    sha256_domain(domains::CANDIDATE_SET_HASH_V1, candidate_set_preimage)
}

/// Canonical limits bytes for `mpb-v1` (currently only the pinned fuel limit).
pub fn limits_bytes_mpb_v1() -> [u8; 1 + 4] {
    let mut out = [0u8; 5];
    out[0] = limits::TAG_MPB_FUEL_LIMIT;
    out[1..].copy_from_slice(&MPB_FUEL_LIMIT_V1.to_le_bytes());
    out
}

pub fn limits_hash_mpb_v1() -> Id32 {
    limits_hash(&limits_bytes_mpb_v1())
}

/// Input written by the host into the guest (private witness).
///
/// Notes:
/// - Fixed-width IDs/hashes are used for all transcript commitments.
/// - Preimage blobs are used so the guest can recompute the same hashes as `mprd-core` without
///   needing to decode hash maps in `no_std`.
/// - `chosen_index` is `u32` (no `usize` in ABI).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestInputV1 {
    pub policy_hash: Id32,
    pub policy_exec_kind_id: Id32,
    pub policy_exec_version_id: Id32,
    pub state_encoding_id: Id32,
    pub action_encoding_id: Id32,
    pub nonce_or_tx_hash: Id32,

    pub chosen_index: u32,
    pub chosen_verdict_allowed: bool,

    /// Preimage bytes for `state_hash` (must match `mprd-core::hash_state` preimage).
    pub state_preimage: Vec<u8>,

    /// Preimage bytes for `candidate_set_hash` (must match `mprd-core::hash_candidate_set` preimage).
    pub candidate_set_preimage: Vec<u8>,

    /// Preimage bytes for `chosen_action_hash` (must match `mprd-core::hash_candidate` preimage).
    pub chosen_action_preimage: Vec<u8>,

    /// Canonical limits bytes; may be empty. The guest commits `limits_hash = H(LIMITS || limits_bytes)`.
    pub limits_bytes: Vec<u8>,
}

/// Input written by the host into the guest (private witness) for journal ABI v2.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestInputV2 {
    pub policy_hash: Id32,
    pub policy_exec_kind_id: Id32,
    pub policy_exec_version_id: Id32,
    pub state_encoding_id: Id32,
    pub action_encoding_id: Id32,
    pub nonce_or_tx_hash: Id32,

    /// Policy authorization context (epoch/root).
    pub policy_epoch: u64,
    pub registry_root: Id32,

    pub chosen_index: u32,
    pub chosen_verdict_allowed: bool,

    pub state_preimage: Vec<u8>,
    pub candidate_set_preimage: Vec<u8>,
    pub chosen_action_preimage: Vec<u8>,

    pub limits_bytes: Vec<u8>,
}

/// Input written by the host into the guest (private witness) for journal ABI v3.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestInputV3 {
    pub policy_hash: Id32,
    pub policy_exec_kind_id: Id32,
    pub policy_exec_version_id: Id32,
    pub state_encoding_id: Id32,
    pub action_encoding_id: Id32,
    pub nonce_or_tx_hash: Id32,

    /// Policy authorization context (epoch/root).
    pub policy_epoch: u64,
    pub registry_root: Id32,

    /// State provenance context (source/epoch/attestation commitment).
    pub state_source_id: Id32,
    pub state_epoch: u64,
    pub state_attestation_hash: Id32,

    pub chosen_index: u32,
    pub chosen_verdict_allowed: bool,

    pub state_preimage: Vec<u8>,
    pub candidate_set_preimage: Vec<u8>,
    pub chosen_action_preimage: Vec<u8>,

    pub limits_bytes: Vec<u8>,
}

/// Variable binding used by MPB policies: `name -> reg`.
///
/// `name` must be valid UTF-8; verifiers/guests must reject invalid encodings (fail-closed).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpbVarBindingV1 {
    pub name: Vec<u8>,
    pub reg: u8,
}

/// Input written by the host into the MPB guest (private witness).
///
/// Notes:
/// - The MPB guest must recompute `policy_hash` from `policy_bytecode` + `policy_variables`.
/// - The MPB guest must evaluate all candidates, run deterministic selection, and set
///   `allowed=true` only if the selector contract is satisfied.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpbGuestInputV1 {
    pub policy_exec_kind_id: Id32,
    pub policy_exec_version_id: Id32,
    pub mpb_register_mapping_id: Id32,
    pub state_encoding_id: Id32,
    pub action_encoding_id: Id32,
    pub nonce_or_tx_hash: Id32,

    /// Fuel limit per candidate evaluation.
    pub mpb_fuel_limit: u32,

    /// MPB policy bytecode.
    pub policy_bytecode: Vec<u8>,

    /// Canonical variable bindings for the policy, in ascending `name` order.
    pub policy_variables: Vec<MpbVarBindingV1>,

    /// Canonical state encoding bytes (hash preimage).
    pub state_preimage: Vec<u8>,

    /// Canonical action encodings for all candidates (each is a candidate hash preimage).
    pub candidates_preimages: Vec<Vec<u8>>,
}

/// Input written by the host into the MPB guest (private witness) for journal ABI v2.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpbGuestInputV2 {
    pub policy_exec_kind_id: Id32,
    pub policy_exec_version_id: Id32,
    pub mpb_register_mapping_id: Id32,
    pub state_encoding_id: Id32,
    pub action_encoding_id: Id32,
    pub nonce_or_tx_hash: Id32,

    /// Policy authorization context (epoch/root).
    pub policy_epoch: u64,
    pub registry_root: Id32,

    pub mpb_fuel_limit: u32,
    pub policy_bytecode: Vec<u8>,
    pub policy_variables: Vec<MpbVarBindingV1>,
    pub state_preimage: Vec<u8>,
    pub candidates_preimages: Vec<Vec<u8>>,
}

/// Input written by the host into the MPB guest (private witness) for journal ABI v3.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpbGuestInputV3 {
    pub policy_exec_kind_id: Id32,
    pub policy_exec_version_id: Id32,
    pub mpb_register_mapping_id: Id32,
    pub state_encoding_id: Id32,
    pub action_encoding_id: Id32,
    pub nonce_or_tx_hash: Id32,

    /// Policy authorization context (epoch/root).
    pub policy_epoch: u64,
    pub registry_root: Id32,

    /// State provenance context (source/epoch/attestation commitment).
    pub state_source_id: Id32,
    pub state_epoch: u64,
    pub state_attestation_hash: Id32,

    pub mpb_fuel_limit: u32,
    pub policy_bytecode: Vec<u8>,
    pub policy_variables: Vec<MpbVarBindingV1>,
    pub state_preimage: Vec<u8>,
    pub candidates_preimages: Vec<Vec<u8>>,
}

/// Value kind for type-safe extraction in Tau-compiled policies (fail-closed on mismatch).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcvValueKindV1 {
    /// Expect `Value::UInt(u64)` in canonical preimages.
    U64 = 0,
    /// Reserved for future use (not supported in v1).
    I64 = 1,
    /// Expect `Value::Bool(bool)` in canonical preimages.
    Bool = 2,
}

/// Operand source for Tau-compiled policies.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcvOperandSourceV1 {
    State = 0,
    Candidate = 1,
    Constant = 2,
}

/// Operand path for Tau-compiled policies (key-hash addressing, MPRD-compatible).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcvOperandPathV1 {
    pub source: TcvOperandSourceV1,
    pub key_hash: Id32,
    pub value_kind: TcvValueKindV1,
    /// For constants: u64 LE in v1.
    pub constant_value: [u8; 8],
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcvArithOpV1 {
    LessThan = 0,
    LessThanEq = 1,
    GreaterThan = 2,
    GreaterThanEq = 3,
    Equals = 4,
    NotEquals = 5,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcvPredicateSpecV1 {
    pub predicate_idx: u32,
    pub op: TcvArithOpV1,
    pub left: TcvOperandPathV1,
    pub right: TcvOperandPathV1,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcvGateTypeV1 {
    And = 0,
    Or = 1,
    Not = 2,
    PredicateInput = 3,
    TemporalInput = 4,
    Constant = 5,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcvGateV1 {
    pub gate_type: TcvGateTypeV1,
    pub out_wire: u32,
    pub in1: u32,
    pub in2: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcvTemporalFieldSpecV1 {
    pub field_idx: u32,
    pub current_key_hash: Id32,
    pub prev_key_hashes: Vec<Id32>,
}

/// Compiled Tau policy artifact for `tau_compiled_v1`.
///
/// Note: The proof statement binds to the canonical bytes of this structure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledTauPolicyV1 {
    pub version: u32,
    pub predicates: Vec<TcvPredicateSpecV1>,
    pub gates: Vec<TcvGateV1>,
    pub output_wire: u32,
    pub temporal_fields: Vec<TcvTemporalFieldSpecV1>,
}

/// Evaluate a validated Tau-compiled circuit over up to 64 candidates using `u64` bitsets.
///
/// - `predicate_bits[p]` is a `u64` mask where bit `i` is candidate `i`'s predicate value.
/// - `temporal_value(field_idx, lookback)` returns the (candidate-invariant) temporal boolean.
///
/// This function assumes the circuit is well-formed (e.g. produced by
/// `decode_compiled_tau_policy_v1`, which validates wiring). Any violation will panic in
/// `no_std` contexts, which is acceptable for fail-closed proving.
pub fn tcv_eval_circuit_bitset_v1_validated<F: Fn(u32, u32) -> bool>(
    policy: &CompiledTauPolicyV1,
    predicate_bits: &[u64],
    mask: u64,
    temporal_value: F,
) -> u64 {
    let mut max_wire: u32 = policy.output_wire;
    for g in &policy.gates {
        max_wire = max_wire.max(g.out_wire);
        match g.gate_type {
            TcvGateTypeV1::And | TcvGateTypeV1::Or => {
                max_wire = max_wire.max(g.in1).max(g.in2);
            }
            TcvGateTypeV1::Not => {
                max_wire = max_wire.max(g.in1);
            }
            _ => {}
        }
    }
    assert!((max_wire as usize) < MAX_TCV_WIRES_V1);

    let mut wires: Vec<u64> = vec![0u64; (max_wire + 1) as usize];

    for g in &policy.gates {
        let out = g.out_wire as usize;
        match g.gate_type {
            TcvGateTypeV1::PredicateInput => {
                let pred_idx = g.in1 as usize;
                wires[out] = predicate_bits[pred_idx] & mask;
            }
            TcvGateTypeV1::Constant => {
                wires[out] = if g.in1 == 1 { mask } else { 0 };
            }
            TcvGateTypeV1::TemporalInput => {
                wires[out] = if temporal_value(g.in1, g.in2) {
                    mask
                } else {
                    0
                };
            }
            TcvGateTypeV1::And => {
                wires[out] = wires[g.in1 as usize] & wires[g.in2 as usize];
            }
            TcvGateTypeV1::Or => {
                wires[out] = wires[g.in1 as usize] | wires[g.in2 as usize];
            }
            TcvGateTypeV1::Not => {
                wires[out] = (!wires[g.in1 as usize]) & mask;
            }
        }
    }

    wires[policy.output_wire as usize] & mask
}

/// Scalar (single-candidate) evaluator for validated Tau-compiled circuits.
pub fn tcv_eval_circuit_scalar_v1_validated<F: Fn(u32, u32) -> bool>(
    policy: &CompiledTauPolicyV1,
    predicate_results: &[bool],
    temporal_value: F,
) -> bool {
    let mut max_wire: u32 = policy.output_wire;
    for g in &policy.gates {
        max_wire = max_wire.max(g.out_wire);
        match g.gate_type {
            TcvGateTypeV1::And | TcvGateTypeV1::Or => {
                max_wire = max_wire.max(g.in1).max(g.in2);
            }
            TcvGateTypeV1::Not => {
                max_wire = max_wire.max(g.in1);
            }
            _ => {}
        }
    }
    assert!((max_wire as usize) < MAX_TCV_WIRES_V1);

    let mut wires: Vec<bool> = vec![false; (max_wire + 1) as usize];

    for g in &policy.gates {
        let out = g.out_wire as usize;
        match g.gate_type {
            TcvGateTypeV1::PredicateInput => {
                wires[out] = predicate_results[g.in1 as usize];
            }
            TcvGateTypeV1::Constant => {
                wires[out] = g.in1 == 1;
            }
            TcvGateTypeV1::TemporalInput => {
                wires[out] = temporal_value(g.in1, g.in2);
            }
            TcvGateTypeV1::And => {
                wires[out] = wires[g.in1 as usize] && wires[g.in2 as usize];
            }
            TcvGateTypeV1::Or => {
                wires[out] = wires[g.in1 as usize] || wires[g.in2 as usize];
            }
            TcvGateTypeV1::Not => {
                wires[out] = !wires[g.in1 as usize];
            }
        }
    }

    wires[policy.output_wire as usize]
}

/// Input written by the host into the Tau-compiled guest (private witness) for journal ABI v3.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TauCompiledGuestInputV3 {
    pub policy_exec_kind_id: Id32,
    pub policy_exec_version_id: Id32,
    pub state_encoding_id: Id32,
    pub action_encoding_id: Id32,
    pub nonce_or_tx_hash: Id32,

    /// Policy authorization context (epoch/root).
    pub policy_epoch: u64,
    pub registry_root: Id32,

    /// State provenance context (source/epoch/attestation commitment).
    pub state_source_id: Id32,
    pub state_epoch: u64,
    pub state_attestation_hash: Id32,

    /// Canonical compiled artifact bytes (policy_hash = H(MPRD_TAU_COMPILED_POLICY_V1 || bytes)).
    pub compiled_policy_bytes: Vec<u8>,

    /// Canonical state encoding bytes (hash preimage).
    pub state_preimage: Vec<u8>,

    /// Canonical action encodings for all candidates (each is a candidate hash preimage).
    pub candidates_preimages: Vec<Vec<u8>>,

    /// Canonical limits bytes; may be empty.
    pub limits_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcvDecodeError {
    Truncated,
    TrailingBytes,
    UnsupportedVersion,
    TooLarge,
    TooManyPredicates,
    TooManyGates,
    TooManyTemporalFields,
    LookbackExceeded,
    InvalidEnumTag,
    InvalidWiring,
    ReservedValueKind,
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, TcvDecodeError> {
    if *cursor >= bytes.len() {
        return Err(TcvDecodeError::Truncated);
    }
    let v = bytes[*cursor];
    *cursor += 1;
    Ok(v)
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, TcvDecodeError> {
    if *cursor + 4 > bytes.len() {
        return Err(TcvDecodeError::Truncated);
    }
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(&bytes[*cursor..*cursor + 4]);
    *cursor += 4;
    Ok(u32::from_le_bytes(tmp))
}

fn read_bytes<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], TcvDecodeError> {
    if *cursor + N > bytes.len() {
        return Err(TcvDecodeError::Truncated);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

/// Decode canonical `CompiledTauPolicyV1` bytes (fail-closed).
pub fn decode_compiled_tau_policy_v1(bytes: &[u8]) -> Result<CompiledTauPolicyV1, TcvDecodeError> {
    if bytes.len() > MAX_TCV_COMPILED_POLICY_BYTES_V1 {
        return Err(TcvDecodeError::TooLarge);
    }
    let mut cursor = 0usize;
    let version = read_u32(bytes, &mut cursor)?;
    if version != 1 {
        return Err(TcvDecodeError::UnsupportedVersion);
    }

    let predicate_count = read_u32(bytes, &mut cursor)? as usize;
    if predicate_count > MAX_TCV_PREDICATES_V1 {
        return Err(TcvDecodeError::TooManyPredicates);
    }
    let mut predicates = Vec::with_capacity(predicate_count);
    let mut prev_pred: Option<u32> = None;
    for _ in 0..predicate_count {
        let predicate_idx = read_u32(bytes, &mut cursor)?;
        if let Some(p) = prev_pred {
            if predicate_idx <= p {
                return Err(TcvDecodeError::InvalidEnumTag);
            }
        }
        prev_pred = Some(predicate_idx);

        let op = match read_u8(bytes, &mut cursor)? {
            0 => TcvArithOpV1::LessThan,
            1 => TcvArithOpV1::LessThanEq,
            2 => TcvArithOpV1::GreaterThan,
            3 => TcvArithOpV1::GreaterThanEq,
            4 => TcvArithOpV1::Equals,
            5 => TcvArithOpV1::NotEquals,
            _ => return Err(TcvDecodeError::InvalidEnumTag),
        };

        let left = decode_operand_path(bytes, &mut cursor)?;
        let right = decode_operand_path(bytes, &mut cursor)?;
        predicates.push(TcvPredicateSpecV1 {
            predicate_idx,
            op,
            left,
            right,
        });
    }

    let gate_count = read_u32(bytes, &mut cursor)? as usize;
    if gate_count > MAX_TCV_GATES_V1 {
        return Err(TcvDecodeError::TooManyGates);
    }
    let mut gates = Vec::with_capacity(gate_count);
    for _ in 0..gate_count {
        let gate_type = match read_u8(bytes, &mut cursor)? {
            0 => TcvGateTypeV1::And,
            1 => TcvGateTypeV1::Or,
            2 => TcvGateTypeV1::Not,
            3 => TcvGateTypeV1::PredicateInput,
            4 => TcvGateTypeV1::TemporalInput,
            5 => TcvGateTypeV1::Constant,
            _ => return Err(TcvDecodeError::InvalidEnumTag),
        };
        let out_wire = read_u32(bytes, &mut cursor)?;
        let in1 = read_u32(bytes, &mut cursor)?;
        let in2 = read_u32(bytes, &mut cursor)?;
        gates.push(TcvGateV1 {
            gate_type,
            out_wire,
            in1,
            in2,
        });
    }

    let output_wire = read_u32(bytes, &mut cursor)?;

    let tf_count = read_u32(bytes, &mut cursor)? as usize;
    if tf_count > MAX_TCV_TEMPORAL_FIELDS_V1 {
        return Err(TcvDecodeError::TooManyTemporalFields);
    }
    let mut temporal_fields = Vec::with_capacity(tf_count);
    let mut prev_tf: Option<u32> = None;
    for _ in 0..tf_count {
        let field_idx = read_u32(bytes, &mut cursor)?;
        if let Some(p) = prev_tf {
            if field_idx <= p {
                return Err(TcvDecodeError::InvalidEnumTag);
            }
        }
        prev_tf = Some(field_idx);

        let current_key_hash = read_bytes::<32>(bytes, &mut cursor)?;
        let prev_count = read_u32(bytes, &mut cursor)? as usize;
        if prev_count > MAX_TCV_TEMPORAL_LOOKBACK_V1 {
            return Err(TcvDecodeError::LookbackExceeded);
        }
        let mut prev_key_hashes = Vec::with_capacity(prev_count);
        for _ in 0..prev_count {
            prev_key_hashes.push(read_bytes::<32>(bytes, &mut cursor)?);
        }
        temporal_fields.push(TcvTemporalFieldSpecV1 {
            field_idx,
            current_key_hash,
            prev_key_hashes,
        });
    }

    if cursor != bytes.len() {
        return Err(TcvDecodeError::TrailingBytes);
    }

    // Fail-closed: ensure the gate list is well-formed and evaluable as a straight-line circuit.
    //
    // This prevents:
    // - duplicate writes to the same wire,
    // - referencing wires before they are written,
    // - out-of-range predicate/temporal references,
    // - or oversized wire indices (DoS).
    {
        let mut max_wire: u32 = output_wire;
        for g in &gates {
            max_wire = max_wire.max(g.out_wire);
            match g.gate_type {
                TcvGateTypeV1::And | TcvGateTypeV1::Or => {
                    max_wire = max_wire.max(g.in1).max(g.in2);
                }
                TcvGateTypeV1::Not => {
                    max_wire = max_wire.max(g.in1);
                }
                _ => {}
            }
        }
        if (max_wire as usize) >= MAX_TCV_WIRES_V1 {
            return Err(TcvDecodeError::InvalidWiring);
        }

        let mut written: Vec<bool> = vec![false; (max_wire + 1) as usize];
        for g in &gates {
            let out = g.out_wire as usize;
            if out >= written.len() || written[out] {
                return Err(TcvDecodeError::InvalidWiring);
            }
            match g.gate_type {
                TcvGateTypeV1::PredicateInput => {
                    if (g.in1 as usize) >= predicate_count {
                        return Err(TcvDecodeError::InvalidWiring);
                    }
                }
                TcvGateTypeV1::Constant => {
                    if g.in1 != 0 && g.in1 != 1 {
                        return Err(TcvDecodeError::InvalidWiring);
                    }
                }
                TcvGateTypeV1::TemporalInput => {
                    let field_idx = g.in1 as usize;
                    if field_idx >= temporal_fields.len() {
                        return Err(TcvDecodeError::InvalidWiring);
                    }
                    let lookback = g.in2 as usize;
                    if lookback > temporal_fields[field_idx].prev_key_hashes.len() {
                        return Err(TcvDecodeError::InvalidWiring);
                    }
                }
                TcvGateTypeV1::And | TcvGateTypeV1::Or => {
                    let in1 = g.in1 as usize;
                    let in2 = g.in2 as usize;
                    if in1 >= written.len()
                        || in2 >= written.len()
                        || !written[in1]
                        || !written[in2]
                    {
                        return Err(TcvDecodeError::InvalidWiring);
                    }
                }
                TcvGateTypeV1::Not => {
                    let in1 = g.in1 as usize;
                    if in1 >= written.len() || !written[in1] {
                        return Err(TcvDecodeError::InvalidWiring);
                    }
                }
            }
            written[out] = true;
        }

        let out = output_wire as usize;
        if out >= written.len() || !written[out] {
            return Err(TcvDecodeError::InvalidWiring);
        }
    }

    Ok(CompiledTauPolicyV1 {
        version,
        predicates,
        gates,
        output_wire,
        temporal_fields,
    })
}

fn decode_operand_path(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<TcvOperandPathV1, TcvDecodeError> {
    let source = match read_u8(bytes, cursor)? {
        0 => TcvOperandSourceV1::State,
        1 => TcvOperandSourceV1::Candidate,
        2 => TcvOperandSourceV1::Constant,
        _ => return Err(TcvDecodeError::InvalidEnumTag),
    };
    let key_hash = read_bytes::<32>(bytes, cursor)?;
    let value_kind = match read_u8(bytes, cursor)? {
        0 => TcvValueKindV1::U64,
        1 => return Err(TcvDecodeError::ReservedValueKind),
        2 => TcvValueKindV1::Bool,
        _ => return Err(TcvDecodeError::InvalidEnumTag),
    };
    let constant_value = read_bytes::<8>(bytes, cursor)?;
    Ok(TcvOperandPathV1 {
        source,
        key_hash,
        value_kind,
        constant_value,
    })
}

/// Journal committed by the guest (public output).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestJournalV1 {
    pub journal_version: u32,

    pub policy_hash: Id32,
    pub policy_exec_kind_id: Id32,
    pub policy_exec_version_id: Id32,
    pub state_encoding_id: Id32,
    pub action_encoding_id: Id32,

    pub state_hash: Id32,
    pub candidate_set_hash: Id32,
    pub chosen_action_hash: Id32,
    pub limits_hash: Id32,
    pub nonce_or_tx_hash: Id32,

    pub chosen_index: u32,
    pub allowed: bool,

    pub decision_commitment: Id32,
}

/// Journal committed by the guest (public output), ABI v2.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestJournalV2 {
    pub journal_version: u32,

    pub policy_hash: Id32,
    pub policy_exec_kind_id: Id32,
    pub policy_exec_version_id: Id32,
    pub state_encoding_id: Id32,
    pub action_encoding_id: Id32,

    /// Policy authorization context (epoch/root).
    pub policy_epoch: u64,
    pub registry_root: Id32,

    pub state_hash: Id32,
    pub candidate_set_hash: Id32,
    pub chosen_action_hash: Id32,
    pub limits_hash: Id32,
    pub nonce_or_tx_hash: Id32,

    pub chosen_index: u32,
    pub allowed: bool,

    pub decision_commitment: Id32,
}

/// Journal committed by the guest (public output), ABI v3.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestJournalV3 {
    pub journal_version: u32,

    pub policy_hash: Id32,
    pub policy_exec_kind_id: Id32,
    pub policy_exec_version_id: Id32,
    pub state_encoding_id: Id32,
    pub action_encoding_id: Id32,

    /// Policy authorization context (epoch/root).
    pub policy_epoch: u64,
    pub registry_root: Id32,

    /// State provenance context (source/epoch/attestation commitment).
    pub state_source_id: Id32,
    pub state_epoch: u64,
    pub state_attestation_hash: Id32,

    pub state_hash: Id32,
    pub candidate_set_hash: Id32,
    pub chosen_action_hash: Id32,
    pub limits_hash: Id32,
    pub nonce_or_tx_hash: Id32,

    pub chosen_index: u32,
    pub allowed: bool,

    pub decision_commitment: Id32,
}

pub fn compute_decision_commitment_v1(j: &GuestJournalV1) -> Id32 {
    // Canonical ordering: domain || journal_version || ids/hashes || chosen_index || allowed
    let mut hasher = Sha256::new();
    hasher.update(domains::DECISION_COMMITMENT);
    update_decision_commitment_common_v1_fields(
        &mut hasher,
        DecisionCommitmentCommonV1Fields {
            journal_version: j.journal_version,
            policy_hash: &j.policy_hash,
            policy_exec_kind_id: &j.policy_exec_kind_id,
            policy_exec_version_id: &j.policy_exec_version_id,
            state_encoding_id: &j.state_encoding_id,
            action_encoding_id: &j.action_encoding_id,
            state_hash: &j.state_hash,
            candidate_set_hash: &j.candidate_set_hash,
            chosen_action_hash: &j.chosen_action_hash,
            limits_hash: &j.limits_hash,
            nonce_or_tx_hash: &j.nonce_or_tx_hash,
            chosen_index: j.chosen_index,
            allowed: j.allowed,
        },
    );
    hasher.finalize().into()
}

pub fn compute_decision_commitment_v2(j: &GuestJournalV2) -> Id32 {
    let mut hasher = Sha256::new();
    hasher.update(domains::DECISION_COMMITMENT_V2);
    hasher.update(j.policy_epoch.to_le_bytes());
    hasher.update(j.registry_root);
    update_decision_commitment_common_v1_fields(
        &mut hasher,
        DecisionCommitmentCommonV1Fields {
            journal_version: j.journal_version,
            policy_hash: &j.policy_hash,
            policy_exec_kind_id: &j.policy_exec_kind_id,
            policy_exec_version_id: &j.policy_exec_version_id,
            state_encoding_id: &j.state_encoding_id,
            action_encoding_id: &j.action_encoding_id,
            state_hash: &j.state_hash,
            candidate_set_hash: &j.candidate_set_hash,
            chosen_action_hash: &j.chosen_action_hash,
            limits_hash: &j.limits_hash,
            nonce_or_tx_hash: &j.nonce_or_tx_hash,
            chosen_index: j.chosen_index,
            allowed: j.allowed,
        },
    );
    hasher.finalize().into()
}

pub fn compute_decision_commitment_v3(j: &GuestJournalV3) -> Id32 {
    let mut hasher = Sha256::new();
    hasher.update(domains::DECISION_COMMITMENT_V3);
    hasher.update(j.policy_epoch.to_le_bytes());
    hasher.update(j.registry_root);
    hasher.update(j.state_source_id);
    hasher.update(j.state_epoch.to_le_bytes());
    hasher.update(j.state_attestation_hash);
    update_decision_commitment_common_v1_fields(
        &mut hasher,
        DecisionCommitmentCommonV1Fields {
            journal_version: j.journal_version,
            policy_hash: &j.policy_hash,
            policy_exec_kind_id: &j.policy_exec_kind_id,
            policy_exec_version_id: &j.policy_exec_version_id,
            state_encoding_id: &j.state_encoding_id,
            action_encoding_id: &j.action_encoding_id,
            state_hash: &j.state_hash,
            candidate_set_hash: &j.candidate_set_hash,
            chosen_action_hash: &j.chosen_action_hash,
            limits_hash: &j.limits_hash,
            nonce_or_tx_hash: &j.nonce_or_tx_hash,
            chosen_index: j.chosen_index,
            allowed: j.allowed,
        },
    );
    hasher.finalize().into()
}

struct DecisionCommitmentCommonV1Fields<'a> {
    journal_version: u32,
    policy_hash: &'a Id32,
    policy_exec_kind_id: &'a Id32,
    policy_exec_version_id: &'a Id32,
    state_encoding_id: &'a Id32,
    action_encoding_id: &'a Id32,
    state_hash: &'a Id32,
    candidate_set_hash: &'a Id32,
    chosen_action_hash: &'a Id32,
    limits_hash: &'a Id32,
    nonce_or_tx_hash: &'a Id32,
    chosen_index: u32,
    allowed: bool,
}

fn update_decision_commitment_common_v1_fields(
    hasher: &mut Sha256,
    fields: DecisionCommitmentCommonV1Fields<'_>,
) {
    hasher.update(fields.journal_version.to_le_bytes());
    hasher.update(fields.policy_hash);
    hasher.update(fields.policy_exec_kind_id);
    hasher.update(fields.policy_exec_version_id);
    hasher.update(fields.state_encoding_id);
    hasher.update(fields.action_encoding_id);
    hasher.update(fields.state_hash);
    hasher.update(fields.candidate_set_hash);
    hasher.update(fields.chosen_action_hash);
    hasher.update(fields.limits_hash);
    hasher.update(fields.nonce_or_tx_hash);
    hasher.update(fields.chosen_index.to_le_bytes());
    hasher.update([fields.allowed as u8]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn gate(tag: u8, out_wire: u32, in1: u32, in2: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(tag);
        v.extend_from_slice(&out_wire.to_le_bytes());
        v.extend_from_slice(&in1.to_le_bytes());
        v.extend_from_slice(&in2.to_le_bytes());
        v
    }

    fn encode_compiled_tau_policy_v1_for_tests(
        predicate_count: u32,
        gates: Vec<u8>,
        output_wire: u32,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1u32.to_le_bytes()); // version
        out.extend_from_slice(&predicate_count.to_le_bytes());

        // Emit `predicate_count` dummy predicate specs (sorted).
        for idx in 0..predicate_count {
            out.extend_from_slice(&idx.to_le_bytes()); // predicate_idx
            out.push(4u8); // Equals

            // left operand: constant u64 1
            out.push(2u8); // source=Constant
            out.extend_from_slice(&[0u8; 32]); // key_hash (unused)
            out.push(0u8); // value_kind=U64
            out.extend_from_slice(&1u64.to_le_bytes()); // constant_value

            // right operand: constant u64 1
            out.push(2u8);
            out.extend_from_slice(&[0u8; 32]);
            out.push(0u8);
            out.extend_from_slice(&1u64.to_le_bytes());
        }

        // Gates.
        let gate_count: u32 = (gates.len() / 13)
            .try_into()
            .expect("gate_count must fit u32");
        out.extend_from_slice(&gate_count.to_le_bytes());
        out.extend_from_slice(&gates);

        // Output wire.
        out.extend_from_slice(&output_wire.to_le_bytes());

        // Temporal fields (none for tests here).
        out.extend_from_slice(&0u32.to_le_bytes());

        out
    }

    #[test]
    fn decode_compiled_tau_policy_v1_accepts_minimal_well_formed_policy() {
        let mut gates = Vec::new();
        gates.extend_from_slice(&gate(3, 0, 0, 0)); // PredicateInput -> output wire 0
        let bytes = encode_compiled_tau_policy_v1_for_tests(1, gates, 0);
        let decoded = decode_compiled_tau_policy_v1(&bytes).expect("decode");
        assert_eq!(decoded.predicates.len(), 1);
        assert_eq!(decoded.gates.len(), 1);
        assert_eq!(decoded.output_wire, 0);
    }

    #[test]
    fn decode_compiled_tau_policy_v1_rejects_duplicate_out_wires() {
        let mut gates = Vec::new();
        gates.extend_from_slice(&gate(3, 0, 0, 0)); // PredicateInput -> wire 0
        gates.extend_from_slice(&gate(5, 0, 1, 0)); // Constant -> wire 0 (duplicate)
        let bytes = encode_compiled_tau_policy_v1_for_tests(1, gates, 0);
        let err = decode_compiled_tau_policy_v1(&bytes).expect_err("must reject");
        assert!(matches!(err, TcvDecodeError::InvalidWiring));
    }

    #[test]
    fn decode_compiled_tau_policy_v1_rejects_unwritten_wire_inputs() {
        let mut gates = Vec::new();
        gates.extend_from_slice(&gate(3, 0, 0, 0)); // PredicateInput -> wire 0
        gates.extend_from_slice(&gate(0, 1, 0, 2)); // And -> wire 1, references wire 2 (unwritten)
        let bytes = encode_compiled_tau_policy_v1_for_tests(1, gates, 1);
        let err = decode_compiled_tau_policy_v1(&bytes).expect_err("must reject");
        assert!(matches!(err, TcvDecodeError::InvalidWiring));
    }

    fn prng_next(state: &mut u64) -> u64 {
        // xorshift64*
        let mut x = *state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        *state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn prng_range(state: &mut u64, upper: u32) -> u32 {
        if upper == 0 {
            return 0;
        }
        (prng_next(state) % (upper as u64)) as u32
    }

    fn dummy_predicate(idx: u32) -> TcvPredicateSpecV1 {
        TcvPredicateSpecV1 {
            predicate_idx: idx,
            op: TcvArithOpV1::Equals,
            left: TcvOperandPathV1 {
                source: TcvOperandSourceV1::Constant,
                key_hash: [0u8; 32],
                value_kind: TcvValueKindV1::U64,
                constant_value: 1u64.to_le_bytes(),
            },
            right: TcvOperandPathV1 {
                source: TcvOperandSourceV1::Constant,
                key_hash: [0u8; 32],
                value_kind: TcvValueKindV1::U64,
                constant_value: 1u64.to_le_bytes(),
            },
        }
    }

    fn gen_random_policy(seed: u64) -> (CompiledTauPolicyV1, Vec<bool>) {
        let mut s = seed;
        let predicate_count = 1 + prng_range(&mut s, 8) as usize;
        let mut predicates = Vec::with_capacity(predicate_count);
        for i in 0..predicate_count {
            predicates.push(dummy_predicate(i as u32));
        }

        let tf_count = prng_range(&mut s, 4) as usize;
        let mut temporal_fields = Vec::with_capacity(tf_count);
        for i in 0..tf_count {
            let prev_count = prng_range(&mut s, (MAX_TCV_TEMPORAL_LOOKBACK_V1 + 1) as u32) as usize;
            temporal_fields.push(TcvTemporalFieldSpecV1 {
                field_idx: i as u32,
                current_key_hash: [i as u8; 32],
                prev_key_hashes: vec![[0u8; 32]; prev_count],
            });
        }
        let temporal_values: Vec<bool> = (0..tf_count)
            .flat_map(|f| {
                let prev = temporal_fields[f].prev_key_hashes.len();
                (0..=prev)
                    .map(|_| (prng_next(&mut s) & 1) == 1)
                    .collect::<Vec<_>>()
            })
            .collect();

        let gate_count = 1 + prng_range(&mut s, 50) as usize;
        let mut gates = Vec::with_capacity(gate_count);
        let mut available: Vec<u32> = Vec::with_capacity(gate_count);

        for out_wire in 0..(gate_count as u32) {
            let can_unary = !available.is_empty();
            let can_binary = available.len() >= 2;
            let can_temporal = !temporal_fields.is_empty();
            let mut options: Vec<u8> = Vec::new();
            // Always allow primary inputs.
            options.push(0); // PredicateInput
            options.push(1); // Constant
            if can_temporal {
                options.push(2); // TemporalInput
            }
            if can_unary {
                options.push(3); // Not
            }
            if can_binary {
                options.push(4); // And
                options.push(5); // Or
            }

            let choice = options[prng_range(&mut s, options.len() as u32) as usize];
            let gate = match choice {
                0 => TcvGateV1 {
                    gate_type: TcvGateTypeV1::PredicateInput,
                    out_wire,
                    in1: prng_range(&mut s, predicate_count as u32),
                    in2: 0,
                },
                1 => TcvGateV1 {
                    gate_type: TcvGateTypeV1::Constant,
                    out_wire,
                    in1: prng_range(&mut s, 2),
                    in2: 0,
                },
                2 => {
                    let field_idx = prng_range(&mut s, temporal_fields.len() as u32);
                    let prev = temporal_fields[field_idx as usize].prev_key_hashes.len() as u32;
                    let lookback = prng_range(&mut s, prev + 1);
                    TcvGateV1 {
                        gate_type: TcvGateTypeV1::TemporalInput,
                        out_wire,
                        in1: field_idx,
                        in2: lookback,
                    }
                }
                3 => TcvGateV1 {
                    gate_type: TcvGateTypeV1::Not,
                    out_wire,
                    in1: available[prng_range(&mut s, available.len() as u32) as usize],
                    in2: 0,
                },
                4 => {
                    let a = available[prng_range(&mut s, available.len() as u32) as usize];
                    let b = available[prng_range(&mut s, available.len() as u32) as usize];
                    TcvGateV1 {
                        gate_type: TcvGateTypeV1::And,
                        out_wire,
                        in1: a,
                        in2: b,
                    }
                }
                _ => {
                    let a = available[prng_range(&mut s, available.len() as u32) as usize];
                    let b = available[prng_range(&mut s, available.len() as u32) as usize];
                    TcvGateV1 {
                        gate_type: TcvGateTypeV1::Or,
                        out_wire,
                        in1: a,
                        in2: b,
                    }
                }
            };

            gates.push(gate);
            available.push(out_wire);
        }

        let output_wire = prng_range(&mut s, gate_count as u32);
        (
            CompiledTauPolicyV1 {
                version: 1,
                predicates,
                gates,
                output_wire,
                temporal_fields,
            },
            temporal_values,
        )
    }

    #[test]
    fn tcv_bitset_eval_matches_scalar_for_random_policies() {
        for seed in 0u64..200 {
            let (policy, temporal_values) =
                gen_random_policy(seed.wrapping_mul(1337) ^ 0xA5A5_A5A5_A5A5_A5A5);
            let predicate_count = policy.predicates.len();
            let mut s = seed ^ 0xDEAD_BEEF_CAFE_BABE;

            let n = 1 + prng_range(&mut s, 64) as u32;
            let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };

            let mut predicate_bits = vec![0u64; predicate_count];
            for pb in &mut predicate_bits {
                *pb = prng_next(&mut s) & mask;
            }

            let out_bits =
                tcv_eval_circuit_bitset_v1_validated(&policy, &predicate_bits, mask, |f, l| {
                    let f = f as usize;
                    if f >= policy.temporal_fields.len() {
                        return false;
                    }
                    let prev = policy.temporal_fields[f].prev_key_hashes.len();
                    if (l as usize) > prev {
                        return false;
                    }
                    let idx = policy
                        .temporal_fields
                        .iter()
                        .take(f)
                        .map(|tf| tf.prev_key_hashes.len() + 1)
                        .sum::<usize>()
                        + (l as usize);
                    temporal_values.get(idx).copied().unwrap_or(false)
                });

            for i in 0..n {
                let mut predicate_results = vec![false; predicate_count];
                for (p, bits) in predicate_bits.iter().enumerate() {
                    predicate_results[p] = ((bits >> i) & 1) == 1;
                }
                let scalar =
                    tcv_eval_circuit_scalar_v1_validated(&policy, &predicate_results, |f, l| {
                        let f = f as usize;
                        if f >= policy.temporal_fields.len() {
                            return false;
                        }
                        let prev = policy.temporal_fields[f].prev_key_hashes.len();
                        if (l as usize) > prev {
                            return false;
                        }
                        let idx = policy
                            .temporal_fields
                            .iter()
                            .take(f)
                            .map(|tf| tf.prev_key_hashes.len() + 1)
                            .sum::<usize>()
                            + (l as usize);
                        temporal_values.get(idx).copied().unwrap_or(false)
                    });
                let bit = ((out_bits >> i) & 1) == 1;
                assert_eq!(scalar, bit, "seed={seed} candidate={i}");
            }
        }
    }

    #[test]
    fn tcv_eval_perf_smoke() {
        use std::time::Instant;

        let do_perf = std::env::var("MPRD_PERF").as_deref() == Ok("1");

        let (policy, temporal_values) = if do_perf {
            // Deterministic "worst-case-ish" circuit to make the speedup observable.
            let predicate_count = 32usize;
            let mut predicates = Vec::with_capacity(predicate_count);
            for i in 0..predicate_count {
                predicates.push(dummy_predicate(i as u32));
            }

            let gate_count = MAX_TCV_GATES_V1.min(4096);
            let mut gates = Vec::with_capacity(gate_count);
            for out_wire in 0..(gate_count as u32) {
                let gate = match out_wire {
                    0 => TcvGateV1 {
                        gate_type: TcvGateTypeV1::PredicateInput,
                        out_wire,
                        in1: 0,
                        in2: 0,
                    },
                    1 => TcvGateV1 {
                        gate_type: TcvGateTypeV1::PredicateInput,
                        out_wire,
                        in1: 1,
                        in2: 0,
                    },
                    _ => {
                        // Alternate between And/Or/Not to keep dataflow non-trivial.
                        let a = out_wire - 1;
                        let b = out_wire - 2;
                        match out_wire % 3 {
                            0 => TcvGateV1 {
                                gate_type: TcvGateTypeV1::And,
                                out_wire,
                                in1: a,
                                in2: b,
                            },
                            1 => TcvGateV1 {
                                gate_type: TcvGateTypeV1::Or,
                                out_wire,
                                in1: a,
                                in2: b,
                            },
                            _ => TcvGateV1 {
                                gate_type: TcvGateTypeV1::Not,
                                out_wire,
                                in1: a,
                                in2: 0,
                            },
                        }
                    }
                };
                gates.push(gate);
            }

            (
                CompiledTauPolicyV1 {
                    version: 1,
                    predicates,
                    gates,
                    output_wire: (gate_count as u32).saturating_sub(1),
                    temporal_fields: Vec::new(),
                },
                Vec::new(),
            )
        } else {
            gen_random_policy(0xBADC0FFEE0DDF00D)
        };

        let predicate_count = policy.predicates.len();
        let n = 64u32;
        let mask = u64::MAX;

        let mut s = 0x1234_5678_9ABC_DEF0u64;
        let mut predicate_bits = vec![0u64; predicate_count];
        for pb in &mut predicate_bits {
            *pb = prng_next(&mut s) & mask;
        }

        let temporal = |f: u32, l: u32| {
            let f = f as usize;
            if f >= policy.temporal_fields.len() {
                return false;
            }
            let prev = policy.temporal_fields[f].prev_key_hashes.len();
            if (l as usize) > prev {
                return false;
            }
            let idx = policy
                .temporal_fields
                .iter()
                .take(f)
                .map(|tf| tf.prev_key_hashes.len() + 1)
                .sum::<usize>()
                + (l as usize);
            temporal_values.get(idx).copied().unwrap_or(false)
        };

        let iters = if do_perf { 25u32 } else { 1u32 };

        let t0 = Instant::now();
        let mut out_bits = 0u64;
        for _ in 0..iters {
            out_bits =
                tcv_eval_circuit_bitset_v1_validated(&policy, &predicate_bits, mask, &temporal);
        }
        let bitset_us = t0.elapsed().as_micros();

        let t1 = Instant::now();
        let mut out_bits_scalar = 0u64;
        for _ in 0..iters {
            out_bits_scalar = 0;
            for i in 0..n {
                let mut predicate_results = vec![false; predicate_count];
                for (p, bits) in predicate_bits.iter().enumerate() {
                    predicate_results[p] = ((bits >> i) & 1) == 1;
                }
                let scalar =
                    tcv_eval_circuit_scalar_v1_validated(&policy, &predicate_results, &temporal);
                if scalar {
                    out_bits_scalar |= 1u64 << i;
                }
            }
        }
        let scalar_us = t1.elapsed().as_micros();

        assert_eq!(out_bits, out_bits_scalar);

        if do_perf {
            std::eprintln!(
                "tcv_eval_perf_smoke: iters={} gates={} preds={} scalar_us={} bitset_us={} speedup_x~{:.1}",
                iters,
                policy.gates.len(),
                predicate_count,
                scalar_us,
                bitset_us,
                (scalar_us as f64) / (bitset_us.max(1) as f64),
            );
        }
    }

    #[test]
    fn id_derivation_is_deterministic() {
        let a = state_encoding_id_v1();
        let b = state_encoding_id_v1();
        assert_eq!(a, b);
    }

    #[test]
    fn decision_commitment_is_deterministic() {
        let mut j = GuestJournalV1 {
            journal_version: JOURNAL_VERSION_V1,
            policy_hash: [1u8; 32],
            policy_exec_kind_id: policy_exec_kind_tau_cli_wff_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            state_encoding_id: state_encoding_id_v1(),
            action_encoding_id: action_encoding_id_v1(),
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            limits_hash: limits_hash(&[]),
            nonce_or_tx_hash: [5u8; 32],
            chosen_index: 7,
            allowed: true,
            decision_commitment: [0u8; 32],
        };

        j.decision_commitment = compute_decision_commitment_v1(&j);
        let c1 = j.decision_commitment;
        let c2 = compute_decision_commitment_v1(&j);
        assert_eq!(c1, c2);
    }

    #[test]
    fn decision_commitment_v2_is_deterministic() {
        let mut j = GuestJournalV2 {
            journal_version: JOURNAL_VERSION_V2,
            policy_hash: [1u8; 32],
            policy_exec_kind_id: policy_exec_kind_tau_cli_wff_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            state_encoding_id: state_encoding_id_v1(),
            action_encoding_id: action_encoding_id_v1(),
            policy_epoch: 42,
            registry_root: [9u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            limits_hash: limits_hash(&[]),
            nonce_or_tx_hash: [5u8; 32],
            chosen_index: 7,
            allowed: true,
            decision_commitment: [0u8; 32],
        };
        j.decision_commitment = compute_decision_commitment_v2(&j);
        assert_eq!(j.decision_commitment, compute_decision_commitment_v2(&j));
    }

    #[test]
    fn decision_commitment_v3_is_deterministic() {
        let mut j = GuestJournalV3 {
            journal_version: JOURNAL_VERSION_V3,
            policy_hash: [1u8; 32],
            policy_exec_kind_id: policy_exec_kind_tau_cli_wff_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            state_encoding_id: state_encoding_id_v1(),
            action_encoding_id: action_encoding_id_v1(),
            policy_epoch: 42,
            registry_root: [9u8; 32],
            state_source_id: [7u8; 32],
            state_epoch: 123,
            state_attestation_hash: [6u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            limits_hash: limits_hash(&[]),
            nonce_or_tx_hash: [5u8; 32],
            chosen_index: 7,
            allowed: true,
            decision_commitment: [0u8; 32],
        };
        j.decision_commitment = compute_decision_commitment_v3(&j);
        assert_eq!(j.decision_commitment, compute_decision_commitment_v3(&j));
    }

    #[test]
    fn decision_commitment_domains_are_separated() {
        let base = GuestJournalV1 {
            journal_version: JOURNAL_VERSION_V1,
            policy_hash: [1u8; 32],
            policy_exec_kind_id: [2u8; 32],
            policy_exec_version_id: [3u8; 32],
            state_encoding_id: [4u8; 32],
            action_encoding_id: [5u8; 32],
            state_hash: [6u8; 32],
            candidate_set_hash: [7u8; 32],
            chosen_action_hash: [8u8; 32],
            limits_hash: [9u8; 32],
            nonce_or_tx_hash: [10u8; 32],
            chosen_index: 11,
            allowed: true,
            decision_commitment: [0u8; 32],
        };

        let v1 = compute_decision_commitment_v1(&base);

        let v2 = compute_decision_commitment_v2(&GuestJournalV2 {
            journal_version: JOURNAL_VERSION_V2,
            policy_epoch: 0,
            registry_root: [0u8; 32],
            decision_commitment: [0u8; 32],
            policy_hash: base.policy_hash,
            policy_exec_kind_id: base.policy_exec_kind_id,
            policy_exec_version_id: base.policy_exec_version_id,
            state_encoding_id: base.state_encoding_id,
            action_encoding_id: base.action_encoding_id,
            state_hash: base.state_hash,
            candidate_set_hash: base.candidate_set_hash,
            chosen_action_hash: base.chosen_action_hash,
            limits_hash: base.limits_hash,
            nonce_or_tx_hash: base.nonce_or_tx_hash,
            chosen_index: base.chosen_index,
            allowed: base.allowed,
        });

        let v3 = compute_decision_commitment_v3(&GuestJournalV3 {
            journal_version: JOURNAL_VERSION_V3,
            policy_epoch: 0,
            registry_root: [0u8; 32],
            state_source_id: [0u8; 32],
            state_epoch: 0,
            state_attestation_hash: [0u8; 32],
            decision_commitment: [0u8; 32],
            policy_hash: base.policy_hash,
            policy_exec_kind_id: base.policy_exec_kind_id,
            policy_exec_version_id: base.policy_exec_version_id,
            state_encoding_id: base.state_encoding_id,
            action_encoding_id: base.action_encoding_id,
            state_hash: base.state_hash,
            candidate_set_hash: base.candidate_set_hash,
            chosen_action_hash: base.chosen_action_hash,
            limits_hash: base.limits_hash,
            nonce_or_tx_hash: base.nonce_or_tx_hash,
            chosen_index: base.chosen_index,
            allowed: base.allowed,
        });

        assert_ne!(v1, v2);
        assert_ne!(v2, v3);
        assert_ne!(v1, v3);
    }

    fn any_id32() -> impl Strategy<Value = Id32> {
        proptest::array::uniform32(any::<u8>())
    }

    fn journal_v3_strategy() -> impl Strategy<Value = GuestJournalV3> {
        (
            (
                any_id32(),
                any_id32(),
                any_id32(),
                any_id32(),
                any_id32(),
                any::<u64>(),
                any_id32(),
                any_id32(),
            ),
            (
                any::<u64>(),
                any_id32(),
                any_id32(),
                any_id32(),
                any_id32(),
                any_id32(),
                any_id32(),
                any::<u32>(),
                any::<bool>(),
            ),
        )
            .prop_map(
                |(
                    (
                        policy_hash,
                        policy_exec_kind_id,
                        policy_exec_version_id,
                        state_encoding_id,
                        action_encoding_id,
                        policy_epoch,
                        registry_root,
                        state_source_id,
                    ),
                    (
                        state_epoch,
                        state_attestation_hash,
                        state_hash,
                        candidate_set_hash,
                        chosen_action_hash,
                        limits_hash,
                        nonce_or_tx_hash,
                        chosen_index,
                        allowed,
                    ),
                )| GuestJournalV3 {
                    journal_version: JOURNAL_VERSION_V3,
                    policy_hash,
                    policy_exec_kind_id,
                    policy_exec_version_id,
                    state_encoding_id,
                    action_encoding_id,
                    policy_epoch,
                    registry_root,
                    state_source_id,
                    state_epoch,
                    state_attestation_hash,
                    state_hash,
                    candidate_set_hash,
                    chosen_action_hash,
                    limits_hash,
                    nonce_or_tx_hash,
                    chosen_index,
                    allowed,
                    decision_commitment: [0u8; 32],
                },
            )
    }

    proptest! {
        #[test]
        fn decision_commitment_v3_changes_on_single_field_mutation(
            mut j in journal_v3_strategy(),
            which in 0u8..=17u8,
            byte in 0usize..32,
            bit in 0u8..8u8,
        ) {
            let original = compute_decision_commitment_v3(&j);

            match which {
                0 => j.policy_hash[byte] ^= 1u8 << bit,
                1 => j.policy_exec_kind_id[byte] ^= 1u8 << bit,
                2 => j.policy_exec_version_id[byte] ^= 1u8 << bit,
                3 => j.state_encoding_id[byte] ^= 1u8 << bit,
                4 => j.action_encoding_id[byte] ^= 1u8 << bit,
                5 => j.registry_root[byte] ^= 1u8 << bit,
                6 => j.state_source_id[byte] ^= 1u8 << bit,
                7 => j.state_attestation_hash[byte] ^= 1u8 << bit,
                8 => j.state_hash[byte] ^= 1u8 << bit,
                9 => j.candidate_set_hash[byte] ^= 1u8 << bit,
                10 => j.chosen_action_hash[byte] ^= 1u8 << bit,
                11 => j.limits_hash[byte] ^= 1u8 << bit,
                12 => j.nonce_or_tx_hash[byte] ^= 1u8 << bit,
                13 => j.policy_epoch ^= 1u64 << (bit as u32),
                14 => j.state_epoch ^= 1u64 << (bit as u32),
                15 => j.chosen_index ^= 1u32 << (bit as u32),
                16 => j.allowed = !j.allowed,
                _ => j.journal_version = j.journal_version.wrapping_add(1),
            }

            let mutated = compute_decision_commitment_v3(&j);
            prop_assert_ne!(original, mutated);
        }
    }
}
