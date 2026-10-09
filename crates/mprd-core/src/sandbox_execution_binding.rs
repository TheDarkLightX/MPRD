//! Exact MPRD binding for policy-admitted sandbox executions.
//!
//! A VM, microVM, WASM engine, container, or desktop sandbox is an imperative
//! execution shell. It is not an authority. This module gives MPRD a small,
//! canonical action language for authorizing one exact sandbox plan and later
//! checking that an untrusted runtime receipt preserved that plan.

use crate::{hash::hash_candidate, CandidateAction, Hash32, Score, Value};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use thiserror::Error;

pub const ACTION_TYPE_SANDBOX_RUN_V1: &str = "sandbox_run";

pub const PARAM_PLAN_HASH: &str = "sandbox_plan_hash";
pub const PARAM_POLICY_HASH: &str = "sandbox_policy_hash";
pub const PARAM_RUNTIME_PROFILE_HASH: &str = "sandbox_runtime_profile_hash";
pub const PARAM_NETWORK_POLICY_HASH: &str = "sandbox_network_policy_hash";
pub const PARAM_EXECUTION_NONCE: &str = "sandbox_execution_nonce";
pub const PARAM_EXECUTION_EPOCH: &str = "sandbox_execution_epoch";
pub const PARAM_MAX_WALL_TIME_MS: &str = "sandbox_max_wall_time_ms";
pub const PARAM_MAX_MEMORY_MIB: &str = "sandbox_max_memory_mib";
pub const PARAM_MAX_OUTPUT_BYTES: &str = "sandbox_max_output_bytes";
pub const PARAM_RECEIPT_REQUIRED: &str = "sandbox_receipt_required";

const SANDBOX_BINDING_DOMAIN_V1: &[u8] = b"mprd:sandbox-run-binding:v1";
const SANDBOX_RECEIPT_DOMAIN_V1: &[u8] = b"mprd:sandbox-run-receipt:v1";
const ZERO_HASH: Hash32 = Hash32([0; 32]);

const REQUIRED_KEYS: [&str; 10] = [
    PARAM_PLAN_HASH,
    PARAM_POLICY_HASH,
    PARAM_RUNTIME_PROFILE_HASH,
    PARAM_NETWORK_POLICY_HASH,
    PARAM_EXECUTION_NONCE,
    PARAM_EXECUTION_EPOCH,
    PARAM_MAX_WALL_TIME_MS,
    PARAM_MAX_MEMORY_MIB,
    PARAM_MAX_OUTPUT_BYTES,
    PARAM_RECEIPT_REQUIRED,
];

/// Untrusted proposal for one policy-admitted sandbox execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxRunProposalV1 {
    pub plan_hash: Hash32,
    pub sandbox_policy_hash: Hash32,
    pub runtime_profile_hash: Hash32,
    pub network_policy_hash: Hash32,
    pub execution_nonce: Hash32,
    pub execution_epoch: u64,
    pub max_wall_time_ms: u64,
    pub max_memory_mib: u64,
    pub max_output_bytes: u64,
}

/// Constructor-gated binding reconstructed from a canonical `sandbox_run`
/// candidate whose candidate hash has already been checked.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdmittedSandboxRunBindingV1 {
    plan_hash: Hash32,
    sandbox_policy_hash: Hash32,
    runtime_profile_hash: Hash32,
    network_policy_hash: Hash32,
    execution_nonce: Hash32,
    execution_epoch: u64,
    max_wall_time_ms: u64,
    max_memory_mib: u64,
    max_output_bytes: u64,
    candidate_hash: Hash32,
    binding_hash: Hash32,
}

impl AdmittedSandboxRunBindingV1 {
    pub fn plan_hash(&self) -> &Hash32 {
        &self.plan_hash
    }

    pub fn sandbox_policy_hash(&self) -> &Hash32 {
        &self.sandbox_policy_hash
    }

    pub fn runtime_profile_hash(&self) -> &Hash32 {
        &self.runtime_profile_hash
    }

    pub fn network_policy_hash(&self) -> &Hash32 {
        &self.network_policy_hash
    }

    pub fn execution_nonce(&self) -> &Hash32 {
        &self.execution_nonce
    }

    pub fn execution_epoch(&self) -> u64 {
        self.execution_epoch
    }

    pub fn max_wall_time_ms(&self) -> u64 {
        self.max_wall_time_ms
    }

    pub fn max_memory_mib(&self) -> u64 {
        self.max_memory_mib
    }

    pub fn max_output_bytes(&self) -> u64 {
        self.max_output_bytes
    }

    pub fn candidate_hash(&self) -> &Hash32 {
        &self.candidate_hash
    }

    pub fn binding_hash(&self) -> &Hash32 {
        &self.binding_hash
    }
}

/// Runtime termination reported by the untrusted sandbox adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxRuntimeTerminationV1 {
    Exited,
    TimedOut,
    OutOfMemory,
    PolicyDenied,
    RuntimeFailure,
}

impl SandboxRuntimeTerminationV1 {
    fn tag(self) -> u8 {
        match self {
            Self::Exited => 0,
            Self::TimedOut => 1,
            Self::OutOfMemory => 2,
            Self::PolicyDenied => 3,
            Self::RuntimeFailure => 4,
        }
    }
}

/// Untrusted structural receipt reference returned by a sandbox adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxRuntimeReceiptRefV1 {
    pub plan_hash: Hash32,
    pub runtime_profile_hash: Hash32,
    pub execution_nonce: Hash32,
    pub receipt_hash: Hash32,
    pub output_manifest_hash: Hash32,
    pub runtime_attestation_hash: Hash32,
    pub termination: SandboxRuntimeTerminationV1,
    pub exit_code: Option<i32>,
    pub wall_time_ms: u64,
    pub peak_memory_mib: u64,
    pub total_output_bytes: u64,
}

/// Constructor-gated receipt binding safe to carry into later MPRD decisions.
///
/// Validation proves identity and resource binding. It does not prove semantic
/// correctness of the sandbox output.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidatedSandboxReceiptBindingV1 {
    receipt: SandboxRuntimeReceiptRefV1,
    sandbox_binding_hash: Hash32,
    receipt_binding_hash: Hash32,
}

impl ValidatedSandboxReceiptBindingV1 {
    pub fn receipt(&self) -> &SandboxRuntimeReceiptRefV1 {
        &self.receipt
    }

    pub fn sandbox_binding_hash(&self) -> &Hash32 {
        &self.sandbox_binding_hash
    }

    pub fn receipt_binding_hash(&self) -> &Hash32 {
        &self.receipt_binding_hash
    }

    pub fn succeeded(&self) -> bool {
        self.receipt.termination == SandboxRuntimeTerminationV1::Exited
            && self.receipt.exit_code == Some(0)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SandboxExecutionBindingError {
    #[error("sandbox_run contains unknown parameter: {0}")]
    UnknownParameter(String),
    #[error("sandbox_run is missing required parameter: {0}")]
    MissingParameter(&'static str),
    #[error("sandbox parameter {0} must be a non-zero 32-byte hash")]
    InvalidHash(&'static str),
    #[error("sandbox parameter {0} must be a positive unsigned integer")]
    InvalidPositiveInteger(&'static str),
    #[error("sandbox_receipt_required must be true")]
    ReceiptNotRequired,
    #[error("candidate action type is not sandbox_run")]
    WrongActionType,
    #[error("candidate_hash does not match the canonical sandbox candidate")]
    CandidateHashMismatch,
    #[error("sandbox runtime receipt does not match admitted {0}")]
    ReceiptBindingMismatch(&'static str),
    #[error("sandbox runtime receipt has an invalid exit-code/termination combination")]
    InvalidExitCode,
    #[error("sandbox runtime receipt is missing non-zero {0}")]
    MissingReceiptCommitment(&'static str),
    #[error("sandbox runtime receipt exceeds {field}: {actual} > {max}")]
    ReceiptResourceExceeded {
        field: &'static str,
        actual: u64,
        max: u64,
    },
}

/// Build a canonical MPRD candidate for one exact Helix sandbox plan.
pub fn sandbox_run_candidate_v1(
    proposal: SandboxRunProposalV1,
    score: Score,
) -> Result<CandidateAction, SandboxExecutionBindingError> {
    validate_proposal(&proposal)?;
    let params = proposal_to_params(&proposal);
    validate_sandbox_run_params_v1(&params)?;
    let mut candidate = CandidateAction {
        action_type: ACTION_TYPE_SANDBOX_RUN_V1.to_string(),
        params,
        score,
        candidate_hash: ZERO_HASH,
    };
    candidate.candidate_hash = hash_candidate(&candidate);
    Ok(candidate)
}

/// Validate the exact parameter schema used by `validation::validate_action_schema_v1`.
pub fn validate_sandbox_run_params_v1(
    params: &HashMap<String, Value>,
) -> Result<(), SandboxExecutionBindingError> {
    let required = REQUIRED_KEYS.iter().copied().collect::<BTreeSet<_>>();
    for key in params.keys() {
        if !required.contains(key.as_str()) {
            return Err(SandboxExecutionBindingError::UnknownParameter(key.clone()));
        }
    }
    for key in REQUIRED_KEYS {
        if !params.contains_key(key) {
            return Err(SandboxExecutionBindingError::MissingParameter(key));
        }
    }

    for key in [
        PARAM_PLAN_HASH,
        PARAM_POLICY_HASH,
        PARAM_RUNTIME_PROFILE_HASH,
        PARAM_NETWORK_POLICY_HASH,
        PARAM_EXECUTION_NONCE,
    ] {
        read_hash(params, key)?;
    }
    for key in [
        PARAM_EXECUTION_EPOCH,
        PARAM_MAX_WALL_TIME_MS,
        PARAM_MAX_MEMORY_MIB,
        PARAM_MAX_OUTPUT_BYTES,
    ] {
        read_positive_u64(params, key)?;
    }
    match params.get(PARAM_RECEIPT_REQUIRED) {
        Some(Value::Bool(true)) => Ok(()),
        _ => Err(SandboxExecutionBindingError::ReceiptNotRequired),
    }
}

/// Reconstruct the constructor-gated binding from a hash-valid candidate.
pub fn admitted_sandbox_run_binding_v1(
    candidate: &CandidateAction,
) -> Result<AdmittedSandboxRunBindingV1, SandboxExecutionBindingError> {
    if candidate.action_type != ACTION_TYPE_SANDBOX_RUN_V1 {
        return Err(SandboxExecutionBindingError::WrongActionType);
    }
    validate_sandbox_run_params_v1(&candidate.params)?;
    let expected_candidate_hash = hash_candidate(candidate);
    if candidate.candidate_hash == ZERO_HASH || candidate.candidate_hash != expected_candidate_hash
    {
        return Err(SandboxExecutionBindingError::CandidateHashMismatch);
    }

    let plan_hash = read_hash(&candidate.params, PARAM_PLAN_HASH)?;
    let sandbox_policy_hash = read_hash(&candidate.params, PARAM_POLICY_HASH)?;
    let runtime_profile_hash = read_hash(&candidate.params, PARAM_RUNTIME_PROFILE_HASH)?;
    let network_policy_hash = read_hash(&candidate.params, PARAM_NETWORK_POLICY_HASH)?;
    let execution_nonce = read_hash(&candidate.params, PARAM_EXECUTION_NONCE)?;
    let execution_epoch = read_positive_u64(&candidate.params, PARAM_EXECUTION_EPOCH)?;
    let max_wall_time_ms = read_positive_u64(&candidate.params, PARAM_MAX_WALL_TIME_MS)?;
    let max_memory_mib = read_positive_u64(&candidate.params, PARAM_MAX_MEMORY_MIB)?;
    let max_output_bytes = read_positive_u64(&candidate.params, PARAM_MAX_OUTPUT_BYTES)?;
    let binding_hash = sandbox_binding_hash(
        &plan_hash,
        &sandbox_policy_hash,
        &runtime_profile_hash,
        &network_policy_hash,
        &execution_nonce,
        execution_epoch,
        max_wall_time_ms,
        max_memory_mib,
        max_output_bytes,
        &candidate.candidate_hash,
    );

    Ok(AdmittedSandboxRunBindingV1 {
        plan_hash,
        sandbox_policy_hash,
        runtime_profile_hash,
        network_policy_hash,
        execution_nonce,
        execution_epoch,
        max_wall_time_ms,
        max_memory_mib,
        max_output_bytes,
        candidate_hash: candidate.candidate_hash,
        binding_hash,
    })
}

/// Validate a runtime receipt against the exact MPRD-authorized sandbox plan.
pub fn validate_sandbox_runtime_receipt_v1(
    admitted: &AdmittedSandboxRunBindingV1,
    receipt: SandboxRuntimeReceiptRefV1,
) -> Result<ValidatedSandboxReceiptBindingV1, SandboxExecutionBindingError> {
    if receipt.plan_hash != admitted.plan_hash {
        return Err(SandboxExecutionBindingError::ReceiptBindingMismatch(
            "plan_hash",
        ));
    }
    if receipt.runtime_profile_hash != admitted.runtime_profile_hash {
        return Err(SandboxExecutionBindingError::ReceiptBindingMismatch(
            "runtime_profile_hash",
        ));
    }
    if receipt.execution_nonce != admitted.execution_nonce {
        return Err(SandboxExecutionBindingError::ReceiptBindingMismatch(
            "execution_nonce",
        ));
    }
    require_receipt_hash("receipt_hash", receipt.receipt_hash)?;
    require_receipt_hash("output_manifest_hash", receipt.output_manifest_hash)?;
    require_receipt_hash("runtime_attestation_hash", receipt.runtime_attestation_hash)?;

    match (receipt.termination, receipt.exit_code) {
        (SandboxRuntimeTerminationV1::Exited, Some(_)) => {}
        (SandboxRuntimeTerminationV1::Exited, None) | (_, Some(_)) => {
            return Err(SandboxExecutionBindingError::InvalidExitCode)
        }
        (_, None) => {}
    }

    for (field, actual, max) in [
        (
            "wall_time_ms",
            receipt.wall_time_ms,
            admitted.max_wall_time_ms,
        ),
        (
            "peak_memory_mib",
            receipt.peak_memory_mib,
            admitted.max_memory_mib,
        ),
        (
            "total_output_bytes",
            receipt.total_output_bytes,
            admitted.max_output_bytes,
        ),
    ] {
        if actual > max {
            return Err(SandboxExecutionBindingError::ReceiptResourceExceeded {
                field,
                actual,
                max,
            });
        }
    }

    let receipt_binding_hash = sandbox_receipt_binding_hash(admitted, &receipt);
    Ok(ValidatedSandboxReceiptBindingV1 {
        receipt,
        sandbox_binding_hash: admitted.binding_hash,
        receipt_binding_hash,
    })
}

fn validate_proposal(proposal: &SandboxRunProposalV1) -> Result<(), SandboxExecutionBindingError> {
    for (field, hash) in [
        (PARAM_PLAN_HASH, proposal.plan_hash),
        (PARAM_POLICY_HASH, proposal.sandbox_policy_hash),
        (PARAM_RUNTIME_PROFILE_HASH, proposal.runtime_profile_hash),
        (PARAM_NETWORK_POLICY_HASH, proposal.network_policy_hash),
        (PARAM_EXECUTION_NONCE, proposal.execution_nonce),
    ] {
        if hash == ZERO_HASH {
            return Err(SandboxExecutionBindingError::InvalidHash(field));
        }
    }
    for (field, value) in [
        (PARAM_EXECUTION_EPOCH, proposal.execution_epoch),
        (PARAM_MAX_WALL_TIME_MS, proposal.max_wall_time_ms),
        (PARAM_MAX_MEMORY_MIB, proposal.max_memory_mib),
        (PARAM_MAX_OUTPUT_BYTES, proposal.max_output_bytes),
    ] {
        if value == 0 {
            return Err(SandboxExecutionBindingError::InvalidPositiveInteger(field));
        }
    }
    Ok(())
}

fn proposal_to_params(proposal: &SandboxRunProposalV1) -> HashMap<String, Value> {
    HashMap::from([
        (
            PARAM_PLAN_HASH.to_string(),
            Value::Bytes(proposal.plan_hash.0.to_vec()),
        ),
        (
            PARAM_POLICY_HASH.to_string(),
            Value::Bytes(proposal.sandbox_policy_hash.0.to_vec()),
        ),
        (
            PARAM_RUNTIME_PROFILE_HASH.to_string(),
            Value::Bytes(proposal.runtime_profile_hash.0.to_vec()),
        ),
        (
            PARAM_NETWORK_POLICY_HASH.to_string(),
            Value::Bytes(proposal.network_policy_hash.0.to_vec()),
        ),
        (
            PARAM_EXECUTION_NONCE.to_string(),
            Value::Bytes(proposal.execution_nonce.0.to_vec()),
        ),
        (
            PARAM_EXECUTION_EPOCH.to_string(),
            Value::UInt(proposal.execution_epoch),
        ),
        (
            PARAM_MAX_WALL_TIME_MS.to_string(),
            Value::UInt(proposal.max_wall_time_ms),
        ),
        (
            PARAM_MAX_MEMORY_MIB.to_string(),
            Value::UInt(proposal.max_memory_mib),
        ),
        (
            PARAM_MAX_OUTPUT_BYTES.to_string(),
            Value::UInt(proposal.max_output_bytes),
        ),
        (PARAM_RECEIPT_REQUIRED.to_string(), Value::Bool(true)),
    ])
}

fn read_hash(
    params: &HashMap<String, Value>,
    key: &'static str,
) -> Result<Hash32, SandboxExecutionBindingError> {
    let Some(Value::Bytes(bytes)) = params.get(key) else {
        return Err(SandboxExecutionBindingError::InvalidHash(key));
    };
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| SandboxExecutionBindingError::InvalidHash(key))?;
    let hash = Hash32(array);
    if hash == ZERO_HASH {
        return Err(SandboxExecutionBindingError::InvalidHash(key));
    }
    Ok(hash)
}

fn read_positive_u64(
    params: &HashMap<String, Value>,
    key: &'static str,
) -> Result<u64, SandboxExecutionBindingError> {
    let value = match params.get(key) {
        Some(Value::UInt(value)) => *value,
        Some(Value::Int(value)) if *value > 0 => *value as u64,
        _ => return Err(SandboxExecutionBindingError::InvalidPositiveInteger(key)),
    };
    if value == 0 {
        return Err(SandboxExecutionBindingError::InvalidPositiveInteger(key));
    }
    Ok(value)
}

fn require_receipt_hash(
    field: &'static str,
    hash: Hash32,
) -> Result<(), SandboxExecutionBindingError> {
    if hash == ZERO_HASH {
        return Err(SandboxExecutionBindingError::MissingReceiptCommitment(
            field,
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sandbox_binding_hash(
    plan_hash: &Hash32,
    sandbox_policy_hash: &Hash32,
    runtime_profile_hash: &Hash32,
    network_policy_hash: &Hash32,
    execution_nonce: &Hash32,
    execution_epoch: u64,
    max_wall_time_ms: u64,
    max_memory_mib: u64,
    max_output_bytes: u64,
    candidate_hash: &Hash32,
) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(SANDBOX_BINDING_DOMAIN_V1);
    hasher.update(plan_hash.0);
    hasher.update(sandbox_policy_hash.0);
    hasher.update(runtime_profile_hash.0);
    hasher.update(network_policy_hash.0);
    hasher.update(execution_nonce.0);
    hasher.update(execution_epoch.to_le_bytes());
    hasher.update(max_wall_time_ms.to_le_bytes());
    hasher.update(max_memory_mib.to_le_bytes());
    hasher.update(max_output_bytes.to_le_bytes());
    hasher.update(candidate_hash.0);
    Hash32(hasher.finalize().into())
}

fn sandbox_receipt_binding_hash(
    admitted: &AdmittedSandboxRunBindingV1,
    receipt: &SandboxRuntimeReceiptRefV1,
) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(SANDBOX_RECEIPT_DOMAIN_V1);
    hasher.update(admitted.binding_hash.0);
    hasher.update(receipt.plan_hash.0);
    hasher.update(receipt.runtime_profile_hash.0);
    hasher.update(receipt.execution_nonce.0);
    hasher.update(receipt.receipt_hash.0);
    hasher.update(receipt.output_manifest_hash.0);
    hasher.update(receipt.runtime_attestation_hash.0);
    hasher.update([receipt.termination.tag()]);
    match receipt.exit_code {
        Some(code) => {
            hasher.update([1]);
            hasher.update(code.to_le_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(receipt.wall_time_ms.to_le_bytes());
    hasher.update(receipt.peak_memory_mib.to_le_bytes());
    hasher.update(receipt.total_output_bytes.to_le_bytes());
    Hash32(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn proposal() -> SandboxRunProposalV1 {
        SandboxRunProposalV1 {
            plan_hash: hash(1),
            sandbox_policy_hash: hash(2),
            runtime_profile_hash: hash(3),
            network_policy_hash: hash(4),
            execution_nonce: hash(5),
            execution_epoch: 7,
            max_wall_time_ms: 30_000,
            max_memory_mib: 2_048,
            max_output_bytes: 10_000_000,
        }
    }

    fn admitted() -> AdmittedSandboxRunBindingV1 {
        let candidate = sandbox_run_candidate_v1(proposal(), Score(9)).expect("candidate");
        admitted_sandbox_run_binding_v1(&candidate).expect("admitted")
    }

    fn receipt() -> SandboxRuntimeReceiptRefV1 {
        SandboxRuntimeReceiptRefV1 {
            plan_hash: hash(1),
            runtime_profile_hash: hash(3),
            execution_nonce: hash(5),
            receipt_hash: hash(6),
            output_manifest_hash: hash(7),
            runtime_attestation_hash: hash(8),
            termination: SandboxRuntimeTerminationV1::Exited,
            exit_code: Some(0),
            wall_time_ms: 1_000,
            peak_memory_mib: 512,
            total_output_bytes: 1_024,
        }
    }

    #[test]
    fn canonical_candidate_roundtrips_to_binding() {
        let candidate = sandbox_run_candidate_v1(proposal(), Score(9)).expect("candidate");
        let binding = admitted_sandbox_run_binding_v1(&candidate).expect("binding");
        assert_eq!(binding.plan_hash(), &hash(1));
        assert_eq!(binding.candidate_hash(), &candidate.candidate_hash);
        assert_ne!(binding.binding_hash(), &ZERO_HASH);
    }

    #[test]
    fn unknown_parameters_fail_closed() {
        let mut params = proposal_to_params(&proposal());
        params.insert("native_host_fallback".to_string(), Value::Bool(true));
        assert!(matches!(
            validate_sandbox_run_params_v1(&params),
            Err(SandboxExecutionBindingError::UnknownParameter(key))
                if key == "native_host_fallback"
        ));
    }

    #[test]
    fn zero_nonce_is_rejected() {
        let mut value = proposal();
        value.execution_nonce = ZERO_HASH;
        assert_eq!(
            sandbox_run_candidate_v1(value, Score(0)),
            Err(SandboxExecutionBindingError::InvalidHash(
                PARAM_EXECUTION_NONCE
            ))
        );
    }

    #[test]
    fn candidate_hash_drift_is_rejected() {
        let mut candidate = sandbox_run_candidate_v1(proposal(), Score(9)).expect("candidate");
        candidate.score = Score(10);
        assert_eq!(
            admitted_sandbox_run_binding_v1(&candidate),
            Err(SandboxExecutionBindingError::CandidateHashMismatch)
        );
    }

    #[test]
    fn valid_receipt_is_bound_and_successful() {
        let validated =
            validate_sandbox_runtime_receipt_v1(&admitted(), receipt()).expect("receipt");
        assert!(validated.succeeded());
        assert_ne!(validated.receipt_binding_hash(), &ZERO_HASH);
    }

    #[test]
    fn cross_plan_receipt_replay_is_rejected() {
        let mut value = receipt();
        value.plan_hash = hash(99);
        assert_eq!(
            validate_sandbox_runtime_receipt_v1(&admitted(), value),
            Err(SandboxExecutionBindingError::ReceiptBindingMismatch(
                "plan_hash"
            ))
        );
    }

    #[test]
    fn resource_overrun_is_rejected() {
        let mut value = receipt();
        value.wall_time_ms = 30_001;
        assert_eq!(
            validate_sandbox_runtime_receipt_v1(&admitted(), value),
            Err(SandboxExecutionBindingError::ReceiptResourceExceeded {
                field: "wall_time_ms",
                actual: 30_001,
                max: 30_000,
            })
        );
    }

    #[test]
    fn timeout_receipt_is_valid_but_not_successful() {
        let mut value = receipt();
        value.termination = SandboxRuntimeTerminationV1::TimedOut;
        value.exit_code = None;
        let validated = validate_sandbox_runtime_receipt_v1(&admitted(), value).expect("receipt");
        assert!(!validated.succeeded());
    }

    #[test]
    fn non_exit_termination_must_not_have_exit_code() {
        let mut value = receipt();
        value.termination = SandboxRuntimeTerminationV1::PolicyDenied;
        assert_eq!(
            validate_sandbox_runtime_receipt_v1(&admitted(), value),
            Err(SandboxExecutionBindingError::InvalidExitCode)
        );
    }
}
