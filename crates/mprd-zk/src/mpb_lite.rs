use mprd_core::{DecisionToken, Hash32, MprdError, ProofBundle, Result};
use mprd_proof::{Hash256, LocalVerificationResult, MpbLocalVerifier, MpbProofBundle};
use mprd_risc0_shared::{
    mpb_register_mapping_id_v1, Id32, MpbVarBindingV1, MAX_CANDIDATES_V1,
    MAX_CANDIDATE_PREIMAGE_BYTES_V1, MAX_STATE_PREIMAGE_BYTES_V1,
};
use serde::{Deserialize, Serialize};

pub const MPB_LITE_ARTIFACT_VERSION_V1: u32 = 1;
pub const MPB_LITE_CONTEXT_DOMAIN_V1: &[u8] = b"MPRD_MPB_LITE_CONTEXT_V1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpbLiteArtifactV1 {
    pub version: u32,
    pub mpb_register_mapping_id: Id32,
    /// Canonical variable bindings for the policy, in ascending `name` order.
    pub policy_variables: Vec<MpbVarBindingV1>,
    /// Canonical state hash preimage bytes (enables verifier recomputation).
    pub state_preimage: Vec<u8>,
    /// Ordered candidate hashes (membership + candidate_set_hash verification).
    pub candidate_hashes: Vec<Id32>,
    pub chosen_index: u32,
    /// Computational proof of MPB execution for the chosen candidate.
    pub mpb_proof_bundle: MpbProofBundle,
    /// Canonical limits bytes committed by the prover (e.g., MPB fuel limit tag).
    ///
    /// NOTE: `serde(default)` preserves bincode decode for older artifacts, but verifiers
    /// MUST fail-closed if this is missing/empty.
    #[serde(default)]
    pub limits_bytes: Vec<u8>,
    /// Canonical chosen action preimage bytes (for binding MPB registers to the committed action).
    ///
    /// NOTE: `serde(default)` preserves bincode decode for older artifacts, but verifiers
    /// MUST fail-closed if this is missing/empty.
    #[serde(default)]
    pub chosen_action_preimage: Vec<u8>,
}

pub fn mpb_lite_context_hash_v1(token: &DecisionToken, proof: &ProofBundle) -> Hash256 {
    mpb_lite_context_hash_parts_v1(token, &proof.candidate_set_hash, &proof.limits_hash)
}

pub fn mpb_lite_context_hash_parts_v1(
    token: &DecisionToken,
    candidate_set_hash: &Hash32,
    limits_hash: &Hash32,
) -> Hash256 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(MPB_LITE_CONTEXT_DOMAIN_V1);
    hasher.update(token.policy_hash.0);
    hasher.update(token.policy_ref.policy_epoch.to_le_bytes());
    hasher.update(token.policy_ref.registry_root.0);
    hasher.update(token.state_hash.0);
    hasher.update(token.state_ref.state_source_id.0);
    hasher.update(token.state_ref.state_epoch.to_le_bytes());
    hasher.update(token.state_ref.state_attestation_hash.0);
    hasher.update(candidate_set_hash.0);
    hasher.update(token.chosen_action_hash.0);
    hasher.update(token.nonce_or_tx_hash.0);
    hasher.update(limits_hash.0);
    hasher.finalize().into()
}

pub fn registers_input_hash(registers: &[i64]) -> Hash256 {
    let mut bytes = Vec::with_capacity(registers.len() * 8);
    for r in registers {
        bytes.extend_from_slice(&r.to_le_bytes());
    }
    mprd_proof::sha256(&bytes)
}

pub fn verify_mpb_proof_bundle(bundle: &MpbProofBundle) -> Result<()> {
    let verifier = MpbLocalVerifier::new();
    match verifier.verify(bundle) {
        LocalVerificationResult::Success => Ok(()),
        LocalVerificationResult::Failure(msg) => Err(MprdError::ZkError(format!(
            "mpb-proof verification failed: {msg}"
        ))),
    }
}

pub fn verify_mpb_proof_bundle_with_inputs(
    bundle: &MpbProofBundle,
    expected_bytecode_hash: &Hash256,
    expected_input_hash: &Hash256,
) -> Result<()> {
    let verifier = MpbLocalVerifier::new();
    match verifier.verify_with_inputs(bundle, expected_bytecode_hash, expected_input_hash) {
        LocalVerificationResult::Success => Ok(()),
        LocalVerificationResult::Failure(msg) => Err(MprdError::ZkError(format!(
            "mpb-proof verification failed: {msg}"
        ))),
    }
}

pub fn validate_vars_canonical(vars: &[MpbVarBindingV1]) -> Result<()> {
    if vars.is_empty() {
        return Ok(());
    }
    let mut prev: Option<&[u8]> = None;
    for v in vars {
        if v.reg as usize >= mprd_mpb::MpbVm::MAX_REGISTERS {
            return Err(MprdError::InvalidInput("mpb var reg out of range".into()));
        }
        if core::str::from_utf8(&v.name).is_err() {
            return Err(MprdError::InvalidInput("mpb var name not utf-8".into()));
        }
        if let Some(p) = prev {
            if v.name.as_slice() <= p {
                return Err(MprdError::InvalidInput(
                    "mpb policy_variables must be sorted and unique".into(),
                ));
            }
        }
        prev = Some(v.name.as_slice());
    }
    Ok(())
}

pub fn verify_artifact_header(a: &MpbLiteArtifactV1) -> Result<()> {
    if a.version != MPB_LITE_ARTIFACT_VERSION_V1 {
        return Err(MprdError::ZkError(
            "unsupported mpb lite artifact version".into(),
        ));
    }
    if a.mpb_register_mapping_id != mpb_register_mapping_id_v1() {
        return Err(MprdError::ZkError(
            "unsupported mpb_register_mapping_id".into(),
        ));
    }
    // NOTE: empty `state_preimage` is valid (represents an empty map); enforce only an upper bound.
    if a.state_preimage.len() > MAX_STATE_PREIMAGE_BYTES_V1 {
        return Err(MprdError::ZkError("invalid state_preimage size".into()));
    }
    if a.candidate_hashes.is_empty() || a.candidate_hashes.len() > MAX_CANDIDATES_V1 {
        return Err(MprdError::ZkError("invalid candidate_hashes size".into()));
    }
    if (a.chosen_index as usize) >= a.candidate_hashes.len() {
        return Err(MprdError::ZkError("chosen_index out of bounds".into()));
    }
    validate_vars_canonical(&a.policy_variables)?;
    if a.chosen_action_preimage.is_empty()
        || a.chosen_action_preimage.len() > MAX_CANDIDATE_PREIMAGE_BYTES_V1
    {
        return Err(MprdError::ZkError(
            "invalid chosen_action_preimage size".into(),
        ));
    }
    if a.limits_bytes.is_empty() || a.limits_bytes.len() > 64 {
        return Err(MprdError::ZkError("invalid limits_bytes size".into()));
    }
    Ok(())
}

pub fn policy_hash_from_artifact_v1(bytecode: &[u8], vars: &[MpbVarBindingV1]) -> Hash32 {
    let refs: Vec<(&[u8], u8)> = vars.iter().map(|v| (v.name.as_slice(), v.reg)).collect();
    Hash32(mprd_mpb::policy_hash_v1(bytecode, &refs))
}
