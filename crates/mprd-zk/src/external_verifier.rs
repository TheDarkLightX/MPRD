//! External verifier for MPRD proof bundles.
//!
//! This module provides standalone verification of MPRD proofs without
//! requiring the full MPRD runtime. It can be used by:
//!
//! - Third-party auditors
//! - On-chain verification contracts
//! - Browser/WASM verification
//!
//! # Usage
//!
//! ```rust,ignore
//! use mprd_zk::external_verifier::{ExternalVerifier, VerificationRequest};
//!
//! let verifier = ExternalVerifier::new();
//! let result = verifier.verify(&request)?;
//! assert!(result.valid);
//! ```

use crate::manifest::GuestImageManifestV1;
use crate::modes::{DeploymentMode, VerificationStep};
use crate::privacy::EncryptedState;
use mprd_core::{PolicyRef, StateRef, TokenVerifyingKey};
use mprd_risc0_shared::{
    action_encoding_id_v1, compute_decision_commitment_v3, limits_hash, limits_hash_mpb_v1,
    policy_exec_kind_host_trusted_id_v0, policy_exec_kind_mpb_id_v1,
    policy_exec_kind_tau_compiled_id_v1, policy_exec_version_id_v1, state_encoding_id_v1,
    GuestJournalV3, JOURNAL_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ERR_INVALID_REQUEST_STRUCTURE: &str = "Invalid request structure";
const ERR_MODE_MISMATCH: &str = "Mode mismatch";
const ERR_MISSING_B_LITE_MODE_MARKER: &str = "Missing B-Lite mode marker";
const ERR_MPB_METADATA_MISSING: &str = "Missing MPB metadata";
const ERR_FAILED_DECODE_MPB_ARTIFACT: &str = "Failed to decode MPB artifact";
const ERR_MPB_ARTIFACT_INVALID: &str = "Invalid MPB artifact";
const ERR_MPB_BINDING_MISMATCH: &str = "MPB artifact bindings do not match request";
const ERR_MPB_PROOF_VERIFICATION_FAILED: &str = "MPB proof verification failed";
const ERR_RISC0_IMAGE_ID_NOT_CONFIGURED: &str = "Risc0 image ID not configured";
const ERR_RISC0_IMAGE_ID_ALL_ZERO: &str = "Invalid (all-zero) Risc0 image ID";
const ERR_EMPTY_RISC0_RECEIPT: &str = "Empty Risc0 receipt";
const ERR_FAILED_DESERIALIZE_RISC0_RECEIPT: &str = "Failed to deserialize Risc0 receipt";
const ERR_FAILED_DECODE_JOURNAL_ROUTING: &str = "Failed to decode journal for routing";
const ERR_UNSUPPORTED_EXEC_KIND_FOR_MODE: &str = "Unsupported policy_exec_kind for mode";
const ERR_RISC0_RECEIPT_VERIFICATION_FAILED: &str = "Risc0 receipt verification failed";
const ERR_FAILED_DECODE_RISC0_JOURNAL: &str = "Failed to decode Risc0 journal";
const ERR_COMMITMENTS_MISMATCH: &str = "Commitments in journal do not match request";
const ERR_MISSING_MODE_C_MARKER: &str = "Missing Mode C marker";
const ERR_MISSING_ENCRYPTION_ALGORITHM: &str = "Missing encryption_algorithm metadata for Mode C";
const ERR_UNSUPPORTED_ENCRYPTION_ALGORITHM: &str = "Unsupported encryption_algorithm for Mode C";
const ERR_MISSING_ENCRYPTED_STATE: &str = "Missing encrypted_state metadata for Mode C";
const ERR_INVALID_ENCRYPTED_STATE: &str = "Invalid encrypted_state metadata";
const ERR_ENCRYPTION_KEY_ID_MISMATCH: &str = "Encryption key_id mismatch for Mode C";

/// External verification request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationRequest {
    /// Deployment mode claimed by the proof.
    pub mode: DeploymentMode,

    /// Policy hash commitment.
    pub policy_hash: [u8; 32],

    /// Policy authorization context (epoch/root).
    pub policy_epoch: u64,
    pub registry_root: [u8; 32],

    /// State provenance context (source/epoch/attestation commitment).
    pub state_source_id: [u8; 32],
    pub state_epoch: u64,
    pub state_attestation_hash: [u8; 32],

    /// State hash commitment.
    pub state_hash: [u8; 32],

    /// Candidate set hash commitment.
    pub candidate_set_hash: [u8; 32],

    /// Chosen action hash commitment.
    pub chosen_action_hash: [u8; 32],

    /// Anti-replay binding committed by the guest.
    pub nonce_or_tx_hash: [u8; 32],

    /// Proof data (format depends on mode).
    pub proof_data: Vec<u8>,

    /// Attestation metadata.
    pub metadata: std::collections::HashMap<String, String>,
}

/// External verification response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResponse {
    /// Whether the proof is valid.
    pub valid: bool,

    /// Deployment mode verified.
    pub mode: DeploymentMode,

    /// Detailed verification steps.
    pub steps: Vec<VerificationStep>,

    /// Error message if invalid.
    pub error: Option<String>,

    /// Timestamp of verification.
    pub verified_at: i64,
}

struct StepLogger<'a> {
    steps: &'a mut Vec<VerificationStep>,
}

impl<'a> StepLogger<'a> {
    fn new(steps: &'a mut Vec<VerificationStep>) -> Self {
        Self { steps }
    }

    fn record(&mut self, name: &str, passed: bool, details: Option<String>) {
        self.steps.push(VerificationStep {
            name: name.into(),
            passed,
            details,
        });
    }

    fn pass(&mut self, name: &str, details: Option<String>) {
        self.record(name, true, details);
    }

    fn fail(&mut self, name: &str, details: Option<String>) {
        self.record(name, false, details);
    }

    fn fail_with<T>(&mut self, name: &str, details: Option<String>, err: &str) -> Result<T, String> {
        self.fail(name, details);
        Err(err.into())
    }
}

struct MpbLiteMeta {
    expected_spot_checks: usize,
    expected_fuel_limit: u32,
}

struct MpbBindings {
    expected_registers: Vec<i64>,
}

/// External verifier for MPRD proofs.
///
/// This verifier operates without access to the original state or candidates,
/// only using the commitments and proof data.
pub struct ExternalVerifier {
    /// Risc0 image ID for Mode B-Full verification.
    risc0_image_id: Option<[u8; 32]>,
    /// Optional signed manifest used for image routing.
    manifest: Option<GuestImageManifestV1>,
}

impl ExternalVerifier {
    /// Create a new external verifier.
    pub fn new() -> Self {
        Self {
            risc0_image_id: None,
            manifest: None,
        }
    }

    /// Create a verifier with a specific Risc0 image ID.
    pub fn with_risc0_image(image_id: [u8; 32]) -> Self {
        Self {
            risc0_image_id: Some(image_id),
            manifest: None,
        }
    }

    /// Create a verifier with a signed guest image manifest (preferred for production).
    pub fn with_verified_manifest(
        manifest: GuestImageManifestV1,
        verifying_key: &TokenVerifyingKey,
    ) -> Result<Self, String> {
        manifest
            .verify_with_key(verifying_key)
            .map_err(|e| format!("Invalid manifest signature: {e}"))?;
        Ok(Self {
            risc0_image_id: None,
            manifest: Some(manifest),
        })
    }

    fn kind_allowed_for_mode(&self, mode: DeploymentMode, kind: &[u8; 32]) -> bool {
        match mode {
            DeploymentMode::TrustlessFull => {
                *kind == policy_exec_kind_mpb_id_v1()
                    || *kind == policy_exec_kind_tau_compiled_id_v1()
            }
            DeploymentMode::Private => *kind == policy_exec_kind_host_trusted_id_v0(),
            _ => false,
        }
    }

    /// Verify a proof bundle.
    pub fn verify(&self, request: &VerificationRequest) -> VerificationResponse {
        let mut steps = Vec::new();
        // Fail-closed: if system clock is broken, use 0 for audit timestamp but continue.
        // This is non-critical since timestamp is only for logging, not security decisions.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        // Step 1: Validate request structure
        let structure_valid = self.validate_structure(request, &mut steps);
        if !structure_valid {
            return VerificationResponse {
                valid: false,
                mode: request.mode,
                steps,
                error: Some(ERR_INVALID_REQUEST_STRUCTURE.into()),
                verified_at: timestamp,
            };
        }

        // Step 2: Verify based on mode
        let mode_result = match request.mode {
            DeploymentMode::LocalTrusted => self.verify_local_trusted(request, &mut steps),
            DeploymentMode::TrustlessLite => self.verify_trustless_lite(request, &mut steps),
            DeploymentMode::TrustlessFull => self.verify_trustless_full(request, &mut steps),
            DeploymentMode::Private => self.verify_private(request, &mut steps),
        };

        VerificationResponse {
            valid: mode_result.is_ok(),
            mode: request.mode,
            steps,
            error: mode_result.err(),
            verified_at: timestamp,
        }
    }

    /// Validate request structure.
    fn validate_structure(
        &self,
        request: &VerificationRequest,
        steps: &mut Vec<VerificationStep>,
    ) -> bool {
        fn validate_proof_data_bound(
            proof_data: &[u8],
            max_payload_bytes: u64,
            expected_kind_when_enveloped: mprd_core::wire::WireKind,
        ) -> (bool, String) {
            if proof_data.starts_with(&mprd_core::wire::MAGIC) {
                let header = match mprd_core::wire::peek_envelope_v1(proof_data) {
                    Ok(h) => h,
                    Err(e) => return (false, format!("Invalid envelope header: {e}")),
                };
                if header.kind != expected_kind_when_enveloped {
                    return (
                        false,
                        format!(
                            "Unexpected envelope kind: expected {:?}, got {:?}",
                            expected_kind_when_enveloped, header.kind
                        ),
                    );
                }
                let payload_len = header.payload_len as u64;
                if payload_len > max_payload_bytes {
                    return (
                        false,
                        format!(
                            "Enveloped payload exceeds bound: payload_len={payload_len} max={max_payload_bytes}"
                        ),
                    );
                }
                return (
                    true,
                    format!(
                        "Enveloped payload within bounds: payload_len={payload_len} max={max_payload_bytes}"
                    ),
                );
            }

            let len = proof_data.len() as u64;
            if len > max_payload_bytes {
                return (
                    false,
                    format!("Proof data exceeds bound: len={len} max={max_payload_bytes}"),
                );
            }
            (
                true,
                format!("Input sizes are within configured bounds (len={len})"),
            )
        }

        let (proof_size_ok, details) = match request.mode {
            DeploymentMode::TrustlessFull | DeploymentMode::Private => validate_proof_data_bound(
                &request.proof_data,
                crate::bounded_deser::MAX_RECEIPT_BYTES,
                mprd_core::wire::WireKind::ZkReceiptBincode,
            ),
            DeploymentMode::TrustlessLite => validate_proof_data_bound(
                &request.proof_data,
                crate::bounded_deser::MAX_MPB_ARTIFACT_BYTES,
                mprd_core::wire::WireKind::MpbArtifactBincode,
            ),
            DeploymentMode::LocalTrusted => {
                let ok = request.proof_data.is_empty();
                let details = if ok {
                    "LocalTrusted requires empty proof_data".to_string()
                } else {
                    "LocalTrusted must not include proof_data".to_string()
                };
                (ok, details)
            }
        };

        steps.push(VerificationStep {
            name: "Structure validation".into(),
            passed: proof_size_ok,
            details: Some(details),
        });

        proof_size_ok
    }

    /// Verify Mode A (Local Trusted).
    fn verify_local_trusted(
        &self,
        request: &VerificationRequest,
        steps: &mut Vec<VerificationStep>,
    ) -> Result<(), String> {
        // Mode A just checks that metadata indicates local mode
        let mode_marker = request.metadata.get("mode");
        let is_local = mode_marker
            .map(|m| m == "Local" || m == "A")
            .unwrap_or(false);

        steps.push(VerificationStep {
            name: "Mode A verification".into(),
            passed: is_local,
            details: Some("Local trusted mode - signature verification only".into()),
        });

        if is_local {
            Ok(())
        } else {
            Err(ERR_MODE_MISMATCH.into())
        }
    }

    /// Verify Mode B-Lite (MPB Proofs).
    fn verify_trustless_lite(
        &self,
        request: &VerificationRequest,
        steps: &mut Vec<VerificationStep>,
    ) -> Result<(), String> {
        let mut log = StepLogger::new(steps);

        Self::verify_mpb_lite_marker(request, &mut log)?;
        Self::verify_mpb_lite_backend(request, &mut log)?;
        let meta = Self::parse_mpb_lite_meta(request, &mut log)?;
        let artifact = Self::decode_mpb_lite_artifact(request, &mut log)?;
        Self::verify_mpb_lite_header(&artifact, &mut log)?;
        Self::verify_mpb_lite_bindings(request, &meta, &artifact, &mut log)?;
        let bindings = Self::verify_mpb_registers(&artifact, &mut log)?;
        Self::verify_mpb_proof_bundle(&artifact, &meta, &bindings, &mut log)?;
        Ok(())
    }

    fn verify_mpb_lite_marker(
        request: &VerificationRequest,
        log: &mut StepLogger<'_>,
    ) -> Result<(), String> {
        let mode_marker = request.metadata.get("mode");
        let is_mpb = mode_marker.map(|m| m == "B-Lite").unwrap_or(false);
        log.record(
            "Mode B-Lite marker",
            is_mpb,
            Some(format!("Mode marker: {:?}", mode_marker)),
        );
        if is_mpb {
            Ok(())
        } else {
            Err(ERR_MISSING_B_LITE_MODE_MARKER.into())
        }
    }

    fn verify_mpb_lite_backend(
        request: &VerificationRequest,
        log: &mut StepLogger<'_>,
    ) -> Result<(), String> {
        let backend = request.metadata.get("proof_backend").map(|s| s.as_str());
        if backend != Some("mpb_lite_v1") {
            return log.fail_with(
                "MPB backend",
                Some(format!("expected mpb_lite_v1, got: {:?}", backend)),
                ERR_MPB_METADATA_MISSING,
            );
        }
        log.pass("MPB backend", Some("mpb_lite_v1".into()));
        Ok(())
    }

    fn parse_mpb_lite_meta(
        request: &VerificationRequest,
        log: &mut StepLogger<'_>,
    ) -> Result<MpbLiteMeta, String> {
        let expected_spot_checks = Self::parse_meta_usize(request, "spot_checks")?;
        let expected_fuel_limit = Self::parse_meta_u32(request, "fuel_limit")?;

        let spot_checks_ok = expected_spot_checks >= 16;
        log.record(
            "MPB spot checks",
            spot_checks_ok,
            Some(format!("expected_spot_checks={expected_spot_checks}")),
        );
        if !spot_checks_ok {
            return Err(ERR_MPB_METADATA_MISSING.into());
        }

        let fuel_ok = expected_fuel_limit > 0;
        log.record(
            "MPB fuel limit",
            fuel_ok,
            Some(format!("expected_fuel_limit={expected_fuel_limit}")),
        );
        if !fuel_ok {
            return Err(ERR_MPB_METADATA_MISSING.into());
        }

        Ok(MpbLiteMeta {
            expected_spot_checks,
            expected_fuel_limit,
        })
    }

    fn decode_mpb_lite_artifact(
        request: &VerificationRequest,
        log: &mut StepLogger<'_>,
    ) -> Result<crate::mpb_lite::MpbLiteArtifactV1, String> {
        let artifact = match crate::bounded_deser::deserialize_mpb_artifact(&request.proof_data) {
            Ok(a) => a,
            Err(e) => {
                return log.fail_with(
                    "MPB artifact decode",
                    Some(e.to_string()),
                    ERR_FAILED_DECODE_MPB_ARTIFACT,
                );
            }
        };
        log.pass(
            "MPB artifact decode",
            Some(format!("bytes={}", request.proof_data.len())),
        );
        Ok(artifact)
    }

    fn verify_mpb_lite_header(
        artifact: &crate::mpb_lite::MpbLiteArtifactV1,
        log: &mut StepLogger<'_>,
    ) -> Result<(), String> {
        if let Err(e) = crate::mpb_lite::verify_artifact_header(artifact) {
            return log.fail_with(
                "MPB artifact header",
                Some(e.to_string()),
                ERR_MPB_ARTIFACT_INVALID,
            );
        }
        log.pass("MPB artifact header", Some("ok".into()));
        Ok(())
    }

    fn verify_mpb_lite_bindings(
        request: &VerificationRequest,
        meta: &MpbLiteMeta,
        artifact: &crate::mpb_lite::MpbLiteArtifactV1,
        log: &mut StepLogger<'_>,
    ) -> Result<(), String> {
        let state_hash = mprd_core::hash::hash_state_preimage_v1(&artifact.state_preimage).0;
        Self::ensure_mpb_binding(log, state_hash == request.state_hash, "state_hash mismatch")?;

        let chosen_action_hash =
            mprd_core::hash::hash_candidate_preimage_v1(&artifact.chosen_action_preimage).0;
        Self::ensure_mpb_binding(
            log,
            chosen_action_hash == request.chosen_action_hash,
            "chosen_action_hash mismatch",
        )?;

        let candidate_set_hash = Self::candidate_set_hash(artifact);
        Self::ensure_mpb_binding(
            log,
            candidate_set_hash == request.candidate_set_hash,
            "candidate_set_hash mismatch",
        )?;

        Self::ensure_chosen_index_binding(request, artifact, log)?;

        let policy_hash = crate::mpb_lite::policy_hash_from_artifact_v1(
            &artifact.mpb_proof_bundle.bytecode,
            &artifact.policy_variables,
        )
        .0;
        Self::ensure_mpb_binding(
            log,
            policy_hash == request.policy_hash,
            "policy_hash mismatch",
        )?;

        let limits_hash = Self::verify_mpb_limits(artifact, meta.expected_fuel_limit, log)?;
        let expected_context = Self::mpb_lite_context(request, &limits_hash);
        Self::ensure_context_binding(artifact, &expected_context, log)?;

        log.pass("MPB binding", Some("ok".into()));
        Ok(())
    }

    fn verify_mpb_registers(
        artifact: &crate::mpb_lite::MpbLiteArtifactV1,
        log: &mut StepLogger<'_>,
    ) -> Result<MpbBindings, String> {
        let bindings: Vec<(&[u8], u8)> = artifact
            .policy_variables
            .iter()
            .map(|b| (b.name.as_slice(), b.reg))
            .collect();
        let regs = mprd_mpb::registers_from_preimages_v1(
            &artifact.state_preimage,
            &artifact.chosen_action_preimage,
            &bindings,
        )
        .map_err(|e| format!("register mapping failed: {e:?}"))?;
        let expected_registers: Vec<i64> = regs.to_vec();
        if artifact.mpb_proof_bundle.registers != expected_registers {
            return log.fail_with(
                "MPB registers",
                Some("registers mismatch".into()),
                ERR_MPB_PROOF_VERIFICATION_FAILED,
            );
        }
        Ok(MpbBindings { expected_registers })
    }

    fn verify_mpb_proof_bundle(
        artifact: &crate::mpb_lite::MpbLiteArtifactV1,
        meta: &MpbLiteMeta,
        bindings: &MpbBindings,
        log: &mut StepLogger<'_>,
    ) -> Result<(), String> {
        let expected_bytecode_hash = mprd_proof::sha256(&artifact.mpb_proof_bundle.bytecode);
        let expected_input_hash =
            crate::mpb_lite::registers_input_hash(&bindings.expected_registers);
        if let Err(e) = crate::mpb_lite::verify_mpb_proof_bundle_with_inputs(
            &artifact.mpb_proof_bundle,
            &expected_bytecode_hash,
            &expected_input_hash,
        ) {
            return log.fail_with(
                "MPB proof",
                Some(e.to_string()),
                ERR_MPB_PROOF_VERIFICATION_FAILED,
            );
        }

        let max = artifact.mpb_proof_bundle.proof.num_steps.saturating_sub(2);
        let expected_checks = meta.expected_spot_checks.min(max);
        let spot_checks_ok = artifact.mpb_proof_bundle.proof.spot_checks.len() == expected_checks;
        log.record(
            "MPB proof",
            spot_checks_ok,
            Some(format!(
                "spot_checks={} expected={expected_checks}",
                artifact.mpb_proof_bundle.proof.spot_checks.len()
            )),
        );
        if !spot_checks_ok {
            return Err(ERR_MPB_PROOF_VERIFICATION_FAILED.into());
        }
        if artifact.mpb_proof_bundle.proof.output == 0 {
            return Err(ERR_MPB_PROOF_VERIFICATION_FAILED.into());
        }

        log.pass("MPB proof verification", Some("verified".into()));
        Ok(())
    }

    fn parse_meta_usize(
        request: &VerificationRequest,
        key: &str,
    ) -> Result<usize, String> {
        request
            .metadata
            .get(key)
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or_else(|| ERR_MPB_METADATA_MISSING.to_string())
    }

    fn parse_meta_u32(request: &VerificationRequest, key: &str) -> Result<u32, String> {
        request
            .metadata
            .get(key)
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| ERR_MPB_METADATA_MISSING.to_string())
    }

    fn candidate_set_hash(
        artifact: &crate::mpb_lite::MpbLiteArtifactV1,
    ) -> [u8; 32] {
        let mut set_preimage = Vec::with_capacity(4 + artifact.candidate_hashes.len() * 32);
        set_preimage.extend_from_slice(&(artifact.candidate_hashes.len() as u32).to_le_bytes());
        for h in &artifact.candidate_hashes {
            set_preimage.extend_from_slice(h);
        }
        mprd_core::hash::hash_candidate_set_preimage_v1(&set_preimage).0
    }

    fn verify_mpb_limits(
        artifact: &crate::mpb_lite::MpbLiteArtifactV1,
        expected_fuel_limit: u32,
        log: &mut StepLogger<'_>,
    ) -> Result<mprd_core::Hash32, String> {
        let limits = match mprd_core::limits::parse_limits_v1(&artifact.limits_bytes) {
            Ok(l) => l,
            Err(e) => {
                return log.fail_with(
                    "MPB limits",
                    Some(e.to_string()),
                    ERR_MPB_BINDING_MISMATCH,
                );
            }
        };
        if limits.mpb_fuel_limit != Some(expected_fuel_limit) {
            return log.fail_with(
                "MPB limits",
                Some("mpb_fuel_limit mismatch".into()),
                ERR_MPB_BINDING_MISMATCH,
            );
        }
        Ok(mprd_core::limits::limits_hash_v1(&artifact.limits_bytes))
    }

    fn ensure_mpb_binding(
        log: &mut StepLogger<'_>,
        ok: bool,
        details: &str,
    ) -> Result<(), String> {
        if ok {
            Ok(())
        } else {
            log.fail("MPB binding", Some(details.into()));
            Err(ERR_MPB_BINDING_MISMATCH.into())
        }
    }

    fn ensure_chosen_index_binding(
        request: &VerificationRequest,
        artifact: &crate::mpb_lite::MpbLiteArtifactV1,
        log: &mut StepLogger<'_>,
    ) -> Result<(), String> {
        let idx = artifact.chosen_index as usize;
        let ok = idx < artifact.candidate_hashes.len()
            && artifact.candidate_hashes[idx] == request.chosen_action_hash;
        Self::ensure_mpb_binding(
            log,
            ok,
            "chosen_index does not select chosen_action_hash",
        )
    }

    fn mpb_lite_context(
        request: &VerificationRequest,
        limits_hash: &mprd_core::Hash32,
    ) -> [u8; 32] {
        let token = mprd_core::DecisionToken {
            policy_hash: mprd_core::Hash32(request.policy_hash),
            policy_ref: PolicyRef {
                policy_epoch: request.policy_epoch,
                registry_root: mprd_core::Hash32(request.registry_root),
            },
            state_hash: mprd_core::Hash32(request.state_hash),
            state_ref: StateRef {
                state_source_id: mprd_core::Hash32(request.state_source_id),
                state_epoch: request.state_epoch,
                state_attestation_hash: mprd_core::Hash32(request.state_attestation_hash),
            },
            chosen_action_hash: mprd_core::Hash32(request.chosen_action_hash),
            nonce_or_tx_hash: mprd_core::Hash32(request.nonce_or_tx_hash),
            timestamp_ms: 0,
            signature: Vec::new(),
        };
        crate::mpb_lite::mpb_lite_context_hash_parts_v1(
            &token,
            &mprd_core::Hash32(request.candidate_set_hash),
            limits_hash,
        )
    }

    fn ensure_context_binding(
        artifact: &crate::mpb_lite::MpbLiteArtifactV1,
        expected_context: &[u8; 32],
        log: &mut StepLogger<'_>,
    ) -> Result<(), String> {
        if artifact.mpb_proof_bundle.proof.context_hash != *expected_context {
            return log.fail_with(
                "MPB context",
                Some("context_hash mismatch".into()),
                ERR_MPB_BINDING_MISMATCH,
            );
        }
        Ok(())
    }

    /// Verify Mode B-Full (Risc0 ZK).
    fn verify_trustless_full(
        &self,
        request: &VerificationRequest,
        steps: &mut Vec<VerificationStep>,
    ) -> Result<(), String> {
        self.verify_trustless_full_with_private_limits(request, steps, None)
    }

    fn verify_trustless_full_with_private_limits(
        &self,
        request: &VerificationRequest,
        steps: &mut Vec<VerificationStep>,
        private_expected_limits: Option<[u8; 32]>,
    ) -> Result<(), String> {
        // Check proof data
        if request.proof_data.is_empty() {
            steps.push(VerificationStep {
                name: "Receipt presence".into(),
                passed: false,
                details: Some("No Risc0 receipt in proof data".into()),
            });
            return Err(ERR_EMPTY_RISC0_RECEIPT.into());
        }

        steps.push(VerificationStep {
            name: "Receipt presence".into(),
            passed: true,
            details: Some(format!("Receipt size: {} bytes", request.proof_data.len())),
        });

        // If no manifest is configured, ensure a pinned image ID is available before parsing
        // any untrusted receipt bytes.
        let pinned_image_id = if self.manifest.is_none() {
            let image_id = match self.risc0_image_id {
                Some(id) => id,
                None => {
                    steps.push(VerificationStep {
                        name: "Risc0 configuration".into(),
                        passed: false,
                        details: Some("Risc0 image ID not configured".into()),
                    });
                    return Err(ERR_RISC0_IMAGE_ID_NOT_CONFIGURED.into());
                }
            };
            if image_id == [0u8; 32] {
                steps.push(VerificationStep {
                    name: "Risc0 configuration".into(),
                    passed: false,
                    details: Some(
                        "Risc0 image ID is all-zero; refusing to verify an unspecified guest"
                            .into(),
                    ),
                });
                return Err(ERR_RISC0_IMAGE_ID_ALL_ZERO.into());
            }
            Some(image_id)
        } else {
            None
        };

        // Deserialize Risc0 receipt (bounded to prevent DoS)
        let receipt: risc0_zkvm::Receipt =
            match crate::bounded_deser::deserialize_receipt(&request.proof_data) {
                Ok(r) => r,
                Err(e) => {
                    steps.push(VerificationStep {
                        name: "Receipt deserialization".into(),
                        passed: false,
                        details: Some(format!("Failed to deserialize receipt: {}", e)),
                    });
                    return Err(ERR_FAILED_DESERIALIZE_RISC0_RECEIPT.into());
                }
            };

        // Select expected image ID from verifier-trusted config:
        // - If a manifest is pinned, route based on the (unverified) journal's exec kind/version.
        // - Otherwise, fall back to a pinned image ID.
        let (image_id, journal_for_routing) = if let Some(ref m) = self.manifest {
            let journal: GuestJournalV3 = match receipt.journal.decode() {
                Ok(j) => j,
                Err(e) => {
                    steps.push(VerificationStep {
                        name: "Journal decode (routing)".into(),
                        passed: false,
                        details: Some(format!("Failed to decode journal for routing: {}", e)),
                    });
                    return Err(ERR_FAILED_DECODE_JOURNAL_ROUTING.into());
                }
            };

            if !self.kind_allowed_for_mode(request.mode, &journal.policy_exec_kind_id) {
                steps.push(VerificationStep {
                    name: "Exec kind allowlist".into(),
                    passed: false,
                    details: Some("Unsupported policy_exec_kind for requested mode".into()),
                });
                return Err(ERR_UNSUPPORTED_EXEC_KIND_FOR_MODE.into());
            }

            let image_id = match m.image_id_for(
                &journal.policy_exec_kind_id,
                &journal.policy_exec_version_id,
            ) {
                Some(id) => id,
                None => {
                    steps.push(VerificationStep {
                        name: "Manifest routing".into(),
                        passed: false,
                        details: Some("Manifest missing image_id for exec kind/version".into()),
                    });
                    return Err("Manifest missing image_id for exec kind/version".into());
                }
            };
            (image_id, Some(journal))
        } else {
            (
                pinned_image_id.expect("pinned_image_id must be set when no manifest"),
                None,
            )
        };

        if image_id == [0u8; 32] {
            steps.push(VerificationStep {
                name: "Risc0 configuration".into(),
                passed: false,
                details: Some(
                    "Risc0 image ID is all-zero; refusing to verify an unspecified guest".into(),
                ),
            });
            return Err(ERR_RISC0_IMAGE_ID_ALL_ZERO.into());
        }

        steps.push(VerificationStep {
            name: "Risc0 configuration".into(),
            passed: true,
            details: Some(format!("Image ID: {}", hex::encode(&image_id[..8]))),
        });

        // Verify against image ID
        let digest = risc0_zkvm::sha::Digest::from_bytes(image_id);
        if let Err(e) = receipt.verify(digest) {
            steps.push(VerificationStep {
                name: "Receipt verification".into(),
                passed: false,
                details: Some(format!("Receipt verification failed: {}", e)),
            });
            return Err(ERR_RISC0_RECEIPT_VERIFICATION_FAILED.into());
        }

        steps.push(VerificationStep {
            name: "Receipt verification".into(),
            passed: true,
            details: Some("Risc0 receipt verified successfully".into()),
        });

        // Decode guest journal (or reuse pre-decoded routing journal).
        let journal: GuestJournalV3 = match journal_for_routing {
            Some(j) => j,
            None => match receipt.journal.decode() {
                Ok(j) => j,
                Err(e) => {
                    steps.push(VerificationStep {
                        name: "Journal decode".into(),
                        passed: false,
                        details: Some(format!("Failed to decode journal: {}", e)),
                    });
                    return Err(ERR_FAILED_DECODE_RISC0_JOURNAL.into());
                }
            },
        };

        let commitments_ok = self.verify_journal_commitments_with_private_limits(
            &journal,
            request,
            private_expected_limits,
        );
        steps.push(VerificationStep {
            name: "Commitment binding".into(),
            passed: commitments_ok,
            details: Some("Journal commitments match request".into()),
        });

        if !commitments_ok {
            return Err(ERR_COMMITMENTS_MISMATCH.into());
        }

        Ok(())
    }

    /// Verify Mode C (Private).
    fn verify_private(
        &self,
        request: &VerificationRequest,
        steps: &mut Vec<VerificationStep>,
    ) -> Result<(), String> {
        let mode_marker = request.metadata.get("mode");
        let is_private = mode_marker
            .map(|m| m == "C" || m == "Private")
            .unwrap_or(false);

        steps.push(VerificationStep {
            name: "Mode C marker".into(),
            passed: is_private,
            details: Some(format!("Mode marker: {:?}", mode_marker)),
        });

        if !is_private {
            return Err(ERR_MISSING_MODE_C_MARKER.into());
        }

        let alg = match request.metadata.get("encryption_algorithm") {
            Some(v) => v,
            None => {
                steps.push(VerificationStep {
                    name: "Encryption algorithm".into(),
                    passed: false,
                    details: Some("encryption_algorithm metadata missing".into()),
                });
                return Err(ERR_MISSING_ENCRYPTION_ALGORITHM.into());
            }
        };
        let alg_ok = alg.as_str() == "AES-256-GCM";
        steps.push(VerificationStep {
            name: "Encryption algorithm".into(),
            passed: alg_ok,
            details: Some(format!("algorithm: {}", alg)),
        });
        if !alg_ok {
            return Err(ERR_UNSUPPORTED_ENCRYPTION_ALGORITHM.into());
        }

        let encrypted_state_json = match request.metadata.get("encrypted_state") {
            Some(v) => v,
            None => {
                steps.push(VerificationStep {
                    name: "Encrypted state metadata".into(),
                    passed: false,
                    details: Some("encrypted_state metadata missing".into()),
                });
                return Err(ERR_MISSING_ENCRYPTED_STATE.into());
            }
        };

        let parsed: Result<EncryptedState, _> = serde_json::from_str(encrypted_state_json);

        let encrypted_state = match parsed {
            Ok(value) => {
                steps.push(VerificationStep {
                    name: "Encrypted state parse".into(),
                    passed: true,
                    details: Some(format!("key_id: {}", value.key_id)),
                });
                value
            }
            Err(e) => {
                steps.push(VerificationStep {
                    name: "Encrypted state parse".into(),
                    passed: false,
                    details: Some(format!("Failed to parse encrypted_state: {}", e)),
                });
                return Err(ERR_INVALID_ENCRYPTED_STATE.into());
            }
        };

        let key_id = request
            .metadata
            .get("encryption_key_id")
            .cloned()
            .unwrap_or_else(|| encrypted_state.key_id.clone());

        if let Some(expected_key_id) = request.metadata.get("encryption_key_id") {
            let key_matches = &encrypted_state.key_id == expected_key_id;
            steps.push(VerificationStep {
                name: "Encryption key binding".into(),
                passed: key_matches,
                details: Some(format!(
                    "expected: {:?}, actual: {}",
                    expected_key_id, encrypted_state.key_id
                )),
            });

            if !key_matches {
                return Err(ERR_ENCRYPTION_KEY_ID_MISMATCH.into());
            }
        }

        let expected_limits = self
            .expected_limits_hash_private_from_parts(request, alg, &key_id, &encrypted_state)
            .ok_or_else(|| "Failed to derive expected private limits hash".to_string())?;

        self.verify_trustless_full_with_private_limits(request, steps, Some(expected_limits))
    }

    /// Verify commitments match journal (for Risc0 proofs).
    pub fn verify_journal_commitments(
        &self,
        journal: &GuestJournalV3,
        request: &VerificationRequest,
    ) -> bool {
        self.verify_journal_commitments_with_private_limits(journal, request, None)
    }

    fn verify_journal_commitments_with_private_limits(
        &self,
        journal: &GuestJournalV3,
        request: &VerificationRequest,
        private_expected_limits: Option<[u8; 32]>,
    ) -> bool {
        if journal.journal_version != JOURNAL_VERSION {
            return false;
        }

        if journal.state_encoding_id != state_encoding_id_v1()
            || journal.action_encoding_id != action_encoding_id_v1()
        {
            return false;
        }

        if journal.policy_exec_version_id != policy_exec_version_id_v1() {
            return false;
        }

        // Enforce deterministic limits hash (fail closed).
        let expected_limits = match request.mode {
            DeploymentMode::TrustlessFull => {
                if journal.policy_exec_kind_id == policy_exec_kind_mpb_id_v1() {
                    limits_hash_mpb_v1()
                } else if journal.policy_exec_kind_id == policy_exec_kind_tau_compiled_id_v1() {
                    limits_hash(&[])
                } else {
                    return false;
                }
            }
            DeploymentMode::Private => {
                if journal.policy_exec_kind_id != policy_exec_kind_host_trusted_id_v0() {
                    return false;
                }
                match private_expected_limits.or_else(|| self.expected_limits_hash_private(request))
                {
                    Some(h) => h,
                    None => return false,
                }
            }
            _ => return false,
        };
        if journal.limits_hash != expected_limits {
            return false;
        }

        if journal.decision_commitment != compute_decision_commitment_v3(journal) {
            return false;
        }

        journal.allowed
            && journal.policy_hash == request.policy_hash
            && journal.policy_epoch == request.policy_epoch
            && journal.registry_root == request.registry_root
            && journal.state_source_id == request.state_source_id
            && journal.state_epoch == request.state_epoch
            && journal.state_attestation_hash == request.state_attestation_hash
            && journal.state_hash == request.state_hash
            && journal.candidate_set_hash == request.candidate_set_hash
            && journal.chosen_action_hash == request.chosen_action_hash
            && journal.nonce_or_tx_hash == request.nonce_or_tx_hash
    }

    fn expected_limits_hash_private(&self, request: &VerificationRequest) -> Option<[u8; 32]> {
        let alg = request.metadata.get("encryption_algorithm")?;
        if alg.as_str() != "AES-256-GCM" {
            return None;
        }

        let encrypted_state_json = request.metadata.get("encrypted_state")?;
        let encrypted_state: EncryptedState = serde_json::from_str(encrypted_state_json).ok()?;

        let key_id = request
            .metadata
            .get("encryption_key_id")
            .cloned()
            .unwrap_or_else(|| encrypted_state.key_id.clone());
        if encrypted_state.key_id != key_id {
            return None;
        }

        self.expected_limits_hash_private_from_parts(request, alg, &key_id, &encrypted_state)
    }

    fn expected_limits_hash_private_from_parts(
        &self,
        request: &VerificationRequest,
        alg: &str,
        key_id: &str,
        encrypted_state: &EncryptedState,
    ) -> Option<[u8; 32]> {
        let ctx_hash = mprd_core::limits::mode_c_encryption_ctx_hash_v1(
            &mprd_core::Hash32(request.state_hash),
            &mprd_core::Hash32(request.nonce_or_tx_hash),
            key_id,
            alg,
            &encrypted_state.nonce,
            &encrypted_state.ciphertext,
        );
        let limits_bytes = mprd_core::limits::limits_bytes_mode_c_encryption_ctx_v1(&ctx_hash);
        Some(limits_hash(&limits_bytes))
    }
}

impl Default for ExternalVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a commitment hash from multiple inputs.
pub fn compute_commitment(inputs: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.update(input);
    }
    hasher.finalize().into()
}

/// Serialize a verification response to JSON.
pub fn serialize_response(response: &VerificationResponse) -> Result<String, String> {
    serde_json::to_string_pretty(response).map_err(|e| format!("Serialization failed: {}", e))
}

/// Deserialize a verification request from JSON.
pub fn deserialize_request(json: &str) -> Result<VerificationRequest, String> {
    serde_json::from_str(json).map_err(|e| format!("Deserialization failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap;

    fn find_step<'a>(response: &'a VerificationResponse, name: &str) -> &'a VerificationStep {
        response
            .steps
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("missing step: {name}"))
    }

    #[test]
    fn external_verifier_validates_structure() {
        let verifier = ExternalVerifier::new();

        let request = VerificationRequest {
            mode: DeploymentMode::TrustlessLite,
            policy_hash: [1u8; 32],
            policy_epoch: 1,
            registry_root: [9u8; 32],
            state_source_id: [7u8; 32],
            state_epoch: 123,
            state_attestation_hash: [6u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            nonce_or_tx_hash: [8u8; 32],
            proof_data: vec![],
            metadata: HashMap::from([
                ("mode".into(), "B-Lite".into()),
                ("proof_type".into(), "MPB".into()),
                ("proof_backend".into(), "mpb_lite_v1".into()),
                ("spot_checks".into(), "64".into()),
                ("fuel_limit".into(), "10000".into()),
            ]),
        };

        let response = verifier.verify(&request);
        assert!(!response.valid);
        assert_eq!(response.mode, DeploymentMode::TrustlessLite);
        assert_eq!(
            response.error.as_deref(),
            Some(ERR_FAILED_DECODE_MPB_ARTIFACT)
        );
    }

    #[test]
    fn external_verifier_accepts_valid_mpb_lite_artifact() {
        use mprd_core::hash::{hash_candidate, hash_state};
        use mprd_core::{
            CandidateAction, Decision, DecisionToken, Hash32, PolicyRef, Score, StateRef,
            StateSnapshot, Value, ZkAttestor,
        };

        let bytecode = mprd_core::mpb::BytecodeBuilder::new()
            .push_i64(1)
            .halt()
            .build();
        let policy_hash = crate::mpb_lite::policy_hash_from_artifact_v1(&bytecode, &[]);

        let mut config = crate::modes_v2::ModeConfig::mode_b_lite_with_checks(16);
        config.mpb_max_fuel = 10_000;
        config.mpb_policy_bytecode = Some(bytecode);
        config.mpb_policy_variables = Some(vec![]);
        let attestor = crate::modes_v2::RobustMpbAttestor::new(config).expect("attestor");

        let mut state = StateSnapshot {
            fields: HashMap::from([("x".into(), Value::Int(1))]),
            policy_inputs: HashMap::new(),
            state_hash: Hash32([0u8; 32]),
            state_ref: StateRef {
                state_source_id: Hash32([7u8; 32]),
                state_epoch: 123,
                state_attestation_hash: Hash32([6u8; 32]),
            },
        };
        state.state_hash = hash_state(&state);

        let mut action = CandidateAction {
            action_type: "noop".into(),
            params: HashMap::new(),
            score: Score(42),
            candidate_hash: Hash32([0u8; 32]),
        };
        action.candidate_hash = hash_candidate(&action);
        let candidates = vec![action.clone()];

        let token = DecisionToken {
            policy_hash: policy_hash.clone(),
            policy_ref: PolicyRef {
                policy_epoch: 1,
                registry_root: Hash32([9u8; 32]),
            },
            state_hash: state.state_hash.clone(),
            state_ref: state.state_ref.clone(),
            chosen_action_hash: action.candidate_hash.clone(),
            nonce_or_tx_hash: Hash32([8u8; 32]),
            timestamp_ms: 0,
            signature: Vec::new(),
        };

        let decision = Decision {
            chosen_index: 0,
            chosen_action: action.clone(),
            policy_hash: policy_hash.clone(),
            decision_commitment: Hash32([1u8; 32]),
        };

        let proof = attestor
            .attest(&token, &decision, &state, &candidates)
            .expect("attest");

        let verifier = ExternalVerifier::new();
        let request = VerificationRequest {
            mode: DeploymentMode::TrustlessLite,
            policy_hash: token.policy_hash.0,
            policy_epoch: token.policy_ref.policy_epoch,
            registry_root: token.policy_ref.registry_root.0,
            state_source_id: token.state_ref.state_source_id.0,
            state_epoch: token.state_ref.state_epoch,
            state_attestation_hash: token.state_ref.state_attestation_hash.0,
            state_hash: token.state_hash.0,
            candidate_set_hash: proof.candidate_set_hash.0,
            chosen_action_hash: token.chosen_action_hash.0,
            nonce_or_tx_hash: token.nonce_or_tx_hash.0,
            proof_data: proof.risc0_receipt.clone(),
            metadata: proof.attestation_metadata.clone(),
        };

        let response = verifier.verify(&request);
        assert!(
            response.valid,
            "steps={:?} err={:?}",
            response.steps, response.error
        );
        assert_eq!(response.error, None);
    }

    #[test]
    fn external_verifier_rejects_oversize_proof_data_fail_closed() {
        let verifier = ExternalVerifier::new();

        let request = VerificationRequest {
            mode: DeploymentMode::TrustlessLite,
            policy_hash: [1u8; 32],
            policy_epoch: 1,
            registry_root: [9u8; 32],
            state_source_id: [7u8; 32],
            state_epoch: 123,
            state_attestation_hash: [6u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            nonce_or_tx_hash: [8u8; 32],
            proof_data: vec![0u8; (crate::bounded_deser::MAX_MPB_ARTIFACT_BYTES as usize) + 1],
            metadata: HashMap::from([("mode".into(), "B-Lite".into())]),
        };

        let response = verifier.verify(&request);
        assert!(!response.valid);
        assert_eq!(
            response.error.as_deref(),
            Some(ERR_INVALID_REQUEST_STRUCTURE)
        );
        assert!(!find_step(&response, "Structure validation").passed);
    }

    #[test]
    fn external_verifier_accepts_enveloped_receipt_overhead_within_bounds() {
        let verifier = ExternalVerifier::with_risc0_image([1u8; 32]);

        let payload = vec![1u8, 2u8, 3u8];
        let proof_data =
            mprd_core::wire::wrap_v1(mprd_core::wire::WireKind::ZkReceiptBincode, 0, &payload);

        let request = VerificationRequest {
            mode: DeploymentMode::TrustlessFull,
            policy_hash: [1u8; 32],
            policy_epoch: 1,
            registry_root: [9u8; 32],
            state_source_id: [7u8; 32],
            state_epoch: 123,
            state_attestation_hash: [6u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            nonce_or_tx_hash: [8u8; 32],
            proof_data,
            metadata: HashMap::new(),
        };

        let response = verifier.verify(&request);
        assert!(!response.valid);
        assert!(find_step(&response, "Structure validation").passed);
        assert_eq!(
            response.error.as_deref(),
            Some(ERR_FAILED_DESERIALIZE_RISC0_RECEIPT)
        );
        assert!(!find_step(&response, "Receipt deserialization").passed);
    }

    #[test]
    fn external_verifier_rejects_oversize_enveloped_proof_data_fail_closed() {
        let verifier = ExternalVerifier::new();

        let payload = vec![0u8; (crate::bounded_deser::MAX_MPB_ARTIFACT_BYTES as usize) + 1];
        let proof_data =
            mprd_core::wire::wrap_v1(mprd_core::wire::WireKind::MpbArtifactBincode, 0, &payload);

        let request = VerificationRequest {
            mode: DeploymentMode::TrustlessLite,
            policy_hash: [1u8; 32],
            policy_epoch: 1,
            registry_root: [9u8; 32],
            state_source_id: [7u8; 32],
            state_epoch: 123,
            state_attestation_hash: [6u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            nonce_or_tx_hash: [8u8; 32],
            proof_data,
            metadata: HashMap::from([("mode".into(), "B-Lite".into())]),
        };

        let response = verifier.verify(&request);
        assert!(!response.valid);
        assert_eq!(
            response.error.as_deref(),
            Some(ERR_INVALID_REQUEST_STRUCTURE)
        );
        assert!(!find_step(&response, "Structure validation").passed);
    }

    #[test]
    fn external_verifier_rejects_wrong_mode() {
        let verifier = ExternalVerifier::new();

        let request = VerificationRequest {
            mode: DeploymentMode::TrustlessLite,
            policy_hash: [1u8; 32],
            policy_epoch: 1,
            registry_root: [9u8; 32],
            state_source_id: [7u8; 32],
            state_epoch: 123,
            state_attestation_hash: [6u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            nonce_or_tx_hash: [8u8; 32],
            proof_data: vec![],
            metadata: HashMap::from([
                ("mode".into(), "B-Full".into()), // Wrong mode!
            ]),
        };

        let response = verifier.verify(&request);
        assert!(!response.valid);
    }

    #[test]
    fn external_verifier_local_mode_requires_marker() {
        let verifier = ExternalVerifier::new();

        let request = VerificationRequest {
            mode: DeploymentMode::LocalTrusted,
            policy_hash: [1u8; 32],
            policy_epoch: 1,
            registry_root: [9u8; 32],
            state_source_id: [7u8; 32],
            state_epoch: 123,
            state_attestation_hash: [6u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            nonce_or_tx_hash: [8u8; 32],
            proof_data: vec![],
            metadata: HashMap::new(),
        };

        let response = verifier.verify(&request);
        assert!(!response.valid);
    }

    #[test]
    fn external_verifier_risc0_requires_config() {
        let verifier = ExternalVerifier::new(); // No image ID

        let request = VerificationRequest {
            mode: DeploymentMode::TrustlessFull,
            policy_hash: [1u8; 32],
            policy_epoch: 1,
            registry_root: [9u8; 32],
            state_source_id: [7u8; 32],
            state_epoch: 123,
            state_attestation_hash: [6u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            nonce_or_tx_hash: [8u8; 32],
            proof_data: vec![1, 2, 3],
            metadata: HashMap::new(),
        };

        let response = verifier.verify(&request);
        assert!(!response.valid);
        assert_eq!(
            response.error.as_deref(),
            Some(ERR_RISC0_IMAGE_ID_NOT_CONFIGURED)
        );
        assert!(!find_step(&response, "Risc0 configuration").passed);
    }

    #[test]
    fn external_verifier_risc0_rejects_all_zero_image_id() {
        let verifier = ExternalVerifier::with_risc0_image([0u8; 32]);

        let request = VerificationRequest {
            mode: DeploymentMode::TrustlessFull,
            policy_hash: [1u8; 32],
            policy_epoch: 1,
            registry_root: [9u8; 32],
            state_source_id: [7u8; 32],
            state_epoch: 123,
            state_attestation_hash: [6u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            nonce_or_tx_hash: [8u8; 32],
            proof_data: vec![1, 2, 3],
            metadata: HashMap::new(),
        };

        let response = verifier.verify(&request);
        assert!(!response.valid);
        assert_eq!(response.error.as_deref(), Some(ERR_RISC0_IMAGE_ID_ALL_ZERO));
        assert!(!find_step(&response, "Risc0 configuration").passed);
    }

    #[test]
    fn commitment_computation() {
        let input1 = [1u8; 32];
        let input2 = [2u8; 32];

        let commitment = compute_commitment(&[&input1, &input2]);
        assert_eq!(commitment.len(), 32);

        // Same inputs should produce same commitment
        let commitment2 = compute_commitment(&[&input1, &input2]);
        assert_eq!(commitment, commitment2);

        // Different inputs should produce different commitment
        let commitment3 = compute_commitment(&[&input2, &input1]);
        assert_ne!(commitment, commitment3);
    }

    #[test]
    fn serialization_roundtrip() {
        let response = VerificationResponse {
            valid: true,
            mode: DeploymentMode::TrustlessLite,
            steps: vec![VerificationStep {
                name: "Test".into(),
                passed: true,
                details: Some("Details".into()),
            }],
            error: None,
            verified_at: 12345,
        };

        let json = serialize_response(&response).unwrap();
        let roundtrip: VerificationResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(roundtrip, response);
    }

    #[test]
    fn verify_journal_commitments_accepts_tau_compiled_in_b_full() {
        let verifier = ExternalVerifier::new();

        let request = VerificationRequest {
            mode: DeploymentMode::TrustlessFull,
            policy_hash: [1u8; 32],
            policy_epoch: 1,
            registry_root: [9u8; 32],
            state_source_id: [7u8; 32],
            state_epoch: 123,
            state_attestation_hash: [6u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            nonce_or_tx_hash: [8u8; 32],
            proof_data: vec![],
            metadata: HashMap::new(),
        };

        let mut journal = GuestJournalV3 {
            journal_version: JOURNAL_VERSION,
            policy_hash: request.policy_hash,
            policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            state_encoding_id: state_encoding_id_v1(),
            action_encoding_id: action_encoding_id_v1(),
            policy_epoch: request.policy_epoch,
            registry_root: request.registry_root,
            state_source_id: request.state_source_id,
            state_epoch: request.state_epoch,
            state_attestation_hash: request.state_attestation_hash,
            state_hash: request.state_hash,
            candidate_set_hash: request.candidate_set_hash,
            chosen_action_hash: request.chosen_action_hash,
            limits_hash: limits_hash(&[]),
            nonce_or_tx_hash: request.nonce_or_tx_hash,
            chosen_index: 0,
            allowed: true,
            decision_commitment: [0u8; 32],
        };
        journal.decision_commitment = compute_decision_commitment_v3(&journal);

        assert!(verifier.verify_journal_commitments(&journal, &request));
    }

    #[test]
    fn verify_journal_commitments_accepts_mpb_in_b_full() {
        let verifier = ExternalVerifier::new();

        let request = VerificationRequest {
            mode: DeploymentMode::TrustlessFull,
            policy_hash: [1u8; 32],
            policy_epoch: 1,
            registry_root: [9u8; 32],
            state_source_id: [7u8; 32],
            state_epoch: 123,
            state_attestation_hash: [6u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            nonce_or_tx_hash: [8u8; 32],
            proof_data: vec![],
            metadata: HashMap::new(),
        };

        let mut journal = GuestJournalV3 {
            journal_version: JOURNAL_VERSION,
            policy_hash: request.policy_hash,
            policy_exec_kind_id: policy_exec_kind_mpb_id_v1(),
            policy_exec_version_id: policy_exec_version_id_v1(),
            state_encoding_id: state_encoding_id_v1(),
            action_encoding_id: action_encoding_id_v1(),
            policy_epoch: request.policy_epoch,
            registry_root: request.registry_root,
            state_source_id: request.state_source_id,
            state_epoch: request.state_epoch,
            state_attestation_hash: request.state_attestation_hash,
            state_hash: request.state_hash,
            candidate_set_hash: request.candidate_set_hash,
            chosen_action_hash: request.chosen_action_hash,
            limits_hash: limits_hash_mpb_v1(),
            nonce_or_tx_hash: request.nonce_or_tx_hash,
            chosen_index: 0,
            allowed: true,
            decision_commitment: [0u8; 32],
        };
        journal.decision_commitment = compute_decision_commitment_v3(&journal);

        assert!(verifier.verify_journal_commitments(&journal, &request));
    }

    proptest! {
        #[test]
        fn verify_journal_commitments_fails_closed_on_any_binding_mismatch(
            which in 0u8..=13u8,
            byte in 0usize..32,
            bit in 0u8..8u8,
        ) {
            let verifier = ExternalVerifier::new();

            let request = VerificationRequest {
                mode: DeploymentMode::TrustlessFull,
                policy_hash: [1u8; 32],
                policy_epoch: 1,
                registry_root: [9u8; 32],
                state_source_id: [7u8; 32],
                state_epoch: 123,
                state_attestation_hash: [6u8; 32],
                state_hash: [2u8; 32],
                candidate_set_hash: [3u8; 32],
                chosen_action_hash: [4u8; 32],
                nonce_or_tx_hash: [8u8; 32],
                proof_data: vec![],
                metadata: HashMap::new(),
            };

            let mut journal = GuestJournalV3 {
                journal_version: JOURNAL_VERSION,
                policy_hash: request.policy_hash,
                policy_exec_kind_id: policy_exec_kind_tau_compiled_id_v1(),
                policy_exec_version_id: policy_exec_version_id_v1(),
                state_encoding_id: state_encoding_id_v1(),
                action_encoding_id: action_encoding_id_v1(),
                policy_epoch: request.policy_epoch,
                registry_root: request.registry_root,
                state_source_id: request.state_source_id,
                state_epoch: request.state_epoch,
                state_attestation_hash: request.state_attestation_hash,
                state_hash: request.state_hash,
                candidate_set_hash: request.candidate_set_hash,
                chosen_action_hash: request.chosen_action_hash,
                limits_hash: limits_hash(&[]),
                nonce_or_tx_hash: request.nonce_or_tx_hash,
                chosen_index: 0,
                allowed: true,
                decision_commitment: [0u8; 32],
            };
            journal.decision_commitment = compute_decision_commitment_v3(&journal);
            prop_assert!(verifier.verify_journal_commitments(&journal, &request));

            match which {
                0 => journal.policy_hash[byte] ^= 1u8 << bit,
                1 => journal.registry_root[byte] ^= 1u8 << bit,
                2 => journal.state_source_id[byte] ^= 1u8 << bit,
                3 => journal.state_attestation_hash[byte] ^= 1u8 << bit,
                4 => journal.state_hash[byte] ^= 1u8 << bit,
                5 => journal.candidate_set_hash[byte] ^= 1u8 << bit,
                6 => journal.chosen_action_hash[byte] ^= 1u8 << bit,
                7 => journal.nonce_or_tx_hash[byte] ^= 1u8 << bit,
                8 => journal.policy_epoch ^= 1u64 << (bit as u32),
                9 => journal.state_epoch ^= 1u64 << (bit as u32),
                10 => journal.allowed = false,
                11 => journal.policy_exec_kind_id[byte] ^= 1u8 << bit,
                12 => journal.state_encoding_id[byte] ^= 1u8 << bit,
                _ => journal.action_encoding_id[byte] ^= 1u8 << bit,
            }
            journal.decision_commitment = compute_decision_commitment_v3(&journal);

            prop_assert!(!verifier.verify_journal_commitments(&journal, &request));
        }
    }
}
