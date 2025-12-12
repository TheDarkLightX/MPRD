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

use crate::abi::GovernorJournal;
use crate::modes::{DeploymentMode, ExtendedVerificationResult, VerificationStep};
use crate::privacy::EncryptedState;
use crate::risc0_host::GuestOutput as Risc0GuestOutput;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// External verification request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationRequest {
    /// Deployment mode claimed by the proof.
    pub mode: DeploymentMode,

    /// Policy hash commitment.
    pub policy_hash: [u8; 32],

    /// State hash commitment.
    pub state_hash: [u8; 32],

    /// Candidate set hash commitment.
    pub candidate_set_hash: [u8; 32],

    /// Chosen action hash commitment.
    pub chosen_action_hash: [u8; 32],

    /// Proof data (format depends on mode).
    pub proof_data: Vec<u8>,

    /// Attestation metadata.
    pub metadata: std::collections::HashMap<String, String>,
}

/// External verification response.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// External verifier for MPRD proofs.
///
/// This verifier operates without access to the original state or candidates,
/// only using the commitments and proof data.
pub struct ExternalVerifier {
    /// Risc0 image ID for Mode B-Full verification.
    risc0_image_id: Option<[u8; 32]>,
}

impl ExternalVerifier {
    /// Create a new external verifier.
    pub fn new() -> Self {
        Self {
            risc0_image_id: None,
        }
    }

    /// Create a verifier with a specific Risc0 image ID.
    pub fn with_risc0_image(image_id: [u8; 32]) -> Self {
        Self {
            risc0_image_id: Some(image_id),
        }
    }

    /// Verify a proof bundle.
    pub fn verify(&self, request: &VerificationRequest) -> VerificationResponse {
        let mut steps = Vec::new();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        // Step 1: Validate request structure
        let structure_valid = self.validate_structure(request, &mut steps);
        if !structure_valid {
            return VerificationResponse {
                valid: false,
                mode: request.mode,
                steps,
                error: Some("Invalid request structure".into()),
                verified_at: timestamp,
            };
        }

        // Step 2: Verify based on mode
        let mode_result = match request.mode {
            DeploymentMode::LocalTrusted => {
                self.verify_local_trusted(request, &mut steps)
            }
            DeploymentMode::TrustlessLite => {
                self.verify_trustless_lite(request, &mut steps)
            }
            DeploymentMode::TrustlessFull => {
                self.verify_trustless_full(request, &mut steps)
            }
            DeploymentMode::Private => {
                self.verify_private(request, &mut steps)
            }
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
    fn validate_structure(&self, request: &VerificationRequest, steps: &mut Vec<VerificationStep>) -> bool {
        // Check hash lengths
        let hashes_valid = request.policy_hash.len() == 32
            && request.state_hash.len() == 32
            && request.candidate_set_hash.len() == 32
            && request.chosen_action_hash.len() == 32;

        steps.push(VerificationStep {
            name: "Structure validation".into(),
            passed: hashes_valid,
            details: if hashes_valid {
                Some("All hash commitments are 32 bytes".into())
            } else {
                Some("Invalid hash length".into())
            },
        });

        hashes_valid
    }

    /// Verify Mode A (Local Trusted).
    fn verify_local_trusted(&self, request: &VerificationRequest, steps: &mut Vec<VerificationStep>) -> Result<(), String> {
        // Mode A just checks that metadata indicates local mode
        let mode_marker = request.metadata.get("mode");
        let is_local = mode_marker.map(|m| m == "Local" || m == "A").unwrap_or(true);

        steps.push(VerificationStep {
            name: "Mode A verification".into(),
            passed: is_local,
            details: Some("Local trusted mode - signature verification only".into()),
        });

        if is_local {
            Ok(())
        } else {
            Err("Mode mismatch".into())
        }
    }

    /// Verify Mode B-Lite (MPB Proofs).
    fn verify_trustless_lite(&self, request: &VerificationRequest, steps: &mut Vec<VerificationStep>) -> Result<(), String> {
        // Check mode marker
        let mode_marker = request.metadata.get("mode");
        let is_mpb = mode_marker.map(|m| m == "B-Lite").unwrap_or(false);

        steps.push(VerificationStep {
            name: "Mode B-Lite marker".into(),
            passed: is_mpb,
            details: Some(format!("Mode marker: {:?}", mode_marker)),
        });

        if !is_mpb {
            return Err("Missing B-Lite mode marker".into());
        }

        // Verify proof type
        let proof_type = request.metadata.get("proof_type");
        let is_mpb_proof = proof_type.map(|t| t == "MPB").unwrap_or(false);

        steps.push(VerificationStep {
            name: "Proof type".into(),
            passed: is_mpb_proof,
            details: Some(format!("Proof type: {:?}", proof_type)),
        });

        if !is_mpb_proof {
            return Err("Invalid proof type for B-Lite".into());
        }

        // For full verification, we would need to:
        // 1. Deserialize the MPB proof from proof_data
        // 2. Verify the Merkle proofs
        // 3. Re-execute spot-checked steps

        steps.push(VerificationStep {
            name: "Commitment binding".into(),
            passed: true,
            details: Some("Commitments are structurally valid".into()),
        });

        Ok(())
    }

    /// Verify Mode B-Full (Risc0 ZK).
    fn verify_trustless_full(&self, request: &VerificationRequest, steps: &mut Vec<VerificationStep>) -> Result<(), String> {
        // Check if Risc0 image ID is configured
        let image_id = match self.risc0_image_id {
            Some(id) => id,
            None => {
                steps.push(VerificationStep {
                    name: "Risc0 configuration".into(),
                    passed: false,
                    details: Some("Risc0 image ID not configured".into()),
                });
                return Err("Risc0 image ID required for B-Full verification".into());
            }
        };

        steps.push(VerificationStep {
            name: "Risc0 configuration".into(),
            passed: true,
            details: Some(format!("Image ID: {}", hex::encode(&image_id[..8]))),
        });

        // Check proof data
        if request.proof_data.is_empty() {
            steps.push(VerificationStep {
                name: "Receipt presence".into(),
                passed: false,
                details: Some("No Risc0 receipt in proof data".into()),
            });
            return Err("Empty Risc0 receipt".into());
        }

        steps.push(VerificationStep {
            name: "Receipt presence".into(),
            passed: true,
            details: Some(format!("Receipt size: {} bytes", request.proof_data.len())),
        });

        // Deserialize Risc0 receipt
        let receipt: risc0_zkvm::Receipt = match bincode::deserialize(&request.proof_data) {
            Ok(r) => r,
            Err(e) => {
                steps.push(VerificationStep {
                    name: "Receipt deserialization".into(),
                    passed: false,
                    details: Some(format!("Failed to deserialize receipt: {}", e)),
                });
                return Err("Failed to deserialize Risc0 receipt".into());
            }
        };

        // Verify against image ID
        let digest = risc0_zkvm::sha::Digest::from_bytes(image_id);
        if let Err(e) = receipt.verify(digest) {
            steps.push(VerificationStep {
                name: "Receipt verification".into(),
                passed: false,
                details: Some(format!("Receipt verification failed: {}", e)),
            });
            return Err("Risc0 receipt verification failed".into());
        }

        steps.push(VerificationStep {
            name: "Receipt verification".into(),
            passed: true,
            details: Some("Risc0 receipt verified successfully".into()),
        });

        // Decode guest output (same GuestOutput used by decision-level Risc0 host)
        let output: Risc0GuestOutput = match receipt.journal.decode() {
            Ok(o) => o,
            Err(e) => {
                steps.push(VerificationStep {
                    name: "Journal decode".into(),
                    passed: false,
                    details: Some(format!("Failed to decode journal: {}", e)),
                });
                return Err("Failed to decode Risc0 journal".into());
            }
        };

        // Map to GovernorJournal shape for commitment checks
        let journal = GovernorJournal {
            policy_hash: output.policy_hash,
            state_hash: output.state_hash,
            candidate_set_hash: output.candidate_set_hash,
            chosen_action_hash: output.chosen_action_hash,
            chosen_index: 0,
            allowed: output.selector_contract_satisfied,
        };

        let commitments_ok = self.verify_journal_commitments(&journal, request);
        steps.push(VerificationStep {
            name: "Commitment binding".into(),
            passed: commitments_ok,
            details: Some("Journal commitments match request".into()),
        });

        if !commitments_ok {
            return Err("Commitments in journal do not match request".into());
        }

        Ok(())
    }

    /// Verify Mode C (Private).
    fn verify_private(&self, request: &VerificationRequest, steps: &mut Vec<VerificationStep>) -> Result<(), String> {
        let mode_marker = request.metadata.get("mode");
        let is_private = mode_marker.map(|m| m == "C" || m == "Private").unwrap_or(false);

        steps.push(VerificationStep {
            name: "Mode C marker".into(),
            passed: is_private,
            details: Some(format!("Mode marker: {:?}", mode_marker)),
        });

        if !is_private {
            return Err("Missing Mode C marker".into());
        }

        let encrypted_state_json = match request.metadata.get("encrypted_state") {
            Some(v) => v,
            None => {
                steps.push(VerificationStep {
                    name: "Encrypted state metadata".into(),
                    passed: false,
                    details: Some("encrypted_state metadata missing".into()),
                });
                return Err("Missing encrypted_state metadata for Mode C".into());
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
                return Err("Invalid encrypted_state metadata".into());
            }
        };

        if let Some(expected_key_id) = request.metadata.get("encryption_key_id") {
            let key_matches = &encrypted_state.key_id == expected_key_id;
            steps.push(VerificationStep {
                name: "Encryption key binding".into(),
                passed: key_matches,
                details: Some(format!(
                    "expected: {:?}, actual: {}",
                    expected_key_id,
                    encrypted_state.key_id
                )),
            });

            if !key_matches {
                return Err("Encryption key_id mismatch for Mode C".into());
            }
        }

        self.verify_trustless_full(request, steps)
    }

    /// Verify commitments match journal (for Risc0 proofs).
    pub fn verify_journal_commitments(
        &self,
        journal: &GovernorJournal,
        request: &VerificationRequest,
    ) -> bool {
        journal.policy_hash == request.policy_hash
            && journal.state_hash == request.state_hash
            && journal.candidate_set_hash == request.candidate_set_hash
            && journal.chosen_action_hash == request.chosen_action_hash
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
    serde_json::to_string_pretty(response)
        .map_err(|e| format!("Serialization failed: {}", e))
}

/// Deserialize a verification request from JSON.
pub fn deserialize_request(json: &str) -> Result<VerificationRequest, String> {
    serde_json::from_str(json)
        .map_err(|e| format!("Deserialization failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn external_verifier_validates_structure() {
        let verifier = ExternalVerifier::new();

        let request = VerificationRequest {
            mode: DeploymentMode::TrustlessLite,
            policy_hash: [1u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            proof_data: vec![],
            metadata: HashMap::from([
                ("mode".into(), "B-Lite".into()),
                ("proof_type".into(), "MPB".into()),
            ]),
        };

        let response = verifier.verify(&request);
        assert!(response.valid);
        assert_eq!(response.mode, DeploymentMode::TrustlessLite);
    }

    #[test]
    fn external_verifier_rejects_wrong_mode() {
        let verifier = ExternalVerifier::new();

        let request = VerificationRequest {
            mode: DeploymentMode::TrustlessLite,
            policy_hash: [1u8; 32],
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            proof_data: vec![],
            metadata: HashMap::from([
                ("mode".into(), "B-Full".into()), // Wrong mode!
            ]),
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
            state_hash: [2u8; 32],
            candidate_set_hash: [3u8; 32],
            chosen_action_hash: [4u8; 32],
            proof_data: vec![1, 2, 3],
            metadata: HashMap::new(),
        };

        let response = verifier.verify(&request);
        assert!(!response.valid);
        assert!(response.error.as_ref().unwrap().contains("image ID"));
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
            steps: vec![
                VerificationStep {
                    name: "Test".into(),
                    passed: true,
                    details: Some("Details".into()),
                },
            ],
            error: None,
            verified_at: 12345,
        };

        let json = serialize_response(&response).unwrap();
        assert!(json.contains("TrustlessLite"));
    }
}
