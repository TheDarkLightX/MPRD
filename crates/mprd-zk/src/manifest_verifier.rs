use crate::manifest::GuestImageManifestV1;
use crate::risc0_host::Risc0Verifier;
use mprd_core::{
    DecisionToken, ProofBundle, TokenVerifyingKey, VerificationStatus, ZkLocalVerifier,
};
use mprd_risc0_shared::GuestJournalV3;

/// Fail-closed Risc0 verifier that routes to an allowlisted image ID using a pinned, signed
/// guest image manifest.
///
/// Routing is based on the (unverified) journal's `(policy_exec_kind_id, policy_exec_version_id)`,
/// then the receipt is verified against the selected image ID. Any mismatch fails closed.
pub struct ManifestBoundRisc0Verifier {
    manifest: GuestImageManifestV1,
}

impl ManifestBoundRisc0Verifier {
    pub fn new_verified(
        manifest: GuestImageManifestV1,
        verifying_key: &TokenVerifyingKey,
    ) -> mprd_core::Result<Self> {
        manifest.verify_with_key(verifying_key)?;
        Ok(Self { manifest })
    }
}

impl ZkLocalVerifier for ManifestBoundRisc0Verifier {
    fn verify(&self, token: &DecisionToken, proof: &ProofBundle) -> VerificationStatus {
        if proof.risc0_receipt.is_empty() {
            return VerificationStatus::Failure("No Risc0 receipt in proof bundle".into());
        }

        // Deserialize the receipt (bounded to prevent DoS).
        let receipt: risc0_zkvm::Receipt =
            match crate::bounded_deser::deserialize_receipt(&proof.risc0_receipt) {
                Ok(r) => r,
                Err(e) => {
                    return VerificationStatus::Failure(format!(
                        "Failed to deserialize receipt: {e}"
                    ))
                }
            };

        // Decode the journal *before* verifying (untrusted) to determine routing.
        let journal: GuestJournalV3 = match receipt.journal.decode() {
            Ok(j) => j,
            Err(e) => return VerificationStatus::Failure(format!("Failed to decode journal: {e}")),
        };

        // Select the expected image ID from the verifier-trusted manifest.
        let image_id = match self.manifest.image_id_for(
            &journal.policy_exec_kind_id,
            &journal.policy_exec_version_id,
        ) {
            Some(id) => id,
            None => {
                return VerificationStatus::Failure(
                    "Manifest missing image_id for policy_exec_kind/version".into(),
                )
            }
        };

        if image_id == [0u8; 32] {
            return VerificationStatus::Failure(
                "Invalid (all-zero) image_id selected from manifest".into(),
            );
        }

        // Cryptographically verify the receipt against the allowlisted image ID.
        let digest = risc0_zkvm::sha::Digest::from_bytes(image_id);
        if let Err(e) = receipt.verify(digest) {
            return VerificationStatus::Failure(format!("Receipt verification failed: {e}"));
        }

        let verifier = Risc0Verifier::new(
            image_id,
            journal.policy_exec_kind_id,
            journal.policy_exec_version_id,
        );
        verifier.verify_decoded_journal(token, proof, &journal)
    }
}
