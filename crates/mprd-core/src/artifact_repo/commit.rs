//! Algorithm 2: Verify Commit Header + Signature.
//!
//! Ensures the commit is signed by an allowed signer and is structurally sane
//! before fetching any tree blocks.

use ed25519_dalek::{Signature, VerifyingKey};

use super::codec::decode_commit;
use super::error::{ArtifactRepoError, Result};
use super::store::TrustAnchors;
use super::types::{compute_block_id, BlockId, BlockTag, Commit, CommitId, Id32};

/// Verify commit header and signature (Algorithm 2).
///
/// # Preconditions
/// - `commit_bytes` is bounded by MAX_BLOCK_BYTES (caller responsibility)
///
/// # Postconditions
/// - Returns parsed Commit if:
///   - Content addressing is valid (sha256 matches commit_id)
///   - Block tag is Commit (0x03) and codec version is 1
///   - Signer is in trusted_commit_signers
///   - Ed25519 signature is valid
/// - Fails closed on any error
///
/// # Complexity
/// - Time: O(1)
/// - Space: O(1)
/// - I/O: 0
pub fn verify_commit_header_and_signature(
    commit_id: &CommitId,
    commit_bytes: &[u8],
    trust_anchors: &TrustAnchors,
) -> Result<Commit> {
    // Step 0: Verify content addressing
    let computed_id = compute_block_id(commit_bytes);
    if computed_id != *commit_id {
        return Err(ArtifactRepoError::ContentAddressMismatch {
            expected: *commit_id,
            actual: computed_id,
        });
    }

    // Step 1: Parse commit bytes with bounded decoder
    if commit_bytes.len() < 2 {
        return Err(ArtifactRepoError::MalformedCommit(
            "commit too short".into(),
        ));
    }

    // Verify outer block header
    let tag = commit_bytes[0];
    let version = commit_bytes[1];

    if tag != BlockTag::Commit as u8 {
        return Err(ArtifactRepoError::InvalidBlockTag(tag));
    }
    if version != 1 {
        return Err(ArtifactRepoError::InvalidCodecVersion(version));
    }

    // Decode commit structure
    let commit = decode_commit(commit_bytes)?;

    // Verify repo_version
    if commit.repo_version != 1 {
        return Err(ArtifactRepoError::MalformedCommit(format!(
            "unsupported repo_version: {}",
            commit.repo_version
        )));
    }

    // Step 2: Verify signer is trusted
    if !trust_anchors.is_commit_signer_trusted(&commit.signer_pubkey) {
        return Err(ArtifactRepoError::SignerNotTrusted(commit.signer_pubkey));
    }

    // Step 3: Compute canonical signing_bytes
    let signing_bytes = commit.signing_bytes();

    // Step 4: Verify Ed25519 signature
    let verifying_key = VerifyingKey::from_bytes(&commit.signer_pubkey)
        .map_err(|_| ArtifactRepoError::SignatureVerificationFailed)?;

    let signature = Signature::from_bytes(&commit.signature);

    verifying_key
        .verify_strict(&signing_bytes, &signature)
        .map_err(|_| ArtifactRepoError::SignatureVerificationFailed)?;

    // Step 5: Return parsed commit
    Ok(commit)
}

/// Create a signed commit (for publishers).
///
/// # Preconditions
/// - `signing_key` is a valid Ed25519 signing key
///
/// # Postconditions
/// - Returns (CommitId, commit_bytes) where commit_bytes is the encoded commit block
#[derive(Clone, Copy, Debug)]
pub struct CommitFields {
    pub repo_version: u32,
    pub prev_commit: CommitId,
    pub commit_height: u64,
    pub repo_root: BlockId,
    pub policy_epoch: u64,
    pub registry_root: Id32,
    pub manifest_digest: Id32,
    pub signed_at_ms: i64,
}

fn build_unsigned_commit(fields: CommitFields, signer_pubkey: [u8; 32]) -> Commit {
    Commit {
        repo_version: fields.repo_version,
        prev_commit: fields.prev_commit,
        commit_height: fields.commit_height,
        repo_root: fields.repo_root,
        policy_epoch: fields.policy_epoch,
        registry_root: fields.registry_root,
        manifest_digest: fields.manifest_digest,
        signed_at_ms: fields.signed_at_ms,
        signer_pubkey,
        signature: [0u8; 64],
    }
}

pub fn create_signed_commit(
    fields: CommitFields,
    signing_key: &ed25519_dalek::SigningKey,
) -> (CommitId, Vec<u8>) {
    use ed25519_dalek::Signer;

    let signer_pubkey: [u8; 32] = signing_key.verifying_key().to_bytes();

    // Create commit without signature first to get signing bytes
    let mut commit = build_unsigned_commit(fields, signer_pubkey);

    // Sign
    let signing_bytes = commit.signing_bytes();
    let signature = signing_key.sign(&signing_bytes);
    commit.signature = signature.to_bytes();

    // Encode
    let commit_bytes = super::codec::encode_commit(&commit);
    let commit_id = compute_block_id(&commit_bytes);

    (commit_id, commit_bytes)
}

/// Create a signed commit (for publishers) using an `mprd-core` TokenSigningKey.
///
/// This avoids exposing `ed25519_dalek::SigningKey` to downstream crates.
pub fn create_signed_commit_with_token_key(
    fields: CommitFields,
    signing_key: &crate::TokenSigningKey,
) -> (CommitId, Vec<u8>) {
    let signer_pubkey: [u8; 32] = signing_key.verifying_key().to_bytes();

    let mut commit = build_unsigned_commit(fields, signer_pubkey);

    let signing_bytes = commit.signing_bytes();
    commit.signature = signing_key.sign_bytes(&signing_bytes);

    let commit_bytes = super::codec::encode_commit(&commit);
    let commit_id = compute_block_id(&commit_bytes);

    (commit_id, commit_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn create_test_commit() -> (CommitId, Vec<u8>, SigningKey) {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);

        let (commit_id, commit_bytes) = create_signed_commit(
            CommitFields {
                repo_version: 1,
                prev_commit: CommitId::ZERO,
                commit_height: 1,
                repo_root: super::super::types::BlockId::ZERO,
                policy_epoch: 100,
                registry_root: super::super::types::Id32::ZERO,
                manifest_digest: super::super::types::Id32::ZERO,
                signed_at_ms: 1234567890,
            },
            &signing_key,
        );

        (commit_id, commit_bytes, signing_key)
    }

    #[test]
    fn verify_valid_commit() {
        let (commit_id, commit_bytes, signing_key) = create_test_commit();
        let pubkey = signing_key.verifying_key().to_bytes();

        let trust_anchors = TrustAnchors::new().with_commit_signer(pubkey);

        let commit = verify_commit_header_and_signature(&commit_id, &commit_bytes, &trust_anchors)
            .expect("should verify");

        assert_eq!(commit.repo_version, 1);
        assert_eq!(commit.commit_height, 1);
        assert_eq!(commit.policy_epoch, 100);
        assert_eq!(commit.signer_pubkey, pubkey);
    }

    #[test]
    fn reject_wrong_content_address() {
        let (_, commit_bytes, signing_key) = create_test_commit();
        let pubkey = signing_key.verifying_key().to_bytes();
        let trust_anchors = TrustAnchors::new().with_commit_signer(pubkey);

        let wrong_id = super::super::types::Id32([0xaa; 32]);

        let result = verify_commit_header_and_signature(&wrong_id, &commit_bytes, &trust_anchors);
        assert!(matches!(
            result,
            Err(ArtifactRepoError::ContentAddressMismatch { .. })
        ));
    }

    #[test]
    fn reject_untrusted_signer() {
        let (commit_id, commit_bytes, _) = create_test_commit();

        // Empty trust anchors
        let trust_anchors = TrustAnchors::new();

        let result = verify_commit_header_and_signature(&commit_id, &commit_bytes, &trust_anchors);
        assert!(matches!(
            result,
            Err(ArtifactRepoError::SignerNotTrusted(_))
        ));
    }

    #[test]
    fn reject_tampered_signature() {
        let (_commit_id, mut commit_bytes, signing_key) = create_test_commit();
        let pubkey = signing_key.verifying_key().to_bytes();
        let trust_anchors = TrustAnchors::new().with_commit_signer(pubkey);

        // Tamper with signature (last 64 bytes)
        let len = commit_bytes.len();
        commit_bytes[len - 1] ^= 0xFF;

        // Recompute commit_id for tampered bytes
        let tampered_id = compute_block_id(&commit_bytes);

        let result =
            verify_commit_header_and_signature(&tampered_id, &commit_bytes, &trust_anchors);
        assert!(matches!(
            result,
            Err(ArtifactRepoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn commit_roundtrip() {
        let (commit_id, commit_bytes, signing_key) = create_test_commit();
        let pubkey = signing_key.verifying_key().to_bytes();
        let trust_anchors = TrustAnchors::new().with_commit_signer(pubkey);

        let commit = verify_commit_header_and_signature(&commit_id, &commit_bytes, &trust_anchors)
            .expect("should verify");

        // Re-encode should produce same bytes
        let re_encoded = super::super::codec::encode_commit(&commit);
        assert_eq!(commit_bytes, re_encoded);
    }
}
