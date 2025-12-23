//! Algorithms 10 & 11: Commit Chain Fetch and Verification.
//!
//! Algorithm 10: Fetch a range of commits by walking backward via prev_commit.
//! Algorithm 11: Verify that a sequence of commits forms a valid, unbroken chain.

use super::bounds::MAX_COMMIT_CHAIN;
use super::commit::verify_commit_header_and_signature;
use super::error::{ArtifactRepoError, Result};
use super::store::{BlockStore, TrustAnchors};
use super::types::{Commit, CommitId};

/// Fetch a range of commits by walking backward from a known commit (Algorithm 10).
///
/// # Preconditions
/// - `to_commit` is a valid commit block ID
/// - Store contains all commits in the chain
///
/// # Postconditions
/// - Returns commits in ascending height order
/// - All commits are signature-verified
/// - Fails closed if chain exceeds MAX_COMMIT_CHAIN
///
/// # Complexity
/// - Time: O(c) where c = commits fetched
/// - Space: O(c)
/// - I/O: c commit fetches
/// - Network RTT: O(c) sequential (can't parallelize due to prev_commit dependency)
pub fn fetch_commit_chain<S: BlockStore>(
    store: &S,
    to_commit: CommitId,
    from_height: Option<u64>,
    trust_anchors: &TrustAnchors,
) -> Result<Vec<(CommitId, Commit)>> {
    let mut result: Vec<(CommitId, Commit)> = Vec::new();
    let mut current_id = to_commit;
    let mut commits_fetched = 0usize;

    loop {
        if commits_fetched >= MAX_COMMIT_CHAIN {
            // Check if we've reached genesis or target height
            if !current_id.is_zero() {
                return Err(ArtifactRepoError::BoundsExceeded("MAX_COMMIT_CHAIN"));
            }
            break;
        }

        // Fetch commit bytes
        let commit_bytes = store
            .get(&current_id)
            .ok_or(ArtifactRepoError::CommitNotFound(current_id))?;

        // Verify commit header and signature (Algorithm 2)
        let commit = verify_commit_header_and_signature(&current_id, &commit_bytes, trust_anchors)?;

        result.push((current_id, commit.clone()));
        commits_fetched += 1;

        // Stop conditions
        if let Some(h) = from_height {
            if commit.commit_height <= h {
                break;
            }
        }

        // Genesis commit (prev_commit == ZERO)
        if commit.prev_commit.is_zero() {
            break;
        }

        current_id = commit.prev_commit;
    }

    // Reverse to get ascending height order
    result.reverse();

    Ok(result)
}

/// Verify that a sequence of commits forms a valid, unbroken chain (Algorithm 11).
///
/// # Preconditions
/// - `commits` is in ascending height order
/// - All commit bytes are already fetched
///
/// # Postconditions
/// - Returns ChainVerified with start/end height and signer
/// - Fails closed on any broken link, signature failure, or height gap
/// - Partial verification is never returned
///
/// # Complexity
/// - Time: O(c) where c = number of commits
/// - Space: O(1)
/// - I/O: 0 (commits already fetched)
pub fn verify_commit_chain(
    commits: &[(CommitId, Vec<u8>)],
    trust_anchors: &TrustAnchors,
) -> Result<ChainVerified> {
    if commits.is_empty() {
        return Ok(ChainVerified {
            start_height: 0,
            end_height: 0,
            signer: None,
        });
    }

    // Verify first commit
    let (first_id, first_bytes) = &commits[0];
    let first = verify_commit_header_and_signature(first_id, first_bytes, trust_anchors)?;

    let mut prev = first.clone();
    let mut prev_id = *first_id;

    for (curr_id, curr_bytes) in commits.iter().skip(1) {
        // Verify commit header and signature (Algorithm 2)
        let curr = verify_commit_header_and_signature(curr_id, curr_bytes, trust_anchors)?;

        // Chain linkage
        if curr.prev_commit != prev_id {
            return Err(ArtifactRepoError::ChainBroken {
                height: curr.commit_height,
                reason: format!(
                    "prev_commit mismatch: expected {}, got {}",
                    prev_id, curr.prev_commit
                ),
            });
        }

        // Height must increment by exactly 1
        if curr.commit_height != prev.commit_height + 1 {
            return Err(ArtifactRepoError::ChainBroken {
                height: curr.commit_height,
                reason: format!(
                    "height gap: expected {}, got {}",
                    prev.commit_height + 1,
                    curr.commit_height
                ),
            });
        }

        // Same signer chain (multi-signer would need different logic)
        if curr.signer_pubkey != prev.signer_pubkey {
            return Err(ArtifactRepoError::ChainBroken {
                height: curr.commit_height,
                reason: "signer changed mid-chain".into(),
            });
        }

        // Time monotonicity (weak: allows equal timestamps)
        if curr.signed_at_ms < prev.signed_at_ms {
            return Err(ArtifactRepoError::ChainBroken {
                height: curr.commit_height,
                reason: format!(
                    "time went backward: {} < {}",
                    curr.signed_at_ms, prev.signed_at_ms
                ),
            });
        }

        prev = curr;
        prev_id = *curr_id;
    }

    Ok(ChainVerified {
        start_height: first.commit_height,
        end_height: prev.commit_height,
        signer: Some(first.signer_pubkey),
    })
}

/// Result of commit chain verification.
#[derive(Debug, Clone)]
pub struct ChainVerified {
    pub start_height: u64,
    pub end_height: u64,
    pub signer: Option<[u8; 32]>,
}

/// Detect equivocation: two commits from the same signer at the same height.
///
/// # Returns
/// - Ok(()) if no equivocation detected
/// - Err with equivocation details if detected
pub fn detect_equivocation(commits: &[(CommitId, Commit)]) -> Result<()> {
    use std::collections::HashMap;

    // Map (signer, height) → CommitId
    let mut seen: HashMap<([u8; 32], u64), CommitId> = HashMap::new();

    for (commit_id, commit) in commits {
        let key = (commit.signer_pubkey, commit.commit_height);

        if let Some(existing_id) = seen.get(&key) {
            if existing_id != commit_id {
                return Err(ArtifactRepoError::EquivocationDetected(format!(
                    "signer {} produced two commits at height {}: {} and {}",
                    hex::encode(&commit.signer_pubkey[..8]),
                    commit.commit_height,
                    existing_id,
                    commit_id
                )));
            }
        } else {
            seen.insert(key, *commit_id);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_repo::codec::decode_commit;
    use crate::artifact_repo::commit::{create_signed_commit_with_token_key, CommitFields};
    use crate::artifact_repo::store::MemoryBlockStore;
    use crate::artifact_repo::types::Id32;
    use crate::crypto::TokenSigningKey;
    use proptest::prelude::*;

    fn create_test_chain(
        store: &MemoryBlockStore,
        signing_key: &TokenSigningKey,
        count: usize,
    ) -> Vec<(CommitId, Vec<u8>)> {
        let mut commits = Vec::new();
        let mut prev_commit = CommitId::ZERO;

        for i in 0..count {
            let (commit_id, commit_bytes) = create_signed_commit_with_token_key(
                CommitFields {
                    repo_version: 1,
                    prev_commit,
                    commit_height: i as u64,
                    repo_root: Id32::ZERO,
                    policy_epoch: 100,
                    registry_root: Id32::ZERO,
                    manifest_digest: Id32::ZERO,
                    signed_at_ms: 1000 + i as i64,
                },
                signing_key,
            );

            store.put(commit_id, commit_bytes.clone()).unwrap();
            commits.push((commit_id, commit_bytes));
            prev_commit = commit_id;
        }

        commits
    }

    #[test]
    fn verify_empty_chain() {
        let trust_anchors = TrustAnchors::new();
        let result = verify_commit_chain(&[], &trust_anchors).unwrap();

        assert_eq!(result.start_height, 0);
        assert_eq!(result.end_height, 0);
        assert!(result.signer.is_none());
    }

    #[test]
    fn verify_single_commit() {
        let store = MemoryBlockStore::new();
        let signing_key = TokenSigningKey::from_seed(&[1u8; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();

        let commits = create_test_chain(&store, &signing_key, 1);
        let trust_anchors = TrustAnchors::new().with_commit_signer(pubkey);

        let result = verify_commit_chain(&commits, &trust_anchors).unwrap();

        assert_eq!(result.start_height, 0);
        assert_eq!(result.end_height, 0);
        assert_eq!(result.signer, Some(pubkey));
    }

    #[test]
    fn verify_valid_chain() {
        let store = MemoryBlockStore::new();
        let signing_key = TokenSigningKey::from_seed(&[2u8; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();

        let commits = create_test_chain(&store, &signing_key, 5);
        let trust_anchors = TrustAnchors::new().with_commit_signer(pubkey);

        let result = verify_commit_chain(&commits, &trust_anchors).unwrap();

        assert_eq!(result.start_height, 0);
        assert_eq!(result.end_height, 4);
        assert_eq!(result.signer, Some(pubkey));
    }

    #[test]
    fn fetch_chain_backward() {
        let store = MemoryBlockStore::new();
        let signing_key = TokenSigningKey::from_seed(&[3u8; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();

        let commits = create_test_chain(&store, &signing_key, 5);
        let trust_anchors = TrustAnchors::new().with_commit_signer(pubkey);

        // Fetch from last commit
        let (last_id, _) = commits.last().unwrap();
        let fetched = fetch_commit_chain(&store, *last_id, None, &trust_anchors).unwrap();

        assert_eq!(fetched.len(), 5);
        // Should be in ascending order
        assert_eq!(fetched[0].1.commit_height, 0);
        assert_eq!(fetched[4].1.commit_height, 4);
    }

    #[test]
    fn fetch_chain_with_from_height() {
        let store = MemoryBlockStore::new();
        let signing_key = TokenSigningKey::from_seed(&[4u8; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();

        let commits = create_test_chain(&store, &signing_key, 10);
        let trust_anchors = TrustAnchors::new().with_commit_signer(pubkey);

        // Fetch from last commit, stopping at height 5
        let (last_id, _) = commits.last().unwrap();
        let fetched = fetch_commit_chain(&store, *last_id, Some(5), &trust_anchors).unwrap();

        // Should have heights 5-9
        assert_eq!(fetched.len(), 5);
        assert_eq!(fetched[0].1.commit_height, 5);
        assert_eq!(fetched[4].1.commit_height, 9);
    }

    #[test]
    fn detect_no_equivocation() {
        let store = MemoryBlockStore::new();
        let signing_key = TokenSigningKey::from_seed(&[5u8; 32]);

        let commits: Vec<_> = create_test_chain(&store, &signing_key, 5)
            .into_iter()
            .map(|(id, bytes)| {
                let commit = decode_commit(&bytes).unwrap();
                (id, commit)
            })
            .collect();

        detect_equivocation(&commits).expect("no equivocation");
    }

    #[test]
    fn detect_equivocation_same_height() {
        let signing_key = TokenSigningKey::from_seed(&[6u8; 32]);

        // Create two different commits at the same height
        let (id1, bytes1) = create_signed_commit_with_token_key(
            CommitFields {
                repo_version: 1,
                prev_commit: CommitId::ZERO,
                commit_height: 5,
                repo_root: Id32::ZERO,
                policy_epoch: 100,
                registry_root: Id32::ZERO,
                manifest_digest: Id32::ZERO,
                signed_at_ms: 1000,
            },
            &signing_key,
        );

        let (id2, bytes2) = create_signed_commit_with_token_key(
            CommitFields {
                repo_version: 1,
                prev_commit: CommitId::ZERO,
                commit_height: 5,            // Same height!
                repo_root: Id32([0x11; 32]), // Different root
                policy_epoch: 100,
                registry_root: Id32::ZERO,
                manifest_digest: Id32::ZERO,
                signed_at_ms: 1001,
            },
            &signing_key,
        );

        let commit1 = decode_commit(&bytes1).unwrap();
        let commit2 = decode_commit(&bytes2).unwrap();

        let commits = vec![(id1, commit1), (id2, commit2)];

        let result = detect_equivocation(&commits);
        assert!(matches!(
            result,
            Err(ArtifactRepoError::EquivocationDetected(_))
        ));
    }

    fn chain_from_seed(
        store: &MemoryBlockStore,
        seed: [u8; 32],
        len: usize,
    ) -> (TokenSigningKey, Vec<(CommitId, Vec<u8>)>) {
        let key = TokenSigningKey::from_seed(&seed);
        let commits = create_test_chain(store, &key, len);
        (key, commits)
    }

    proptest! {
        #[test]
        fn verify_commit_chain_accepts_valid_chains(
            seed in any::<[u8; 32]>(),
            len in 1usize..20,
        ) {
            let store = MemoryBlockStore::new();
            let (key, commits) = chain_from_seed(&store, seed, len);
            let trust_anchors = TrustAnchors::new().with_commit_signer(key.verifying_key().to_bytes());

            let verified = verify_commit_chain(&commits, &trust_anchors).expect("valid chain");
            prop_assert_eq!(verified.start_height, 0);
            prop_assert_eq!(verified.end_height, (len - 1) as u64);
        }

        #[test]
        fn verify_commit_chain_fails_closed_on_height_gap(
            seed in any::<[u8; 32]>(),
            len in 2usize..20,
        ) {
            let store = MemoryBlockStore::new();
            let (key, mut commits) = chain_from_seed(&store, seed, len);
            let trust_anchors = TrustAnchors::new().with_commit_signer(key.verifying_key().to_bytes());

            // Replace commit at index 1 with a valid signed commit at height 2 (gap).
            let prev_id = commits[0].0;
            let (bad_id, bad_bytes) = create_signed_commit_with_token_key(
                CommitFields {
                    repo_version: 1,
                    prev_commit: prev_id,
                    commit_height: 2,
                    repo_root: Id32::ZERO,
                    policy_epoch: 100,
                    registry_root: Id32::ZERO,
                    manifest_digest: Id32::ZERO,
                    signed_at_ms: 1002,
                },
                &key,
            );
            store.put(bad_id, bad_bytes.clone()).unwrap();
            commits[1] = (bad_id, bad_bytes);

            prop_assert!(verify_commit_chain(&commits, &trust_anchors).is_err());
        }

        #[test]
        fn verify_commit_chain_fails_closed_on_prev_commit_mismatch(
            seed in any::<[u8; 32]>(),
            len in 2usize..20,
            wrong_prev in any::<[u8; 32]>(),
        ) {
            let store = MemoryBlockStore::new();
            let (key, mut commits) = chain_from_seed(&store, seed, len);
            let trust_anchors = TrustAnchors::new().with_commit_signer(key.verifying_key().to_bytes());

            let wrong_prev = Id32(wrong_prev);
            let (bad_id, bad_bytes) = create_signed_commit_with_token_key(
                CommitFields {
                    repo_version: 1,
                    prev_commit: wrong_prev,
                    commit_height: 1,
                    repo_root: Id32::ZERO,
                    policy_epoch: 100,
                    registry_root: Id32::ZERO,
                    manifest_digest: Id32::ZERO,
                    signed_at_ms: 1001,
                },
                &key,
            );
            store.put(bad_id, bad_bytes.clone()).unwrap();
            commits[1] = (bad_id, bad_bytes);

            prop_assert!(verify_commit_chain(&commits, &trust_anchors).is_err());
        }

        #[test]
        fn verify_commit_chain_fails_closed_when_signer_changes_mid_chain(
            seed1 in any::<[u8; 32]>(),
            seed2 in any::<[u8; 32]>(),
            len in 3usize..20,
        ) {
            prop_assume!(seed1 != seed2);
            let store = MemoryBlockStore::new();

            let key1 = TokenSigningKey::from_seed(&seed1);
            let key2 = TokenSigningKey::from_seed(&seed2);

            let mut commits = create_test_chain(&store, &key1, len);

            // Replace commit at index 1 with one signed by key2.
            let prev_id = commits[0].0;
            let (bad_id, bad_bytes) = create_signed_commit_with_token_key(
                CommitFields {
                    repo_version: 1,
                    prev_commit: prev_id,
                    commit_height: 1,
                    repo_root: Id32::ZERO,
                    policy_epoch: 100,
                    registry_root: Id32::ZERO,
                    manifest_digest: Id32::ZERO,
                    signed_at_ms: 1001,
                },
                &key2,
            );
            store.put(bad_id, bad_bytes.clone()).unwrap();
            commits[1] = (bad_id, bad_bytes);

            // Trust anchors must include both signers so the failure is "signer changed", not "untrusted".
            let trust_anchors = TrustAnchors::new()
                .with_commit_signer(key1.verifying_key().to_bytes())
                .with_commit_signer(key2.verifying_key().to_bytes());

            prop_assert!(verify_commit_chain(&commits, &trust_anchors).is_err());
        }
    }
}
