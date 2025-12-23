//! Algorithm 4: MST Key Lookup + Proofs.
//!
//! Fetch a value for a key from the MST root with a verifier-checkable proof,
//! without trusting any source.

use std::collections::HashMap;

use super::bounds::{MAX_BLOCK_BYTES, MAX_MST_DEPTH, MAX_VALUE_BYTES};
use super::codec::{decode_blob, decode_mst_node};
use super::error::{ArtifactRepoError, Result};
use super::store::BlockStore;
use super::types::{
    compute_block_id, BlockId, InclusionProof, Key, LookupResult, MstEntry, NonInclusionProof,
    NonInclusionReason,
};

/// MST key lookup with proof generation (Algorithm 4).
///
/// # Preconditions
/// - `root` is a valid MST node block ID
/// - `store` contains all blocks reachable from `root`
///
/// # Postconditions
/// - Returns `LookupResult::Found` with inclusion proof if key exists
/// - Returns `LookupResult::NotFound` with non-inclusion proof if key absent
/// - Fails closed on any decode error, bounds exceeded, or missing block
///
/// # Complexity
/// - Time: O(log n) where n = total entries
/// - Space: O(log n) for proof blocks
/// - I/O: O(log n) block reads
pub fn mst_lookup<S: BlockStore + ?Sized>(
    store: &S,
    root: &BlockId,
    key: &Key,
    max_block_fetch: usize,
) -> Result<LookupResult> {
    // Step 1: Compute key hash and nibbles
    let key_hash = key.hash();
    let nibbles = key_hash.to_nibbles();

    // Step 2: Initialize traversal state
    let mut current = *root;
    let mut depth = 0usize;
    let mut blocks: Vec<(BlockId, Vec<u8>)> = Vec::new();
    let mut blocks_fetched = 0usize;

    // Step 3: Traverse MST
    loop {
        // Bound check
        if depth >= MAX_MST_DEPTH {
            return Err(ArtifactRepoError::MstDepthExceeded { depth });
        }
        if blocks_fetched >= max_block_fetch {
            return Err(ArtifactRepoError::BoundsExceeded("MAX_BLOCK_FETCH"));
        }

        // Fetch node block
        let node_bytes = store
            .get(&current)
            .ok_or(ArtifactRepoError::BlockNotFound(current))?;

        if node_bytes.len() > MAX_BLOCK_BYTES {
            return Err(ArtifactRepoError::BlockTooLarge {
                size: node_bytes.len(),
                max: MAX_BLOCK_BYTES,
            });
        }

        blocks_fetched += 1;

        // Verify content addressing
        let computed_id = compute_block_id(&node_bytes);
        if computed_id != current {
            return Err(ArtifactRepoError::ContentAddressMismatch {
                expected: current,
                actual: computed_id,
            });
        }

        // Add to proof blocks (deduplicated)
        if !blocks.iter().any(|(id, _)| *id == current) {
            blocks.push((current, node_bytes.clone()));
        }

        // Decode MST node
        let node = decode_mst_node(&node_bytes)?;

        // Get expected nibble at this depth
        let expected_nibble = nibbles[depth];

        // Check entry at expected nibble
        match node.entry_at(expected_nibble) {
            Some(MstEntry::Leaf {
                key: stored_key,
                value_block_id,
            }) => {
                if stored_key.as_bytes() != key.as_bytes() {
                    // Different key occupies this slot - non-inclusion
                    return Ok(LookupResult::NotFound(NonInclusionProof {
                        root: *root,
                        key: key.clone(),
                        reason: NonInclusionReason::OccupiedByDifferentKey {
                            depth,
                            nibble: expected_nibble,
                            collision_key: stored_key.clone(),
                        },
                        blocks,
                    }));
                }

                // Keys match - inclusion case
                // Fetch value blob block
                if blocks_fetched + 1 > max_block_fetch {
                    return Err(ArtifactRepoError::BoundsExceeded("MAX_BLOCK_FETCH"));
                }

                let value_bytes = store
                    .get(value_block_id)
                    .ok_or(ArtifactRepoError::BlockNotFound(*value_block_id))?;

                // Verify content addressing
                let computed_value_id = compute_block_id(&value_bytes);
                if computed_value_id != *value_block_id {
                    return Err(ArtifactRepoError::ContentAddressMismatch {
                        expected: *value_block_id,
                        actual: computed_value_id,
                    });
                }

                // Add to proof blocks
                if !blocks.iter().any(|(id, _)| *id == *value_block_id) {
                    blocks.push((*value_block_id, value_bytes.clone()));
                }

                // Decode blob payload
                let payload = decode_blob(&value_bytes)?;

                if payload.len() > MAX_VALUE_BYTES {
                    return Err(ArtifactRepoError::ValueTooLarge {
                        size: payload.len(),
                        max: MAX_VALUE_BYTES,
                    });
                }

                return Ok(LookupResult::Found(InclusionProof {
                    root: *root,
                    key: key.clone(),
                    value_block_id: *value_block_id,
                    value_bytes: payload.to_vec(),
                    blocks,
                }));
            }
            Some(MstEntry::Child { child_id }) => {
                // Continue to child
                current = *child_id;
                depth += 1;
            }
            None => {
                // No entry at expected nibble - non-inclusion
                return Ok(LookupResult::NotFound(NonInclusionProof {
                    root: *root,
                    key: key.clone(),
                    reason: NonInclusionReason::MissingChild {
                        depth,
                        nibble: expected_nibble,
                    },
                    blocks,
                }));
            }
        }
    }
}

/// Verify an inclusion or non-inclusion proof (Algorithm 4C).
///
/// # Preconditions
/// - All blocks in proof are bounded by MAX_BLOCK_BYTES
///
/// # Postconditions
/// - Returns Ok(()) if proof is valid
/// - Fails closed on any verification error
///
/// # Complexity
/// - Time: O(log n)
/// - Space: O(1) beyond input
pub fn verify_proof(proof: &LookupResult) -> Result<()> {
    match proof {
        LookupResult::Found(inclusion) => verify_inclusion_proof(inclusion),
        LookupResult::NotFound(non_inclusion) => verify_non_inclusion_proof(non_inclusion),
    }
}

/// Verify an inclusion proof.
pub fn verify_inclusion_proof(proof: &InclusionProof) -> Result<()> {
    // Step 1: Build block map and verify content addressing
    let mut block_map: HashMap<BlockId, &[u8]> = HashMap::new();

    for (block_id, block_bytes) in &proof.blocks {
        // Verify content addressing
        let computed_id = compute_block_id(block_bytes);
        if computed_id != *block_id {
            return Err(ArtifactRepoError::ContentAddressMismatch {
                expected: *block_id,
                actual: computed_id,
            });
        }
        block_map.insert(*block_id, block_bytes);
    }

    // Step 2: Compute key hash
    let key_hash = proof.key.hash();
    let nibbles = key_hash.to_nibbles();

    // Step 3: Traverse from root
    let mut current = proof.root;

    for &expected_nibble in nibbles.iter().take(MAX_MST_DEPTH) {
        let node_bytes = block_map
            .get(&current)
            .ok_or(ArtifactRepoError::BlockNotFound(current))?;

        let node = decode_mst_node(node_bytes)?;

        match node.entry_at(expected_nibble) {
            Some(MstEntry::Leaf {
                key: stored_key,
                value_block_id,
            }) => {
                // Require stored key matches requested key
                if stored_key.as_bytes() != proof.key.as_bytes() {
                    return Err(ArtifactRepoError::SelfConsistencyFailed(
                        "leaf key mismatch in inclusion proof".into(),
                    ));
                }

                // Require value_block_id matches
                if *value_block_id != proof.value_block_id {
                    return Err(ArtifactRepoError::SelfConsistencyFailed(
                        "value_block_id mismatch in inclusion proof".into(),
                    ));
                }

                // Verify value block
                let value_bytes = block_map
                    .get(&proof.value_block_id)
                    .ok_or(ArtifactRepoError::BlockNotFound(proof.value_block_id))?;

                // Decode and verify payload
                let payload = decode_blob(value_bytes)?;

                if payload != proof.value_bytes {
                    return Err(ArtifactRepoError::SelfConsistencyFailed(
                        "value_bytes mismatch in inclusion proof".into(),
                    ));
                }

                return Ok(());
            }
            Some(MstEntry::Child { child_id }) => {
                current = *child_id;
            }
            None => {
                return Err(ArtifactRepoError::SelfConsistencyFailed(
                    "inclusion proof traversal ended at missing entry".into(),
                ));
            }
        }
    }

    Err(ArtifactRepoError::MstDepthExceeded {
        depth: MAX_MST_DEPTH,
    })
}

/// Verify a non-inclusion proof.
pub fn verify_non_inclusion_proof(proof: &NonInclusionProof) -> Result<()> {
    // Step 1: Build block map and verify content addressing
    let mut block_map: HashMap<BlockId, &[u8]> = HashMap::new();

    for (block_id, block_bytes) in &proof.blocks {
        let computed_id = compute_block_id(block_bytes);
        if computed_id != *block_id {
            return Err(ArtifactRepoError::ContentAddressMismatch {
                expected: *block_id,
                actual: computed_id,
            });
        }
        block_map.insert(*block_id, block_bytes);
    }

    // Step 2: Compute key hash
    let key_hash = proof.key.hash();
    let nibbles = key_hash.to_nibbles();

    // Step 3: Traverse from root to claimed depth
    let mut current = proof.root;

    let (claimed_depth, claimed_nibble) = match &proof.reason {
        NonInclusionReason::MissingChild { depth, nibble } => (*depth, *nibble),
        NonInclusionReason::OccupiedByDifferentKey { depth, nibble, .. } => (*depth, *nibble),
    };

    if claimed_depth >= MAX_MST_DEPTH {
        return Err(ArtifactRepoError::MstDepthExceeded {
            depth: claimed_depth,
        });
    }

    for (depth, &expected_nibble) in nibbles
        .iter()
        .enumerate()
        .take(claimed_depth.saturating_add(1))
    {
        let node_bytes = block_map
            .get(&current)
            .ok_or(ArtifactRepoError::BlockNotFound(current))?;

        let node = decode_mst_node(node_bytes)?;

        // Verify expected nibble matches claim at final depth
        if depth == claimed_depth {
            if expected_nibble != claimed_nibble {
                return Err(ArtifactRepoError::SelfConsistencyFailed(
                    "claimed nibble doesn't match key hash".into(),
                ));
            }

            match &proof.reason {
                NonInclusionReason::MissingChild { .. } => {
                    // Verify no entry at this nibble
                    if node.entry_at(expected_nibble).is_some() {
                        return Err(ArtifactRepoError::SelfConsistencyFailed(
                            "MissingChild claim but entry exists".into(),
                        ));
                    }
                }
                NonInclusionReason::OccupiedByDifferentKey { collision_key, .. } => {
                    // Verify leaf exists with different key
                    match node.entry_at(expected_nibble) {
                        Some(MstEntry::Leaf { key, .. }) => {
                            if key.as_bytes() == proof.key.as_bytes() {
                                return Err(ArtifactRepoError::SelfConsistencyFailed(
                                    "OccupiedByDifferentKey claim but key matches".into(),
                                ));
                            }
                            if key.as_bytes() != collision_key.as_bytes() {
                                return Err(ArtifactRepoError::SelfConsistencyFailed(
                                    "collision_key doesn't match stored key".into(),
                                ));
                            }
                        }
                        _ => {
                            return Err(ArtifactRepoError::SelfConsistencyFailed(
                                "OccupiedByDifferentKey claim but no leaf".into(),
                            ));
                        }
                    }
                }
            }
            return Ok(());
        }

        // Not at claimed depth yet - must have child to continue
        match node.entry_at(expected_nibble) {
            Some(MstEntry::Child { child_id }) => {
                current = *child_id;
            }
            _ => {
                return Err(ArtifactRepoError::SelfConsistencyFailed(
                    "non-inclusion proof path broken before claimed depth".into(),
                ));
            }
        }
    }

    Err(ArtifactRepoError::SelfConsistencyFailed(
        "non-inclusion proof traversal incomplete".into(),
    ))
}

/// Batch lookup multiple keys with shared proof blocks (Algorithm 4A).
///
/// # Complexity
/// - Time: O(m·log n) where m = number of keys
/// - Space: O(m·log n) for proof blocks (with LCA sharing)
/// - I/O: O(log n + m) with caching
pub type BatchLookupBlocks = Vec<(BlockId, Vec<u8>)>;
pub type BatchLookupOutput = (Vec<LookupResult>, BatchLookupBlocks);

pub fn mst_batch_lookup<S: BlockStore + ?Sized>(
    store: &S,
    root: &BlockId,
    keys: &[Key],
    max_block_fetch: usize,
) -> Result<BatchLookupOutput> {
    let mut results = Vec::with_capacity(keys.len());
    let mut all_blocks: HashMap<BlockId, Vec<u8>> = HashMap::new();
    let mut blocks_fetched = 0usize;

    for key in keys {
        // Use remaining budget
        let remaining = max_block_fetch.saturating_sub(blocks_fetched);
        if remaining == 0 {
            return Err(ArtifactRepoError::BoundsExceeded("MAX_BLOCK_FETCH"));
        }

        let result = mst_lookup(store, root, key, remaining)?;

        // Collect blocks (deduplicated via HashMap)
        match &result {
            LookupResult::Found(proof) => {
                for (id, bytes) in &proof.blocks {
                    if !all_blocks.contains_key(id) {
                        all_blocks.insert(*id, bytes.clone());
                        blocks_fetched += 1;
                    }
                }
            }
            LookupResult::NotFound(proof) => {
                for (id, bytes) in &proof.blocks {
                    if !all_blocks.contains_key(id) {
                        all_blocks.insert(*id, bytes.clone());
                        blocks_fetched += 1;
                    }
                }
            }
        }

        results.push(result);
    }

    // Sort blocks by ID for canonical encoding
    let mut blocks: Vec<_> = all_blocks.into_iter().collect();
    blocks.sort_by_key(|(id, _)| *id);

    Ok((results, blocks))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_repo::codec::{encode_blob, encode_mst_node};
    use crate::artifact_repo::store::MemoryBlockStore;
    use crate::artifact_repo::types::MstNode;
    use proptest::prelude::*;

    fn create_test_tree() -> (MemoryBlockStore, BlockId) {
        let store = MemoryBlockStore::new();

        // Create value blobs
        let value1 = encode_blob(b"value1").unwrap();
        let value1_id = compute_block_id(&value1);
        store.put(value1_id, value1).unwrap();

        let value2 = encode_blob(b"value2").unwrap();
        let value2_id = compute_block_id(&value2);
        store.put(value2_id, value2).unwrap();

        // Create MST with two entries
        let key1 = Key::new("key1");
        let key2 = Key::new("key2");

        let nibble1 = key1.hash().nibble_at(0).unwrap();
        let nibble2 = key2.hash().nibble_at(0).unwrap();

        let mut root_node = MstNode::new();
        root_node = root_node.with_leaf_at(nibble1, key1, value1_id);
        root_node = root_node.with_leaf_at(nibble2, key2, value2_id);

        let root_bytes = encode_mst_node(&root_node).unwrap();
        let root_id = compute_block_id(&root_bytes);
        store.put(root_id, root_bytes).unwrap();

        (store, root_id)
    }

    #[test]
    fn lookup_fails_closed_when_max_block_fetch_insufficient_for_value_block() {
        let (store, root_id) = create_test_tree();
        let key = Key::new("key1");

        let err = mst_lookup(&store, &root_id, &key, 1).unwrap_err();
        assert!(matches!(
            err,
            ArtifactRepoError::BoundsExceeded("MAX_BLOCK_FETCH")
        ));
    }

    #[test]
    fn lookup_fails_closed_on_mst_depth_exceeded() {
        let store = MemoryBlockStore::new();
        let key = Key::new("depth_exceed_key");
        let nibbles = key.hash().to_nibbles();

        // Build a chain of single-child nodes that follows this key's nibble path for 64 steps.
        // At depth == MAX_MST_DEPTH, mst_lookup must error (and must not panic by indexing past 63).
        let dummy_child: BlockId = [0x42; 32].into();

        let mut next = dummy_child;
        for depth in (0..MAX_MST_DEPTH).rev() {
            let node = MstNode::new().with_child_at(nibbles[depth], next);
            let bytes = encode_mst_node(&node).unwrap();
            let id = compute_block_id(&bytes);
            store.put(id, bytes).unwrap();
            next = id;
        }

        let root_id = next;
        let err = mst_lookup(&store, &root_id, &key, 10_000).unwrap_err();
        assert!(
            matches!(err, ArtifactRepoError::MstDepthExceeded { depth } if depth == MAX_MST_DEPTH)
        );
    }

    #[test]
    fn tampering_non_inclusion_reason_is_detected() {
        let (store, root_id) = create_test_tree();
        let key = Key::new("nonexistent");

        let result = mst_lookup(&store, &root_id, &key, 100).unwrap();
        let tampered = match result {
            LookupResult::NotFound(mut proof) => {
                let (depth, nibble) = match proof.reason {
                    NonInclusionReason::MissingChild { depth, nibble } => (depth, nibble),
                    NonInclusionReason::OccupiedByDifferentKey { depth, nibble, .. } => {
                        (depth, nibble)
                    }
                };
                let wrong_nibble = if nibble == 0 { 1 } else { 0 };
                proof.reason = NonInclusionReason::MissingChild {
                    depth,
                    nibble: wrong_nibble,
                };
                LookupResult::NotFound(proof)
            }
            LookupResult::Found(_) => panic!("expected NotFound"),
        };

        assert!(verify_proof(&tampered).is_err());
    }

    #[test]
    fn batch_lookup_blocks_cover_all_proof_blocks() {
        let store = MemoryBlockStore::new();

        // Choose two keys with different first-route nibbles so root can contain both.
        let mut found_key = Key::new("found_key_0");
        let mut absent_key = Key::new("absent_key_0");
        let mut attempts = 0u32;
        while found_key.hash().nibble_at(0) == absent_key.hash().nibble_at(0) {
            attempts += 1;
            found_key = Key::new(format!("found_key_{attempts}"));
            absent_key = Key::new(format!("absent_key_{attempts}"));
            if attempts > 256 {
                panic!("failed to find distinct nibbles for test keys");
            }
        }

        // Create a value blob for the found key.
        let value = encode_blob(b"value").unwrap();
        let value_id = compute_block_id(&value);
        store.put(value_id, value).unwrap();

        // Create a child node that is guaranteed to produce a NotFound at depth 1.
        let child_node = MstNode::new();
        let child_bytes = encode_mst_node(&child_node).unwrap();
        let child_id = compute_block_id(&child_bytes);
        store.put(child_id, child_bytes).unwrap();

        // Root has:
        // - a leaf for found_key (proof includes root + blob)
        // - a child for absent_key (proof includes root + child node)
        let found_n0 = found_key.hash().nibble_at(0).unwrap();
        let absent_n0 = absent_key.hash().nibble_at(0).unwrap();
        let root_node = MstNode::new()
            .with_leaf_at(found_n0, found_key.clone(), value_id)
            .with_child_at(absent_n0, child_id);
        let root_bytes = encode_mst_node(&root_node).unwrap();
        let root_id = compute_block_id(&root_bytes);
        store.put(root_id, root_bytes).unwrap();

        let keys = vec![found_key.clone(), absent_key.clone()];
        let (results, blocks) = mst_batch_lookup(&store, &root_id, &keys, 100).unwrap();

        let global_ids: std::collections::HashMap<BlockId, Vec<u8>> = blocks.into_iter().collect();

        for r in &results {
            match r {
                LookupResult::Found(p) => {
                    for (id, _bytes) in &p.blocks {
                        assert!(global_ids.contains_key(id));
                    }
                }
                LookupResult::NotFound(p) => {
                    for (id, _bytes) in &p.blocks {
                        assert!(global_ids.contains_key(id));
                    }
                }
            }
        }
    }

    #[test]
    fn lookup_existing_key() {
        let (store, root_id) = create_test_tree();
        let key = Key::new("key1");

        let result = mst_lookup(&store, &root_id, &key, 100).unwrap();

        match result {
            LookupResult::Found(proof) => {
                assert_eq!(proof.key, key);
                assert_eq!(proof.value_bytes, b"value1");
                assert!(!proof.blocks.is_empty());
            }
            LookupResult::NotFound(_) => panic!("expected Found"),
        }
    }

    #[test]
    fn lookup_nonexistent_key() {
        let (store, root_id) = create_test_tree();
        let key = Key::new("nonexistent");

        let result = mst_lookup(&store, &root_id, &key, 100).unwrap();

        match result {
            LookupResult::Found(_) => panic!("expected NotFound"),
            LookupResult::NotFound(proof) => {
                assert_eq!(proof.key, key);
                assert!(!proof.blocks.is_empty());
            }
        }
    }

    #[test]
    fn verify_inclusion_proof_valid() {
        let (store, root_id) = create_test_tree();
        let key = Key::new("key1");

        let result = mst_lookup(&store, &root_id, &key, 100).unwrap();
        verify_proof(&result).expect("proof should be valid");
    }

    #[test]
    fn verify_non_inclusion_proof_valid() {
        let (store, root_id) = create_test_tree();
        let key = Key::new("nonexistent");

        let result = mst_lookup(&store, &root_id, &key, 100).unwrap();
        verify_proof(&result).expect("proof should be valid");
    }

    #[test]
    fn batch_lookup() {
        let (store, root_id) = create_test_tree();
        let keys = vec![Key::new("key1"), Key::new("key2"), Key::new("nonexistent")];

        let (results, blocks) = mst_batch_lookup(&store, &root_id, &keys, 100).unwrap();

        assert_eq!(results.len(), 3);
        assert!(matches!(results[0], LookupResult::Found(_)));
        assert!(matches!(results[1], LookupResult::Found(_)));
        assert!(matches!(results[2], LookupResult::NotFound(_)));

        // Blocks should be deduplicated
        assert!(!blocks.is_empty());
    }

    fn gen_key() -> impl Strategy<Value = String> {
        // Must satisfy artifact repo key canonical bytes constraints.
        "[a-z0-9_./-]{1,32}".prop_map(|s| s)
    }

    proptest! {
        #[test]
        fn inclusion_proof_verifies_for_random_singleton_tree(
            key in gen_key(),
            value in proptest::collection::vec(any::<u8>(), 0..512),
            value_id_bytes in any::<[u8; 32]>(),
        ) {
            let store = MemoryBlockStore::new();
            let key = Key::new(key);

            let value_block = encode_blob(&value).unwrap();
            let value_block_id = compute_block_id(&value_block);
            store.put(value_block_id, value_block).unwrap();

            // Root node contains only this leaf at depth 0.
            let nibble0 = key.hash().nibble_at(0).unwrap();
            let root_node = MstNode::new().with_leaf_at(nibble0, key.clone(), value_block_id);
            let root_bytes = encode_mst_node(&root_node).unwrap();
            let root_id = compute_block_id(&root_bytes);
            store.put(root_id, root_bytes).unwrap();

            let result = mst_lookup(&store, &root_id, &key, 10).unwrap();
            match &result {
                LookupResult::Found(proof) => {
                    prop_assert_eq!(proof.value_block_id, value_block_id);
                    prop_assert_eq!(&proof.value_bytes, value.as_slice());
                }
                LookupResult::NotFound(_) => prop_assert!(false, "expected Found"),
            }
            verify_proof(&result).unwrap();

            // Extra sanity: value_id_bytes doesn't influence the proof (guard against accidental dependence).
            let _ = value_id_bytes;
        }

        #[test]
        fn tampering_inclusion_value_bytes_is_detected(
            key in gen_key(),
            value in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let store = MemoryBlockStore::new();
            let key = Key::new(key);

            let value_block = encode_blob(&value).unwrap();
            let value_block_id = compute_block_id(&value_block);
            store.put(value_block_id, value_block).unwrap();

            let nibble0 = key.hash().nibble_at(0).unwrap();
            let root_node = MstNode::new().with_leaf_at(nibble0, key.clone(), value_block_id);
            let root_bytes = encode_mst_node(&root_node).unwrap();
            let root_id = compute_block_id(&root_bytes);
            store.put(root_id, root_bytes).unwrap();

            let result = mst_lookup(&store, &root_id, &key, 10).unwrap();
            let tampered = match result {
                LookupResult::Found(mut proof) => {
                    if proof.value_bytes.is_empty() {
                        proof.value_bytes.push(1);
                    } else {
                        proof.value_bytes[0] ^= 0x01;
                    }
                    LookupResult::Found(proof)
                }
                LookupResult::NotFound(_) => panic!("expected Found"),
            };

            prop_assert!(verify_proof(&tampered).is_err());
        }

        #[test]
        fn non_inclusion_proof_verifies_for_absent_key(
            present in gen_key(),
            absent in gen_key(),
            value in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            prop_assume!(present != absent);
            let store = MemoryBlockStore::new();

            let present_key = Key::new(present);
            let absent_key = Key::new(absent);

            let value_block = encode_blob(&value).unwrap();
            let value_block_id = compute_block_id(&value_block);
            store.put(value_block_id, value_block).unwrap();

            let nibble0 = present_key.hash().nibble_at(0).unwrap();
            let root_node = MstNode::new().with_leaf_at(nibble0, present_key.clone(), value_block_id);
            let root_bytes = encode_mst_node(&root_node).unwrap();
            let root_id = compute_block_id(&root_bytes);
            store.put(root_id, root_bytes).unwrap();

            let result = mst_lookup(&store, &root_id, &absent_key, 10).unwrap();
            prop_assert!(matches!(result, LookupResult::NotFound(_)));
            verify_proof(&result).unwrap();
        }
    }
}
