//! Algorithm 8: MST Insert/Delete (COW Mutation).
//!
//! Insert or delete a key→value mapping, returning a new root.
//! All operations are copy-on-write (COW) - no existing blocks are mutated.

use super::bounds::MAX_MST_DEPTH;
use super::codec::{decode_mst_node, encode_mst_node};
use super::error::{ArtifactRepoError, Result};
use super::store::BlockStore;
use super::types::{compute_block_id, BlockId, Key, MstEntry, MstNode};

/// Insert a key-value pair into the MST, returning the new root (Algorithm 8 - Insert).
///
/// # Preconditions
/// - `root` is None (empty tree) or a valid MST node block ID
/// - `value_block_id` points to a valid blob block
///
/// # Postconditions
/// - Returns new root block ID
/// - All new blocks are written to store
/// - Existing blocks are not mutated (COW)
///
/// # Invariants maintained
/// - INV-SORTED: Entries within each node sorted by nibble
/// - INV-UNIQUE: No duplicate keys
/// - INV-CANONICAL: Same key set → same root hash
/// - INV-COW: No existing blocks mutated
///
/// # Complexity
/// - Time: O(log n)
/// - Space: O(log n) recursion stack
/// - I/O: O(log n) reads + O(log n) writes
pub fn mst_insert<S: BlockStore>(
    store: &S,
    root: Option<BlockId>,
    key: &Key,
    value_block_id: BlockId,
) -> Result<BlockId> {
    let key_hash = key.hash();
    let nibbles = key_hash.to_nibbles();

    match root {
        None => {
            // Create single-entry tree
            let nibble = nibbles[0];
            let node = MstNode::new().with_leaf_at(nibble, key.clone(), value_block_id);
            let node_bytes = encode_mst_node(&node)?;
            let node_id = compute_block_id(&node_bytes);
            store.put(node_id, node_bytes)?;
            Ok(node_id)
        }
        Some(root_id) => insert_recursive(store, &root_id, &nibbles, 0, key, value_block_id),
    }
}

fn insert_recursive<S: BlockStore>(
    store: &S,
    node_id: &BlockId,
    nibbles: &[u8; 64],
    depth: usize,
    key: &Key,
    value_block_id: BlockId,
) -> Result<BlockId> {
    if depth >= MAX_MST_DEPTH {
        return Err(ArtifactRepoError::KeyHashCollision { depth });
    }

    // Fetch and decode current node
    let node_bytes = store
        .get(node_id)
        .ok_or(ArtifactRepoError::BlockNotFound(*node_id))?;
    let node = decode_mst_node(&node_bytes)?;

    let nibble = nibbles[depth];
    let existing = node.entry_at(nibble);

    let new_node = match existing {
        None => {
            // No entry at this nibble: insert leaf here
            node.with_leaf_at(nibble, key.clone(), value_block_id)
        }
        Some(MstEntry::Leaf {
            key: existing_key,
            value_block_id: _,
        }) if existing_key.as_bytes() == key.as_bytes() => {
            // Update existing leaf (same key)
            node.with_leaf_at(nibble, key.clone(), value_block_id)
        }
        Some(MstEntry::Leaf {
            key: existing_key,
            value_block_id: existing_value,
        }) => {
            // Collision at same nibble: push both down into a new child subtree
            let existing_nibbles = existing_key.hash().to_nibbles();
            let child_id = create_split_node(
                store,
                SplitNodeInputs {
                    key1: existing_key,
                    val1: *existing_value,
                    key2: key,
                    val2: value_block_id,
                    nibbles1: &existing_nibbles,
                    nibbles2: nibbles,
                },
                depth + 1,
            )?;
            node.with_child_at(nibble, child_id)
        }
        Some(MstEntry::Child { child_id }) => {
            // Recurse into child
            let new_child_id =
                insert_recursive(store, child_id, nibbles, depth + 1, key, value_block_id)?;
            node.with_child_at(nibble, new_child_id)
        }
    };

    // Store new node
    let new_node_bytes = encode_mst_node(&new_node)?;
    let new_node_id = compute_block_id(&new_node_bytes);
    store.put(new_node_id, new_node_bytes)?;

    Ok(new_node_id)
}

/// Create a split node when two keys collide at the same nibble.
struct SplitNodeInputs<'a> {
    key1: &'a Key,
    val1: BlockId,
    key2: &'a Key,
    val2: BlockId,
    nibbles1: &'a [u8; 64],
    nibbles2: &'a [u8; 64],
}

fn create_split_node<S: BlockStore>(
    store: &S,
    inputs: SplitNodeInputs<'_>,
    depth: usize,
) -> Result<BlockId> {
    if depth >= MAX_MST_DEPTH {
        return Err(ArtifactRepoError::KeyHashCollision { depth });
    }

    let n1 = inputs.nibbles1[depth];
    let n2 = inputs.nibbles2[depth];

    let node = if n1 == n2 {
        // Same nibble at this depth: create child and recurse
        let child_id = create_split_node(store, inputs, depth + 1)?;
        MstNode::new().with_child_at(n1, child_id)
    } else {
        // Different nibbles: place both leaves in this node
        MstNode::new()
            .with_leaf_at(n1, inputs.key1.clone(), inputs.val1)
            .with_leaf_at(n2, inputs.key2.clone(), inputs.val2)
    };

    let node_bytes = encode_mst_node(&node)?;
    let node_id = compute_block_id(&node_bytes);
    store.put(node_id, node_bytes)?;

    Ok(node_id)
}

/// Delete a key from the MST, returning the new root (Algorithm 8 - Delete).
///
/// # Preconditions
/// - `root` is None (empty tree) or a valid MST node block ID
///
/// # Postconditions
/// - Returns Some(new_root) if tree is non-empty after deletion
/// - Returns None if tree becomes empty
/// - Key not found: returns original root (no change)
/// - All new blocks are written to store
/// - Existing blocks are not mutated (COW)
///
/// # Invariants maintained
/// - INV-CANONICAL: Maintains canonical form by collapsing single-leaf subtrees
///
/// # Complexity
/// - Time: O(log n)
/// - Space: O(log n) recursion stack
/// - I/O: O(log n) reads + O(log n) writes
pub fn mst_delete<S: BlockStore>(
    store: &S,
    root: Option<BlockId>,
    key: &Key,
) -> Result<Option<BlockId>> {
    match root {
        None => Ok(None), // Nothing to delete
        Some(root_id) => {
            let key_hash = key.hash();
            let nibbles = key_hash.to_nibbles();
            delete_recursive(store, &root_id, &nibbles, 0, key)
        }
    }
}

fn delete_recursive<S: BlockStore>(
    store: &S,
    node_id: &BlockId,
    nibbles: &[u8; 64],
    depth: usize,
    key: &Key,
) -> Result<Option<BlockId>> {
    if depth >= MAX_MST_DEPTH {
        return Err(ArtifactRepoError::MstDepthExceeded { depth });
    }

    // Fetch and decode current node
    let node_bytes = store
        .get(node_id)
        .ok_or(ArtifactRepoError::BlockNotFound(*node_id))?;
    let node = decode_mst_node(&node_bytes)?;

    let nibble = nibbles[depth];
    let existing = node.entry_at(nibble);

    let new_node = match existing {
        None => {
            // Key not found, no change
            return Ok(Some(*node_id));
        }
        Some(MstEntry::Leaf {
            key: existing_key, ..
        }) if existing_key.as_bytes() == key.as_bytes() => {
            // Found the key to delete
            node.without_entry_at(nibble)
        }
        Some(MstEntry::Leaf { .. }) => {
            // Different key at this nibble, no change
            return Ok(Some(*node_id));
        }
        Some(MstEntry::Child { child_id }) => {
            // Recurse into child
            let new_child_opt = delete_recursive(store, child_id, nibbles, depth + 1, key)?;

            match new_child_opt {
                None => {
                    // Child subtree now empty
                    node.without_entry_at(nibble)
                }
                Some(new_child_id) => {
                    // Canonicalization (MANDATORY): if the child subtree now contains
                    // exactly one leaf, collapse it upward into a leaf at this nibble.
                    if let Some((leaf_key, leaf_value)) = extract_single_leaf(store, &new_child_id)?
                    {
                        node.with_leaf_at(nibble, leaf_key, leaf_value)
                    } else {
                        node.with_child_at(nibble, new_child_id)
                    }
                }
            }
        }
    };

    if new_node.is_empty() {
        return Ok(None);
    }

    // Store new node
    let new_node_bytes = encode_mst_node(&new_node)?;
    let new_node_id = compute_block_id(&new_node_bytes);
    store.put(new_node_id, new_node_bytes)?;

    Ok(Some(new_node_id))
}

/// Extract the single leaf from a subtree if it contains exactly one leaf.
///
/// Returns Some((key, value)) iff:
/// - The subtree is a chain of single-child nodes ending in a single leaf
/// - There is no branching
///
/// Returns None if the subtree has multiple entries or is empty.
fn extract_single_leaf<S: BlockStore>(
    store: &S,
    node_id: &BlockId,
) -> Result<Option<(Key, BlockId)>> {
    let mut current_id = *node_id;
    let mut depth = 0;

    loop {
        if depth >= MAX_MST_DEPTH {
            return Ok(None);
        }

        let node_bytes = store
            .get(&current_id)
            .ok_or(ArtifactRepoError::BlockNotFound(current_id))?;
        let node = decode_mst_node(&node_bytes)?;

        let entry_count = node.entry_count();

        if entry_count == 0 {
            return Ok(None);
        }

        if entry_count > 1 {
            return Ok(None); // Branching, can't collapse
        }

        // Exactly one entry
        let (_, entry) = node.iter().next().unwrap();

        match entry {
            MstEntry::Leaf {
                key,
                value_block_id,
            } => {
                return Ok(Some((key.clone(), *value_block_id)));
            }
            MstEntry::Child { child_id } => {
                current_id = *child_id;
                depth += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_repo::codec::encode_blob;
    use crate::artifact_repo::lookup::{mst_lookup, verify_proof};
    use crate::artifact_repo::store::MemoryBlockStore;
    use crate::artifact_repo::types::LookupResult;
    use proptest::prelude::*;

    fn create_value(store: &MemoryBlockStore, data: &[u8]) -> BlockId {
        let blob = encode_blob(data).unwrap();
        let id = compute_block_id(&blob);
        store.put(id, blob).unwrap();
        id
    }

    #[test]
    fn extract_single_leaf_fails_closed_when_chain_exceeds_max_depth() {
        let store = MemoryBlockStore::new();
        let value_id = create_value(&store, b"v");

        let leaf_node = MstNode::new().with_leaf_at(0, Key::new("k"), value_id);
        let leaf_bytes = encode_mst_node(&leaf_node).unwrap();
        let mut current_id = compute_block_id(&leaf_bytes);
        store.put(current_id, leaf_bytes).unwrap();

        // Build a single-child chain of length MAX_MST_DEPTH above the leaf, so the leaf is at depth == MAX_MST_DEPTH.
        for _ in 0..MAX_MST_DEPTH {
            let parent = MstNode::new().with_child_at(0, current_id);
            let parent_bytes = encode_mst_node(&parent).unwrap();
            let parent_id = compute_block_id(&parent_bytes);
            store.put(parent_id, parent_bytes).unwrap();
            current_id = parent_id;
        }

        let extracted = extract_single_leaf(&store, &current_id).unwrap();
        assert!(extracted.is_none());
    }

    #[test]
    fn insert_into_empty_tree() {
        let store = MemoryBlockStore::new();
        let value_id = create_value(&store, b"value1");

        let root = mst_insert(&store, None, &Key::new("key1"), value_id).unwrap();

        assert!(!root.is_zero());
        assert!(store.contains(&root));
    }

    #[test]
    fn insert_multiple_keys() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let v2 = create_value(&store, b"value2");
        let v3 = create_value(&store, b"value3");

        let root = mst_insert(&store, None, &Key::new("key1"), v1).unwrap();
        let root = mst_insert(&store, Some(root), &Key::new("key2"), v2).unwrap();
        let root = mst_insert(&store, Some(root), &Key::new("key3"), v3).unwrap();

        assert!(!root.is_zero());
    }

    #[test]
    fn update_existing_key() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let v2 = create_value(&store, b"value2");

        let root1 = mst_insert(&store, None, &Key::new("key1"), v1).unwrap();
        let root2 = mst_insert(&store, Some(root1), &Key::new("key1"), v2).unwrap();

        // Different roots (COW)
        assert_ne!(root1, root2);
    }

    #[test]
    fn delete_from_empty_tree() {
        let store = MemoryBlockStore::new();

        let result = mst_delete(&store, None, &Key::new("key1")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn delete_only_key() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");

        let root = mst_insert(&store, None, &Key::new("key1"), v1).unwrap();
        let result = mst_delete(&store, Some(root), &Key::new("key1")).unwrap();

        assert!(result.is_none()); // Tree becomes empty
    }

    #[test]
    fn delete_nonexistent_key() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");

        let root = mst_insert(&store, None, &Key::new("key1"), v1).unwrap();
        let result = mst_delete(&store, Some(root), &Key::new("nonexistent")).unwrap();

        assert_eq!(result, Some(root)); // No change
    }

    #[test]
    fn delete_preserves_other_keys() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let v2 = create_value(&store, b"value2");

        let root = mst_insert(&store, None, &Key::new("key1"), v1).unwrap();
        let root = mst_insert(&store, Some(root), &Key::new("key2"), v2).unwrap();
        let result = mst_delete(&store, Some(root), &Key::new("key1")).unwrap();

        assert!(result.is_some());
        assert_ne!(result.unwrap(), root); // COW
    }

    #[test]
    fn insert_delete_roundtrip() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let v2 = create_value(&store, b"value2");
        let v3 = create_value(&store, b"value3");

        // Insert three keys
        let root = mst_insert(&store, None, &Key::new("a"), v1).unwrap();
        let root = mst_insert(&store, Some(root), &Key::new("b"), v2).unwrap();
        let root = mst_insert(&store, Some(root), &Key::new("c"), v3).unwrap();

        // Delete middle key
        let root = mst_delete(&store, Some(root), &Key::new("b"))
            .unwrap()
            .unwrap();

        // Re-insert should work
        let _root = mst_insert(&store, Some(root), &Key::new("b"), v2).unwrap();
    }

    #[test]
    fn canonical_form_after_delete() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let v2 = create_value(&store, b"value2");

        // Insert two keys that might share a prefix
        let root = mst_insert(&store, None, &Key::new("aaa"), v1).unwrap();
        let root = mst_insert(&store, Some(root), &Key::new("aab"), v2).unwrap();

        // Delete one - should trigger canonicalization if they shared a child node
        let result = mst_delete(&store, Some(root), &Key::new("aaa")).unwrap();

        assert!(result.is_some());
    }

    fn gen_key() -> impl Strategy<Value = String> {
        // Must satisfy codec key canonical bytes constraints.
        "[a-z0-9_./-]{1,24}".prop_map(|s| s)
    }

    proptest! {
        #[test]
        fn insertion_order_does_not_change_root_for_same_mapping(
            kvs in proptest::collection::btree_map(gen_key(), proptest::collection::vec(any::<u8>(), 0..64), 1..12),
        ) {
            // Build root by insertion in forward order.
            let store_a = MemoryBlockStore::new();
            let mut root_a: Option<BlockId> = None;
            for (k, v) in kvs.iter() {
                let value_id = create_value(&store_a, v);
                root_a = Some(mst_insert(&store_a, root_a, &Key::new(k.clone()), value_id).unwrap());
            }
            let root_a = root_a.unwrap();

            // Build root by insertion in reverse order in a separate store.
            let store_b = MemoryBlockStore::new();
            let mut root_b: Option<BlockId> = None;
            for (k, v) in kvs.iter().rev() {
                let value_id = create_value(&store_b, v);
                root_b = Some(mst_insert(&store_b, root_b, &Key::new(k.clone()), value_id).unwrap());
            }
            let root_b = root_b.unwrap();

            prop_assert_eq!(root_a, root_b);
        }

        #[test]
        fn inserted_keys_are_retrievable_with_verifiable_proofs(
            kvs in proptest::collection::btree_map(gen_key(), proptest::collection::vec(any::<u8>(), 0..64), 1..10),
        ) {
            let store = MemoryBlockStore::new();
            let mut root: Option<BlockId> = None;

            for (k, v) in kvs.iter() {
                let value_id = create_value(&store, v);
                root = Some(mst_insert(&store, root, &Key::new(k.clone()), value_id).unwrap());
            }
            let root = root.unwrap();

            // Verify each key can be looked up and proof verifies.
            for (k, v) in kvs.iter() {
                let key = Key::new(k.clone());
                let result = mst_lookup(&store, &root, &key, 500).unwrap();
                verify_proof(&result).unwrap();
                match result {
                    LookupResult::Found(p) => prop_assert_eq!(p.value_bytes.as_slice(), v.as_slice()),
                    LookupResult::NotFound(_) => prop_assert!(false, "expected Found"),
                }
            }
        }

        #[test]
        fn deleting_all_keys_yields_empty_tree(
            kvs in proptest::collection::btree_map(gen_key(), proptest::collection::vec(any::<u8>(), 0..32), 1..12),
        ) {
            let store = MemoryBlockStore::new();
            let mut root: Option<BlockId> = None;
            let mut keys: Vec<Key> = Vec::new();

            for (k, v) in kvs.iter() {
                let key = Key::new(k.clone());
                let value_id = create_value(&store, v);
                root = Some(mst_insert(&store, root, &key, value_id).unwrap());
                keys.push(key);
            }

            for key in keys {
                root = mst_delete(&store, root, &key).unwrap();
            }

            prop_assert!(root.is_none());
        }
    }
}
