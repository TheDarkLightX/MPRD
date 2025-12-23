//! Algorithm 7: Hash-Guided Diff (Incremental Sync).
//!
//! Efficiently compute the difference between two MST states without
//! downloading both trees fully. Critical for incremental sync.

use super::bounds::{MAX_BLOCK_FETCH, MAX_DIFF_ENTRIES, MAX_MST_DEPTH};
use super::codec::decode_mst_node;
use super::error::{ArtifactRepoError, Result};
use super::store::BlockStore;
use super::types::{BlockId, DiffEntry, MstEntry};

/// Hash-guided diff between two MST states (Algorithm 7).
///
/// # Key Insight
/// If two subtree roots have identical hashes, they contain identical data
/// (collision resistance). Skip entire subtrees when hashes match.
///
/// # Preconditions
/// - `old_root` is None (empty) or a valid MST node block ID
/// - `new_root` is None (empty) or a valid MST node block ID
/// - Store contains all reachable blocks from both roots
///
/// # Postconditions
/// - Returns Vec<DiffEntry> with all changes: Added, Deleted, Modified
/// - Fails closed on any decode error or bounds exceeded
///
/// # Complexity
/// - Best case: O(1) when roots identical
/// - Typical case: O(k · log(n/k)) where k = changed entries
/// - Worst case: O(n) when trees completely different
///
/// This is **optimal** for Merkle tree diff.
pub fn mst_diff<S: BlockStore>(
    store: &S,
    old_root: Option<BlockId>,
    new_root: Option<BlockId>,
) -> Result<Vec<DiffEntry>> {
    let mut state = DiffState {
        store,
        result: Vec::new(),
        blocks_fetched: 0,
    };

    // Handle empty cases
    if old_root.is_none() && new_root.is_none() {
        return Ok(vec![]);
    }

    // Critical optimization: identical hash = skip
    if old_root == new_root {
        return Ok(vec![]);
    }

    diff_recursive(&mut state, old_root.as_ref(), new_root.as_ref(), 0)?;

    Ok(state.result)
}

struct DiffState<'a, S: BlockStore> {
    store: &'a S,
    result: Vec<DiffEntry>,
    blocks_fetched: usize,
}

fn diff_recursive<S: BlockStore>(
    state: &mut DiffState<'_, S>,
    old_id: Option<&BlockId>,
    new_id: Option<&BlockId>,
    depth: usize,
) -> Result<()> {
    // Bound checks
    if depth > MAX_MST_DEPTH {
        return Err(ArtifactRepoError::MstDepthExceeded { depth });
    }
    if state.blocks_fetched > MAX_BLOCK_FETCH {
        return Err(ArtifactRepoError::BoundsExceeded("MAX_BLOCK_FETCH"));
    }
    if state.result.len() > MAX_DIFF_ENTRIES {
        return Err(ArtifactRepoError::DiffBoundsExceeded {
            count: state.result.len(),
            max: MAX_DIFF_ENTRIES,
        });
    }

    // Handle empty subtree cases
    match (old_id, new_id) {
        (None, None) => return Ok(()),
        (Some(old), None) => {
            // All entries in old subtree are deleted
            enumerate_all_as_deleted(state, old, depth)?;
            return Ok(());
        }
        (None, Some(new)) => {
            // All entries in new subtree are added
            enumerate_all_as_added(state, new, depth)?;
            return Ok(());
        }
        (Some(old), Some(new)) => {
            // Critical optimization: identical hash = skip subtree
            if old == new {
                return Ok(());
            }
            // Fall through to compare nodes
        }
    }

    let old_id = old_id.unwrap();
    let new_id = new_id.unwrap();

    // Fetch both nodes
    let old_bytes = state
        .store
        .get(old_id)
        .ok_or(ArtifactRepoError::BlockNotFound(*old_id))?;
    state.blocks_fetched += 1;

    let new_bytes = state
        .store
        .get(new_id)
        .ok_or(ArtifactRepoError::BlockNotFound(*new_id))?;
    state.blocks_fetched += 1;

    let old_node = decode_mst_node(&old_bytes)?;
    let new_node = decode_mst_node(&new_bytes)?;

    // Merge-walk over nibble-indexed entries
    for nibble in 0..16u8 {
        let old_entry = old_node.entry_at(nibble);
        let new_entry = new_node.entry_at(nibble);

        match (old_entry, new_entry) {
            (None, None) => continue,
            (Some(old), None) => {
                // Entry removed
                add_deletions(state, old, depth)?;
            }
            (None, Some(new)) => {
                // Entry added
                add_additions(state, new, depth)?;
            }
            (Some(old), Some(new)) => {
                compare_entries(state, old, new, depth)?;
            }
        }
    }

    Ok(())
}

fn compare_entries<S: BlockStore>(
    state: &mut DiffState<'_, S>,
    old: &MstEntry,
    new: &MstEntry,
    depth: usize,
) -> Result<()> {
    match (old, new) {
        (MstEntry::Child { child_id: old_id }, MstEntry::Child { child_id: new_id }) => {
            // Both are children - recurse if different
            if old_id != new_id {
                diff_recursive(state, Some(old_id), Some(new_id), depth + 1)?;
            }
        }
        (
            MstEntry::Leaf {
                key: old_key,
                value_block_id: old_value,
            },
            MstEntry::Leaf {
                key: new_key,
                value_block_id: new_value,
            },
        ) => {
            // Both are leaves
            if old_key.as_bytes() == new_key.as_bytes() {
                // Same key
                if old_value != new_value {
                    state.result.push(DiffEntry::Modified {
                        key: old_key.clone(),
                        old_value: *old_value,
                        new_value: *new_value,
                    });
                }
            } else {
                // Different keys at same nibble (shouldn't happen in well-formed tree)
                state.result.push(DiffEntry::Deleted {
                    key: old_key.clone(),
                    value: *old_value,
                });
                state.result.push(DiffEntry::Added {
                    key: new_key.clone(),
                    value: *new_value,
                });
            }
        }
        (old_entry, new_entry) => {
            // Type changed (child↔leaf)
            add_deletions(state, old_entry, depth)?;
            add_additions(state, new_entry, depth)?;
        }
    }
    Ok(())
}

fn add_deletions<S: BlockStore>(
    state: &mut DiffState<'_, S>,
    entry: &MstEntry,
    depth: usize,
) -> Result<()> {
    match entry {
        MstEntry::Leaf {
            key,
            value_block_id,
        } => {
            state.result.push(DiffEntry::Deleted {
                key: key.clone(),
                value: *value_block_id,
            });
        }
        MstEntry::Child { child_id } => {
            enumerate_all_as_deleted(state, child_id, depth + 1)?;
        }
    }
    Ok(())
}

fn add_additions<S: BlockStore>(
    state: &mut DiffState<'_, S>,
    entry: &MstEntry,
    depth: usize,
) -> Result<()> {
    match entry {
        MstEntry::Leaf {
            key,
            value_block_id,
        } => {
            state.result.push(DiffEntry::Added {
                key: key.clone(),
                value: *value_block_id,
            });
        }
        MstEntry::Child { child_id } => {
            enumerate_all_as_added(state, child_id, depth + 1)?;
        }
    }
    Ok(())
}

/// Enumerate all leaves in a subtree as deletions (ENUMERATE_ALL from spec).
fn enumerate_all_as_deleted<S: BlockStore>(
    state: &mut DiffState<'_, S>,
    root_id: &BlockId,
    depth: usize,
) -> Result<()> {
    if state.blocks_fetched >= MAX_BLOCK_FETCH {
        return Err(ArtifactRepoError::BoundsExceeded("MAX_BLOCK_FETCH"));
    }
    if depth > MAX_MST_DEPTH {
        return Err(ArtifactRepoError::MstDepthExceeded { depth });
    }

    let node_bytes = state
        .store
        .get(root_id)
        .ok_or(ArtifactRepoError::BlockNotFound(*root_id))?;
    state.blocks_fetched += 1;

    let node = decode_mst_node(&node_bytes)?;

    for nibble in 0..16u8 {
        if let Some(entry) = node.entry_at(nibble) {
            match entry {
                MstEntry::Leaf {
                    key,
                    value_block_id,
                } => {
                    state.result.push(DiffEntry::Deleted {
                        key: key.clone(),
                        value: *value_block_id,
                    });
                }
                MstEntry::Child { child_id } => {
                    enumerate_all_as_deleted(state, child_id, depth + 1)?;
                }
            }
        }
    }

    Ok(())
}

/// Enumerate all leaves in a subtree as additions.
fn enumerate_all_as_added<S: BlockStore>(
    state: &mut DiffState<'_, S>,
    root_id: &BlockId,
    depth: usize,
) -> Result<()> {
    if state.blocks_fetched >= MAX_BLOCK_FETCH {
        return Err(ArtifactRepoError::BoundsExceeded("MAX_BLOCK_FETCH"));
    }
    if depth > MAX_MST_DEPTH {
        return Err(ArtifactRepoError::MstDepthExceeded { depth });
    }

    let node_bytes = state
        .store
        .get(root_id)
        .ok_or(ArtifactRepoError::BlockNotFound(*root_id))?;
    state.blocks_fetched += 1;

    let node = decode_mst_node(&node_bytes)?;

    for nibble in 0..16u8 {
        if let Some(entry) = node.entry_at(nibble) {
            match entry {
                MstEntry::Leaf {
                    key,
                    value_block_id,
                } => {
                    state.result.push(DiffEntry::Added {
                        key: key.clone(),
                        value: *value_block_id,
                    });
                }
                MstEntry::Child { child_id } => {
                    enumerate_all_as_added(state, child_id, depth + 1)?;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_repo::codec::encode_blob;
    use crate::artifact_repo::mutation::{mst_delete, mst_insert};
    use crate::artifact_repo::store::MemoryBlockStore;
    use crate::artifact_repo::types::{compute_block_id, Key};

    fn create_value(store: &MemoryBlockStore, data: &[u8]) -> BlockId {
        let blob = encode_blob(data).unwrap();
        let id = compute_block_id(&blob);
        store.put(id, blob).unwrap();
        id
    }

    #[test]
    fn diff_empty_trees() {
        let store = MemoryBlockStore::new();
        let diff = mst_diff(&store, None, None).unwrap();
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_identical_trees() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let root = mst_insert(&store, None, &Key::new("key1"), v1).unwrap();

        let diff = mst_diff(&store, Some(root), Some(root)).unwrap();
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_empty_to_populated() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let v2 = create_value(&store, b"value2");

        let root = mst_insert(&store, None, &Key::new("key1"), v1).unwrap();
        let root = mst_insert(&store, Some(root), &Key::new("key2"), v2).unwrap();

        let diff = mst_diff(&store, None, Some(root)).unwrap();

        assert_eq!(diff.len(), 2);
        assert!(diff.iter().all(|e| matches!(e, DiffEntry::Added { .. })));
    }

    #[test]
    fn diff_populated_to_empty() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let root = mst_insert(&store, None, &Key::new("key1"), v1).unwrap();

        let diff = mst_diff(&store, Some(root), None).unwrap();

        assert_eq!(diff.len(), 1);
        assert!(matches!(diff[0], DiffEntry::Deleted { .. }));
    }

    #[test]
    fn diff_added_key() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let v2 = create_value(&store, b"value2");

        let root1 = mst_insert(&store, None, &Key::new("key1"), v1).unwrap();
        let root2 = mst_insert(&store, Some(root1), &Key::new("key2"), v2).unwrap();

        let diff = mst_diff(&store, Some(root1), Some(root2)).unwrap();

        assert_eq!(diff.len(), 1);
        match &diff[0] {
            DiffEntry::Added { key, value } => {
                assert_eq!(key.as_bytes(), b"key2");
                assert_eq!(*value, v2);
            }
            _ => panic!("expected Added"),
        }
    }

    #[test]
    fn diff_deleted_key() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let v2 = create_value(&store, b"value2");

        let root1 = mst_insert(&store, None, &Key::new("key1"), v1).unwrap();
        let root1 = mst_insert(&store, Some(root1), &Key::new("key2"), v2).unwrap();
        let root2 = mst_delete(&store, Some(root1), &Key::new("key1"))
            .unwrap()
            .unwrap();

        let diff = mst_diff(&store, Some(root1), Some(root2)).unwrap();

        assert_eq!(diff.len(), 1);
        match &diff[0] {
            DiffEntry::Deleted { key, value } => {
                assert_eq!(key.as_bytes(), b"key1");
                assert_eq!(*value, v1);
            }
            _ => panic!("expected Deleted"),
        }
    }

    #[test]
    fn diff_modified_value() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let v2 = create_value(&store, b"value2");

        let root1 = mst_insert(&store, None, &Key::new("key1"), v1).unwrap();
        let root2 = mst_insert(&store, Some(root1), &Key::new("key1"), v2).unwrap();

        let diff = mst_diff(&store, Some(root1), Some(root2)).unwrap();

        assert_eq!(diff.len(), 1);
        match &diff[0] {
            DiffEntry::Modified {
                key,
                old_value,
                new_value,
            } => {
                assert_eq!(key.as_bytes(), b"key1");
                assert_eq!(*old_value, v1);
                assert_eq!(*new_value, v2);
            }
            _ => panic!("expected Modified"),
        }
    }

    #[test]
    fn diff_multiple_changes() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let v2 = create_value(&store, b"value2");
        let v3 = create_value(&store, b"value3");
        let v4 = create_value(&store, b"value4");

        // Old tree: key1=v1, key2=v2
        let old_root = mst_insert(&store, None, &Key::new("key1"), v1).unwrap();
        let old_root = mst_insert(&store, Some(old_root), &Key::new("key2"), v2).unwrap();

        // New tree: key1=v3 (modified), key3=v4 (added), key2 deleted
        let new_root = mst_insert(&store, None, &Key::new("key1"), v3).unwrap();
        let new_root = mst_insert(&store, Some(new_root), &Key::new("key3"), v4).unwrap();

        let diff = mst_diff(&store, Some(old_root), Some(new_root)).unwrap();

        // Should have: Modified(key1), Deleted(key2), Added(key3)
        assert_eq!(diff.len(), 3);

        let has_modified = diff
            .iter()
            .any(|e| matches!(e, DiffEntry::Modified { key, .. } if key.as_bytes() == b"key1"));
        let has_deleted = diff
            .iter()
            .any(|e| matches!(e, DiffEntry::Deleted { key, .. } if key.as_bytes() == b"key2"));
        let has_added = diff
            .iter()
            .any(|e| matches!(e, DiffEntry::Added { key, .. } if key.as_bytes() == b"key3"));

        assert!(has_modified, "should have Modified(key1)");
        assert!(has_deleted, "should have Deleted(key2)");
        assert!(has_added, "should have Added(key3)");
    }
}
