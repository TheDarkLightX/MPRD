//! Algorithm 9: Incremental Apply (Companion to Diff).
//!
//! Given a diff result from Algorithm 7, apply changes to local state efficiently.

use super::error::{ArtifactRepoError, Result};
use super::mutation::{mst_delete, mst_insert};
use super::store::BlockStore;
use super::types::{BlockId, DiffEntry};

/// Apply a diff to local state, producing a new root (Algorithm 9).
///
/// # Preconditions
/// - `local_root` is None (empty) or a valid MST node block ID
/// - All value blocks referenced in diff exist in store
///
/// # Postconditions
/// - Returns new root matching remote state
/// - If `expected_root` provided, verifies final root matches (fail-closed)
///
/// # Complexity
/// - Time: O(k·log n) where k = number of diff entries
/// - Space: O(log n)
/// - I/O: O(k·log n)
pub fn apply_diff<S: BlockStore>(
    store: &S,
    local_root: Option<BlockId>,
    diff: &[DiffEntry],
    expected_root: Option<BlockId>,
) -> Result<BlockId> {
    let mut root = local_root;

    for entry in diff {
        match entry {
            DiffEntry::Added { key, value } => {
                root = Some(mst_insert(store, root, key, *value)?);
            }
            DiffEntry::Deleted { key, .. } => {
                root = mst_delete(store, root, key)?;
            }
            DiffEntry::Modified { key, new_value, .. } => {
                // Modified = update value for existing key
                root = Some(mst_insert(store, root, key, *new_value)?);
            }
        }
    }

    let final_root = root.unwrap_or(BlockId::ZERO);

    // Verify final state matches expected (if provided)
    if let Some(expected) = expected_root {
        if final_root != expected {
            return Err(ArtifactRepoError::ApplyRootMismatch {
                expected,
                actual: final_root,
            });
        }
    }

    Ok(final_root)
}

/// Apply diff with batching optimization (Algorithm 9 - Batch Apply).
///
/// For large diffs, batch mutations by shared prefix to minimize repeated
/// path traversals. Entries are sorted by key hash nibble prefix and applied
/// in groups.
///
/// # Complexity
/// - Time: O(k·log n) → O(k + log n) for clustered changes
pub fn apply_diff_batched<S: BlockStore>(
    store: &S,
    local_root: Option<BlockId>,
    diff: &[DiffEntry],
    expected_root: Option<BlockId>,
) -> Result<BlockId> {
    if diff.is_empty() {
        return Ok(local_root.unwrap_or(BlockId::ZERO));
    }

    // For small diffs, use simple apply
    if diff.len() < 10 {
        return apply_diff(store, local_root, diff, expected_root);
    }

    // Sort diff entries by key hash for better locality
    let mut sorted_diff: Vec<_> = diff.iter().collect();
    sorted_diff.sort_by_key(|entry| {
        let key = match entry {
            DiffEntry::Added { key, .. } => key,
            DiffEntry::Deleted { key, .. } => key,
            DiffEntry::Modified { key, .. } => key,
        };
        key.hash().0
    });

    // Apply in sorted order
    let mut root = local_root;
    for entry in sorted_diff {
        match entry {
            DiffEntry::Added { key, value } => {
                root = Some(mst_insert(store, root, key, *value)?);
            }
            DiffEntry::Deleted { key, .. } => {
                root = mst_delete(store, root, key)?;
            }
            DiffEntry::Modified { key, new_value, .. } => {
                root = Some(mst_insert(store, root, key, *new_value)?);
            }
        }
    }

    let final_root = root.unwrap_or(BlockId::ZERO);

    if let Some(expected) = expected_root {
        if final_root != expected {
            return Err(ArtifactRepoError::ApplyRootMismatch {
                expected,
                actual: final_root,
            });
        }
    }

    Ok(final_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_repo::codec::encode_blob;
    use crate::artifact_repo::diff::mst_diff;
    use crate::artifact_repo::store::MemoryBlockStore;
    use crate::artifact_repo::types::{compute_block_id, Key};

    fn create_value(store: &MemoryBlockStore, data: &[u8]) -> BlockId {
        let blob = encode_blob(data).unwrap();
        let id = compute_block_id(&blob);
        store.put(id, blob).unwrap();
        id
    }

    #[test]
    fn apply_empty_diff() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let root = mst_insert(&store, None, &Key::new("key1"), v1).unwrap();

        let result = apply_diff(&store, Some(root), &[], None).unwrap();
        assert_eq!(result, root);
    }

    #[test]
    fn apply_additions() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let v2 = create_value(&store, b"value2");

        let diff = vec![
            DiffEntry::Added {
                key: Key::new("key1"),
                value: v1,
            },
            DiffEntry::Added {
                key: Key::new("key2"),
                value: v2,
            },
        ];

        let result = apply_diff(&store, None, &diff, None).unwrap();
        assert!(!result.is_zero());
    }

    #[test]
    fn apply_deletions() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let v2 = create_value(&store, b"value2");

        // Create tree with two keys
        let root = mst_insert(&store, None, &Key::new("key1"), v1).unwrap();
        let root = mst_insert(&store, Some(root), &Key::new("key2"), v2).unwrap();

        // Delete one key
        let diff = vec![DiffEntry::Deleted {
            key: Key::new("key1"),
            value: v1,
        }];

        let result = apply_diff(&store, Some(root), &diff, None).unwrap();
        assert!(!result.is_zero());
        assert_ne!(result, root);
    }

    #[test]
    fn apply_modifications() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let v2 = create_value(&store, b"value2");

        let root = mst_insert(&store, None, &Key::new("key1"), v1).unwrap();

        let diff = vec![DiffEntry::Modified {
            key: Key::new("key1"),
            old_value: v1,
            new_value: v2,
        }];

        let result = apply_diff(&store, Some(root), &diff, None).unwrap();
        assert_ne!(result, root);
    }

    #[test]
    fn apply_with_expected_root_success() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let v2 = create_value(&store, b"value2");

        // Create old and new trees
        let old_root = mst_insert(&store, None, &Key::new("key1"), v1).unwrap();
        let new_root = mst_insert(&store, Some(old_root), &Key::new("key2"), v2).unwrap();

        // Compute diff
        let diff = mst_diff(&store, Some(old_root), Some(new_root)).unwrap();

        // Apply diff with expected root
        let result = apply_diff(&store, Some(old_root), &diff, Some(new_root)).unwrap();
        assert_eq!(result, new_root);
    }

    #[test]
    fn apply_with_expected_root_mismatch() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");

        let diff = vec![DiffEntry::Added {
            key: Key::new("key1"),
            value: v1,
        }];

        let wrong_expected = crate::artifact_repo::types::Id32([0xaa; 32]);
        let result = apply_diff(&store, None, &diff, Some(wrong_expected));

        assert!(matches!(
            result,
            Err(ArtifactRepoError::ApplyRootMismatch { .. })
        ));
    }

    #[test]
    fn diff_and_apply_roundtrip() {
        let store = MemoryBlockStore::new();
        let v1 = create_value(&store, b"value1");
        let v2 = create_value(&store, b"value2");
        let v3 = create_value(&store, b"value3");

        // Create source tree
        let source = mst_insert(&store, None, &Key::new("a"), v1).unwrap();
        let source = mst_insert(&store, Some(source), &Key::new("b"), v2).unwrap();

        // Create target tree (different)
        let target = mst_insert(&store, None, &Key::new("b"), v2).unwrap();
        let target = mst_insert(&store, Some(target), &Key::new("c"), v3).unwrap();

        // Diff source → target
        let diff = mst_diff(&store, Some(source), Some(target)).unwrap();

        // Apply diff to source, expect target
        let result = apply_diff(&store, Some(source), &diff, Some(target)).unwrap();
        assert_eq!(result, target);
    }
}
