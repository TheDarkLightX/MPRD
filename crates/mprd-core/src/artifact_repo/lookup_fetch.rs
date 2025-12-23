//! MST lookup that fetches missing blocks from untrusted sources (Algorithm 4 + 5).
//!
//! This is a convenience wrapper for clients that want end-to-end lookup without
//! pre-populating a `BlockStore`.

use super::bounds::RuntimeBounds;
use super::codec::{decode_blob, decode_mst_node};
use super::error::{ArtifactRepoError, Result};
use super::fetch::{fetch_block_multi_source, ClientInstanceId};
use super::store::{BlockSource, BlockStore};
use super::types::{
    compute_block_id, BlockId, InclusionProof, Key, LookupResult, MstEntry, NonInclusionProof,
    NonInclusionReason,
};

/// Perform an MST lookup, fetching required blocks from sources into the store as needed.
pub async fn mst_lookup_fetching(
    store: &dyn BlockStore,
    root: &BlockId,
    key: &Key,
    block_sources: &[&dyn BlockSource],
    bounds: &RuntimeBounds,
    client_instance_id: &ClientInstanceId,
) -> Result<LookupResult> {
    let key_hash = key.hash();
    let nibbles = key_hash.to_nibbles();

    let mut current = *root;
    let mut depth = 0usize;
    let mut blocks: Vec<(BlockId, Vec<u8>)> = Vec::new();
    let mut remaining = bounds.max_block_fetch;

    loop {
        if depth > super::bounds::MAX_MST_DEPTH {
            return Err(ArtifactRepoError::MstDepthExceeded { depth });
        }
        if remaining == 0 {
            return Err(ArtifactRepoError::BoundsExceeded("MAX_BLOCK_FETCH"));
        }

        // Ensure current node block is present.
        let node_bytes = match store.get(&current) {
            Some(b) => b,
            None => {
                consume_budget(&mut remaining)?;
                let b = fetch_block_multi_source(
                    store,
                    &current,
                    block_sources,
                    bounds,
                    client_instance_id,
                )
                .await?;
                b
            }
        };

        // Verify content address.
        let computed_id = compute_block_id(&node_bytes);
        if computed_id != current {
            return Err(ArtifactRepoError::ContentAddressMismatch {
                expected: current,
                actual: computed_id,
            });
        }

        if !blocks.iter().any(|(id, _)| *id == current) {
            blocks.push((current, node_bytes.clone()));
        }

        let node = decode_mst_node(&node_bytes)?;
        let expected_nibble = nibbles[depth];

        match node.entry_at(expected_nibble) {
            Some(MstEntry::Leaf {
                key: stored_key,
                value_block_id,
            }) => {
                if stored_key.as_bytes() != key.as_bytes() {
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

                if remaining == 0 {
                    return Err(ArtifactRepoError::BoundsExceeded("MAX_BLOCK_FETCH"));
                }

                let value_bytes = match store.get(value_block_id) {
                    Some(b) => b,
                    None => {
                        consume_budget(&mut remaining)?;
                        let b = fetch_block_multi_source(
                            store,
                            value_block_id,
                            block_sources,
                            bounds,
                            client_instance_id,
                        )
                        .await?;
                        b
                    }
                };

                let computed_value_id = compute_block_id(&value_bytes);
                if computed_value_id != *value_block_id {
                    return Err(ArtifactRepoError::ContentAddressMismatch {
                        expected: *value_block_id,
                        actual: computed_value_id,
                    });
                }

                if !blocks.iter().any(|(id, _)| *id == *value_block_id) {
                    blocks.push((*value_block_id, value_bytes.clone()));
                }

                let payload = decode_blob(&value_bytes)?;
                if payload.len() > bounds.max_value_bytes {
                    return Err(ArtifactRepoError::ValueTooLarge {
                        size: payload.len(),
                        max: bounds.max_value_bytes,
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
                current = *child_id;
                depth += 1;
            }
            None => {
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

fn consume_budget(remaining: &mut usize) -> Result<()> {
    if *remaining == 0 {
        return Err(ArtifactRepoError::BoundsExceeded("MAX_BLOCK_FETCH"));
    }
    *remaining = remaining.saturating_sub(1);
    Ok(())
}
