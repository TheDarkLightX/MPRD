//! Algorithm 5: Bounded multi-source block fetch scheduler.
//!
//! This module provides:
//! - deterministic scheduling of untrusted sources for a given block fetch,
//! - bounded retries,
//! - strict content-address verification (fail-closed),
//! - optional local caching via `BlockStore`.
//!
//! Note: timeouts and parallel hedging are intentionally not implemented here to avoid
//! coupling `mprd-core` to a specific async runtime. Callers can wrap `get_block()` with
//! timeout logic externally if needed.

use super::bounds::SOURCE_SHUFFLE_PREFIX;
use super::error::{ArtifactRepoError, Result};
use super::store::{BlockSource, BlockStore};
use super::types::{compute_block_id, BlockId, Id32, SourceId};
use sha2::{Digest, Sha256};

/// Deterministic client instance identifier for scheduling.
///
/// This is used only to decorrelate source ordering across clients.
pub type ClientInstanceId = Id32;

/// Compute the deterministic source order for attempting a block fetch.
///
/// Returns a vector of indexes into `sources`.
pub fn schedule_sources_for_block(
    client_instance_id: &ClientInstanceId,
    block_id: &BlockId,
    attempt: u32,
    sources: &[SourceId],
) -> Vec<usize> {
    let seed = shuffle_seed(client_instance_id, block_id, attempt);
    shuffled_indexes(&seed, sources.len())
}

/// Fetch a block from untrusted sources and cache it in the store.
pub async fn fetch_block_multi_source(
    store: &dyn BlockStore,
    block_id: &BlockId,
    block_sources: &[&dyn BlockSource],
    bounds: &super::bounds::RuntimeBounds,
    client_instance_id: &ClientInstanceId,
) -> Result<Vec<u8>> {
    if let Some(bytes) = store.get(block_id) {
        return Ok(bytes);
    }

    if block_sources.is_empty() {
        return Err(ArtifactRepoError::AllSourcesFailed);
    }

    let source_ids: Vec<SourceId> = block_sources.iter().map(|s| s.source_id()).collect();

    let mut last_err: Option<ArtifactRepoError> = None;
    for attempt in 0..bounds.max_retries {
        let order =
            schedule_sources_for_block(client_instance_id, block_id, attempt as u32, &source_ids);

        for idx in order {
            let src = block_sources[idx];
            match src.get_block(block_id).await {
                Ok(bytes) => {
                    if bytes.len() > bounds.max_block_bytes {
                        last_err = Some(ArtifactRepoError::BlockTooLarge {
                            size: bytes.len(),
                            max: bounds.max_block_bytes,
                        });
                        continue;
                    }
                    let computed = compute_block_id(&bytes);
                    if computed != *block_id {
                        last_err = Some(ArtifactRepoError::ContentAddressMismatch {
                            expected: *block_id,
                            actual: computed,
                        });
                        continue;
                    }

                    store.put(*block_id, bytes.clone())?;
                    return Ok(bytes);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
    }

    Err(last_err.unwrap_or(ArtifactRepoError::AllSourcesFailed))
}

fn shuffle_seed(
    client_instance_id: &ClientInstanceId,
    block_id: &BlockId,
    attempt: u32,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SOURCE_SHUFFLE_PREFIX);
    h.update(client_instance_id.0);
    h.update(block_id.0);
    h.update(attempt.to_le_bytes());
    h.finalize().into()
}

fn shuffled_indexes(seed: &[u8; 32], n: usize) -> Vec<usize> {
    let mut out: Vec<usize> = (0..n).collect();
    if n <= 1 {
        return out;
    }

    // Fisher-Yates shuffle using a counter-based hash PRNG.
    for i in (1..n).rev() {
        let r = prng_u64(seed, i as u64);
        let j = (r % ((i + 1) as u64)) as usize;
        out.swap(i, j);
    }
    out
}

fn prng_u64(seed: &[u8; 32], counter: u64) -> u64 {
    let mut h = Sha256::new();
    h.update(seed);
    h.update(counter.to_le_bytes());
    let digest: [u8; 32] = h.finalize().into();
    u64::from_le_bytes(digest[..8].try_into().expect("slice length"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_repo::types::compute_source_id;

    #[test]
    fn schedule_is_deterministic() {
        let client = Id32([1u8; 32]);
        let block = Id32([2u8; 32]);
        let sources = vec![
            compute_source_id(b"a"),
            compute_source_id(b"b"),
            compute_source_id(b"c"),
            compute_source_id(b"d"),
        ];

        let o1 = schedule_sources_for_block(&client, &block, 0, &sources);
        let o2 = schedule_sources_for_block(&client, &block, 0, &sources);
        assert_eq!(o1, o2);
        assert_eq!(o1.len(), sources.len());
    }

    #[test]
    fn schedule_changes_with_attempt() {
        let client = Id32([1u8; 32]);
        let block = Id32([2u8; 32]);
        let sources = vec![
            compute_source_id(b"a"),
            compute_source_id(b"b"),
            compute_source_id(b"c"),
            compute_source_id(b"d"),
        ];

        let o1 = schedule_sources_for_block(&client, &block, 0, &sources);
        let o2 = schedule_sources_for_block(&client, &block, 1, &sources);
        assert_ne!(o1, o2);
    }
}
