use mprd_core::crypto::{TokenSigningKey, TokenVerifyingKey};
use mprd_core::hash;
use mprd_core::{CandidateAction, Hash32, MprdError, MAX_CANDIDATES};
use serde::{Deserialize, Serialize};

pub type Hash32Bytes = [u8; 32];

pub mod domains {
    pub const MODEL_VERSION_ID_V1: &[u8] = b"MPRD_MODEL_VERSION_ID_V1";
    pub const MODEL_CHALLENGE_ID_V1: &[u8] = b"MPRD_MODEL_CHALLENGE_ID_V1";
    pub const MODEL_CHALLENGE_SET_V1: &[u8] = b"MPRD_MODEL_CHALLENGE_SET_V1";
    pub const MODEL_OUTPUTS_BYTES_V1: &[u8] = b"MPRD_MODEL_OUTPUTS_BYTES_V1";
    pub const MODEL_OUTPUT_COMMIT_V1: &[u8] = b"MPRD_MODEL_OUTPUT_COMMIT_V1";
    pub const VALIDATOR_REPORT_BYTES_V1: &[u8] = b"MPRD_VALIDATOR_REPORT_BYTES_V1";
    pub const VALIDATOR_REPORT_COMMIT_V1: &[u8] = b"MPRD_VALIDATOR_REPORT_COMMIT_V1";
    pub const ROUTER_SEED_V1: &[u8] = b"MPRD_ROUTER_SEED_V1";
    pub const MODELS_MARKET_SNAPSHOT_BYTES_V1: &[u8] = b"MPRD_MODELS_MARKET_SNAPSHOT_BYTES_V1";
    pub const MODELS_MARKET_SNAPSHOT_SIG_V1: &[u8] = b"MPRD_MODELS_MARKET_SNAPSHOT_SIG_V1";
    pub const MODELS_MARKET_SNAPSHOT_HASH_V1: &[u8] = b"MPRD_MODELS_MARKET_SNAPSHOT_HASH_V1";
    pub const MODELS_MARKET_CHECKPOINT_BYTES_V1: &[u8] = b"MPRD_MODELS_MARKET_CHECKPOINT_BYTES_V1";
    pub const MODELS_MARKET_CHECKPOINT_SIG_V1: &[u8] = b"MPRD_MODELS_MARKET_CHECKPOINT_SIG_V1";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarketError {
    ChallengeCountMismatch,
    TooManyCandidates { got: usize, max: usize },
    ReportTooManyEntries { got: usize, max: usize },
    ReportNotSortedOrHasDuplicates,
    InvalidTrimBps { got: u16 },
    Overflow,
    UnsupportedSnapshotVersion,
    SnapshotMinersNotCanonical,
    UnsupportedCheckpointVersion,
}

fn hash_domain_bytes(domain: &[u8], data: &[u8]) -> Hash32Bytes {
    hash::sha256_domain(domain, data).0
}

fn u32_le(x: u32) -> [u8; 4] {
    x.to_le_bytes()
}

fn u64_le(x: u64) -> [u8; 8] {
    x.to_le_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StatePrivacyModeTagV1 {
    PublicState = 0,
    RedactedState = 1,
    SyntheticState = 2,
    LocalOnly = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelVersionV1 {
    pub weights_hash: Hash32Bytes,
    pub code_hash: Hash32Bytes,
    pub prompt_template_hash: Hash32Bytes,
    pub inference_params_hash: Hash32Bytes,
    pub output_schema_hash: Hash32Bytes,
}

impl ModelVersionV1 {
    pub fn new(
        weights_hash: Hash32Bytes,
        code_hash: Hash32Bytes,
        prompt_template_hash: Option<Hash32Bytes>,
        inference_params_hash: Option<Hash32Bytes>,
        output_schema_hash: Hash32Bytes,
    ) -> Self {
        Self {
            weights_hash,
            code_hash,
            prompt_template_hash: prompt_template_hash.unwrap_or([0u8; 32]),
            inference_params_hash: inference_params_hash.unwrap_or([0u8; 32]),
            output_schema_hash,
        }
    }

    pub fn model_version_id(&self) -> Hash32Bytes {
        let mut buf = Vec::with_capacity(32 * 5);
        buf.extend_from_slice(&self.weights_hash);
        buf.extend_from_slice(&self.code_hash);
        buf.extend_from_slice(&self.prompt_template_hash);
        buf.extend_from_slice(&self.inference_params_hash);
        buf.extend_from_slice(&self.output_schema_hash);
        hash_domain_bytes(domains::MODEL_VERSION_ID_V1, &buf)
    }
}

pub fn challenge_id_v1(
    epoch_id: u64,
    challenge_index: u32,
    state_privacy_mode_tag: StatePrivacyModeTagV1,
    state_ref_hash: Hash32Bytes,
    scoring_harness_hash: Hash32Bytes,
    scoring_params_hash: Hash32Bytes,
) -> Hash32Bytes {
    let mut buf = Vec::with_capacity(8 + 4 + 1 + 32 + 32 + 32);
    buf.extend_from_slice(&u64_le(epoch_id));
    buf.extend_from_slice(&u32_le(challenge_index));
    buf.push(state_privacy_mode_tag as u8);
    buf.extend_from_slice(&state_ref_hash);
    buf.extend_from_slice(&scoring_harness_hash);
    buf.extend_from_slice(&scoring_params_hash);
    hash_domain_bytes(domains::MODEL_CHALLENGE_ID_V1, &buf)
}

pub fn challenge_set_hash_v1(epoch_id: u64, challenge_ids: &[Hash32Bytes]) -> Hash32Bytes {
    let mut buf = Vec::with_capacity(8 + 4 + 32 * challenge_ids.len());
    buf.extend_from_slice(&u64_le(epoch_id));
    buf.extend_from_slice(&u32_le(challenge_ids.len() as u32));
    for id in challenge_ids {
        buf.extend_from_slice(id);
    }
    hash_domain_bytes(domains::MODEL_CHALLENGE_SET_V1, &buf)
}

/// Canonical outputs encoding (used for commit/reveal).
///
/// Layout (little-endian):
/// - `u32 K`
/// - for each `j`:
///   - `challenge_id[j]` (32 bytes)
///   - `u32 n`
///   - for each candidate:
///     - `u32 len`
///     - `candidate_preimage_v1` bytes (exactly `len`)
pub fn encode_outputs_v1(
    challenge_ids: &[Hash32Bytes],
    outputs: &[Vec<CandidateAction>],
) -> Result<Vec<u8>, MarketError> {
    if challenge_ids.len() != outputs.len() {
        return Err(MarketError::ChallengeCountMismatch);
    }

    let mut buf = Vec::new();
    buf.extend_from_slice(&u32_le(outputs.len() as u32));
    for (challenge_id, candidates) in challenge_ids.iter().zip(outputs.iter()) {
        buf.extend_from_slice(challenge_id);
        if candidates.len() > MAX_CANDIDATES {
            return Err(MarketError::TooManyCandidates {
                got: candidates.len(),
                max: MAX_CANDIDATES,
            });
        }
        buf.extend_from_slice(&u32_le(candidates.len() as u32));
        for c in candidates {
            let preimage = hash::candidate_hash_preimage(c);
            buf.extend_from_slice(&u32_le(preimage.len() as u32));
            buf.extend_from_slice(&preimage);
        }
    }
    Ok(buf)
}

pub fn outputs_bytes_hash_v1(encoded_outputs: &[u8]) -> Hash32Bytes {
    hash_domain_bytes(domains::MODEL_OUTPUTS_BYTES_V1, encoded_outputs)
}

pub fn model_output_commit_v1(
    epoch_id: u64,
    challenge_set_hash: Hash32Bytes,
    model_version_id: Hash32Bytes,
    outputs_bytes_hash: Hash32Bytes,
    nonce_m: Hash32Bytes,
) -> Hash32Bytes {
    let mut buf = Vec::with_capacity(8 + 32 + 32 + 32 + 32);
    buf.extend_from_slice(&u64_le(epoch_id));
    buf.extend_from_slice(&challenge_set_hash);
    buf.extend_from_slice(&model_version_id);
    buf.extend_from_slice(&outputs_bytes_hash);
    buf.extend_from_slice(&nonce_m);
    hash_domain_bytes(domains::MODEL_OUTPUT_COMMIT_V1, &buf)
}

/// Canonical validator report bytes.
///
/// Layout (little-endian):
/// - `u32 num_entries`
/// - for each entry sorted by `miner_pubkey` bytes ascending:
///   - `miner_pubkey` (32 bytes)
///   - `i64 score` (little-endian)
pub fn encode_validator_report_v1(
    entries_sorted_unique: &[(Hash32Bytes, i64)],
    max_entries: usize,
) -> Result<Vec<u8>, MarketError> {
    if entries_sorted_unique.len() > max_entries {
        return Err(MarketError::ReportTooManyEntries {
            got: entries_sorted_unique.len(),
            max: max_entries,
        });
    }

    for w in entries_sorted_unique.windows(2) {
        if w[0].0 >= w[1].0 {
            return Err(MarketError::ReportNotSortedOrHasDuplicates);
        }
    }

    let mut buf = Vec::with_capacity(4 + entries_sorted_unique.len() * (32 + 8));
    buf.extend_from_slice(&u32_le(entries_sorted_unique.len() as u32));
    for (miner_pubkey, score) in entries_sorted_unique {
        buf.extend_from_slice(miner_pubkey);
        buf.extend_from_slice(&score.to_le_bytes());
    }
    Ok(buf)
}

pub fn validator_report_bytes_hash_v1(report_bytes: &[u8]) -> Hash32Bytes {
    hash_domain_bytes(domains::VALIDATOR_REPORT_BYTES_V1, report_bytes)
}

pub fn validator_report_commit_v1(
    epoch_id: u64,
    challenge_set_hash: Hash32Bytes,
    report_bytes_hash: Hash32Bytes,
    nonce_v: Hash32Bytes,
) -> Hash32Bytes {
    let mut buf = Vec::with_capacity(8 + 32 + 32 + 32);
    buf.extend_from_slice(&u64_le(epoch_id));
    buf.extend_from_slice(&challenge_set_hash);
    buf.extend_from_slice(&report_bytes_hash);
    buf.extend_from_slice(&nonce_v);
    hash_domain_bytes(domains::VALIDATOR_REPORT_COMMIT_V1, &buf)
}

pub fn router_seed_v1(policy_hash: Hash32, state_hash: Hash32, epoch_id: u64) -> Hash32Bytes {
    let mut buf = Vec::with_capacity(32 + 32 + 8);
    buf.extend_from_slice(&policy_hash.0);
    buf.extend_from_slice(&state_hash.0);
    buf.extend_from_slice(&u64_le(epoch_id));
    hash_domain_bytes(domains::ROUTER_SEED_V1, &buf)
}

/// Deterministic Fisher–Yates shuffle, using SHA-256 as a PRF:
/// `j = u64_le(H(seed || u32_le(i))[0..8]) % (i+1)`.
pub fn deterministic_shuffle_v1<T>(items: &mut [T], seed: Hash32Bytes) {
    for i in (1..items.len()).rev() {
        let mut buf = Vec::with_capacity(32 + 4);
        buf.extend_from_slice(&seed);
        buf.extend_from_slice(&u32_le(i as u32));
        let h = hash::sha256(&buf).0;
        let mut eight = [0u8; 8];
        eight.copy_from_slice(&h[0..8]);
        let r = u64::from_le_bytes(eight);
        let j = (r % ((i + 1) as u64)) as usize;
        items.swap(i, j);
    }
}

// =============================================================================
// Score aggregation helpers (off-chain v0.1)
// =============================================================================

/// Maximum trimming parameter (basis points) accepted by `weighted_trimmed_mean_i64_v1`.
///
/// Trimming removes `trim_bps/10_000` of total weight from *each* side, so it must be `< 50%`.
pub const MAX_TRIM_BPS_V1: u16 = 4900;

fn integer_sqrt_u128_floor(x: u128) -> u64 {
    // sqrt(u128::MAX) < 2^64, so u64 is sufficient.
    let mut lo: u64 = 0;
    let mut hi: u64 = u64::MAX;
    while lo < hi {
        // Upper-mid without overflow: `lo + ceil((hi-lo)/2)`.
        let diff = hi - lo;
        let mid = lo + (diff / 2) + (diff % 2);
        let mid_sq = (mid as u128) * (mid as u128);
        if mid_sq <= x {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

/// Stake → weight mapping used for score aggregation (default: `sqrt(stake)`).
pub fn stake_weight_sqrt_v1(stake: u128) -> u64 {
    integer_sqrt_u128_floor(stake).max(1)
}

/// Deterministic weighted trimmed mean aggregation for `i64` scores.
///
/// - `samples`: `(score, weight)` pairs (weights are integer).
/// - `trim_bps`: basis points trimmed from each side by total weight (0..=4900).
///
/// Returns 0 when no weight remains after trimming.
pub fn weighted_trimmed_mean_i64_v1(
    samples: &[(i64, u64)],
    trim_bps: u16,
) -> Result<i64, MarketError> {
    if trim_bps > MAX_TRIM_BPS_V1 {
        return Err(MarketError::InvalidTrimBps { got: trim_bps });
    }

    let mut items: Vec<(i64, u64)> = samples.iter().copied().filter(|(_, w)| *w > 0).collect();
    if items.is_empty() {
        return Ok(0);
    }
    items.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    let total_weight: u128 = items.iter().map(|(_, w)| *w as u128).sum();
    let trim_each: u128 = (total_weight * (trim_bps as u128)) / 10_000u128;
    let mut left_trim = trim_each;
    let mut right_trim = trim_each;

    // Trim left by weight.
    let mut left_idx = 0usize;
    while left_idx < items.len() && left_trim > 0 {
        let (score, w) = items[left_idx];
        let w_u = w as u128;
        if w_u <= left_trim {
            left_trim -= w_u;
            left_idx += 1;
        } else {
            let remaining = (w_u - left_trim) as u64;
            items[left_idx] = (score, remaining);
            left_trim = 0;
        }
    }

    // Trim right by weight.
    let mut right_idx = items.len();
    while right_idx > left_idx && right_trim > 0 {
        let (score, w) = items[right_idx - 1];
        let w_u = w as u128;
        if w_u <= right_trim {
            right_trim -= w_u;
            right_idx -= 1;
        } else {
            let remaining = (w_u - right_trim) as u64;
            items[right_idx - 1] = (score, remaining);
            right_trim = 0;
        }
    }

    if left_idx >= right_idx {
        return Ok(0);
    }

    let mut sum: i128 = 0;
    let mut kept_weight: u128 = 0;
    for (score, w) in &items[left_idx..right_idx] {
        let term = (*score as i128)
            .checked_mul(*w as i128)
            .ok_or(MarketError::Overflow)?;
        sum = sum.checked_add(term).ok_or(MarketError::Overflow)?;
        kept_weight = kept_weight
            .checked_add(*w as u128)
            .ok_or(MarketError::Overflow)?;
    }
    if kept_weight == 0 {
        return Ok(0);
    }
    Ok((sum / (kept_weight as i128)) as i64)
}

// =============================================================================
// Models market score snapshots (off-chain v0.1)
// =============================================================================

/// Signed snapshot schema version.
pub const MODELS_MARKET_SNAPSHOT_VERSION_V1: u32 = 1;
pub const MODELS_MARKET_CHECKPOINT_VERSION_V1: u32 = 1;

/// Maximum miners included in a single snapshot (DoS bound).
pub const MAX_SNAPSHOT_MINERS_V1: usize = 4096;

/// Maximum endpoint URL length allowed in a snapshot (DoS bound).
pub const MAX_ENDPOINT_URL_BYTES_V1: usize = 512;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MinerScoreEntryV1 {
    /// Miner identity (32 bytes). Interpretation depends on deployment.
    pub miner_pubkey: Hash32Bytes,
    /// Current model version being served.
    pub model_version_id: Hash32Bytes,
    /// Routing endpoint (e.g., HTTPS base URL for proposer API).
    pub endpoint: String,
    /// Aggregated score for this miner (fixed-point i64; scale pinned by deployment).
    pub score: i64,
}

/// Unsigned score snapshot. This is what signers attest to.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelsMarketSnapshotV1 {
    pub snapshot_version: u32,
    /// Monotonic epoch id of the market (not necessarily a chain epoch).
    pub epoch_id: u64,
    /// Challenge set binding for this epoch (prevents equivocation about evaluation workload).
    pub challenge_set_hash: Hash32Bytes,
    /// Optional deployment-defined scope id (e.g., a chain id or market instance id).
    pub scope_id: Hash32Bytes,
    /// Sorted, canonical list of miner entries.
    pub miners: Vec<MinerScoreEntryV1>,
}

impl ModelsMarketSnapshotV1 {
    pub fn signing_bytes_v1(&self) -> Result<Vec<u8>, MarketError> {
        if self.snapshot_version != MODELS_MARKET_SNAPSHOT_VERSION_V1 {
            return Err(MarketError::UnsupportedSnapshotVersion);
        }

        if self.miners.len() > MAX_SNAPSHOT_MINERS_V1 {
            return Err(MarketError::ReportTooManyEntries {
                got: self.miners.len(),
                max: MAX_SNAPSHOT_MINERS_V1,
            });
        }

        // Fail-closed: require already canonical (sorted by miner_pubkey, unique).
        let mut miners = self.miners.clone();
        miners.sort_by(|a, b| a.miner_pubkey.cmp(&b.miner_pubkey));
        if miners != self.miners {
            return Err(MarketError::SnapshotMinersNotCanonical);
        }
        for w in self.miners.windows(2) {
            if w[0].miner_pubkey >= w[1].miner_pubkey {
                return Err(MarketError::SnapshotMinersNotCanonical);
            }
        }
        for m in &self.miners {
            if m.endpoint.is_empty() || m.endpoint.len() > MAX_ENDPOINT_URL_BYTES_V1 {
                return Err(MarketError::SnapshotMinersNotCanonical);
            }
        }

        let mut out = Vec::new();
        out.extend_from_slice(domains::MODELS_MARKET_SNAPSHOT_BYTES_V1);
        out.extend_from_slice(&self.snapshot_version.to_le_bytes());
        out.extend_from_slice(&self.epoch_id.to_le_bytes());
        out.extend_from_slice(&self.challenge_set_hash);
        out.extend_from_slice(&self.scope_id);
        out.extend_from_slice(&(self.miners.len() as u32).to_le_bytes());
        for m in &self.miners {
            out.extend_from_slice(&m.miner_pubkey);
            out.extend_from_slice(&m.model_version_id);
            out.extend_from_slice(&m.score.to_le_bytes());
            out.extend_from_slice(&(m.endpoint.len() as u32).to_le_bytes());
            out.extend_from_slice(m.endpoint.as_bytes());
        }
        Ok(out)
    }

    pub fn snapshot_hash_v1(&self) -> Result<Hash32Bytes, MarketError> {
        let bytes = self.signing_bytes_v1()?;
        Ok(hash_domain_bytes(
            domains::MODELS_MARKET_SNAPSHOT_HASH_V1,
            &bytes,
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedModelsMarketSnapshotV1 {
    pub snapshot: ModelsMarketSnapshotV1,
    pub signed_at_ms: i64,
    /// Public key used to sign this snapshot (ed25519).
    pub signer_pubkey: [u8; 32],
    /// Signature over `MODELS_MARKET_SNAPSHOT_SIG_V1 || signing_bytes_v1 || signed_at_ms`.
    pub signature: Vec<u8>,
}

impl SignedModelsMarketSnapshotV1 {
    pub fn signing_bytes_v1(&self) -> Result<Vec<u8>, MarketError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(domains::MODELS_MARKET_SNAPSHOT_SIG_V1);
        bytes.extend_from_slice(&self.signed_at_ms.to_le_bytes());
        bytes.extend_from_slice(&self.snapshot.signing_bytes_v1()?);
        Ok(bytes)
    }

    pub fn verify_with_key(&self, vk: &TokenVerifyingKey) -> Result<(), MprdError> {
        if vk.to_bytes() != self.signer_pubkey {
            return Err(MprdError::SignatureInvalid(
                "models_market snapshot signer_pubkey does not match expected key".into(),
            ));
        }
        let msg = self
            .signing_bytes_v1()
            .map_err(|e| MprdError::InvalidInput(format!("invalid snapshot: {:?}", e)))?;
        vk.verify_bytes(&msg, &self.signature)?;
        Ok(())
    }

    pub fn sign(
        signing_key: &TokenSigningKey,
        signed_at_ms: i64,
        mut snapshot: ModelsMarketSnapshotV1,
    ) -> Result<Self, MprdError> {
        // Canonicalize miner ordering (fail-closed at signing time).
        snapshot
            .miners
            .sort_by(|a, b| a.miner_pubkey.cmp(&b.miner_pubkey));
        snapshot.snapshot_version = MODELS_MARKET_SNAPSHOT_VERSION_V1;

        let tmp = SignedModelsMarketSnapshotV1 {
            snapshot,
            signed_at_ms,
            signer_pubkey: signing_key.verifying_key().to_bytes(),
            signature: Vec::new(),
        };
        let msg = tmp
            .signing_bytes_v1()
            .map_err(|e| MprdError::InvalidInput(format!("invalid snapshot: {:?}", e)))?;
        let sig = signing_key.sign_bytes(&msg);
        Ok(SignedModelsMarketSnapshotV1 {
            signature: sig.to_vec(),
            ..tmp
        })
    }
}

/// A signed checkpoint over a specific snapshot hash, with optional hash-chaining.
///
/// This is useful for pre-testnet deployments (Option A) to reduce equivocation by publishing
/// checkpoint hashes to any public, append-only medium (git commits, web pages, etc.), and later
/// reusing the same commitment format for on-chain anchoring (Option B).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelsMarketCheckpointV1 {
    pub checkpoint_version: u32,
    pub epoch_id: u64,
    pub scope_id: Hash32Bytes,
    pub snapshot_hash: Hash32Bytes,
    /// Previous checkpoint hash (or `[0;32]` for genesis).
    pub prev_checkpoint_hash: Hash32Bytes,
}

impl ModelsMarketCheckpointV1 {
    pub fn bytes_v1(&self) -> Result<Vec<u8>, MarketError> {
        if self.checkpoint_version != MODELS_MARKET_CHECKPOINT_VERSION_V1 {
            return Err(MarketError::UnsupportedCheckpointVersion);
        }

        let mut out = Vec::with_capacity(32 + 4 + 8 + 32 + 32 + 32);
        out.extend_from_slice(domains::MODELS_MARKET_CHECKPOINT_BYTES_V1);
        out.extend_from_slice(&self.checkpoint_version.to_le_bytes());
        out.extend_from_slice(&self.epoch_id.to_le_bytes());
        out.extend_from_slice(&self.scope_id);
        out.extend_from_slice(&self.snapshot_hash);
        out.extend_from_slice(&self.prev_checkpoint_hash);
        Ok(out)
    }

    pub fn checkpoint_hash_v1(&self) -> Result<Hash32Bytes, MarketError> {
        Ok(hash::sha256(&self.bytes_v1()?).0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedModelsMarketCheckpointV1 {
    pub checkpoint: ModelsMarketCheckpointV1,
    pub signed_at_ms: i64,
    pub signer_pubkey: [u8; 32],
    pub signature: Vec<u8>,
}

impl SignedModelsMarketCheckpointV1 {
    pub fn signing_bytes_v1(&self) -> Result<Vec<u8>, MarketError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(domains::MODELS_MARKET_CHECKPOINT_SIG_V1);
        bytes.extend_from_slice(&self.signed_at_ms.to_le_bytes());
        bytes.extend_from_slice(&self.checkpoint.bytes_v1()?);
        Ok(bytes)
    }

    pub fn verify_with_key(&self, vk: &TokenVerifyingKey) -> Result<(), MprdError> {
        if vk.to_bytes() != self.signer_pubkey {
            return Err(MprdError::SignatureInvalid(
                "models_market checkpoint signer_pubkey does not match expected key".into(),
            ));
        }
        let msg = self
            .signing_bytes_v1()
            .map_err(|e| MprdError::InvalidInput(format!("invalid checkpoint: {:?}", e)))?;
        vk.verify_bytes(&msg, &self.signature)?;
        Ok(())
    }

    pub fn sign(
        signing_key: &TokenSigningKey,
        signed_at_ms: i64,
        checkpoint: ModelsMarketCheckpointV1,
    ) -> Result<Self, MprdError> {
        let tmp = SignedModelsMarketCheckpointV1 {
            checkpoint,
            signed_at_ms,
            signer_pubkey: signing_key.verifying_key().to_bytes(),
            signature: Vec::new(),
        };
        let msg = tmp
            .signing_bytes_v1()
            .map_err(|e| MprdError::InvalidInput(format!("invalid checkpoint: {:?}", e)))?;
        let sig = signing_key.sign_bytes(&msg);
        Ok(SignedModelsMarketCheckpointV1 {
            signature: sig.to_vec(),
            ..tmp
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mprd_core::{Score, Value};
    use proptest::prelude::*;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
    use std::collections::HashMap;

    fn rand_hash(rng: &mut StdRng) -> Hash32Bytes {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        b
    }

    #[test]
    fn model_version_id_is_deterministic() {
        let mut rng = StdRng::seed_from_u64(1);
        let mv = ModelVersionV1::new(
            rand_hash(&mut rng),
            rand_hash(&mut rng),
            None,
            None,
            rand_hash(&mut rng),
        );
        assert_eq!(mv.model_version_id(), mv.model_version_id());
    }

    #[test]
    fn challenge_set_hash_binds_epoch_and_order() {
        let mut rng = StdRng::seed_from_u64(2);
        let a = rand_hash(&mut rng);
        let b = rand_hash(&mut rng);
        let h1 = challenge_set_hash_v1(1, &[a, b]);
        let h2 = challenge_set_hash_v1(2, &[a, b]);
        let h3 = challenge_set_hash_v1(1, &[b, a]);
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn encode_outputs_rejects_too_many_candidates() {
        let mut rng = StdRng::seed_from_u64(3);
        let challenge_ids = vec![rand_hash(&mut rng)];
        let mut candidates = Vec::new();
        for _ in 0..(MAX_CANDIDATES + 1) {
            candidates.push(CandidateAction {
                action_type: "x".into(),
                params: HashMap::new(),
                score: Score(0),
                candidate_hash: Hash32([0u8; 32]),
            });
        }
        let err = encode_outputs_v1(&challenge_ids, &[candidates]).unwrap_err();
        assert!(matches!(err, MarketError::TooManyCandidates { .. }));
    }

    #[test]
    fn output_commit_changes_if_nonce_changes() {
        let epoch_id = 7u64;
        let challenge_set_hash = [1u8; 32];
        let model_version_id = [2u8; 32];
        let outputs_bytes_hash = [3u8; 32];
        let c1 = model_output_commit_v1(
            epoch_id,
            challenge_set_hash,
            model_version_id,
            outputs_bytes_hash,
            [9u8; 32],
        );
        let c2 = model_output_commit_v1(
            epoch_id,
            challenge_set_hash,
            model_version_id,
            outputs_bytes_hash,
            [8u8; 32],
        );
        assert_ne!(c1, c2);
    }

    #[test]
    fn report_encoding_requires_sorted_unique() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let ok = encode_validator_report_v1(&[(a, 1), (b, 2)], 10).expect("ok");
        assert!(!ok.is_empty());

        let dup = encode_validator_report_v1(&[(a, 1), (a, 2)], 10).unwrap_err();
        assert!(matches!(dup, MarketError::ReportNotSortedOrHasDuplicates));

        let unsorted = encode_validator_report_v1(&[(b, 2), (a, 1)], 10).unwrap_err();
        assert!(matches!(
            unsorted,
            MarketError::ReportNotSortedOrHasDuplicates
        ));
    }

    #[test]
    fn deterministic_shuffle_is_stable() {
        let seed = [7u8; 32];
        let mut items = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
        deterministic_shuffle_v1(&mut items, seed);
        assert_eq!(items, vec![1, 5, 3, 0, 7, 6, 4, 2]);
    }

    #[test]
    fn stake_weight_never_panics_on_extremes() {
        assert_eq!(stake_weight_sqrt_v1(0), 1);
        assert!(stake_weight_sqrt_v1(u128::MAX) > 0);
    }

    proptest! {
        #[test]
        fn integer_sqrt_floor_is_correct(x in any::<u128>()) {
            let r = integer_sqrt_u128_floor(x);
            let r_sq = (r as u128) * (r as u128);
            prop_assert!(r_sq <= x);

            let rp1 = (r as u128) + 1;
            let next_sq = rp1.checked_mul(rp1);
            if let Some(next_sq) = next_sq {
                prop_assert!(next_sq > x);
            } else {
                // (r+1)^2 overflowed u128; that can only happen at the top boundary,
                // so it is necessarily > x.
                prop_assert!(true);
            }
        }
    }

    #[test]
    fn weighted_trimmed_mean_is_deterministic() {
        let samples = vec![(10i64, 2u64), (20i64, 2u64), (30i64, 2u64)];
        let a = weighted_trimmed_mean_i64_v1(&samples, 0).expect("ok");
        let b = weighted_trimmed_mean_i64_v1(&samples, 0).expect("ok");
        assert_eq!(a, b);
    }

    #[test]
    fn weighted_trimmed_mean_trims_outlier() {
        // Total weight = 100. Trim 10% from each side => drop 10 weight from low/high.
        // Outlier has weight 10, so it should be trimmed away.
        let samples = vec![(0i64, 10u64), (100i64, 80u64), (10_000i64, 10u64)];
        let mean = weighted_trimmed_mean_i64_v1(&samples, 1000).expect("ok");
        assert_eq!(mean, 100);
    }

    #[test]
    fn weighted_trimmed_mean_rejects_invalid_trim() {
        let samples = vec![(1i64, 1u64)];
        let err = weighted_trimmed_mean_i64_v1(&samples, 5000).unwrap_err();
        assert!(matches!(err, MarketError::InvalidTrimBps { .. }));
    }

    #[test]
    fn outputs_encoding_is_deterministic_for_same_candidate_preimages() {
        let challenge_id = [9u8; 32];
        let c = CandidateAction {
            action_type: "transfer".into(),
            params: HashMap::from([("amount".into(), Value::UInt(1))]),
            score: Score(10),
            candidate_hash: Hash32([0u8; 32]),
        };
        let b1 = encode_outputs_v1(&[challenge_id], &[vec![c.clone()]]).expect("encode");
        let b2 = encode_outputs_v1(&[challenge_id], &[vec![c]]).expect("encode");
        assert_eq!(b1, b2);
        assert_eq!(outputs_bytes_hash_v1(&b1), outputs_bytes_hash_v1(&b2));
    }

    #[test]
    fn signed_snapshot_roundtrip() {
        let sk = TokenSigningKey::from_seed(&[7u8; 32]);
        let vk = sk.verifying_key();
        let snapshot = ModelsMarketSnapshotV1 {
            snapshot_version: MODELS_MARKET_SNAPSHOT_VERSION_V1,
            epoch_id: 7,
            challenge_set_hash: [1u8; 32],
            scope_id: [2u8; 32],
            miners: vec![MinerScoreEntryV1 {
                miner_pubkey: [9u8; 32],
                model_version_id: [8u8; 32],
                endpoint: "https://example.com".into(),
                score: 123,
            }],
        };
        let signed = SignedModelsMarketSnapshotV1::sign(&sk, 999, snapshot).expect("sign");
        signed.verify_with_key(&vk).expect("verify");
    }

    #[test]
    fn snapshot_hash_is_deterministic() {
        let snapshot = ModelsMarketSnapshotV1 {
            snapshot_version: MODELS_MARKET_SNAPSHOT_VERSION_V1,
            epoch_id: 7,
            challenge_set_hash: [1u8; 32],
            scope_id: [2u8; 32],
            miners: vec![MinerScoreEntryV1 {
                miner_pubkey: [9u8; 32],
                model_version_id: [8u8; 32],
                endpoint: "https://example.com".into(),
                score: 123,
            }],
        };
        assert_eq!(
            snapshot.snapshot_hash_v1().expect("h1"),
            snapshot.snapshot_hash_v1().expect("h2")
        );
    }

    #[test]
    fn signed_checkpoint_roundtrip() {
        let sk = TokenSigningKey::from_seed(&[9u8; 32]);
        let vk = sk.verifying_key();
        let checkpoint = ModelsMarketCheckpointV1 {
            checkpoint_version: MODELS_MARKET_CHECKPOINT_VERSION_V1,
            epoch_id: 7,
            scope_id: [2u8; 32],
            snapshot_hash: [3u8; 32],
            prev_checkpoint_hash: [0u8; 32],
        };
        let signed = SignedModelsMarketCheckpointV1::sign(&sk, 111, checkpoint).expect("sign");
        signed.verify_with_key(&vk).expect("verify");
    }
}
