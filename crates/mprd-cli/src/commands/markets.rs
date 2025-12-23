//! Models market CLI utilities (build/sign/verify/checkpoint).

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

use mprd_core::{TokenSigningKey, TokenVerifyingKey};
use mprd_models_market::{
    challenge_set_hash_v1, encode_validator_report_v1, stake_weight_sqrt_v1,
    validator_report_bytes_hash_v1, validator_report_commit_v1, weighted_trimmed_mean_i64_v1,
    MinerScoreEntryV1, ModelsMarketCheckpointV1, ModelsMarketSnapshotV1,
    SignedModelsMarketCheckpointV1, SignedModelsMarketSnapshotV1, MAX_ENDPOINT_URL_BYTES_V1,
    MAX_SNAPSHOT_MINERS_V1, MAX_TRIM_BPS_V1, MODELS_MARKET_CHECKPOINT_VERSION_V1,
    MODELS_MARKET_SNAPSHOT_VERSION_V1,
};

#[derive(Debug, Error)]
enum BuildSnapshotError {
    #[error("trim_bps must be <= {max} (got {got})")]
    TrimBpsTooHigh { got: u16, max: u16 },
    #[error("too many miners: {got} (max {max})")]
    TooManyMiners { got: usize, max: usize },
    #[error("miners list must be sorted and unique by miner_pubkey (fail-closed)")]
    MinersNotSortedOrUnique,
    #[error("invalid miner endpoint (empty or too long) (fail-closed)")]
    InvalidMinerEndpoint,
    #[error("validator stake must be > 0 (fail-closed)")]
    ValidatorStakeZero,
    #[error("invalid validator report entries (fail-closed)")]
    InvalidValidatorReportEntries,
    #[error("report_bytes_hash mismatch (fail-closed)")]
    ReportBytesHashMismatch,
    #[error("report_commit requires nonce_v (fail-closed)")]
    ReportCommitMissingNonce,
    #[error("validator report_commit mismatch (fail-closed)")]
    ReportCommitMismatch,
    #[error("aggregation failed (fail-closed)")]
    AggregationFailed,
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_millis() as i64
}

fn parse_key_hex(hex_seed: &str) -> Result<TokenSigningKey> {
    TokenSigningKey::from_hex(hex_seed).context("invalid signing key hex (expected 32-byte seed)")
}

fn parse_vk_hex(hex_key: &str) -> Result<TokenVerifyingKey> {
    TokenVerifyingKey::from_hex(hex_key).context("invalid verifying key hex (expected 32 bytes)")
}

fn parse_hash32_hex(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).context("invalid hex")?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelsMarketEpochInputV1 {
    pub epoch_id: u64,
    pub scope_id: [u8; 32],
    pub challenge_ids: Vec<[u8; 32]>,
    pub miners: Vec<MinerRegistrationV1>,
    pub validator_reports: Vec<ValidatorReportRevealV1>,
    /// Optional default trimming parameter in basis points.
    pub trim_bps: Option<u16>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinerRegistrationV1 {
    pub miner_pubkey: [u8; 32],
    pub model_version_id: [u8; 32],
    pub endpoint: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorReportRevealV1 {
    pub validator_pubkey: [u8; 32],
    pub stake: u128,
    /// Entries MUST be sorted by miner_pubkey bytes ascending and unique.
    pub entries: Vec<ValidatorReportEntryV1>,
    /// Optional: if present, must match the canonical report bytes hash.
    pub report_bytes_hash: Option<[u8; 32]>,
    /// Optional: if present, commit must verify against `nonce_v` and report_bytes_hash.
    pub report_commit: Option<[u8; 32]>,
    pub nonce_v: Option<[u8; 32]>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorReportEntryV1 {
    pub miner_pubkey: [u8; 32],
    pub score: i64,
}

fn entry_lookup_score(entries_sorted: &[ValidatorReportEntryV1], miner_pubkey: [u8; 32]) -> i64 {
    match entries_sorted.binary_search_by(|e| e.miner_pubkey.cmp(&miner_pubkey)) {
        Ok(i) => entries_sorted[i].score,
        Err(_) => 0,
    }
}

fn build_snapshot_from_epoch_input(
    input: ModelsMarketEpochInputV1,
    trim_bps_override: Option<u16>,
) -> std::result::Result<ModelsMarketSnapshotV1, BuildSnapshotError> {
    let trim_bps = trim_bps_override.or(input.trim_bps).unwrap_or(0);
    if trim_bps > MAX_TRIM_BPS_V1 {
        return Err(BuildSnapshotError::TrimBpsTooHigh {
            got: trim_bps,
            max: MAX_TRIM_BPS_V1,
        });
    }
    if input.miners.len() > MAX_SNAPSHOT_MINERS_V1 {
        return Err(BuildSnapshotError::TooManyMiners {
            got: input.miners.len(),
            max: MAX_SNAPSHOT_MINERS_V1,
        });
    }

    let challenge_set_hash = challenge_set_hash_v1(input.epoch_id, &input.challenge_ids);

    let mut miners: Vec<MinerScoreEntryV1> = input
        .miners
        .into_iter()
        .map(|m| MinerScoreEntryV1 {
            miner_pubkey: m.miner_pubkey,
            model_version_id: m.model_version_id,
            endpoint: m.endpoint,
            score: 0,
        })
        .collect();

    miners.sort_by(|a, b| a.miner_pubkey.cmp(&b.miner_pubkey));
    for w in miners.windows(2) {
        if w[0].miner_pubkey >= w[1].miner_pubkey {
            return Err(BuildSnapshotError::MinersNotSortedOrUnique);
        }
    }
    for m in &miners {
        if m.endpoint.is_empty() || m.endpoint.len() > MAX_ENDPOINT_URL_BYTES_V1 {
            return Err(BuildSnapshotError::InvalidMinerEndpoint);
        }
    }

    let mut reports = Vec::with_capacity(input.validator_reports.len());
    for r in input.validator_reports {
        if r.stake == 0 {
            return Err(BuildSnapshotError::ValidatorStakeZero);
        }

        // Validate canonical ordering by encoding.
        let pairs: Vec<([u8; 32], i64)> = r
            .entries
            .iter()
            .map(|e| (e.miner_pubkey, e.score))
            .collect();
        let report_bytes = encode_validator_report_v1(&pairs, miners.len())
            .map_err(|_| BuildSnapshotError::InvalidValidatorReportEntries)?;
        let computed_hash = validator_report_bytes_hash_v1(&report_bytes);

        if let Some(expected_hash) = r.report_bytes_hash {
            if expected_hash != computed_hash {
                return Err(BuildSnapshotError::ReportBytesHashMismatch);
            }
        }

        if let Some(commit) = r.report_commit {
            let nonce_v = r
                .nonce_v
                .ok_or(BuildSnapshotError::ReportCommitMissingNonce)?;
            let expected = validator_report_commit_v1(
                input.epoch_id,
                challenge_set_hash,
                computed_hash,
                nonce_v,
            );
            if expected != commit {
                return Err(BuildSnapshotError::ReportCommitMismatch);
            }
        }

        reports.push((r.entries, stake_weight_sqrt_v1(r.stake)));
    }

    // Aggregate score per miner.
    let mut out_miners = Vec::with_capacity(miners.len());
    for m in miners {
        let mut samples: Vec<(i64, u64)> = Vec::with_capacity(reports.len());
        for (entries, weight) in &reports {
            let s = entry_lookup_score(entries, m.miner_pubkey);
            samples.push((s, *weight));
        }
        let agg = weighted_trimmed_mean_i64_v1(&samples, trim_bps)
            .map_err(|_| BuildSnapshotError::AggregationFailed)?;
        out_miners.push(MinerScoreEntryV1 { score: agg, ..m });
    }

    Ok(ModelsMarketSnapshotV1 {
        snapshot_version: MODELS_MARKET_SNAPSHOT_VERSION_V1,
        epoch_id: input.epoch_id,
        challenge_set_hash,
        scope_id: input.scope_id,
        miners: out_miners,
    })
}

pub fn build_snapshot(input: PathBuf, output: PathBuf, trim_bps: Option<u16>) -> Result<()> {
    let json = fs::read_to_string(&input)
        .with_context(|| format!("failed to read epoch input: {}", input.display()))?;
    let input: ModelsMarketEpochInputV1 =
        serde_json::from_str(&json).context("invalid models market epoch input JSON")?;

    let snapshot = build_snapshot_from_epoch_input(input, trim_bps)?;
    fs::write(&output, serde_json::to_vec_pretty(&snapshot)?)
        .with_context(|| format!("failed to write: {}", output.display()))?;
    Ok(())
}

pub fn step_epoch(
    input: PathBuf,
    signed_snapshot_out: PathBuf,
    signed_checkpoint_out: PathBuf,
    prev_checkpoint_hash_hex: String,
    signing_key_hex: String,
    trim_bps: Option<u16>,
) -> Result<()> {
    let json = fs::read_to_string(&input)
        .with_context(|| format!("failed to read epoch input: {}", input.display()))?;
    let input: ModelsMarketEpochInputV1 =
        serde_json::from_str(&json).context("invalid models market epoch input JSON")?;

    let snapshot = build_snapshot_from_epoch_input(input, trim_bps)?;
    let sk = parse_key_hex(&signing_key_hex)?;
    let signed_snapshot =
        SignedModelsMarketSnapshotV1::sign(&sk, now_ms(), snapshot).context("sign snapshot")?;

    let snapshot_hash = signed_snapshot
        .snapshot
        .snapshot_hash_v1()
        .map_err(|e| anyhow::anyhow!("failed to compute snapshot hash: {:?}", e))?;

    let checkpoint = ModelsMarketCheckpointV1 {
        checkpoint_version: MODELS_MARKET_CHECKPOINT_VERSION_V1,
        epoch_id: signed_snapshot.snapshot.epoch_id,
        scope_id: signed_snapshot.snapshot.scope_id,
        snapshot_hash,
        prev_checkpoint_hash: parse_hash32_hex(&prev_checkpoint_hash_hex)?,
    };
    let signed_checkpoint = SignedModelsMarketCheckpointV1::sign(&sk, now_ms(), checkpoint)
        .context("sign checkpoint")?;

    fs::write(
        &signed_snapshot_out,
        serde_json::to_vec_pretty(&signed_snapshot)?,
    )
    .with_context(|| format!("failed to write: {}", signed_snapshot_out.display()))?;
    fs::write(
        &signed_checkpoint_out,
        serde_json::to_vec_pretty(&signed_checkpoint)?,
    )
    .with_context(|| format!("failed to write: {}", signed_checkpoint_out.display()))?;
    Ok(())
}

pub fn sign_snapshot(input: PathBuf, output: PathBuf, signing_key_hex: String) -> Result<()> {
    let json = fs::read_to_string(&input)
        .with_context(|| format!("failed to read snapshot: {}", input.display()))?;
    let snapshot: ModelsMarketSnapshotV1 =
        serde_json::from_str(&json).context("invalid snapshot JSON")?;

    let sk = parse_key_hex(&signing_key_hex)?;
    let signed = SignedModelsMarketSnapshotV1::sign(&sk, now_ms(), snapshot)
        .context("failed to sign snapshot")?;

    fs::write(&output, serde_json::to_vec_pretty(&signed)?)
        .with_context(|| format!("failed to write: {}", output.display()))?;
    Ok(())
}

pub fn verify_snapshot(signed_snapshot: PathBuf, verifying_key_hex: String) -> Result<()> {
    let json = fs::read_to_string(&signed_snapshot)
        .with_context(|| format!("failed to read: {}", signed_snapshot.display()))?;
    let signed: SignedModelsMarketSnapshotV1 =
        serde_json::from_str(&json).context("invalid signed snapshot JSON")?;

    let vk = parse_vk_hex(&verifying_key_hex)?;
    signed
        .verify_with_key(&vk)
        .context("snapshot signature invalid")?;
    Ok(())
}

pub fn sign_checkpoint(
    signed_snapshot: PathBuf,
    output: PathBuf,
    signing_key_hex: String,
    prev_checkpoint_hash_hex: String,
) -> Result<()> {
    let json = fs::read_to_string(&signed_snapshot)
        .with_context(|| format!("failed to read: {}", signed_snapshot.display()))?;
    let signed: SignedModelsMarketSnapshotV1 =
        serde_json::from_str(&json).context("invalid signed snapshot JSON")?;

    let snapshot_hash = signed
        .snapshot
        .snapshot_hash_v1()
        .map_err(|e| anyhow::anyhow!("failed to compute snapshot hash: {:?}", e))?;

    let checkpoint = ModelsMarketCheckpointV1 {
        checkpoint_version: MODELS_MARKET_CHECKPOINT_VERSION_V1,
        epoch_id: signed.snapshot.epoch_id,
        scope_id: signed.snapshot.scope_id,
        snapshot_hash,
        prev_checkpoint_hash: parse_hash32_hex(&prev_checkpoint_hash_hex)?,
    };

    let sk = parse_key_hex(&signing_key_hex)?;
    let signed = SignedModelsMarketCheckpointV1::sign(&sk, now_ms(), checkpoint)
        .context("failed to sign checkpoint")?;

    fs::write(&output, serde_json::to_vec_pretty(&signed)?)
        .with_context(|| format!("failed to write: {}", output.display()))?;
    Ok(())
}

pub fn verify_checkpoint(
    signed_checkpoint: PathBuf,
    verifying_key_hex: String,
    expected_prev_checkpoint_hash_hex: Option<String>,
) -> Result<()> {
    let json = fs::read_to_string(&signed_checkpoint)
        .with_context(|| format!("failed to read: {}", signed_checkpoint.display()))?;
    let signed: SignedModelsMarketCheckpointV1 =
        serde_json::from_str(&json).context("invalid signed checkpoint JSON")?;

    let vk = parse_vk_hex(&verifying_key_hex)?;
    signed
        .verify_with_key(&vk)
        .context("checkpoint signature invalid")?;

    if let Some(expected) = expected_prev_checkpoint_hash_hex {
        let expected = parse_hash32_hex(&expected)?;
        if signed.checkpoint.prev_checkpoint_hash != expected {
            anyhow::bail!("prev_checkpoint_hash mismatch (fail-closed)");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn b32(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn build_snapshot_rejects_trim_bps_over_max() {
        let input = ModelsMarketEpochInputV1 {
            epoch_id: 1,
            scope_id: b32(1),
            challenge_ids: vec![b32(2)],
            miners: vec![MinerRegistrationV1 {
                miner_pubkey: b32(3),
                model_version_id: b32(4),
                endpoint: "https://example.com".to_string(),
            }],
            validator_reports: vec![ValidatorReportRevealV1 {
                validator_pubkey: b32(5),
                stake: 1,
                entries: vec![ValidatorReportEntryV1 {
                    miner_pubkey: b32(3),
                    score: 7,
                }],
                report_bytes_hash: None,
                report_commit: None,
                nonce_v: None,
            }],
            trim_bps: None,
        };

        let err = build_snapshot_from_epoch_input(input, Some(MAX_TRIM_BPS_V1 + 1))
            .expect_err("must reject");
        assert!(matches!(err, BuildSnapshotError::TrimBpsTooHigh { .. }));
    }

    #[test]
    fn build_snapshot_rejects_unsorted_or_duplicate_miner_pubkeys() {
        let miners = vec![
            MinerRegistrationV1 {
                miner_pubkey: b32(2),
                model_version_id: b32(9),
                endpoint: "https://a".to_string(),
            },
            MinerRegistrationV1 {
                miner_pubkey: b32(2),
                model_version_id: b32(9),
                endpoint: "https://b".to_string(),
            },
        ];

        let input = ModelsMarketEpochInputV1 {
            epoch_id: 1,
            scope_id: b32(1),
            challenge_ids: vec![b32(7)],
            miners,
            validator_reports: vec![ValidatorReportRevealV1 {
                validator_pubkey: b32(3),
                stake: 1,
                entries: vec![],
                report_bytes_hash: None,
                report_commit: None,
                nonce_v: None,
            }],
            trim_bps: Some(0),
        };

        let err = build_snapshot_from_epoch_input(input, None).expect_err("must reject");
        assert!(matches!(err, BuildSnapshotError::MinersNotSortedOrUnique));
    }

    #[test]
    fn build_snapshot_rejects_report_commit_without_nonce() {
        let miner_pubkey = b32(10);
        let input = ModelsMarketEpochInputV1 {
            epoch_id: 42,
            scope_id: b32(1),
            challenge_ids: vec![b32(2)],
            miners: vec![MinerRegistrationV1 {
                miner_pubkey,
                model_version_id: b32(3),
                endpoint: "https://example.com".to_string(),
            }],
            validator_reports: vec![ValidatorReportRevealV1 {
                validator_pubkey: b32(4),
                stake: 1,
                entries: vec![ValidatorReportEntryV1 {
                    miner_pubkey,
                    score: 1,
                }],
                report_bytes_hash: None,
                report_commit: Some([9u8; 32]),
                nonce_v: None,
            }],
            trim_bps: None,
        };

        let err = build_snapshot_from_epoch_input(input, None).expect_err("must reject");
        assert!(matches!(err, BuildSnapshotError::ReportCommitMissingNonce));
    }

    proptest! {
        #[test]
        fn build_snapshot_is_order_invariant_for_miners(
            miner_keys in proptest::collection::btree_set(any::<[u8; 32]>(), 1..20),
            epoch_id in 0u64..1_000,
            stake in 1u128..1_000_000,
        ) {
            let mut miner_keys: Vec<[u8; 32]> = miner_keys.into_iter().collect();

            // Build miners in a "shuffled" order (reverse), then rely on SUT sorting.
            let mut miners_rev = Vec::with_capacity(miner_keys.len());
            for k in miner_keys.iter().rev() {
                miners_rev.push(MinerRegistrationV1 {
                    miner_pubkey: *k,
                    model_version_id: [0u8; 32],
                    endpoint: "https://example.com".to_string(),
                });
            }

            // Use a validator report with a subset of entries, sorted/unique (required by encoder).
            miner_keys.sort();
            let pairs: Vec<ValidatorReportEntryV1> = miner_keys
                .iter()
                .take((miner_keys.len() / 2).max(1))
                .map(|k| ValidatorReportEntryV1 { miner_pubkey: *k, score: 1 })
                .collect();

            let input_a = ModelsMarketEpochInputV1 {
                epoch_id,
                scope_id: b32(1),
                challenge_ids: vec![b32(2), b32(3)],
                miners: miners_rev.clone(),
                validator_reports: vec![ValidatorReportRevealV1 {
                    validator_pubkey: b32(9),
                    stake,
                    entries: pairs.clone(),
                    report_bytes_hash: None,
                    report_commit: None,
                    nonce_v: None,
                }],
                trim_bps: None,
            };

            let input_b = ModelsMarketEpochInputV1 {
                miners: {
                    let mut ms = miners_rev;
                    ms.reverse();
                    ms
                },
                ..input_a.clone()
            };

            let snap_a = build_snapshot_from_epoch_input(input_a, None).expect("snapshot a");
            let snap_b = build_snapshot_from_epoch_input(input_b, None).expect("snapshot b");

            prop_assert_eq!(snap_a.challenge_set_hash, snap_b.challenge_set_hash);
            prop_assert_eq!(snap_a.scope_id, snap_b.scope_id);
            prop_assert_eq!(snap_a.miners.len(), snap_b.miners.len());
            prop_assert!(snap_a.miners.windows(2).all(|w| w[0].miner_pubkey < w[1].miner_pubkey));
            prop_assert_eq!(
                snap_a.miners.iter().map(|m| m.miner_pubkey).collect::<Vec<_>>(),
                snap_b.miners.iter().map(|m| m.miner_pubkey).collect::<Vec<_>>(),
            );
        }
    }
}
