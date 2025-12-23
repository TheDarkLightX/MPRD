//! ASDE CLI utilities (off-chain epoch runner + checkpoint verification).

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use mprd_asde::{
    apply_service_fee_vouchers_v1, capped_proportional_allocate_v1, checkpoint_hash_v1,
    df_table_hash_v1, merkle_root_v1, ss_base_q32_32, ss_effective_q32_32,
    voucher_available_balance_sfa_v1, AllocationInputV1, EpochSummaryV1, FeeEventV1,
    SignedCheckpointV1, StakeEventV1, VoucherGrantV1, VoucherSpendV1, SCALE_Q32_32,
};
use mprd_core::{TokenSigningKey, TokenVerifyingKey};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsdeParamsV1 {
    /// Fixed epoch length in integer days. Must be >= 1.
    pub epoch_days: u32,
    /// Voucher expiry in epochs (>= 1).
    pub voucher_ttl_epochs: u64,
    /// α_min as Q32.32 (fraction of service-fee inflow reserved for scarcity floor).
    pub alpha_min_q32_32: u64,
    /// v_max_share as Q32.32 (maximum share of service-fee inflow that can go to vouchers).
    pub v_max_share_q32_32: u64,
    /// Minimum operational reserve in SFA (absolute units).
    pub ops_min_sfa: u128,
    /// Target base-share issuance per epoch in Q32.32 (for difficulty control).
    pub target_issued_ss_base_q32_32: u128,
    /// Proportional gain kP as Q32.32.
    pub kp_q32_32: u64,
    /// Difficulty clamps (Q32.32).
    pub difficulty_min_q32_32: u128,
    pub difficulty_max_q32_32: u128,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StakePositionV1 {
    pub user_pubkey: [u8; 32],
    pub amount_agrs: u128,
    pub lock_days: u32,
    pub stake_epoch_id: u64,
    /// Base stake shares in Q32.32.
    pub ss_base_q32_32: u128,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsdeStateV1 {
    pub positions: Vec<StakePositionV1>,
}

fn parse_u128_dec(s: &str) -> Result<u128> {
    s.parse::<u128>().context("invalid u128 decimal")
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

fn parse_pubkey_hex(hex_str: &str) -> Result<[u8; 32]> {
    parse_hash32_hex(hex_str)
}

fn compute_params_hash(params: &AsdeParamsV1) -> [u8; 32] {
    // Minimal deterministic commitment for off-chain audit. This is not a consensus rule
    // yet; it exists so epoch summaries can bind the exact parameters used.
    let mut out = Vec::new();
    out.extend_from_slice(b"ASDE_PARAMS_V1");
    out.extend_from_slice(&params.epoch_days.to_le_bytes());
    out.extend_from_slice(&params.voucher_ttl_epochs.to_le_bytes());
    out.extend_from_slice(&params.alpha_min_q32_32.to_le_bytes());
    out.extend_from_slice(&params.v_max_share_q32_32.to_le_bytes());
    out.extend_from_slice(&params.ops_min_sfa.to_le_bytes());
    out.extend_from_slice(&params.target_issued_ss_base_q32_32.to_le_bytes());
    out.extend_from_slice(&params.kp_q32_32.to_le_bytes());
    out.extend_from_slice(&params.difficulty_min_q32_32.to_le_bytes());
    out.extend_from_slice(&params.difficulty_max_q32_32.to_le_bytes());
    mprd_core::hash::sha256_domain(b"ASDE_PARAMS_HASH_V1", &out).0
}

fn voucher_budget_sfa(service_fee_inflow_sfa: u128, params: &AsdeParamsV1) -> Result<u128> {
    let alpha = params.alpha_min_q32_32 as u128;
    let vmax = params.v_max_share_q32_32 as u128;

    // scarcity_min = floor(alpha * S_e / SCALE)
    let scarcity_min = (service_fee_inflow_sfa)
        .checked_mul(alpha)
        .context("overflow: alpha*S_e")?
        / SCALE_Q32_32;
    let cap = (service_fee_inflow_sfa)
        .checked_mul(vmax)
        .context("overflow: vmax*S_e")?
        / SCALE_Q32_32;

    let floor = scarcity_min
        .checked_add(params.ops_min_sfa)
        .context("overflow: floors")?;
    let residual = service_fee_inflow_sfa.saturating_sub(floor);
    Ok(cap.min(residual))
}

fn update_difficulty_q32_32(
    difficulty_e: u128,
    issued_ss_base: u128,
    params: &AsdeParamsV1,
) -> Result<u128> {
    let target = params.target_issued_ss_base_q32_32;
    if target == 0 {
        return Ok(difficulty_e);
    }

    // ratio_q = issued/target in Q32.32
    let ratio_q = (issued_ss_base)
        .checked_mul(SCALE_Q32_32)
        .context("overflow: issued*scale")?
        / target;
    let ratio_q_i = i128::try_from(ratio_q).context("overflow: ratio_q")?;
    let err_q = ratio_q_i - SCALE_Q32_32 as i128;
    let kp_q = i128::from(params.kp_q32_32);
    let delta_num = kp_q.checked_mul(err_q).context("overflow: kp*err")?;
    let delta_q = delta_num / SCALE_Q32_32 as i128;

    // difficulty_next = difficulty_e * (1 + delta)
    let one_q = SCALE_Q32_32 as i128;
    let mult_q = one_q.checked_add(delta_q).context("overflow: mult_q")?;
    let difficulty_i = i128::try_from(difficulty_e).context("overflow: difficulty_e")?;
    let mut next = difficulty_i
        .checked_mul(mult_q)
        .context("overflow: diff*mult")?
        / one_q;
    if next < 0 {
        next = 0;
    }

    let next_u = next as u128;
    Ok(next_u.clamp(params.difficulty_min_q32_32, params.difficulty_max_q32_32))
}

fn compute_elapsed_days(epoch_id: u64, stake_epoch_id: u64, epoch_days: u32) -> u32 {
    let epochs = epoch_id.saturating_sub(stake_epoch_id);
    let days = epochs.saturating_mul(epoch_days as u64);
    days.min(u32::MAX as u64) as u32
}

fn df_for_days(df_table_q32_32: &[u64], days: u32) -> Result<u128> {
    let idx = days as usize;
    let value = df_table_q32_32
        .get(idx)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("DF table missing index {} (fail-closed)", idx))?;
    Ok(value as u128)
}

struct StepEpochCoreInput {
    epoch_id: u64,
    state: AsdeStateV1,
    stake_events: Vec<StakeEventV1>,
    fee_events: Vec<FeeEventV1>,
    df_table_q32_32: Vec<u64>,
    params: AsdeParamsV1,
    difficulty_e_q32_32: u128,
    prev_checkpoint_hash: [u8; 32],
    signing_key: TokenSigningKey,
}

fn step_epoch_core(
    input: StepEpochCoreInput,
) -> Result<(
    AsdeStateV1,
    EpochSummaryV1,
    Vec<VoucherGrantV1>,
    SignedCheckpointV1,
)> {
    let StepEpochCoreInput {
        epoch_id,
        mut state,
        stake_events,
        fee_events,
        df_table_q32_32,
        params,
        difficulty_e_q32_32,
        prev_checkpoint_hash,
        signing_key,
    } = input;
    if params.epoch_days == 0 {
        anyhow::bail!("params.epoch_days must be >= 1");
    }
    if params.voucher_ttl_epochs == 0 {
        anyhow::bail!("params.voucher_ttl_epochs must be >= 1");
    }

    if df_table_q32_32.is_empty() || df_table_q32_32[0] != (SCALE_Q32_32 as u64) {
        anyhow::bail!("df_table[0] must be exactly 1.0 in Q32.32 (2^32)");
    }
    let max_df_days: u32 = (df_table_q32_32.len() - 1).try_into().unwrap_or(u32::MAX);

    // Fail-closed: persisted positions must be representable by the DF table.
    for p in &state.positions {
        if p.lock_days > max_df_days {
            anyhow::bail!(
                "state position lock_days {} exceeds df_table max day {} (fail-closed)",
                p.lock_days,
                max_df_days
            );
        }
    }

    for e in &stake_events {
        if e.lock_days > max_df_days {
            anyhow::bail!(
                "stake event {} lock_days {} exceeds df_table max day {} (fail-closed)",
                e.event_id,
                e.lock_days,
                max_df_days
            );
        }
        if e.stake_epoch_id != epoch_id {
            anyhow::bail!(
                "stake event {} has stake_epoch_id {} but step_epoch epoch_id is {}",
                e.event_id,
                e.stake_epoch_id,
                epoch_id
            );
        }
    }

    for e in &fee_events {
        if e.epoch_id != epoch_id {
            anyhow::bail!(
                "fee event {} has epoch_id {} but step_epoch epoch_id is {} (fail-closed)",
                e.event_id,
                e.epoch_id,
                epoch_id
            );
        }
    }

    let difficulty_e = difficulty_e_q32_32;
    if difficulty_e == 0 {
        anyhow::bail!("difficulty_e_q32_32 must be > 0");
    }

    // Apply stake events: mint base shares for new positions.
    let mut issued_ss_base = 0u128;
    for event in &stake_events {
        let ss_base = ss_base_q32_32(event.amount_agrs, difficulty_e)
            .map_err(|e| anyhow::anyhow!("ss_base calc failed: {}", e))?;
        issued_ss_base = issued_ss_base
            .checked_add(ss_base)
            .context("overflow: issued_ss_base")?;
        state.positions.push(StakePositionV1 {
            user_pubkey: event.user_pubkey,
            amount_agrs: event.amount_agrs,
            lock_days: event.lock_days,
            stake_epoch_id: event.stake_epoch_id,
            ss_base_q32_32: ss_base,
        });
    }

    // Compute per-user effective weights.
    let mut weights_by_user: BTreeMap<[u8; 32], u128> = BTreeMap::new();
    for p in &state.positions {
        let elapsed_days = compute_elapsed_days(epoch_id, p.stake_epoch_id, params.epoch_days);
        let days = elapsed_days.min(p.lock_days);
        let df = df_for_days(&df_table_q32_32, days)?;
        let eff = ss_effective_q32_32(p.ss_base_q32_32, df)
            .map_err(|e| anyhow::anyhow!("ss_effective calc failed: {}", e))?;
        *weights_by_user.entry(p.user_pubkey).or_default() += eff;
    }

    let service_fee_inflow_sfa: u128 = fee_events
        .iter()
        .try_fold(0u128, |acc, e| acc.checked_add(e.service_fee_amount_sfa))
        .context("overflow: service_fee_inflow_sfa")?;

    let budget_sfa = voucher_budget_sfa(service_fee_inflow_sfa, &params)?;

    let allocation_inputs: Vec<AllocationInputV1> = weights_by_user
        .iter()
        .map(|(user_pubkey, weight)| AllocationInputV1 {
            user_pubkey: *user_pubkey,
            weight: *weight,
            cap_sfa: None,
        })
        .collect();
    let allocations = capped_proportional_allocate_v1(&allocation_inputs, budget_sfa)
        .map_err(|e| anyhow::anyhow!("allocation failed: {}", e))?;

    let expiry_epoch_id = epoch_id
        .checked_add(params.voucher_ttl_epochs)
        .context("overflow: expiry_epoch_id")?;
    let mut grants: Vec<VoucherGrantV1> = Vec::with_capacity(allocations.len());
    for (i, a) in allocations.iter().enumerate() {
        grants.push(VoucherGrantV1 {
            grant_id: i as u64,
            user_pubkey: a.user_pubkey,
            voucher_amount_sfa: a.amount_sfa,
            expiry_epoch_id,
            epoch_id,
        });
    }

    let stake_events_root = merkle_root_v1(stake_events.iter().map(|e| e.leaf_hash_v1()).collect());
    let fee_events_root = merkle_root_v1(fee_events.iter().map(|e| e.leaf_hash_v1()).collect());
    let voucher_grants_root = merkle_root_v1(grants.iter().map(|g| g.leaf_hash_v1()).collect());

    let df_table_hash = df_table_hash_v1(&df_table_q32_32);
    let params_hash = compute_params_hash(&params);

    let difficulty_e_plus_1 = update_difficulty_q32_32(difficulty_e, issued_ss_base, &params)?;
    let summary = EpochSummaryV1 {
        epoch_id,
        difficulty_e,
        difficulty_e_plus_1,
        df_table_hash,
        params_hash,
        service_fee_inflow_sfa,
        voucher_budget_sfa: budget_sfa,
        stake_events_root,
        fee_events_root,
        voucher_grants_root,
    };

    let checkpoint_hash = checkpoint_hash_v1(epoch_id, summary.hash_v1(), prev_checkpoint_hash);
    let signed_checkpoint = SignedCheckpointV1::sign(checkpoint_hash, &signing_key);

    Ok((state, summary, grants, signed_checkpoint))
}

pub struct StepEpochArgs {
    pub epoch_id: u64,
    pub state_in: PathBuf,
    pub state_out: PathBuf,
    pub stake_events_path: PathBuf,
    pub fee_events_path: PathBuf,
    pub df_table_path: PathBuf,
    pub params_path: PathBuf,
    pub difficulty_e_q32_32_dec: String,
    pub epoch_summary_out: PathBuf,
    pub voucher_grants_out: PathBuf,
    pub prev_checkpoint_hash_hex: String,
    pub checkpoint_out: PathBuf,
    pub signing_key_hex: String,
    pub allow_empty_state: bool,
}

pub fn step_epoch(args: StepEpochArgs) -> Result<()> {
    let StepEpochArgs {
        epoch_id,
        state_in,
        state_out,
        stake_events_path,
        fee_events_path,
        df_table_path,
        params_path,
        difficulty_e_q32_32_dec,
        epoch_summary_out,
        voucher_grants_out,
        prev_checkpoint_hash_hex,
        checkpoint_out,
        signing_key_hex,
        allow_empty_state,
    } = args;
    let state: AsdeStateV1 = if state_in.exists() {
        let json = fs::read_to_string(&state_in)
            .with_context(|| format!("failed to read state: {}", state_in.display()))?;
        serde_json::from_str(&json).context("invalid ASDE state JSON")?
    } else if allow_empty_state {
        AsdeStateV1::default()
    } else {
        anyhow::bail!(
            "state file not found: {} (pass --allow-empty-state to start empty)",
            state_in.display()
        );
    };

    let params_json = fs::read_to_string(&params_path)
        .with_context(|| format!("failed to read params: {}", params_path.display()))?;
    let params: AsdeParamsV1 = serde_json::from_str(&params_json).context("invalid params JSON")?;

    let df_table_json = fs::read_to_string(&df_table_path)
        .with_context(|| format!("failed to read df_table: {}", df_table_path.display()))?;
    let df_table_q32_32: Vec<u64> =
        serde_json::from_str(&df_table_json).context("invalid df_table JSON")?;

    let stake_events_json = fs::read_to_string(&stake_events_path).with_context(|| {
        format!(
            "failed to read stake_events: {}",
            stake_events_path.display()
        )
    })?;
    let stake_events: Vec<StakeEventV1> =
        serde_json::from_str(&stake_events_json).context("invalid stake_events JSON")?;

    let fee_events_json = fs::read_to_string(&fee_events_path)
        .with_context(|| format!("failed to read fee_events: {}", fee_events_path.display()))?;
    let fee_events: Vec<FeeEventV1> =
        serde_json::from_str(&fee_events_json).context("invalid fee_events JSON")?;

    let difficulty_e = parse_u128_dec(&difficulty_e_q32_32_dec)?;
    let prev_checkpoint_hash = parse_hash32_hex(&prev_checkpoint_hash_hex)?;
    let sk = TokenSigningKey::from_hex(&signing_key_hex)
        .context("invalid signing key hex (expected 32-byte seed)")?;

    let (state, summary, grants, signed_checkpoint) = step_epoch_core(StepEpochCoreInput {
        epoch_id,
        state,
        stake_events,
        fee_events,
        df_table_q32_32,
        params,
        difficulty_e_q32_32: difficulty_e,
        prev_checkpoint_hash,
        signing_key: sk,
    })?;

    fs::write(&epoch_summary_out, serde_json::to_vec_pretty(&summary)?)
        .with_context(|| format!("failed to write: {}", epoch_summary_out.display()))?;
    fs::write(&voucher_grants_out, serde_json::to_vec_pretty(&grants)?)
        .with_context(|| format!("failed to write: {}", voucher_grants_out.display()))?;
    fs::write(
        &checkpoint_out,
        serde_json::to_vec_pretty(&signed_checkpoint)?,
    )
    .with_context(|| format!("failed to write: {}", checkpoint_out.display()))?;
    fs::write(&state_out, serde_json::to_vec_pretty(&state)?)
        .with_context(|| format!("failed to write: {}", state_out.display()))?;

    Ok(())
}

pub fn verify_checkpoint(checkpoint: PathBuf, verifying_key_hex: String) -> Result<()> {
    let json = fs::read_to_string(&checkpoint)
        .with_context(|| format!("failed to read: {}", checkpoint.display()))?;
    let signed: SignedCheckpointV1 =
        serde_json::from_str(&json).context("invalid signed checkpoint JSON")?;

    let vk = TokenVerifyingKey::from_hex(&verifying_key_hex)
        .context("invalid verifying key hex (expected 32 bytes)")?;
    let signer_pubkey = vk.to_bytes();
    if signer_pubkey != signed.public_key {
        anyhow::bail!("checkpoint signer_pubkey mismatch (fail-closed)");
    }
    signed.verify().context("checkpoint signature invalid")?;
    Ok(())
}

pub fn compute_service_fee_discount(
    service_fee_sfa_dec: String,
    voucher_grants_path: PathBuf,
    voucher_spends_path: Option<PathBuf>,
    user_pubkey_hex: String,
    epoch_id: u64,
) -> Result<()> {
    let service_fee_sfa = parse_u128_dec(&service_fee_sfa_dec)?;
    let user_pubkey = parse_pubkey_hex(&user_pubkey_hex)?;

    let json = fs::read_to_string(&voucher_grants_path).with_context(|| {
        format!(
            "failed to read voucher grants: {}",
            voucher_grants_path.display()
        )
    })?;
    let grants: Vec<VoucherGrantV1> =
        serde_json::from_str(&json).context("invalid voucher grants JSON")?;

    let spends: Vec<VoucherSpendV1> = if let Some(path) = voucher_spends_path {
        let json = fs::read_to_string(&path)
            .with_context(|| format!("failed to read voucher spends: {}", path.display()))?;
        serde_json::from_str(&json).context("invalid voucher spends JSON")?
    } else {
        Vec::new()
    };

    let available = voucher_available_balance_sfa_v1(&grants, &spends, user_pubkey, epoch_id)
        .map_err(|e| anyhow::anyhow!("voucher balance computation failed (fail-closed): {}", e))?;

    let (discount, net) = apply_service_fee_vouchers_v1(service_fee_sfa, available);
    println!("service_fee_sfa: {}", service_fee_sfa);
    println!("voucher_available_sfa: {}", available);
    println!("discount_applied_sfa: {}", discount);
    println!("net_service_fee_sfa: {}", net);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn params_for_test() -> AsdeParamsV1 {
        AsdeParamsV1 {
            epoch_days: 7,
            voucher_ttl_epochs: 4,
            alpha_min_q32_32: (SCALE_Q32_32 / 10) as u64, // 0.1
            v_max_share_q32_32: (SCALE_Q32_32 / 2) as u64, // 0.5
            ops_min_sfa: 10,
            target_issued_ss_base_q32_32: SCALE_Q32_32,
            kp_q32_32: (SCALE_Q32_32 / 10) as u64, // 0.1
            difficulty_min_q32_32: 1,
            difficulty_max_q32_32: 10_000 * SCALE_Q32_32,
        }
    }

    #[test]
    fn voucher_budget_is_never_greater_than_inflow() {
        let params = params_for_test();
        let budget = voucher_budget_sfa(1_000, &params).expect("budget");
        assert!(budget <= 1_000);
    }

    #[test]
    fn update_difficulty_returns_input_when_target_is_zero() {
        let mut params = params_for_test();
        params.target_issued_ss_base_q32_32 = 0;
        let out = update_difficulty_q32_32(123, 999, &params).expect("ok");
        assert_eq!(out, 123);
    }

    #[test]
    fn update_difficulty_fails_closed_on_unrepresentable_difficulty() {
        let params = params_for_test();
        let err = update_difficulty_q32_32(u128::MAX, 1, &params).expect_err("must error");
        assert!(err.to_string().contains("difficulty_e"));
    }

    proptest! {
        #[test]
        fn voucher_budget_respects_cap_and_residual(
            inflow in 0u128..=1_000_000_000_000u128,
            ops_min in 0u128..=1_000_000u128,
            alpha in 0u64..=(SCALE_Q32_32 as u64),
            vmax in 0u64..=(SCALE_Q32_32 as u64),
        ) {
            let params = AsdeParamsV1 {
                epoch_days: 1,
                voucher_ttl_epochs: 1,
                alpha_min_q32_32: alpha,
                v_max_share_q32_32: vmax,
                ops_min_sfa: ops_min,
                target_issued_ss_base_q32_32: SCALE_Q32_32,
                kp_q32_32: 0,
                difficulty_min_q32_32: 1,
                difficulty_max_q32_32: u128::MAX,
            };

            let budget = voucher_budget_sfa(inflow, &params).expect("budget");

            let scarcity_min = inflow.saturating_mul(alpha as u128) / SCALE_Q32_32;
            let cap = inflow.saturating_mul(vmax as u128) / SCALE_Q32_32;
            let floor = scarcity_min.saturating_add(ops_min);
            let residual = inflow.saturating_sub(floor);

            prop_assert!(budget <= inflow);
            prop_assert!(budget <= cap.min(residual));
        }

        #[test]
        fn update_difficulty_is_clamped_and_nonzero_for_reasonable_inputs(
            difficulty_e in 1u128..=1_000_000u128,
            issued in 0u128..=1_000_000u128,
            target in 1u128..=1_000_000u128,
            kp in 0u64..=(SCALE_Q32_32 as u64),
            diff_min in 0u128..=1_000u128,
            diff_max in 1_001u128..=2_000_000u128,
        ) {
            let params = AsdeParamsV1 {
                epoch_days: 1,
                voucher_ttl_epochs: 1,
                alpha_min_q32_32: 0,
                v_max_share_q32_32: 0,
                ops_min_sfa: 0,
                target_issued_ss_base_q32_32: target,
                kp_q32_32: kp,
                difficulty_min_q32_32: diff_min,
                difficulty_max_q32_32: diff_max,
            };

            let out = update_difficulty_q32_32(difficulty_e, issued, &params).expect("ok");
            prop_assert!(out >= diff_min);
            prop_assert!(out <= diff_max);
        }
    }

    #[test]
    fn step_epoch_core_fails_closed_on_fee_epoch_mismatch() {
        let params = params_for_test();
        let df_table_q32_32 = vec![SCALE_Q32_32 as u64];
        let state = AsdeStateV1::default();
        let stake_events = vec![];
        let fee_events = vec![FeeEventV1 {
            event_id: 1,
            router_pubkey: [0u8; 32],
            service_fee_amount_sfa: 1,
            epoch_id: 2,
        }];
        let signing_key = TokenSigningKey::from_seed(&[3u8; 32]);

        let err = step_epoch_core(StepEpochCoreInput {
            epoch_id: 1,
            state,
            stake_events,
            fee_events,
            df_table_q32_32,
            params,
            difficulty_e_q32_32: SCALE_Q32_32,
            prev_checkpoint_hash: [0u8; 32],
            signing_key,
        })
        .expect_err("must fail closed");
        assert!(err.to_string().contains("fee event"));
    }

    #[test]
    fn step_epoch_core_emits_signed_checkpoint_and_updates_state() {
        let params = params_for_test();
        let df_table_q32_32 = vec![SCALE_Q32_32 as u64];
        let state = AsdeStateV1::default();
        let stake_events = vec![StakeEventV1 {
            event_id: 1,
            user_pubkey: [9u8; 32],
            amount_agrs: 10,
            lock_days: 0,
            stake_epoch_id: 1,
        }];
        let fee_events = vec![FeeEventV1 {
            event_id: 1,
            router_pubkey: [8u8; 32],
            service_fee_amount_sfa: 100,
            epoch_id: 1,
        }];
        let signing_key = TokenSigningKey::from_seed(&[4u8; 32]);

        let (next_state, summary, _grants, checkpoint) = step_epoch_core(StepEpochCoreInput {
            epoch_id: 1,
            state,
            stake_events,
            fee_events,
            df_table_q32_32,
            params,
            difficulty_e_q32_32: SCALE_Q32_32,
            prev_checkpoint_hash: [0u8; 32],
            signing_key,
        })
        .expect("step");

        assert_eq!(summary.epoch_id, 1);
        assert_eq!(next_state.positions.len(), 1);
        checkpoint.verify().expect("checkpoint signature verifies");
    }
}
