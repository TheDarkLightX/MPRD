use crate::{MprdError, Result};

use super::types::{Bps, BPS_U64};

pub const DF_BASE_X10K: u64 = BPS_U64;
pub const DF_ALPHA_X10K: u64 = 40_000;
pub const DF_DMAX_EPOCHS: u64 = 1460;

pub fn mul_div_floor_u64(a: u64, b: u64, denom: u64) -> Result<u64> {
    if denom == 0 {
        return Err(MprdError::InvalidInput("division by zero".into()));
    }
    let num = (a as u128)
        .checked_mul(b as u128)
        .ok_or_else(|| MprdError::BoundedValueExceeded("u128 overflow in mul".into()))?;
    let out = num / (denom as u128);
    u64::try_from(out).map_err(|_| MprdError::BoundedValueExceeded("u64 overflow in div".into()))
}

pub fn add_u64(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| MprdError::BoundedValueExceeded("u64 overflow in add".into()))
}

pub fn sub_u64(a: u64, b: u64) -> Result<u64> {
    a.checked_sub(b)
        .ok_or_else(|| MprdError::InvalidInput("u64 underflow in sub".into()))
}

pub fn floor_bps(amount: u64, bps: Bps) -> Result<u64> {
    mul_div_floor_u64(amount, bps.as_u64(), BPS_U64)
}

/// Duration factor in x10k, capped, per v6 spec.
pub fn df_x10k(lock_epochs: u64) -> u64 {
    let le = lock_epochs.min(DF_DMAX_EPOCHS);
    DF_BASE_X10K + (DF_ALPHA_X10K * le) / DF_DMAX_EPOCHS
}

/// Share-rate (price) in x10k: `10_000 + floor(10_000 * total_issued / K)`.
pub fn share_rate_x10k(total_shares_issued: u64, share_rate_k: u64) -> Result<u64> {
    if share_rate_k == 0 {
        return Err(MprdError::InvalidInput("share_rate_k must be > 0".into()));
    }
    let bump = mul_div_floor_u64(BPS_U64, total_shares_issued, share_rate_k)?;
    Ok(BPS_U64.saturating_add(bump))
}

/// Stake-units = floor(stake_amount * DF_x10k(lock_epochs) / 10_000).
pub fn stake_units(stake_amount: u64, lock_epochs: u64) -> Result<u64> {
    mul_div_floor_u64(stake_amount, df_x10k(lock_epochs), BPS_U64)
}

/// Shares minted = floor(stake_units * 10_000 / share_rate_x10k(total_issued)).
pub fn shares_minted(
    stake_amount: u64,
    lock_epochs: u64,
    total_shares_issued: u64,
    share_rate_k: u64,
) -> Result<u64> {
    let su = stake_units(stake_amount, lock_epochs)?;
    let sr = share_rate_x10k(total_shares_issued, share_rate_k)?;
    mul_div_floor_u64(su, BPS_U64, sr)
}

/// Linear rage-quit penalty (conservative default): forfeit remaining-time fraction.
///
/// If `elapsed >= lock`, penalty = 0.
/// Else `penalty = floor(stake_amount * (lock-elapsed) / lock)`.
pub fn rage_quit_penalty_linear(
    stake_amount: u64,
    lock_epochs: u64,
    elapsed_epochs: u64,
) -> Result<u64> {
    if lock_epochs == 0 {
        return Err(MprdError::InvalidInput("lock_epochs must be > 0".into()));
    }
    if elapsed_epochs >= lock_epochs {
        return Ok(0);
    }
    let remaining = lock_epochs - elapsed_epochs;
    mul_div_floor_u64(stake_amount, remaining, lock_epochs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn df_x10k_bounds() {
        assert_eq!(df_x10k(0), 10_000);
        assert_eq!(df_x10k(DF_DMAX_EPOCHS), 50_000);
        assert_eq!(df_x10k(DF_DMAX_EPOCHS * 10), 50_000);
    }

    proptest! {
        #[test]
        fn share_rate_is_monotone(t1 in 0u64..1_000_000u64, t2 in 0u64..1_000_000u64) {
            let k = 50_000_000u64;
            let (a,b) = if t1 <= t2 { (t1,t2) } else { (t2,t1) };
            let r1 = share_rate_x10k(a, k).unwrap();
            let r2 = share_rate_x10k(b, k).unwrap();
            prop_assert!(r1 <= r2);
        }

        #[test]
        fn minted_shares_nonincreasing_in_total_issued(
            stake in 1u64..1_000_000u64,
            lock in 1u64..3650u64,
            t1 in 0u64..5_000_000u64,
            t2 in 0u64..5_000_000u64,
        ) {
            let k = 50_000_000u64;
            let (a,b) = if t1 <= t2 { (t1,t2) } else { (t2,t1) };
            let s1 = shares_minted(stake, lock, a, k).unwrap();
            let s2 = shares_minted(stake, lock, b, k).unwrap();
            prop_assert!(s2 <= s1);
        }

        #[test]
        fn rage_quit_penalty_is_bounded(
            stake in 0u64..1_000_000u64,
            lock in 1u64..3650u64,
            elapsed in 0u64..5000u64,
        ) {
            let p = rage_quit_penalty_linear(stake, lock, elapsed).unwrap();
            prop_assert!(p <= stake);
            if elapsed >= lock {
                prop_assert_eq!(p, 0);
            }
        }
    }
}
