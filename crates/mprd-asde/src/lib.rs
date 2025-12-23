use mprd_core::crypto::{PublicKeyBytes, SignatureBytes, TokenSigningKey, TokenVerifyingKey};
use mprd_core::hash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Hash32Bytes = [u8; 32];

pub mod domains {
    pub const STAKE_EVENT_LEAF_V1: &[u8] = b"ASDE_STAKE_EVENT_LEAF_V1";
    pub const FEE_EVENT_LEAF_V1: &[u8] = b"ASDE_FEE_EVENT_LEAF_V1";
    pub const VOUCHER_GRANT_LEAF_V1: &[u8] = b"ASDE_VOUCHER_GRANT_LEAF_V1";
    pub const VOUCHER_SPEND_LEAF_V1: &[u8] = b"ASDE_VOUCHER_SPEND_LEAF_V1";
    pub const MERKLE_NODE_V1: &[u8] = b"ASDE_MERKLE_NODE_V1";
    pub const MERKLE_EMPTY_V1: &[u8] = b"ASDE_MERKLE_EMPTY_V1";
    pub const EPOCH_SUMMARY_V1: &[u8] = b"ASDE_EPOCH_SUMMARY_V1";
    pub const CHECKPOINT_V1: &[u8] = b"ASDE_CHECKPOINT_V1";
    pub const CHECKPOINT_SIG_V1: &[u8] = b"ASDE_CHECKPOINT_SIG_V1";
    pub const DF_TABLE_V1: &[u8] = b"ASDE_DF_TABLE_V1";
}

fn hash_domain_bytes(domain: &[u8], data: &[u8]) -> Hash32Bytes {
    hash::sha256_domain(domain, data).0
}

#[derive(Debug, Error)]
pub enum AsdeError {
    #[error("overflow")]
    Overflow,
    #[error("division by zero")]
    DivisionByZero,
    #[error("signature invalid: {0}")]
    SignatureInvalid(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = core::result::Result<T, AsdeError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StakeEventV1 {
    pub event_id: u64,
    pub user_pubkey: PublicKeyBytes,
    pub amount_agrs: u128,
    pub lock_days: u32,
    pub stake_epoch_id: u64,
}

impl StakeEventV1 {
    pub fn leaf_bytes_v1(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 16 + 4 + 8);
        out.extend_from_slice(&self.event_id.to_le_bytes());
        out.extend_from_slice(&self.user_pubkey);
        out.extend_from_slice(&self.amount_agrs.to_le_bytes());
        out.extend_from_slice(&self.lock_days.to_le_bytes());
        out.extend_from_slice(&self.stake_epoch_id.to_le_bytes());
        out
    }

    pub fn leaf_hash_v1(&self) -> Hash32Bytes {
        hash_domain_bytes(domains::STAKE_EVENT_LEAF_V1, &self.leaf_bytes_v1())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeEventV1 {
    pub event_id: u64,
    pub router_pubkey: PublicKeyBytes,
    pub service_fee_amount_sfa: u128,
    pub epoch_id: u64,
}

impl FeeEventV1 {
    pub fn leaf_bytes_v1(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 16 + 8);
        out.extend_from_slice(&self.event_id.to_le_bytes());
        out.extend_from_slice(&self.router_pubkey);
        out.extend_from_slice(&self.service_fee_amount_sfa.to_le_bytes());
        out.extend_from_slice(&self.epoch_id.to_le_bytes());
        out
    }

    pub fn leaf_hash_v1(&self) -> Hash32Bytes {
        hash_domain_bytes(domains::FEE_EVENT_LEAF_V1, &self.leaf_bytes_v1())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoucherGrantV1 {
    pub grant_id: u64,
    pub user_pubkey: PublicKeyBytes,
    pub voucher_amount_sfa: u128,
    pub expiry_epoch_id: u64,
    pub epoch_id: u64,
}

impl VoucherGrantV1 {
    pub fn leaf_bytes_v1(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 16 + 8 + 8);
        out.extend_from_slice(&self.grant_id.to_le_bytes());
        out.extend_from_slice(&self.user_pubkey);
        out.extend_from_slice(&self.voucher_amount_sfa.to_le_bytes());
        out.extend_from_slice(&self.expiry_epoch_id.to_le_bytes());
        out.extend_from_slice(&self.epoch_id.to_le_bytes());
        out
    }

    pub fn leaf_hash_v1(&self) -> Hash32Bytes {
        hash_domain_bytes(domains::VOUCHER_GRANT_LEAF_V1, &self.leaf_bytes_v1())
    }
}

/// Voucher spend event (service-fee discounts).
///
/// This is an off-chain-first object intended to support fail-closed spend tracking. It binds a
/// spend to a fee receipt commitment (e.g., `mprd-core::fee_router::settlement_receipt_hash_v1`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoucherSpendV1 {
    pub spend_id: u64,
    pub user_pubkey: PublicKeyBytes,
    pub spend_amount_sfa: u128,
    pub spend_epoch_id: u64,
    pub fee_receipt_hash: Hash32Bytes,
}

impl VoucherSpendV1 {
    pub fn leaf_bytes_v1(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 16 + 8 + 32);
        out.extend_from_slice(&self.spend_id.to_le_bytes());
        out.extend_from_slice(&self.user_pubkey);
        out.extend_from_slice(&self.spend_amount_sfa.to_le_bytes());
        out.extend_from_slice(&self.spend_epoch_id.to_le_bytes());
        out.extend_from_slice(&self.fee_receipt_hash);
        out
    }

    pub fn leaf_hash_v1(&self) -> Hash32Bytes {
        hash_domain_bytes(domains::VOUCHER_SPEND_LEAF_V1, &self.leaf_bytes_v1())
    }
}

/// Compute a user's available voucher balance at a given epoch, given grants and spend events.
///
/// Rules (fail-closed):
/// - Only grants with `epoch_id <= at_epoch_id <= expiry_epoch_id` are considered available.
/// - Only spends with `spend_epoch_id <= at_epoch_id` are applied.
/// - Each spend must be satisfiable using grants that were issued by `spend_epoch_id` and not yet
///   expired at `spend_epoch_id` (deterministic "soonest-expiring first" allocation).
pub fn voucher_available_balance_sfa_v1(
    grants: &[VoucherGrantV1],
    spends: &[VoucherSpendV1],
    user_pubkey: PublicKeyBytes,
    at_epoch_id: u64,
) -> Result<u128> {
    let mut grant_indices: Vec<usize> = grants
        .iter()
        .enumerate()
        .filter(|(_, g)| g.user_pubkey == user_pubkey)
        .map(|(i, _)| i)
        .collect();

    // Deterministic allocation order: soonest expiry first, then grant_id.
    grant_indices.sort_by(|&a, &b| {
        let ga = &grants[a];
        let gb = &grants[b];
        ga.expiry_epoch_id
            .cmp(&gb.expiry_epoch_id)
            .then(ga.grant_id.cmp(&gb.grant_id))
    });

    let mut remaining: Vec<u128> = grants.iter().map(|g| g.voucher_amount_sfa).collect();

    let mut spend_indices: Vec<usize> = spends
        .iter()
        .enumerate()
        .filter(|(_, s)| s.user_pubkey == user_pubkey && s.spend_epoch_id <= at_epoch_id)
        .map(|(i, _)| i)
        .collect();
    spend_indices.sort_by(|&a, &b| {
        let sa = &spends[a];
        let sb = &spends[b];
        sa.spend_epoch_id
            .cmp(&sb.spend_epoch_id)
            .then(sa.spend_id.cmp(&sb.spend_id))
    });

    // Fail-closed: reject duplicate spend_id at the same epoch for this user.
    for w in spend_indices.windows(2) {
        let a = &spends[w[0]];
        let b = &spends[w[1]];
        if a.spend_epoch_id == b.spend_epoch_id && a.spend_id == b.spend_id {
            return Err(AsdeError::InvalidInput(
                "duplicate voucher spend_id for user (fail-closed)".into(),
            ));
        }
    }

    for idx in spend_indices {
        let s = &spends[idx];
        let mut need = s.spend_amount_sfa;
        if need == 0 {
            continue;
        }

        for &gi in &grant_indices {
            let g = &grants[gi];
            // Grant must exist by spend_epoch and must not be expired at spend_epoch.
            if s.spend_epoch_id < g.epoch_id || s.spend_epoch_id > g.expiry_epoch_id {
                continue;
            }
            let avail = remaining[gi];
            if avail == 0 {
                continue;
            }
            let take = avail.min(need);
            remaining[gi] = avail - take;
            need -= take;
            if need == 0 {
                break;
            }
        }

        if need != 0 {
            return Err(AsdeError::InvalidInput(
                "insufficient voucher balance for spend (fail-closed)".into(),
            ));
        }
    }

    let mut total = 0u128;
    for &gi in &grant_indices {
        let g = &grants[gi];
        if at_epoch_id < g.epoch_id || at_epoch_id > g.expiry_epoch_id {
            continue;
        }
        total = total
            .checked_add(remaining[gi])
            .ok_or(AsdeError::Overflow)?;
    }
    Ok(total)
}

pub fn merkle_root_v1(mut leaf_hashes: Vec<Hash32Bytes>) -> Hash32Bytes {
    if leaf_hashes.is_empty() {
        return hash_domain_bytes(domains::MERKLE_EMPTY_V1, &[]);
    }

    leaf_hashes.sort_unstable();
    let mut level = leaf_hashes;
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().expect("non-empty");
            level.push(last);
        }

        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&pair[0]);
            buf.extend_from_slice(&pair[1]);
            next.push(hash_domain_bytes(domains::MERKLE_NODE_V1, &buf));
        }
        level = next;
    }

    level[0]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochSummaryV1 {
    pub epoch_id: u64,
    pub difficulty_e: u128,
    pub difficulty_e_plus_1: u128,
    pub df_table_hash: Hash32Bytes,
    pub params_hash: Hash32Bytes,
    pub service_fee_inflow_sfa: u128,
    pub voucher_budget_sfa: u128,
    pub stake_events_root: Hash32Bytes,
    pub fee_events_root: Hash32Bytes,
    pub voucher_grants_root: Hash32Bytes,
}

impl EpochSummaryV1 {
    pub fn bytes_v1(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 16 + 16 + 32 + 32 + 16 + 16 + 32 + 32 + 32);
        out.extend_from_slice(&self.epoch_id.to_le_bytes());
        out.extend_from_slice(&self.difficulty_e.to_le_bytes());
        out.extend_from_slice(&self.difficulty_e_plus_1.to_le_bytes());
        out.extend_from_slice(&self.df_table_hash);
        out.extend_from_slice(&self.params_hash);
        out.extend_from_slice(&self.service_fee_inflow_sfa.to_le_bytes());
        out.extend_from_slice(&self.voucher_budget_sfa.to_le_bytes());
        out.extend_from_slice(&self.stake_events_root);
        out.extend_from_slice(&self.fee_events_root);
        out.extend_from_slice(&self.voucher_grants_root);
        out
    }

    pub fn hash_v1(&self) -> Hash32Bytes {
        hash_domain_bytes(domains::EPOCH_SUMMARY_V1, &self.bytes_v1())
    }
}

pub fn checkpoint_hash_v1(
    epoch_id: u64,
    epoch_summary_hash: Hash32Bytes,
    prev_checkpoint_hash: Hash32Bytes,
) -> Hash32Bytes {
    let mut out = Vec::with_capacity(8 + 32 + 32);
    out.extend_from_slice(&epoch_id.to_le_bytes());
    out.extend_from_slice(&epoch_summary_hash);
    out.extend_from_slice(&prev_checkpoint_hash);
    hash_domain_bytes(domains::CHECKPOINT_V1, &out)
}

pub fn checkpoint_sig_message_v1(checkpoint_hash: Hash32Bytes) -> Hash32Bytes {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&checkpoint_hash);
    hash_domain_bytes(domains::CHECKPOINT_SIG_V1, &out)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedCheckpointV1 {
    pub checkpoint_hash: Hash32Bytes,
    pub public_key: PublicKeyBytes,
    #[serde(with = "serde_signature_bytes")]
    pub signature: SignatureBytes,
}

impl SignedCheckpointV1 {
    pub fn sign(checkpoint_hash: Hash32Bytes, signing_key: &TokenSigningKey) -> Self {
        let public_key = signing_key.verifying_key().to_bytes();
        let message = checkpoint_sig_message_v1(checkpoint_hash);
        let signature = signing_key.sign_bytes(&message);
        Self {
            checkpoint_hash,
            public_key,
            signature,
        }
    }

    pub fn verify(&self) -> Result<()> {
        let verifying_key = TokenVerifyingKey::from_bytes(&self.public_key)
            .map_err(|e| AsdeError::SignatureInvalid(e.to_string()))?;
        let message = checkpoint_sig_message_v1(self.checkpoint_hash);
        verifying_key
            .verify_bytes(&message, &self.signature)
            .map_err(|e| AsdeError::SignatureInvalid(e.to_string()))?;
        Ok(())
    }
}

mod serde_signature_bytes {
    use super::SignatureBytes;
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(sig: &SignatureBytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(sig)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SignatureBytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::<u8>::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(D::Error::custom("signature must be 64 bytes"));
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

pub fn df_table_hash_v1(values_q32_32: &[u64]) -> Hash32Bytes {
    let mut out = Vec::with_capacity(4 + values_q32_32.len() * 8);
    out.extend_from_slice(&(values_q32_32.len() as u32).to_le_bytes());
    for value in values_q32_32 {
        out.extend_from_slice(&value.to_le_bytes());
    }
    hash_domain_bytes(domains::DF_TABLE_V1, &out)
}

pub const SCALE_Q32_32: u128 = 1u128 << 32;

pub fn ss_base_q32_32(amount_agrs: u128, difficulty_q32_32: u128) -> Result<u128> {
    mul_div_u128(amount_agrs, SCALE_Q32_32, difficulty_q32_32)
}

pub fn ss_effective_q32_32(ss_base: u128, df_q32_32: u128) -> Result<u128> {
    mul_div_u128(ss_base, df_q32_32, SCALE_Q32_32)
}

/// Apply service-fee vouchers to a service fee.
///
/// This MUST NOT be used to discount Tau Net network fees (Agoras); it only applies to
/// service fees denominated in SFA.
///
/// Returns `(discount_applied_sfa, net_service_fee_sfa)`.
pub fn apply_service_fee_vouchers_v1(
    service_fee_sfa: u128,
    voucher_balance_sfa: u128,
) -> (u128, u128) {
    let discount = service_fee_sfa.min(voucher_balance_sfa);
    (discount, service_fee_sfa - discount)
}

pub fn clamp_days(day_count: u32, lock_days: u32) -> u32 {
    day_count.min(lock_days)
}

#[derive(Clone, Debug)]
pub struct AllocationInputV1 {
    pub user_pubkey: PublicKeyBytes,
    pub weight: u128,
    pub cap_sfa: Option<u128>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationOutputV1 {
    pub user_pubkey: PublicKeyBytes,
    pub amount_sfa: u128,
}

/// Capped proportional allocation ("water filling") with deterministic tie-breaks.
///
/// Returns allocations sorted by `user_pubkey` bytes ascending.
pub fn capped_proportional_allocate_v1(
    inputs: &[AllocationInputV1],
    budget_sfa: u128,
) -> Result<Vec<AllocationOutputV1>> {
    if budget_sfa == 0 {
        return Ok(Vec::new());
    }

    let mut items: Vec<_> = inputs
        .iter()
        .filter(|item| item.weight > 0)
        .map(|item| {
            let cap = item.cap_sfa.unwrap_or(u128::MAX);
            (item.user_pubkey, item.weight, cap)
        })
        .collect();

    if items.is_empty() {
        return Ok(Vec::new());
    }

    let total_weight: u128 = items
        .iter()
        .try_fold(0u128, |acc, (_, weight, _)| acc.checked_add(*weight))
        .ok_or(AsdeError::Overflow)?;
    if total_weight == 0 {
        return Ok(Vec::new());
    }

    let total_cap: u128 = items
        .iter()
        .try_fold(0u128, |acc, (_, _, cap)| acc.checked_add(*cap))
        .ok_or(AsdeError::Overflow)?;

    let mut remaining_budget = budget_sfa.min(total_cap);

    // Sort by cap/weight ascending (capped first), tie-break by pubkey.
    items.sort_unstable_by(|(pub_a, w_a, cap_a), (pub_b, w_b, cap_b)| {
        let left = mul_u128_to_u256(*cap_a, *w_b);
        let right = mul_u128_to_u256(*cap_b, *w_a);
        match cmp_u256(left, right) {
            core::cmp::Ordering::Equal => pub_a.cmp(pub_b),
            other => other,
        }
    });

    let mut allocations: Vec<(PublicKeyBytes, u128, u128)> = Vec::with_capacity(items.len());
    // Track remaining pool.
    let mut remaining_weight = total_weight;
    let mut index = 0usize;

    while index < items.len() {
        let (user_pubkey, weight, cap) = items[index];
        if remaining_budget == 0 || remaining_weight == 0 {
            break;
        }

        // If proportional share would exceed cap, cap it now.
        // Condition: cap * remaining_weight <= remaining_budget * weight
        let left = mul_u128_to_u256(cap, remaining_weight);
        let right = mul_u128_to_u256(remaining_budget, weight);
        if cmp_u256(left, right) != core::cmp::Ordering::Greater {
            allocations.push((user_pubkey, weight, cap));
            remaining_budget = remaining_budget
                .checked_sub(cap)
                .ok_or(AsdeError::Overflow)?;
            remaining_weight = remaining_weight
                .checked_sub(weight)
                .ok_or(AsdeError::Overflow)?;
            index += 1;
            continue;
        }
        break;
    }

    // Allocate the remaining budget proportionally to remaining items (those not pre-capped).
    let remaining_items = &items[index..];
    let mut outputs: Vec<AllocationOutputV1> = Vec::with_capacity(items.len());

    // Emit capped allocations.
    for (user_pubkey, _, cap) in &allocations {
        outputs.push(AllocationOutputV1 {
            user_pubkey: *user_pubkey,
            amount_sfa: *cap,
        });
    }

    if remaining_budget == 0 || remaining_items.is_empty() || remaining_weight == 0 {
        outputs.sort_by(|a, b| a.user_pubkey.cmp(&b.user_pubkey));
        return Ok(outputs);
    }

    // Largest remainder method to fully use the remaining budget (deterministic).
    let mut provisional: Vec<(PublicKeyBytes, u128, u128)> =
        Vec::with_capacity(remaining_items.len());
    let mut used = 0u128;
    for (user_pubkey, weight, cap) in remaining_items {
        let share = mul_div_u128(remaining_budget, *weight, remaining_weight)?;
        let capped_share = share.min(*cap);
        used = used.checked_add(capped_share).ok_or(AsdeError::Overflow)?;
        let remainder_score = mul_mod_u128(remaining_budget, *weight, remaining_weight);
        provisional.push((*user_pubkey, capped_share, remainder_score));
    }

    if used > remaining_budget {
        return Err(AsdeError::InvalidInput(
            "allocation exceeded remaining budget".into(),
        ));
    }

    let mut remaining = remaining_budget - used;
    if remaining > 0 {
        // remaining < provisional.len() by properties of floors, but guard anyway.
        provisional.sort_unstable_by(|(pub_a, _, rem_a), (pub_b, _, rem_b)| {
            match rem_b.cmp(rem_a) {
                core::cmp::Ordering::Equal => pub_a.cmp(pub_b),
                other => other,
            }
        });

        for item in provisional.iter_mut() {
            if remaining == 0 {
                break;
            }
            // Give +1 to highest remainder items, respecting caps.
            if item.1 < remaining_items_cap(item.0, remaining_items) {
                item.1 = item.1.checked_add(1).ok_or(AsdeError::Overflow)?;
                remaining -= 1;
            }
        }
    }

    for (user_pubkey, amount, _) in provisional {
        if amount > 0 {
            outputs.push(AllocationOutputV1 {
                user_pubkey,
                amount_sfa: amount,
            });
        }
    }

    outputs.sort_by(|a, b| a.user_pubkey.cmp(&b.user_pubkey));
    Ok(outputs)
}

fn remaining_items_cap(
    user_pubkey: PublicKeyBytes,
    remaining_items: &[(PublicKeyBytes, u128, u128)],
) -> u128 {
    remaining_items
        .iter()
        .find(|(pk, _, _)| *pk == user_pubkey)
        .map(|(_, _, cap)| *cap)
        .unwrap_or(u128::MAX)
}

fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

fn mul_div_u128(a: u128, b: u128, c: u128) -> Result<u128> {
    if c == 0 {
        return Err(AsdeError::DivisionByZero);
    }
    if a == 0 || b == 0 {
        return Ok(0);
    }

    // Reduce before multiplication to avoid overflow:
    // (a*b)/c = ((a/g1)*(b/g2))/(c/(g1*g2)) with gcd reductions.
    let g1 = gcd_u128(a, c);
    let a1 = a / g1;
    let c1 = c / g1;

    let g2 = gcd_u128(b, c1);
    let b1 = b / g2;
    let c2 = c1 / g2;

    let product = a1.checked_mul(b1).ok_or(AsdeError::Overflow)?;
    Ok(product / c2)
}

fn add_mod_u128(x: u128, y: u128, modulus: u128) -> u128 {
    debug_assert!(x < modulus);
    debug_assert!(y < modulus);
    let threshold = modulus - y;
    if x >= threshold {
        x - threshold
    } else {
        x + y
    }
}

fn double_mod_u128(x: u128, modulus: u128) -> u128 {
    debug_assert!(x < modulus);
    let threshold = modulus - x;
    if x >= threshold {
        x - threshold
    } else {
        x + x
    }
}

fn mul_mod_u128(a: u128, b: u128, modulus: u128) -> u128 {
    if modulus == 0 {
        return 0;
    }
    if modulus == 1 {
        return 0;
    }
    let mut left = a % modulus;
    let mut right = b;
    let mut acc = 0u128;
    while right != 0 {
        if (right & 1) == 1 {
            acc = add_mod_u128(acc, left, modulus);
        }
        left = double_mod_u128(left, modulus);
        right >>= 1;
    }
    acc
}

#[derive(Clone, Copy)]
struct U256([u64; 4]);

fn mul_u128_to_u256(a: u128, b: u128) -> U256 {
    let a_lo = a as u64;
    let a_hi = (a >> 64) as u64;
    let b_lo = b as u64;
    let b_hi = (b >> 64) as u64;

    let p0 = (a_lo as u128) * (b_lo as u128);
    let p1 = (a_lo as u128) * (b_hi as u128);
    let p2 = (a_hi as u128) * (b_lo as u128);
    let p3 = (a_hi as u128) * (b_hi as u128);

    let p0_lo = p0 as u64;
    let p0_hi = (p0 >> 64) as u64;

    let mid = p1 + p2 + (p0_hi as u128);
    let mid_lo = mid as u64;
    let mid_hi = (mid >> 64) as u64;

    let hi = p3 + (mid_hi as u128);
    let hi_lo = hi as u64;
    let hi_hi = (hi >> 64) as u64;

    U256([p0_lo, mid_lo, hi_lo, hi_hi])
}

fn cmp_u256(left: U256, right: U256) -> core::cmp::Ordering {
    for index in (0..4).rev() {
        match left.0[index].cmp(&right.0[index]) {
            core::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    core::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand::RngCore;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn reference_voucher_balance_sfa_v1(
        grants: &[VoucherGrantV1],
        spends: &[VoucherSpendV1],
        user_pubkey: PublicKeyBytes,
        at_epoch_id: u64,
    ) -> core::result::Result<u128, &'static str> {
        // Filter user-specific grants, sort by (expiry, grant_id).
        let mut user_grants: Vec<(u64, u64, u128)> = grants
            .iter()
            .filter(|g| g.user_pubkey == user_pubkey)
            .map(|g| (g.epoch_id, g.expiry_epoch_id, g.voucher_amount_sfa))
            .collect();

        // Keep stable identity by grant_id: rebuild with it for tie-break parity.
        let mut user_grants_with_id: Vec<(u64, u64, u64, u128)> = grants
            .iter()
            .filter(|g| g.user_pubkey == user_pubkey)
            .map(|g| {
                (
                    g.expiry_epoch_id,
                    g.grant_id,
                    g.epoch_id,
                    g.voucher_amount_sfa,
                )
            })
            .collect();
        user_grants_with_id.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        // remaining per entry, aligned with user_grants_with_id ordering
        let mut remaining: Vec<u128> = user_grants_with_id.iter().map(|x| x.3).collect();

        // Filter spends at/before at_epoch, sort by (spend_epoch, spend_id).
        let mut user_spends: Vec<(u64, u64, u128)> = spends
            .iter()
            .filter(|s| s.user_pubkey == user_pubkey && s.spend_epoch_id <= at_epoch_id)
            .map(|s| (s.spend_epoch_id, s.spend_id, s.spend_amount_sfa))
            .collect();
        user_spends.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        // Fail-closed duplicate spend_id at same spend_epoch.
        for w in user_spends.windows(2) {
            if w[0].0 == w[1].0 && w[0].1 == w[1].1 {
                return Err("duplicate spend_id at epoch");
            }
        }

        // Apply spends using "soonest-expiring first" allocation among grants that are live at spend time.
        for (spend_epoch, _spend_id, spend_amount) in user_spends {
            let mut need = spend_amount;
            if need == 0 {
                continue;
            }

            for (i, (expiry_epoch, _grant_id, grant_epoch, _amt)) in
                user_grants_with_id.iter().enumerate()
            {
                if spend_epoch < *grant_epoch || spend_epoch > *expiry_epoch {
                    continue;
                }
                let avail = remaining[i];
                if avail == 0 {
                    continue;
                }
                let take = avail.min(need);
                remaining[i] = avail - take;
                need -= take;
                if need == 0 {
                    break;
                }
            }

            if need != 0 {
                return Err("overspend");
            }
        }

        // Sum remaining for grants live at at_epoch.
        let mut total = 0u128;
        for (i, (expiry_epoch, _grant_id, grant_epoch, _amt)) in
            user_grants_with_id.iter().enumerate()
        {
            if at_epoch_id < *grant_epoch || at_epoch_id > *expiry_epoch {
                continue;
            }
            total = total.checked_add(remaining[i]).ok_or("overflow")?;
        }

        // Ensure no stray use of the unused vector (defensive).
        let _ = &mut user_grants;

        Ok(total)
    }

    #[test]
    fn merkle_root_empty_is_domain_hash() {
        let root = merkle_root_v1(Vec::new());
        assert_eq!(root, hash_domain_bytes(domains::MERKLE_EMPTY_V1, &[]));
    }

    #[test]
    fn merkle_root_is_order_independent() {
        let a = hash_domain_bytes(b"X", b"a");
        let b = hash_domain_bytes(b"X", b"b");
        let c = hash_domain_bytes(b"X", b"c");

        let r1 = merkle_root_v1(vec![a, b, c]);
        let r2 = merkle_root_v1(vec![c, a, b]);
        assert_eq!(r1, r2);
    }

    #[test]
    fn epoch_summary_hash_is_deterministic() {
        let summary = EpochSummaryV1 {
            epoch_id: 7,
            difficulty_e: 123,
            difficulty_e_plus_1: 456,
            df_table_hash: [1u8; 32],
            params_hash: [2u8; 32],
            service_fee_inflow_sfa: 999,
            voucher_budget_sfa: 111,
            stake_events_root: [3u8; 32],
            fee_events_root: [4u8; 32],
            voucher_grants_root: [5u8; 32],
        };

        assert_eq!(summary.hash_v1(), summary.hash_v1());
    }

    #[test]
    fn checkpoint_signature_verifies() {
        let signing_key = TokenSigningKey::from_seed(&[1u8; 32]);
        let buf = [7u8; 32];

        let signed = SignedCheckpointV1::sign(buf, &signing_key);
        assert!(signed.verify().is_ok());
    }

    #[test]
    fn allocation_respects_budget_and_caps() {
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let inputs = vec![
            AllocationInputV1 {
                user_pubkey: alice,
                weight: 10,
                cap_sfa: Some(3),
            },
            AllocationInputV1 {
                user_pubkey: bob,
                weight: 20,
                cap_sfa: Some(100),
            },
        ];

        let outputs = capped_proportional_allocate_v1(&inputs, 10).unwrap();
        let total: u128 = outputs.iter().map(|o| o.amount_sfa).sum();
        assert!(total <= 10);
        let alice_amt = outputs
            .iter()
            .find(|o| o.user_pubkey == alice)
            .unwrap()
            .amount_sfa;
        assert!(alice_amt <= 3);
    }

    #[test]
    fn apply_service_fee_vouchers_never_underflows() {
        assert_eq!(apply_service_fee_vouchers_v1(0, 10), (0, 0));
        assert_eq!(apply_service_fee_vouchers_v1(10, 0), (0, 10));
        assert_eq!(apply_service_fee_vouchers_v1(10, 3), (3, 7));
        assert_eq!(apply_service_fee_vouchers_v1(10, 30), (10, 0));
    }

    #[test]
    fn voucher_available_balance_accounts_for_spends_and_expiry() {
        let user = [9u8; 32];
        let grants = vec![
            VoucherGrantV1 {
                grant_id: 1,
                user_pubkey: user,
                voucher_amount_sfa: 10,
                expiry_epoch_id: 5,
                epoch_id: 1,
            },
            VoucherGrantV1 {
                grant_id: 2,
                user_pubkey: user,
                voucher_amount_sfa: 5,
                expiry_epoch_id: 2,
                epoch_id: 2,
            },
        ];

        let spends = vec![VoucherSpendV1 {
            spend_id: 1,
            user_pubkey: user,
            spend_amount_sfa: 7,
            spend_epoch_id: 2,
            fee_receipt_hash: [1u8; 32],
        }];

        let b2 = voucher_available_balance_sfa_v1(&grants, &spends, user, 2).expect("ok");
        assert_eq!(b2, 8);

        let b3 = voucher_available_balance_sfa_v1(&grants, &spends, user, 3).expect("ok");
        assert_eq!(b3, 8);
    }

    #[test]
    fn voucher_available_balance_fails_closed_on_overspend() {
        let user = [9u8; 32];
        let grants = vec![VoucherGrantV1 {
            grant_id: 1,
            user_pubkey: user,
            voucher_amount_sfa: 1,
            expiry_epoch_id: 1,
            epoch_id: 1,
        }];
        let spends = vec![VoucherSpendV1 {
            spend_id: 1,
            user_pubkey: user,
            spend_amount_sfa: 2,
            spend_epoch_id: 1,
            fee_receipt_hash: [2u8; 32],
        }];

        let err = voucher_available_balance_sfa_v1(&grants, &spends, user, 1).unwrap_err();
        assert!(matches!(err, AsdeError::InvalidInput(_)));
    }

    #[test]
    fn procedural_voucher_traces_match_reference() {
        // Procedural generation harness:
        // - Generates mixed-valid and invalid voucher traces.
        // - Checks that ASDE's voucher balance function matches an independent reference
        //   implementation, and fails-closed on invalid histories.
        for seed in 0u64..200u64 {
            let mut rng = StdRng::seed_from_u64(seed);

            let mut user = [0u8; 32];
            rng.fill_bytes(&mut user);

            // Mix in other users to ensure filtering correctness.
            let mut other_user = [0u8; 32];
            rng.fill_bytes(&mut other_user);
            if other_user == user {
                other_user[0] ^= 0xFF;
            }

            let grant_count = rng.gen_range(1usize..=25usize);
            let mut grants: Vec<VoucherGrantV1> = Vec::with_capacity(grant_count);
            for i in 0..grant_count {
                let start_epoch = rng.gen_range(1u64..=15u64);
                let end_epoch = start_epoch + rng.gen_range(0u64..=15u64);
                let amount = rng.gen_range(0u128..=200u128);
                let for_user = rng.gen_bool(0.75);
                grants.push(VoucherGrantV1 {
                    grant_id: (i as u64) + 1,
                    user_pubkey: if for_user { user } else { other_user },
                    voucher_amount_sfa: amount,
                    expiry_epoch_id: end_epoch,
                    epoch_id: start_epoch,
                });
            }

            let spend_count = rng.gen_range(0usize..=35usize);
            let mut spends: Vec<VoucherSpendV1> = Vec::with_capacity(spend_count);
            let mut current_epoch = 1u64;
            for i in 0..spend_count {
                current_epoch = current_epoch.max(rng.gen_range(1u64..=30u64));
                let for_user = rng.gen_bool(0.80);

                // 80% chance to pick a small spend, 20% chance to pick a large one (likely invalid).
                let spend_amount = if rng.gen_bool(0.80) {
                    rng.gen_range(0u128..=30u128)
                } else {
                    rng.gen_range(31u128..=500u128)
                };

                // Occasionally introduce a duplicate spend_id at the same epoch for the target user.
                let spend_id = if for_user && rng.gen_bool(0.05) && !spends.is_empty() {
                    spends.last().unwrap().spend_id
                } else {
                    (i as u64) + 1
                };

                let mut receipt_hash = [0u8; 32];
                rng.fill_bytes(&mut receipt_hash);

                spends.push(VoucherSpendV1 {
                    spend_id,
                    user_pubkey: if for_user { user } else { other_user },
                    spend_amount_sfa: spend_amount,
                    spend_epoch_id: current_epoch,
                    fee_receipt_hash: receipt_hash,
                });
            }

            // Probe multiple query epochs per generated trace.
            for _ in 0..5 {
                let at_epoch = rng.gen_range(1u64..=30u64);

                let got = voucher_available_balance_sfa_v1(&grants, &spends, user, at_epoch);
                let expected = reference_voucher_balance_sfa_v1(&grants, &spends, user, at_epoch);

                match (got, expected) {
                    (Ok(g), Ok(e)) => assert_eq!(g, e, "seed={seed} at_epoch={at_epoch}"),
                    (Err(_), Err(_)) => {}
                    (Ok(_), Err(msg)) => panic!(
                        "expected fail-closed but got Ok (seed={seed} at_epoch={at_epoch} err={msg})"
                    ),
                    (Err(err), Ok(_)) => panic!(
                        "unexpected failure (seed={seed} at_epoch={at_epoch} err={err})"
                    ),
                }
            }
        }
    }

    #[test]
    fn procedural_allocation_invariants_hold_and_are_scale_invariant() {
        // Procedural generation harness for capped proportional allocation.
        // Checks:
        // - allocations are sorted by pubkey
        // - each allocation respects caps
        // - total allocation never exceeds min(budget, total_cap)
        // - scaling all weights by a constant leaves allocation unchanged
        for seed in 0u64..200u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let n = rng.gen_range(1usize..=25usize);
            let mut inputs: Vec<AllocationInputV1> = Vec::with_capacity(n);

            // Keep values in a realistic, non-overflowing range for procedural tests.
            // The allocation routine is designed to fail-closed on overflow; production
            // parameter bounds should enforce caps/budgets within a safe range.
            const CAP_MAX_SFA: u128 = 1_000_000;
            const WEIGHT_MAX: u128 = 1_000;

            for _ in 0..n {
                let mut pk = [0u8; 32];
                rng.fill_bytes(&mut pk);
                let weight = rng.gen_range(0u128..=WEIGHT_MAX);
                // Always set an explicit cap in procedural tests to avoid the sentinel
                // `u128::MAX` (used for "no cap") causing overflow in total-cap sums.
                let cap = Some(rng.gen_range(0u128..=CAP_MAX_SFA));
                inputs.push(AllocationInputV1 {
                    user_pubkey: pk,
                    weight,
                    cap_sfa: cap,
                });
            }

            let budget = rng.gen_range(0u128..=CAP_MAX_SFA);
            let out1 = capped_proportional_allocate_v1(&inputs, budget).expect("allocation ok");

            let mut inputs_scaled = inputs.clone();
            for item in inputs_scaled.iter_mut() {
                item.weight = item.weight * 2;
            }
            let out2 =
                capped_proportional_allocate_v1(&inputs_scaled, budget).expect("allocation ok");

            assert_eq!(out1, out2, "scale invariance failed (seed={seed})");

            // Sorted by pubkey.
            for w in out1.windows(2) {
                assert!(
                    w[0].user_pubkey <= w[1].user_pubkey,
                    "not sorted (seed={seed})"
                );
            }

            // Caps and totals.
            let mut total = 0u128;
            for o in &out1 {
                let cap = inputs
                    .iter()
                    .find(|i| i.user_pubkey == o.user_pubkey)
                    .and_then(|i| i.cap_sfa)
                    .unwrap_or(CAP_MAX_SFA);
                assert!(o.amount_sfa <= cap, "cap violated (seed={seed})");
                total = total.saturating_add(o.amount_sfa);
            }

            let total_cap: u128 = inputs
                .iter()
                .filter(|i| i.weight > 0)
                .map(|i| i.cap_sfa.unwrap_or(CAP_MAX_SFA))
                .fold(0u128, |acc, x| acc.saturating_add(x));

            let upper = budget.min(total_cap);
            assert!(total <= upper, "budget exceeded (seed={seed})");
        }
    }

    #[test]
    fn allocation_fails_closed_on_unbounded_cap_overflow() {
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let inputs = vec![
            AllocationInputV1 {
                user_pubkey: alice,
                weight: 1,
                cap_sfa: None, // interpreted as u128::MAX
            },
            AllocationInputV1 {
                user_pubkey: bob,
                weight: 1,
                cap_sfa: Some(1),
            },
        ];

        let err = capped_proportional_allocate_v1(&inputs, 10).unwrap_err();
        assert!(matches!(err, AsdeError::Overflow));
    }

    #[derive(Clone, Debug)]
    enum VoucherAction {
        Grant {
            for_user: bool,
            epoch_id: u8,
            duration: u8,
            amount: u16,
            prepend: bool,
        },
        Spend {
            for_user: bool,
            spend_epoch_id: u8,
            spend_id: u8,
            amount: u16,
            prepend: bool,
        },
        Query {
            at_epoch_id: u8,
        },
    }

    fn voucher_action_strategy() -> impl Strategy<Value = VoucherAction> {
        let grant = (
            any::<bool>(),
            1u8..=64u8,
            0u8..=64u8,
            0u16..=10_000u16,
            any::<bool>(),
        )
            .prop_map(|(for_user, epoch_id, duration, amount, prepend)| {
                VoucherAction::Grant {
                    for_user,
                    epoch_id,
                    duration,
                    amount,
                    prepend,
                }
            });

        let spend = (
            any::<bool>(),
            1u8..=64u8,
            1u8..=64u8,
            0u16..=10_000u16,
            any::<bool>(),
        )
            .prop_map(|(for_user, spend_epoch_id, spend_id, amount, prepend)| {
                VoucherAction::Spend {
                    for_user,
                    spend_epoch_id,
                    spend_id,
                    amount,
                    prepend,
                }
            });

        let query = (1u8..=64u8).prop_map(|at_epoch_id| VoucherAction::Query { at_epoch_id });

        prop_oneof![5 => grant, 5 => spend, 2 => query]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            // Keep runtime bounded in CI, but large enough to discover multi-step traces.
            cases: 256,
            max_shrink_iters: 10_000,
            .. ProptestConfig::default()
        })]

        /// Model-based, stateful security PBT for ASDE voucher accounting.
        ///
        /// This generates mixed-valid and invalid grant/spend histories (including adversarial
        /// orderings via `prepend`) and checks:
        /// - ASDE matches an independent reference model on valid traces
        /// - ASDE fails closed on invalid traces (duplicate spend IDs at an epoch, overspends)
        #[test]
        fn pbt_asde_voucher_trace_matches_reference(
            actions in prop::collection::vec(voucher_action_strategy(), 0..200)
        ) {
            let user: PublicKeyBytes = [1u8; 32];
            let other: PublicKeyBytes = [2u8; 32];

            let mut grants: Vec<VoucherGrantV1> = Vec::new();
            let mut spends: Vec<VoucherSpendV1> = Vec::new();
            let mut next_grant_id: u64 = 1;

            for action in actions {
                match action {
                    VoucherAction::Grant { for_user, epoch_id, duration, amount, prepend } => {
                        let epoch_id = epoch_id as u64;
                        let expiry_epoch_id = (epoch_id + (duration as u64)).min(64);
                        let g = VoucherGrantV1 {
                            grant_id: next_grant_id,
                            user_pubkey: if for_user { user } else { other },
                            voucher_amount_sfa: amount as u128,
                            expiry_epoch_id: expiry_epoch_id.max(epoch_id),
                            epoch_id,
                        };
                        next_grant_id += 1;
                        if prepend {
                            grants.insert(0, g);
                        } else {
                            grants.push(g);
                        }
                    }
                    VoucherAction::Spend { for_user, spend_epoch_id, spend_id, amount, prepend } => {
                        let mut fee_receipt_hash = [0u8; 32];
                        fee_receipt_hash.fill(spend_id);
                        let s = VoucherSpendV1 {
                            spend_id: spend_id as u64,
                            user_pubkey: if for_user { user } else { other },
                            spend_amount_sfa: amount as u128,
                            spend_epoch_id: spend_epoch_id as u64,
                            fee_receipt_hash,
                        };
                        if prepend {
                            spends.insert(0, s);
                        } else {
                            spends.push(s);
                        }
                    }
                    VoucherAction::Query { at_epoch_id } => {
                        let at_epoch_id = at_epoch_id as u64;
                        let got = voucher_available_balance_sfa_v1(&grants, &spends, user, at_epoch_id);
                        let expected = reference_voucher_balance_sfa_v1(&grants, &spends, user, at_epoch_id);

                        match (got, expected) {
                            (Ok(g), Ok(e)) => prop_assert_eq!(g, e),
                            (Err(_), Err(_)) => {}
                            (Ok(_), Err(msg)) => prop_assert!(false, "fail-open: {msg}"),
                            (Err(err), Ok(_)) => prop_assert!(false, "unexpected fail-closed: {err}"),
                        }
                    }
                }
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            max_shrink_iters: 10_000,
            .. ProptestConfig::default()
        })]

        /// Model-based PBT for capped proportional allocation:
        /// - permutation invariance (input order)
        /// - scale invariance (multiplying all weights)
        /// - budget/cap/sortedness invariants
        #[test]
        fn pbt_asde_allocation_invariants(
            n in 1usize..=32usize,
            weights in prop::collection::vec(0u16..=1000u16, 1..=32),
            caps in prop::collection::vec(0u32..=1_000_000u32, 1..=32),
            budget in 0u32..=1_000_000u32
        ) {
            let n = n.min(weights.len()).min(caps.len());
            let mut inputs: Vec<AllocationInputV1> = Vec::with_capacity(n);
            for i in 0..n {
                inputs.push(AllocationInputV1 {
                    user_pubkey: [i as u8; 32],
                    weight: weights[i] as u128,
                    cap_sfa: Some(caps[i] as u128),
                });
            }

            let budget = budget as u128;
            let out = capped_proportional_allocate_v1(&inputs, budget).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let out_rev = capped_proportional_allocate_v1(&inputs.iter().cloned().rev().collect::<Vec<_>>(), budget)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(&out, &out_rev, "permutation invariance failed");

            let mut inputs_scaled = inputs.clone();
            for item in &mut inputs_scaled {
                item.weight *= 7;
            }
            let out_scaled = capped_proportional_allocate_v1(&inputs_scaled, budget)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(&out, &out_scaled, "scale invariance failed");

            // Sortedness, caps, and budget.
            for w in out.windows(2) {
                prop_assert!(w[0].user_pubkey <= w[1].user_pubkey);
            }

            let mut total = 0u128;
            for o in &out {
                let input = inputs.iter().find(|i| i.user_pubkey == o.user_pubkey).unwrap();
                prop_assert!(input.weight > 0);
                let cap = input.cap_sfa.unwrap();
                prop_assert!(o.amount_sfa <= cap);
                total = total.checked_add(o.amount_sfa).ok_or_else(|| TestCaseError::fail("sum overflow"))?;
            }
            let total_cap: u128 = inputs.iter().filter(|i| i.weight > 0).map(|i| i.cap_sfa.unwrap()).sum();
            prop_assert!(total <= budget.min(total_cap));
        }
    }
}
