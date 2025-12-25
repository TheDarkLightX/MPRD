use crate::{hash, Hash32, MprdError, Result};

use super::math::{add_u64, mul_div_floor_u64, sub_u64};
use super::types::{Agrs, AgrsPerBcr, Bcr, OperatorId};

/// Domain tag for canonical bid hashing (v1).
pub const AUCTION_BID_HASH_DOMAIN_V1: &[u8] = b"MPRD_TOKENOMICS_V6_AUCTION_BID_V1";

/// Auction bid (reverse auction): MARKET INPUT.
///
/// Operators sell BCR to the protocol in exchange for (locked) AGRS.
/// Each bid specifies a quantity and a minimum acceptable price.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuctionBid {
    /// Bidder / BCR seller.
    pub operator: OperatorId,
    /// Quantity of BCR offered (will be burned if this bid clears).
    pub qty_bcr: Bcr,
    /// Minimum acceptable price: MARKET-DETERMINED.
    /// Expressed as AGRS per 1 BCR (integer, in smallest AGRS units).
    pub min_price: AgrsPerBcr,
    /// Per-bid nonce contributing to deterministic tie-breaking.
    pub nonce: Hash32,
    /// Canonical bid commitment hash (domain-separated) used for deterministic ordering.
    pub bid_hash: Hash32,
}

impl AuctionBid {
    /// Constructs a bid and computes its canonical `bid_hash`.
    ///
    /// Preconditions:
    /// - `qty_bcr > 0` (empty bids are rejected; fail-closed).
    pub fn new(
        operator: OperatorId,
        qty_bcr: Bcr,
        min_price: AgrsPerBcr,
        nonce: Hash32,
    ) -> Result<AuctionBid> {
        if qty_bcr.get() == 0 {
            return Err(MprdError::InvalidInput("bid qty_bcr must be > 0".into()));
        }
        let bid_hash = bid_hash_v1(operator, qty_bcr, min_price, nonce);
        Ok(AuctionBid {
            operator,
            qty_bcr,
            min_price,
            nonce,
            bid_hash,
        })
    }
}

/// Computes the canonical v1 bid hash.
///
/// Rationale: sorting uses `(min_price, bid_hash)`; the hash gives a stable, deterministic
/// tie-breaker that is independent of insertion order or host platform.
pub fn bid_hash_v1(
    operator: OperatorId,
    qty_bcr: Bcr,
    min_price: AgrsPerBcr,
    nonce: Hash32,
) -> Hash32 {
    // Canonical preimage:
    // domain || operator(32) || qty_u64_le || price_u64_le || nonce(32)
    let mut bytes = Vec::with_capacity(AUCTION_BID_HASH_DOMAIN_V1.len() + 32 + 8 + 8 + 32);
    bytes.extend_from_slice(AUCTION_BID_HASH_DOMAIN_V1);
    bytes.extend_from_slice(&operator.0 .0);
    bytes.extend_from_slice(&qty_bcr.get().to_le_bytes());
    bytes.extend_from_slice(&min_price.get().to_le_bytes());
    bytes.extend_from_slice(&nonce.0);
    hash::sha256(&bytes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuctionClearing {
    /// Clearing price: MARKET-DETERMINED.
    /// Set by the uniform-price prefix-clearing auction.
    pub clearing_price: AgrsPerBcr,
    /// Winning bids (sorted by `(min_price asc, bid_hash asc)`).
    pub winners: Vec<AuctionBid>,
    /// Total BCR purchased (and burned) at clearing.
    pub qty_total: Bcr,
    /// Total payout to winners: `clearing_price * qty_total` (always `<= budget`).
    pub payout_total: Agrs,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuctionOutcome {
    /// Clearing price: MARKET-DETERMINED.
    pub clearing_price: AgrsPerBcr,
    /// Total BCR burned as a result of settlement.
    pub qty_bcr_burned: Bcr,
    /// Total AGRS paid out to winners (locked by the engine).
    pub payout_total: Agrs,
    /// Next epoch carry-in (capped).
    pub carry_out: Agrs,
    /// Budget excess burned due to the carry cap.
    pub burn_excess: Agrs,
    /// Winner count (kept separately to avoid cloning `winners` into outcomes).
    pub winners_len: usize,
}

/// Deterministic v6 clearing (reverse auction; uniform price; budget-bounded).
///
/// Market-determined output: `AuctionClearing::clearing_price`.
///
/// Algorithm: sort bids by `(min_price asc, bid_hash asc)` and take the largest prefix such that
/// `clearing_price * Σqty <= budget`. All winners are paid the final (highest accepted) price.
///
/// Postcondition: `payout_total <= budget` (fail-closed on overflow or inconsistency).
pub fn clear_prefix_budget(budget: Agrs, bids: &[AuctionBid]) -> Result<AuctionClearing> {
    if budget.get() == 0 {
        return Ok(AuctionClearing {
            clearing_price: AgrsPerBcr::new(0),
            winners: Vec::new(),
            qty_total: Bcr::ZERO,
            payout_total: Agrs::ZERO,
        });
    }

    let mut sorted: Vec<AuctionBid> = bids.to_vec();
    sorted.sort_by(|a, b| {
        let ap = a.min_price.get();
        let bp = b.min_price.get();
        ap.cmp(&bp).then_with(|| a.bid_hash.cmp(&b.bid_hash))
    });

    let mut winners: Vec<AuctionBid> = Vec::new();
    let mut qty_sum: u64 = 0;
    let mut price: u64 = 0;

    for b in sorted {
        let q_next = add_u64(qty_sum, b.qty_bcr.get())?;
        let p_next = b.min_price.get();

        let cost_next_u128 = (p_next as u128)
            .checked_mul(q_next as u128)
            .ok_or_else(|| MprdError::BoundedValueExceeded("auction cost overflow".into()))?;
        if cost_next_u128 <= budget.get() as u128 {
            winners.push(b);
            qty_sum = q_next;
            price = p_next;
        } else {
            break;
        }
    }

    let payout_total = (price as u128)
        .checked_mul(qty_sum as u128)
        .ok_or_else(|| MprdError::BoundedValueExceeded("auction payout overflow".into()))?;
    if payout_total > budget.get() as u128 {
        return Err(MprdError::InvalidInput(
            "auction payout exceeds budget (unexpected)".into(),
        ));
    }

    Ok(AuctionClearing {
        clearing_price: AgrsPerBcr::new(price),
        winners,
        qty_total: Bcr::new(qty_sum),
        payout_total: Agrs::new(u64::try_from(payout_total).map_err(|_| {
            MprdError::BoundedValueExceeded("auction payout does not fit u64".into())
        })?),
    })
}

/// Computes the uniform-price payout for a winning bid.
pub fn payout_for(qty_bcr: Bcr, clearing_price: AgrsPerBcr) -> Result<Agrs> {
    mul_div_floor_u64(qty_bcr.get(), clearing_price.get(), 1).map(Agrs::new)
}

/// Applies a carry cap to leftover auction funds.
///
/// Rationale: carry smooths the auction budget across epochs (no “dust loss”), while the cap
/// prevents indefinite hoarding; excess beyond the cap is burned.
///
/// Postconditions:
/// - `carry <= cap`
/// - `carry + burn_excess = leftover` (conservation)
pub fn apply_carry_cap(leftover: Agrs, cap: Agrs) -> Result<(Agrs, Agrs)> {
    let carry = leftover.get().min(cap.get());
    let burn_excess = sub_u64(leftover.get(), carry)?;
    Ok((Agrs::new(carry), Agrs::new(burn_excess)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn op(b: u8) -> OperatorId {
        OperatorId(Hash32([b; 32]))
    }

    proptest! {
        #[test]
        fn clearing_never_exceeds_budget(
            budget in 0u64..1_000_000u64,
            bids in proptest::collection::vec((1u64..10_000u64, 0u64..10_000u64, any::<u8>()), 0..64),
        ) {
            let mut v = Vec::new();
            for (qty, price, salt) in bids {
                let bid = AuctionBid::new(op(salt), Bcr::new(qty), AgrsPerBcr::new(price), Hash32([salt; 32])).unwrap();
                v.push(bid);
            }
            let c = clear_prefix_budget(Agrs::new(budget), &v).unwrap();
            prop_assert!(c.payout_total.get() <= budget);
        }

        #[test]
        fn carry_cap_conserves_leftover(
            leftover in 0u64..10_000_000u64,
            cap in 0u64..10_000_000u64,
        ) {
            let (carry, burn) = apply_carry_cap(Agrs::new(leftover), Agrs::new(cap)).unwrap();
            prop_assert!(carry.get() <= cap);
            prop_assert_eq!(carry.get() + burn.get(), leftover);
        }
    }
}
