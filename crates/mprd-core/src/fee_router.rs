//! Fee router primitives (settlement receipt commitments).
//!
//! This module provides canonical commitment formats for proving that a router
//! actually paid Tau Net network fees for settlement (auditability in Mode B).

use crate::{hash, Hash32};

/// Domain tag for Tau settlement receipt commitments.
pub const TAU_SETTLEMENT_RECEIPT_DOMAIN_V1: &[u8] = b"MPRD_TAU_SETTLEMENT_RECEIPT_V1";

/// Compute a settlement receipt commitment binding an L2 batch to a Tau settlement tx.
///
/// Canonical encoding:
/// `tau_tx_id(32) || tau_block_ref(32) || fee_payer(32) || fee_amount_u128_le(16) || batch_id(32)`.
pub fn settlement_receipt_hash_v1(
    tau_tx_id: Hash32,
    tau_block_ref: Hash32,
    fee_payer: Hash32,
    fee_amount: u128,
    batch_id: Hash32,
) -> Hash32 {
    let mut bytes =
        Vec::with_capacity(TAU_SETTLEMENT_RECEIPT_DOMAIN_V1.len() + 32 + 32 + 32 + 16 + 32);
    bytes.extend_from_slice(TAU_SETTLEMENT_RECEIPT_DOMAIN_V1);
    bytes.extend_from_slice(&tau_tx_id.0);
    bytes.extend_from_slice(&tau_block_ref.0);
    bytes.extend_from_slice(&fee_payer.0);
    bytes.extend_from_slice(&fee_amount.to_le_bytes());
    bytes.extend_from_slice(&batch_id.0);
    Hash32(hash::sha256(&bytes).0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> Hash32 {
        Hash32([b; 32])
    }

    #[test]
    fn settlement_receipt_is_deterministic() {
        let a = settlement_receipt_hash_v1(h(1), h(2), h(3), 123, h(4));
        let b = settlement_receipt_hash_v1(h(1), h(2), h(3), 123, h(4));
        assert_eq!(a, b);
    }

    #[test]
    fn settlement_receipt_changes_on_any_field() {
        let base = settlement_receipt_hash_v1(h(1), h(2), h(3), 123, h(4));
        assert_ne!(
            base,
            settlement_receipt_hash_v1(h(9), h(2), h(3), 123, h(4))
        );
        assert_ne!(
            base,
            settlement_receipt_hash_v1(h(1), h(9), h(3), 123, h(4))
        );
        assert_ne!(
            base,
            settlement_receipt_hash_v1(h(1), h(2), h(9), 123, h(4))
        );
        assert_ne!(
            base,
            settlement_receipt_hash_v1(h(1), h(2), h(3), 124, h(4))
        );
        assert_ne!(
            base,
            settlement_receipt_hash_v1(h(1), h(2), h(3), 123, h(9))
        );
    }
}
