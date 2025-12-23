//! Deterministic `nonce_or_tx_hash` derivation helpers.
//!
//! Production deployments SHOULD derive `nonce_or_tx_hash` from the triggering request (or chain
//! transaction hash), not from randomness. This makes replay protection and idempotency auditable.
//!
//! The orchestrator accepts an optional caller-provided nonce via
//! `orchestrator::RunOnceInputs::nonce_or_tx_hash`.

use crate::{Hash32, NonceHash};
use sha2::{Digest, Sha256};

/// Domain separation tag for nonce derivation.
pub const NONCE_DOMAIN_V1: &[u8] = b"MPRD_NONCE_OR_TX_HASH_V1";

/// Derive a deterministic `nonce_or_tx_hash` from a request binding.
///
/// `context` should include any replay-scope pinning required by the deployment, e.g.:
/// - scope identifier (service/tenant)
/// - `policy_epoch` and/or `registry_root`
/// - chain ID / network ID
///
/// `request_hash` should be a stable hash of the triggering request / tx.
pub fn derive_nonce_or_tx_hash_v1(context: &[u8], request_hash: &Hash32) -> NonceHash {
    let mut hasher = Sha256::new();
    hasher.update(NONCE_DOMAIN_V1);
    hasher.update((context.len() as u32).to_le_bytes());
    hasher.update(context);
    hasher.update(request_hash.0);
    Hash32(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_derivation_is_deterministic() {
        let ctx = b"scope=demo;registry_root=abc";
        let req = Hash32([7u8; 32]);
        assert_eq!(
            derive_nonce_or_tx_hash_v1(ctx, &req),
            derive_nonce_or_tx_hash_v1(ctx, &req)
        );
    }

    #[test]
    fn nonce_derivation_is_domain_separated() {
        let ctx = b"x";
        let req = Hash32([1u8; 32]);
        let n = derive_nonce_or_tx_hash_v1(ctx, &req);
        assert_ne!(n.0, req.0);
    }
}
