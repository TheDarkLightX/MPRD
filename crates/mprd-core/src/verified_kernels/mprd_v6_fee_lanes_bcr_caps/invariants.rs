//! Invariant checker for mprd_v6_fee_lanes_bcr_caps.

use super::{types::*, state::State};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.base_fee_gross < 0u64 || state.base_fee_gross > 12u64 {
        return Err(Error::DomainViolation("base_fee_gross"));
    }
    if state.offset_total < 0u64 || state.offset_total > 12u64 {
        return Err(Error::DomainViolation("offset_total"));
    }
    if state.payer_bcr < 0u64 || state.payer_bcr > 12u64 {
        return Err(Error::DomainViolation("payer_bcr"));
    }
    if state.servicer_tip_total < 0u64 || state.servicer_tip_total > 12u64 {
        return Err(Error::DomainViolation("servicer_tip_total"));
    }

    // EpochOffsetCap50Pct
    if !((state.offset_total <= ({ let n = state.base_fee_gross.checked_mul(50).ok_or(Error::Overflow)?; let d = 100; if d == 0 { 0 } else { n.div_euclid(d) } }))) {
        return Err(Error::InvariantViolation("EpochOffsetCap50Pct"));
    }

    Ok(())
}
