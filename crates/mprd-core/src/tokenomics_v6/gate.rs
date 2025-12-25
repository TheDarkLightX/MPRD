use crate::{MprdError, Result};

use super::actions::ActionV6;
use super::engine::TokenomicsV6;

/// Authorization hook for tokenomics v6 state transitions.
///
/// This is the explicit "rail" check: the v6 engine calls `check()` before mutating state.
///
/// Notes:
/// - This trait should remain IO-free in `mprd-core`; adapters may perform IO externally and then
///   implement a pure `check()` over already-verified evidence.
/// - A production gate should bind its decision to a specific `(policy_hash, state_hash, action_hash)`
///   and (optionally) verify a ZK receipt, consistent with the MPRD decision rail pattern.
pub trait PolicyGateV6 {
    fn check(&self, eng: &TokenomicsV6, action: &ActionV6) -> Result<()>;
}

/// Gate that allows all actions (useful for simulation/tests).
pub struct AllowAllGateV6;

impl PolicyGateV6 for AllowAllGateV6 {
    fn check(&self, _eng: &TokenomicsV6, _action: &ActionV6) -> Result<()> {
        Ok(())
    }
}

/// Gate that denies all actions (useful for tests).
pub struct DenyAllGateV6;

impl PolicyGateV6 for DenyAllGateV6 {
    fn check(&self, _eng: &TokenomicsV6, _action: &ActionV6) -> Result<()> {
        Err(MprdError::InvalidInput("policy denied tokenomics action".into()))
    }
}

