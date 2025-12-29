//! Commands for reserve_management.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Deposit { amt: u64 },
    EnterEmergency,
    ExitEmergency,
    UpdateCoverage,
    Withdraw { amt: u64 },
}
