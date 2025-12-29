//! Commands for rate_limited_withdrawals.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Deposit { amount: u64 },
    EmergencyHalt,
    LiftHalt,
    NewEpoch,
    Pause,
    Resume,
    TickHour,
    Withdraw { amount: u64 },
}
