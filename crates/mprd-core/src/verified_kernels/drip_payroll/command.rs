//! Commands for drip_payroll.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Approve,
    FinalizeEpoch,
    PayRecipient { amt: u64 },
}
