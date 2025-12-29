//! Commands for fee_distribution.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Burn { amt: u64 },
    Collect { amt: u64 },
    Distribute { amt: u64 },
    Finalize,
}
