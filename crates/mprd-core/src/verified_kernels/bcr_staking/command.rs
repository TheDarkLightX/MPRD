//! Commands for bcr_staking.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Bond { amt: u64 },
    FinalizeUnbond,
    Slash,
    Unbond,
}
