//! Commands for nonce_manager_lifecycle.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    AdvanceWindow,
    ConsumeNonce { nonce_time: u64 },
    SetWindowSize { new_size: u64 },
    TickTime { new_time: u64 },
}
