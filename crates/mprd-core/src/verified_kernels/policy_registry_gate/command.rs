//! Commands for policy_registry_gate.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    AdvanceEpoch { new_epoch: u64 },
    Freeze,
    RegisterPolicy { block_height: u64 },
}
