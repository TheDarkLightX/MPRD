//! Commands for executor_action_preimage_binding.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Execute,
    HashMismatch,
    LimitsBindingFail,
    PreimageMissing,
    Reject,
    SchemaInvalid,
}
