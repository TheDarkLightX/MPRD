//! Commands for tau_attestation_replay_guard.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Accept,
    ChainBreaks,
    ReceiveStale,
    Reject,
}
