//! Commands for optimistic_relay_claim.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Challenge,
    Commit,
    Finalize,
    Resolve,
    Slash,
}
