//! Commands for slashing_escrow.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Challenge,
    Lock { amt: u64 },
    Release,
    Slash,
    SubmitEvidence,
}
