//! Commands for opi_oracle_round.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Aggregate,
    Commit,
    Finalize,
    Reveal,
}
