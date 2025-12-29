//! Commands for selector_canonical_tiebreak.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    SelectByScore,
    SelectCanonical,
    SetupAWinsScore,
    SetupBWinsScore,
    SetupTieACanonical,
    SetupTieBCanonical,
}
