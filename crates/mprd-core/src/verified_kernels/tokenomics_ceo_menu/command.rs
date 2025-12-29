//! Commands for tokenomics_ceo_menu.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    StepAuctionDown,
    StepAuctionUp,
    StepBurnDown,
    StepBurnUp,
    StepDripDown,
    StepDripUp,
}
