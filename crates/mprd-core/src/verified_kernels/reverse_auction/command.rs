//! Commands for reverse_auction.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    PlaceBid { amt: u64 },
    Seal,
    Settle,
}
