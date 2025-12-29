//! State struct for reverse_auction.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub best_bid: u64,
    pub bid_count: u64,
    pub phase: Phase,
    pub winner_set: bool,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            phase: Phase::Open,
            best_bid: 1000,
            winner_set: false,
            bid_count: 0,
        }
    }
}
