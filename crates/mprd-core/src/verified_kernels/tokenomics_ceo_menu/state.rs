//! State struct for tokenomics_ceo_menu.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub auction_units: u64,
    pub burn_units: u64,
    pub drip_units: u64,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            auction_units: 20,
            burn_units: 10,
            drip_units: 10,
        }
    }
}
