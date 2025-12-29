//! State struct for mprd_v6_fee_lanes_bcr_caps.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub base_fee_gross: u64,
    pub offset_total: u64,
    pub payer_bcr: u64,
    pub servicer_tip_total: u64,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            base_fee_gross: 0,
            offset_total: 0,
            payer_bcr: 8,
            servicer_tip_total: 0,
        }
    }
}
