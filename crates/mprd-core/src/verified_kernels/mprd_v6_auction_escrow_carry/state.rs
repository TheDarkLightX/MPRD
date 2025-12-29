//! State struct for mprd_v6_auction_escrow_carry.


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub auction_carry: u64,
    pub bcr_balance: u64,
    pub bcr_escrow: u64,
    pub bid1_qty: u64,
    pub bid2_qty: u64,
    pub burned_total: u64,
    pub last_bcr_burned: u64,
    pub last_payout_total: u64,
    pub locked_total: u64,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            bcr_balance: 6,
            bcr_escrow: 0,
            bid1_qty: 0,
            bid2_qty: 0,
            auction_carry: 0,
            burned_total: 0,
            locked_total: 0,
            last_payout_total: 0,
            last_bcr_burned: 0,
        }
    }
}
