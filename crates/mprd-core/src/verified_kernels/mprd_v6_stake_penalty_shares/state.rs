//! State struct for mprd_v6_stake_penalty_shares.


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub agrs_balance: u64,
    pub auction_carry: u64,
    pub burned_total: u64,
    pub shares_active: u64,
    pub stake_active: bool,
    pub stake_amount: u64,
    pub stake_shares: u64,
    pub total_shares_issued: u64,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            agrs_balance: 10,
            shares_active: 0,
            total_shares_issued: 0,
            stake_active: false,
            stake_amount: 0,
            stake_shares: 0,
            auction_carry: 0,
            burned_total: 0,
        }
    }
}
