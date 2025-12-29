//! Commands for mprd_v6_stake_penalty_shares.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    StakeEnd { penalty: u64 },
    StakeStart { amount: u64, shares: u64 },
}
