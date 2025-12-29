//! Commands for mprd_reward_pool.


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    AddToPool { amt: u64 },
    Finalize,
    PayRecipient { amt: u64 },
    StartDistribution,
}
