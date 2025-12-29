//! Commands for mprd_v6_auction_escrow_carry.


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    RevealBid1 { qty: u64 },
    RevealBid2 { qty: u64 },
    Settle { auction_new: u64, bcr_burned: u64, payout_total: u64 },
}
