//! Commands for mprd_v6_fee_lanes_bcr_caps.


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    ApplyTx { base_fee: u64, tip: u64, offset_req: u64 },
}
