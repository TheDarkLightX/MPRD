//! Commands for mprd_emission_schedule.


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    AdvanceEpoch,
    EmitTokens { amt: u64 },
    HalveRate,
}
