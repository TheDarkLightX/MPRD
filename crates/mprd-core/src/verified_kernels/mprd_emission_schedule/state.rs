//! State struct for mprd_emission_schedule.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub emission_rate: u64,
    pub epoch: u64,
    pub epoch_budget: u64,
    pub halving_period: u64,
    pub total_emitted: u64,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            epoch: 0,
            epoch_budget: 0,
            total_emitted: 0,
            halving_period: 10,
            emission_rate: 1000,
        }
    }
}
