//! State struct for mprd_difficulty_adjustment.


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub adjustment_factor: u64,
    pub blocks_in_window: u64,
    pub difficulty_level: u64,
    pub target_rate: u64,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            difficulty_level: 10,
            blocks_in_window: 0,
            target_rate: 10,
            adjustment_factor: 100,
        }
    }
}
