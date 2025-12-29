//! State struct for selector_canonical_tiebreak.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub a_score_higher: bool,
    pub both_allowed: bool,
    pub canonical_a_lt_b: bool,
    pub chosen: Chosen,
    pub score_tie: bool,
}

impl State {
    /// Create initial state (from model 'init' section).
    pub fn init() -> Self {
        Self {
            both_allowed: false,
            score_tie: false,
            canonical_a_lt_b: true,
            a_score_higher: true,
            chosen: Chosen::None,
        }
    }
}
