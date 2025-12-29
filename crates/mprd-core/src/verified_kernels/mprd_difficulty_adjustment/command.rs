//! Commands for mprd_difficulty_adjustment.


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    AdjustDown,
    AdjustUp,
    EndWindow,
    SubmitBlock,
}
