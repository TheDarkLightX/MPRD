//! Commands for decision_token_anti_replay_race.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    AClaim,
    AExecute,
    AReject,
    AStartValidate,
    BClaim,
    BExecute,
    BReject,
    BStartValidate,
}
