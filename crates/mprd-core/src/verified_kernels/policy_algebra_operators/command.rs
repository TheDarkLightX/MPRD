//! Commands for policy_algebra_operators.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    EvalAnd {
        left_result: bool,
        right_result: bool,
    },
    EvalNot {
        sub_result: bool,
    },
    EvalOr {
        left_result: bool,
        right_result: bool,
    },
    PopComposite,
    PushComposite,
    ResetSession,
}
