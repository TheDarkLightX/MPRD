//! Commands for selector_fail_closed_required_limits.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    LimitsInvalid,
    LimitsMissing,
    NoneAllowed,
    ReceiveAllowed,
    Select,
}
