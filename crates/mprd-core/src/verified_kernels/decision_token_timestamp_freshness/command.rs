//! Commands for decision_token_timestamp_freshness.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Reject,
    TokenExpires,
    TokenFuture,
    ValidateFresh,
}
