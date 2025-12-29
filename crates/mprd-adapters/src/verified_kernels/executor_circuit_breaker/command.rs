//! Commands for executor_circuit_breaker.

use super::types::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    RecordSuccess,
    RecordFailure,
    Tick,
    TryHalfOpen,
    ManualReset,
}
