//! Domain types for selector_fail_closed_required_limits.
//! Generated from IR hash: 4e2f069a0802ee16
//! DO NOT EDIT - regenerate from model.

#![allow(dead_code)]

use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum Error {
    #[error("Invariant violated: {0}")]
    InvariantViolation(&'static str),
    #[error("Precondition failed: {0}")]
    PreconditionFailed(&'static str),
    #[error("Arithmetic overflow")]
    Overflow,
    #[error("Arithmetic underflow")]
    Underflow,
    #[error("Invalid state transition")]
    InvalidTransition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResultPhase {
    Pending,
    Decision,
    Error,
}
