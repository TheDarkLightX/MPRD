//! Domain types for executor_circuit_breaker.
//! Generated from IR hash: 2e37ba431252acc0
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
pub enum StatePhase {
    Closed,
    Open,
    Halfopen,
}
