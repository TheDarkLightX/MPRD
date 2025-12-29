//! Domain types for tau_attestation_replay_guard.
//! Generated from IR hash: 9652e0520d8186cc
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
    Accepted,
    Rejected,
}
