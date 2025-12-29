//! Domain types for selector_canonical_tiebreak.
//! Generated from IR hash: 9360e372b178f654
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
pub enum ChosenPhase {
    None,
    A,
    B,
}
