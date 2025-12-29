//! Domain types for fee_distribution.
//! Generated from IR hash: 164fe74e2800ce63
//! DO NOT EDIT - regenerate from model.

#![allow(dead_code)]

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvariantViolation(&'static str),
    PreconditionFailed(&'static str),
    DomainViolation(&'static str),
    ParamDomainViolation(&'static str),
    Overflow,
    Underflow,
    InvalidTransition,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvariantViolation(id) => write!(f, "Invariant violated: {id}"),
            Error::PreconditionFailed(id) => write!(f, "Precondition failed: {id}"),
            Error::DomainViolation(id) => write!(f, "Domain violation: {id}"),
            Error::ParamDomainViolation(id) => write!(f, "Param domain violation: {id}"),
            Error::Overflow => write!(f, "Arithmetic overflow"),
            Error::Underflow => write!(f, "Arithmetic underflow"),
            Error::InvalidTransition => write!(f, "Invalid state transition"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    Collecting,
    Distributing,
    Complete,
}
impl Default for Phase {
    fn default() -> Self {
        Self::Collecting
    }
}
