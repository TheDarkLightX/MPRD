//! Domain types for mprd_operator_mining_round.
//! Generated from IR hash: c74b71cdaf21e05d
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
    Open,
    Closed,
    Proofchecking,
    Evaluated,
    Paid,
    Disputed,
}
impl Default for Phase {
    fn default() -> Self {
        Self::Open
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifierResult {
    Valid,
    Invalid,
    Inconclusive,
}
impl Default for VerifierResult {
    fn default() -> Self {
        Self::Valid
    }
}
