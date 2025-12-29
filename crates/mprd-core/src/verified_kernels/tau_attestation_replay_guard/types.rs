//! Domain types for tau_attestation_replay_guard.
//! Generated from IR hash: 9652e0520d8186cc
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
pub enum ModelResult {
    Pending,
    Accepted,
    Rejected,
}
impl Default for ModelResult {
    fn default() -> Self {
        Self::Pending
    }
}
