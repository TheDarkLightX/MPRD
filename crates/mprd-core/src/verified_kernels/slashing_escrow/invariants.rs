//! Invariant checker for slashing_escrow.

use super::{state::State, types::*};

/// Check all invariants. Returns Err if any violated.
pub fn check_invariants(state: &State) -> Result<(), Error> {
    if state.bond_amount < 100u64 || state.bond_amount > 10000u64 {
        return Err(Error::DomainViolation("bond_amount"));
    }
    if state.challenge_deadline < 0u64 || state.challenge_deadline > 100u64 {
        return Err(Error::DomainViolation("challenge_deadline"));
    }

    // ActiveDeadlinePositive
    if !((!((Phase::Challenged == state.phase) || (Phase::Locked == state.phase)))
        || (state.challenge_deadline > 0))
    {
        return Err(Error::InvariantViolation("ActiveDeadlinePositive"));
    }

    // EvidenceOnlyWhenChallenged
    if !((!state.evidence_submitted)
        || ((Phase::Challenged == state.phase) || (Phase::Slashed == state.phase)))
    {
        return Err(Error::InvariantViolation("EvidenceOnlyWhenChallenged"));
    }

    // LockedNoEvidence
    if !((!(Phase::Locked == state.phase)) || (false == state.evidence_submitted)) {
        return Err(Error::InvariantViolation("LockedNoEvidence"));
    }

    // NonTrivialBond
    if !(state.bond_amount >= 100) {
        return Err(Error::InvariantViolation("NonTrivialBond"));
    }

    // ObjectiveSlashing
    if !((!(Phase::Slashed == state.phase)) || (true == state.evidence_submitted)) {
        return Err(Error::InvariantViolation("ObjectiveSlashing"));
    }

    // ReleasedNoEvidence
    if !((!(Phase::Released == state.phase)) || (false == state.evidence_submitted)) {
        return Err(Error::InvariantViolation("ReleasedNoEvidence"));
    }

    // ResolvedDeadlineZero
    if !((!((Phase::Released == state.phase) || (Phase::Slashed == state.phase)))
        || (0 == state.challenge_deadline))
    {
        return Err(Error::InvariantViolation("ResolvedDeadlineZero"));
    }

    Ok(())
}
