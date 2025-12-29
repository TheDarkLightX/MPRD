use crate::types::{BoundedMap, ErrorCode, Hash32, RelayClaimConfig, MAX_CLAIMS};

pub type Time = u64;
pub type Amount = u64;
pub type RelayId = u64;
pub type ChallengerId = u64;
pub type ClaimId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitArgs {
    pub cid: ClaimId,
    pub relay: RelayId,
    pub bond: Amount,
    pub job: Hash32,
    pub res: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimPhase {
    Committed,
    Challenged {
        challenger: ChallengerId,
        bond_challenger: Amount,
        round: u32,
    },
    Resolved {
        challenger: ChallengerId,
        bond_challenger: Amount,
        verdict: bool,
    },
    FinalizedUnchallenged,
    FinalizedResolved {
        challenger: ChallengerId,
        bond_challenger: Amount,
        verdict: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    relay: RelayId,
    job_hash: Hash32,
    result_hash: Hash32,
    bond_relay: Amount,
    challenge_deadline: Time,
    max_rounds: u32,
    phase: ClaimPhase,
}

impl Claim {
    pub fn phase(&self) -> ClaimPhase {
        self.phase
    }

    pub fn relay(&self) -> RelayId {
        self.relay
    }

    pub fn challenger(&self) -> Option<ChallengerId> {
        match self.phase {
            ClaimPhase::Challenged { challenger, .. }
            | ClaimPhase::Resolved { challenger, .. }
            | ClaimPhase::FinalizedResolved { challenger, .. } => Some(challenger),
            ClaimPhase::Committed | ClaimPhase::FinalizedUnchallenged => None,
        }
    }

    pub fn job_hash(&self) -> Hash32 {
        self.job_hash
    }

    pub fn result_hash(&self) -> Hash32 {
        self.result_hash
    }

    pub fn bond_relay(&self) -> Amount {
        self.bond_relay
    }

    pub fn bond_challenger(&self) -> Amount {
        match self.phase {
            ClaimPhase::Challenged {
                bond_challenger, ..
            }
            | ClaimPhase::Resolved {
                bond_challenger, ..
            }
            | ClaimPhase::FinalizedResolved {
                bond_challenger, ..
            } => bond_challenger,
            ClaimPhase::Committed | ClaimPhase::FinalizedUnchallenged => 0,
        }
    }

    pub fn challenge_deadline(&self) -> Time {
        self.challenge_deadline
    }

    pub fn round(&self) -> u32 {
        match self.phase {
            ClaimPhase::Challenged { round, .. } => round,
            ClaimPhase::Resolved { .. } | ClaimPhase::FinalizedResolved { .. } => self.max_rounds,
            ClaimPhase::Committed | ClaimPhase::FinalizedUnchallenged => 0,
        }
    }

    pub fn max_rounds(&self) -> u32 {
        self.max_rounds
    }

    pub fn verdict(&self) -> Option<bool> {
        match self.phase {
            ClaimPhase::Resolved { verdict, .. }
            | ClaimPhase::FinalizedResolved { verdict, .. } => Some(verdict),
            ClaimPhase::Committed
            | ClaimPhase::Challenged { .. }
            | ClaimPhase::FinalizedUnchallenged => None,
        }
    }

    pub fn relay_bond_slashed(&self) -> bool {
        self.verdict() == Some(false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySM {
    now: Time,
    config: RelayClaimConfig,
    claims: BoundedMap<ClaimId, Claim>,
}

impl RelaySM {
    pub fn new(config: RelayClaimConfig) -> Self {
        Self {
            now: 0,
            config,
            claims: BoundedMap::new(MAX_CLAIMS),
        }
    }

    pub fn new_checked(challenge_window: Time, max_rounds: u32) -> Result<Self, ErrorCode> {
        Ok(Self::new(RelayClaimConfig::new(
            challenge_window,
            max_rounds,
        )?))
    }

    pub fn now(&self) -> Time {
        self.now
    }

    pub fn config(&self) -> &RelayClaimConfig {
        &self.config
    }

    pub fn claim(&self, cid: ClaimId) -> Option<&Claim> {
        self.claims.get(&cid)
    }

    pub fn claims_iter(&self) -> impl Iterator<Item = (&ClaimId, &Claim)> {
        self.claims.iter()
    }

    pub fn step(
        &mut self,
        action: Action,
        correct: &impl Fn(Hash32, Hash32) -> bool,
    ) -> Result<(), ErrorCode> {
        match action {
            Action::Commit {
                cid,
                relay,
                bond,
                job,
                res,
            } => self.commit(CommitArgs {
                cid,
                relay,
                bond,
                job,
                res,
            }),
            Action::Challenge {
                cid,
                challenger,
                bond,
            } => self.challenge(cid, challenger, bond),
            Action::AdvanceRound { cid } => self.advance_round(cid),
            Action::Resolve { cid, verdict } => self.resolve(cid, verdict, correct),
            Action::Finalize { cid } => self.finalize(cid),
            Action::Tick { dt } => self.tick(dt),
        }
    }

    pub fn commit(&mut self, args: CommitArgs) -> Result<(), ErrorCode> {
        let CommitArgs {
            cid,
            relay,
            bond,
            job,
            res,
        } = args;
        if self.claims.contains_key(&cid) {
            return Err(ErrorCode::ClaimNotEmpty);
        }

        let challenge_deadline = self
            .now
            .checked_add(self.config.challenge_window)
            .ok_or(ErrorCode::ArithmeticOverflow)?;

        let cl = Claim {
            relay,
            job_hash: job,
            result_hash: res,
            bond_relay: bond,
            challenge_deadline,
            max_rounds: self.config.max_rounds,
            phase: ClaimPhase::Committed,
        };

        self.claims
            .insert(cid, cl)
            .map_err(|_| ErrorCode::CapacityExceeded)?;
        Ok(())
    }

    pub fn challenge(
        &mut self,
        cid: ClaimId,
        challenger: ChallengerId,
        bond: Amount,
    ) -> Result<(), ErrorCode> {
        let cl = self.claims.get_mut(&cid).ok_or(ErrorCode::ClaimMissing)?;

        if cl.phase != ClaimPhase::Committed {
            return Err(ErrorCode::ClaimWrongPhase);
        }
        if self.now > cl.challenge_deadline {
            return Err(ErrorCode::ChallengeWindowPassed);
        }

        cl.phase = ClaimPhase::Challenged {
            challenger,
            bond_challenger: bond,
            round: 0,
        };
        Ok(())
    }

    pub fn advance_round(&mut self, cid: ClaimId) -> Result<(), ErrorCode> {
        let cl = self.claims.get_mut(&cid).ok_or(ErrorCode::ClaimMissing)?;
        let (challenger, bond_challenger, round) = match cl.phase {
            ClaimPhase::Challenged {
                challenger,
                bond_challenger,
                round,
            } => (challenger, bond_challenger, round),
            _ => return Err(ErrorCode::ClaimWrongPhase),
        };

        if round >= cl.max_rounds {
            return Err(ErrorCode::MaxRoundsExceeded);
        }
        let next_round = round.checked_add(1).ok_or(ErrorCode::ArithmeticOverflow)?;

        cl.phase = ClaimPhase::Challenged {
            challenger,
            bond_challenger,
            round: next_round,
        };
        Ok(())
    }

    pub fn resolve(
        &mut self,
        cid: ClaimId,
        verdict: bool,
        correct: &impl Fn(Hash32, Hash32) -> bool,
    ) -> Result<(), ErrorCode> {
        let cl = self.claims.get_mut(&cid).ok_or(ErrorCode::ClaimMissing)?;
        let (challenger, bond_challenger, round) = match cl.phase {
            ClaimPhase::Challenged {
                challenger,
                bond_challenger,
                round,
            } => (challenger, bond_challenger, round),
            _ => return Err(ErrorCode::ClaimWrongPhase),
        };

        if round != cl.max_rounds {
            return Err(ErrorCode::RoundsNotComplete);
        }
        if verdict != correct(cl.job_hash, cl.result_hash) {
            return Err(ErrorCode::VerdictIncorrect);
        }

        cl.phase = ClaimPhase::Resolved {
            challenger,
            bond_challenger,
            verdict,
        };
        Ok(())
    }

    pub fn finalize(&mut self, cid: ClaimId) -> Result<(), ErrorCode> {
        let cl = self.claims.get_mut(&cid).ok_or(ErrorCode::ClaimMissing)?;
        match cl.phase {
            ClaimPhase::Committed => {
                if cl.challenge_deadline >= self.now {
                    return Err(ErrorCode::ChallengeWindowNotPassed);
                }
                cl.phase = ClaimPhase::FinalizedUnchallenged;
                Ok(())
            }
            ClaimPhase::Resolved {
                challenger,
                bond_challenger,
                verdict,
            } => {
                cl.phase = ClaimPhase::FinalizedResolved {
                    challenger,
                    bond_challenger,
                    verdict,
                };
                Ok(())
            }
            _ => Err(ErrorCode::ClaimWrongPhase),
        }
    }

    pub fn tick(&mut self, dt: Time) -> Result<(), ErrorCode> {
        self.now = self
            .now
            .checked_add(dt)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        Ok(())
    }

    pub fn validate_invariants(&self) -> Result<(), OptimisticRelayInvariantViolation> {
        for (cid, cl) in self.claims.iter() {
            if let ClaimPhase::Challenged { round, .. } = cl.phase {
                if round > cl.max_rounds {
                    return Err(OptimisticRelayInvariantViolation::I3RoundBound { cid: *cid });
                }
            }
        }
        Ok(())
    }
}

impl Default for RelaySM {
    fn default() -> Self {
        Self::new(RelayClaimConfig::new(1, 1).expect("default config is valid"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Commit {
        cid: ClaimId,
        relay: RelayId,
        bond: Amount,
        job: Hash32,
        res: Hash32,
    },
    Challenge {
        cid: ClaimId,
        challenger: ChallengerId,
        bond: Amount,
    },
    AdvanceRound {
        cid: ClaimId,
    },
    Resolve {
        cid: ClaimId,
        verdict: bool,
    },
    Finalize {
        cid: ClaimId,
    },
    Tick {
        dt: Time,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptimisticRelayInvariantViolation {
    I1Soundness { cid: ClaimId },
    I2PhaseShape { cid: ClaimId },
    I3RoundBound { cid: ClaimId },
}

impl std::fmt::Display for OptimisticRelayInvariantViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OptimisticRelayInvariantViolation::I1Soundness { cid } => write!(
                f,
                "I1 violated at claim {cid}: wrong verdict without relay bond slashed"
            ),
            OptimisticRelayInvariantViolation::I2PhaseShape { cid } => write!(
                f,
                "I2 violated at claim {cid}: phase/fields shape inconsistent"
            ),
            OptimisticRelayInvariantViolation::I3RoundBound { cid } => {
                write!(f, "I3 violated at claim {cid}: round > max_rounds")
            }
        }
    }
}

impl std::error::Error for OptimisticRelayInvariantViolation {}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn h(b: u8) -> Hash32 {
        [b; 32]
    }

    fn correct(job: Hash32, res: Hash32) -> bool {
        job == res
    }

    #[test]
    fn unchallenged_commit_finalizes_after_window() {
        let cfg = RelayClaimConfig::new(10, 1).expect("config");
        let mut m = RelaySM::new(cfg);
        m.commit(CommitArgs {
            cid: 1,
            relay: 7,
            bond: 100,
            job: h(111),
            res: h(222),
        })
        .expect("commit");
        m.tick(11).expect("tick");
        m.finalize(1).expect("finalize");
        assert_eq!(
            m.claim(1).map(|c| c.phase()),
            Some(ClaimPhase::FinalizedUnchallenged)
        );
        m.validate_invariants().expect("invariants");
    }

    #[test]
    fn challenged_claim_resolves_and_slashes_on_wrong_result() {
        let cfg = RelayClaimConfig::new(10, 1).expect("config");
        let mut m = RelaySM::new(cfg);
        let cid = 1;
        m.commit(CommitArgs {
            cid,
            relay: 7,
            bond: 100,
            job: h(111),
            res: h(222),
        })
        .expect("commit");
        m.challenge(cid, 9, 50).expect("challenge");
        m.advance_round(cid).expect("advance");
        assert!(m.resolve(cid, false, &correct).is_ok());
        m.finalize(cid).expect("finalize");
        let cl = m.claim(cid).expect("claim");
        assert_eq!(
            cl.phase(),
            ClaimPhase::FinalizedResolved {
                challenger: 9,
                bond_challenger: 50,
                verdict: false
            }
        );
        assert_eq!(cl.verdict(), Some(false));
        assert!(cl.relay_bond_slashed());
        m.validate_invariants().expect("invariants");
    }

    #[test]
    fn resolve_rejects_incorrect_verdict() {
        let cfg = RelayClaimConfig::new(10, 1).expect("config");
        let mut m = RelaySM::new(cfg);
        let cid = 1;
        m.commit(CommitArgs {
            cid,
            relay: 7,
            bond: 100,
            job: h(123),
            res: h(123),
        })
        .expect("commit");
        m.challenge(cid, 9, 50).expect("challenge");
        m.advance_round(cid).expect("advance");
        assert!(m.resolve(cid, false, &correct).is_err());
        m.validate_invariants().expect("invariants");
    }

    proptest! {
        #[test]
        fn random_actions_never_break_invariants(actions in proptest::collection::vec(any::<u8>(), 0..256)) {
            let cfg = RelayClaimConfig::new(8, 3).expect("config");
            let mut m = RelaySM::new(cfg);
            prop_assert!(m.validate_invariants().is_ok());

            for b in actions {
                let cid = (b as u64) % 8;
                let action = match b % 6 {
                    0 => Action::Commit { cid, relay: b as u64, bond: b as u64, job: [b; 32], res: [b.wrapping_add(1); 32] },
                    1 => Action::Challenge { cid, challenger: b as u64, bond: b as u64 },
                    2 => Action::AdvanceRound { cid },
                    3 => Action::Resolve { cid, verdict: (b % 2) == 0 },
                    4 => Action::Finalize { cid },
                    _ => Action::Tick { dt: (b as u64) % 8 },
                };

                let _ = m.step(action, &correct);
                prop_assert!(m.validate_invariants().is_ok());
            }
        }
    }
}
