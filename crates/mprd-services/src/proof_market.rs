use crate::types::{BoundedMap, ErrorCode, MAX_SLOTS};

pub type Time = u64;
pub type Amount = u64;
pub type ProverId = u64;
pub type SlotId = u64;
pub type Hash32 = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotPhase {
    Committed,
    Proving { started_at: Time },
    Settled { payee: ProverId, payout: Amount },
    Expired,
    Slashed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    phase: SlotPhase,
    claimer: ProverId,
    claimer0: ProverId,
    deposit: Amount,
    deadline0: Time,
    deadline: Time,
    job_hash: Hash32,
}

impl Slot {
    pub fn phase(&self) -> SlotPhase {
        self.phase
    }

    pub fn claimer(&self) -> ProverId {
        self.claimer
    }

    pub fn claimer0(&self) -> ProverId {
        self.claimer0
    }

    pub fn deposit(&self) -> Amount {
        self.deposit
    }

    pub fn deadline0(&self) -> Time {
        self.deadline0
    }

    pub fn deadline(&self) -> Time {
        self.deadline
    }

    pub fn job_hash(&self) -> Hash32 {
        self.job_hash
    }

    pub fn proof_verified(&self) -> bool {
        matches!(self.phase, SlotPhase::Settled { .. })
    }

    pub fn proof_binds_job(&self) -> bool {
        matches!(self.phase, SlotPhase::Settled { .. })
    }

    pub fn payee(&self) -> Option<ProverId> {
        match self.phase {
            SlotPhase::Settled { payee, .. } => Some(payee),
            _ => None,
        }
    }

    pub fn payout(&self) -> Amount {
        match self.phase {
            SlotPhase::Settled { payout, .. } => payout,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Market {
    now: Time,
    protocol_subsidy: Amount,
    total_deposits: Amount,
    total_payouts: Amount,
    slots: BoundedMap<SlotId, Slot>,
}

impl Market {
    pub fn new_checked(protocol_subsidy: Amount) -> Result<Self, ErrorCode> {
        Ok(Self {
            now: 0,
            protocol_subsidy,
            total_deposits: 0,
            total_payouts: 0,
            slots: BoundedMap::new(MAX_SLOTS),
        })
    }

    pub fn init(protocol_subsidy: Amount) -> Self {
        Self::new_checked(protocol_subsidy).expect("checked constructor cannot fail")
    }

    pub fn now(&self) -> Time {
        self.now
    }

    pub fn protocol_subsidy(&self) -> Amount {
        self.protocol_subsidy
    }

    pub fn total_deposits(&self) -> Amount {
        self.total_deposits
    }

    pub fn total_payouts(&self) -> Amount {
        self.total_payouts
    }

    pub fn slot(&self, sid: SlotId) -> Option<&Slot> {
        self.slots.get(&sid)
    }

    pub fn slots_iter(&self) -> impl Iterator<Item = (&SlotId, &Slot)> {
        self.slots.iter()
    }

    pub fn step(&mut self, action: Action) -> Result<(), ErrorCode> {
        match action {
            Action::Commit {
                sid,
                p,
                deposit,
                deadline,
                job_hash,
            } => self.commit(sid, p, deposit, deadline, job_hash),
            Action::StartProving { sid } => self.start_proving(sid),
            Action::Settle {
                sid,
                payout,
                job_hash,
            } => self.settle(sid, payout, job_hash),
            Action::Expire { sid } => self.expire(sid),
            Action::Slash { sid } => self.slash(sid),
            Action::Tick { dt } => self.tick(dt),
        }
    }

    pub fn commit(
        &mut self,
        sid: SlotId,
        p: ProverId,
        deposit: Amount,
        deadline: Time,
        job_hash: Hash32,
    ) -> Result<(), ErrorCode> {
        if self.slots.contains_key(&sid) {
            return Err(ErrorCode::SlotNotEmpty);
        }
        if self.now >= deadline {
            return Err(ErrorCode::DeadlinePassed);
        }

        let next_total_deposits = self
            .total_deposits
            .checked_add(deposit)
            .ok_or(ErrorCode::ArithmeticOverflow)?;

        let slot = Slot {
            phase: SlotPhase::Committed,
            claimer: p,
            claimer0: p,
            deposit,
            deadline0: deadline,
            deadline,
            job_hash,
        };

        self.slots
            .insert(sid, slot)
            .map_err(|_| ErrorCode::CapacityExceeded)?;
        self.total_deposits = next_total_deposits;
        Ok(())
    }

    pub fn start_proving(&mut self, sid: SlotId) -> Result<(), ErrorCode> {
        let slot = self.slots.get_mut(&sid).ok_or(ErrorCode::SlotMissing)?;
        if slot.phase != SlotPhase::Committed {
            return Err(ErrorCode::SlotWrongPhase);
        }
        slot.phase = SlotPhase::Proving {
            started_at: self.now,
        };
        Ok(())
    }

    pub fn settle(
        &mut self,
        sid: SlotId,
        payout: Amount,
        job_hash: Hash32,
    ) -> Result<(), ErrorCode> {
        let slot = self.slots.get_mut(&sid).ok_or(ErrorCode::SlotMissing)?;
        if !matches!(slot.phase, SlotPhase::Proving { .. }) {
            return Err(ErrorCode::SlotWrongPhase);
        }
        if self.now > slot.deadline {
            return Err(ErrorCode::DeadlinePassed);
        }
        if payout > slot.deposit {
            return Err(ErrorCode::PayoutExceedsDeposit);
        }
        if slot.job_hash != job_hash {
            return Err(ErrorCode::JobHashMismatch);
        }

        let next_total_payouts = self
            .total_payouts
            .checked_add(payout)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        let budget = self
            .total_deposits
            .checked_add(self.protocol_subsidy)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        if next_total_payouts > budget {
            return Err(ErrorCode::BudgetExceeded);
        }

        self.total_payouts = next_total_payouts;
        slot.phase = SlotPhase::Settled {
            payee: slot.claimer0,
            payout,
        };
        Ok(())
    }

    pub fn expire(&mut self, sid: SlotId) -> Result<(), ErrorCode> {
        let slot = self.slots.get_mut(&sid).ok_or(ErrorCode::SlotMissing)?;
        if !matches!(slot.phase, SlotPhase::Proving { .. }) {
            return Err(ErrorCode::SlotWrongPhase);
        }
        if slot.deadline >= self.now {
            return Err(ErrorCode::DeadlineNotPassed);
        }
        slot.phase = SlotPhase::Expired;
        Ok(())
    }

    pub fn slash(&mut self, sid: SlotId) -> Result<(), ErrorCode> {
        let slot = self.slots.get_mut(&sid).ok_or(ErrorCode::SlotMissing)?;
        if slot.phase != SlotPhase::Expired {
            return Err(ErrorCode::SlotWrongPhase);
        }
        if slot.deadline >= self.now {
            return Err(ErrorCode::DeadlineNotPassed);
        }
        slot.phase = SlotPhase::Slashed;
        Ok(())
    }

    pub fn tick(&mut self, dt: Time) -> Result<(), ErrorCode> {
        self.now = self
            .now
            .checked_add(dt)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        Ok(())
    }

    pub fn validate_invariants(&self) -> Result<(), ProofMarketInvariantViolation> {
        let budget = self
            .total_deposits
            .checked_add(self.protocol_subsidy)
            .ok_or(ProofMarketInvariantViolation::I2BudgetConservation)?;
        if self.total_payouts > budget {
            return Err(ProofMarketInvariantViolation::I2BudgetConservation);
        }

        for (sid, slot) in self.slots.iter() {
            if slot.claimer != slot.claimer0 {
                return Err(ProofMarketInvariantViolation::I1NoDoubleClaim { sid: *sid });
            }

            if slot.deadline0 > slot.deadline {
                return Err(ProofMarketInvariantViolation::I3DeadlineMonotonicity { sid: *sid });
            }

            if slot.phase == SlotPhase::Slashed && slot.deadline >= self.now {
                return Err(ProofMarketInvariantViolation::I4ObjectiveSlashing { sid: *sid });
            }

            if let SlotPhase::Settled { payee, payout } = slot.phase {
                if payout > slot.deposit {
                    return Err(ProofMarketInvariantViolation::I5NoOverpayout { sid: *sid });
                }
                if payout > 0 && payee != slot.claimer0 {
                    return Err(ProofMarketInvariantViolation::I6PayToClaimer { sid: *sid });
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Commit {
        sid: SlotId,
        p: ProverId,
        deposit: Amount,
        deadline: Time,
        job_hash: Hash32,
    },
    StartProving {
        sid: SlotId,
    },
    Settle {
        sid: SlotId,
        payout: Amount,
        job_hash: Hash32,
    },
    Expire {
        sid: SlotId,
    },
    Slash {
        sid: SlotId,
    },
    Tick {
        dt: Time,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofMarketInvariantViolation {
    I1NoDoubleClaim { sid: SlotId },
    I2BudgetConservation,
    I3DeadlineMonotonicity { sid: SlotId },
    I4ObjectiveSlashing { sid: SlotId },
    I5NoOverpayout { sid: SlotId },
    I6PayToClaimer { sid: SlotId },
}

impl std::fmt::Display for ProofMarketInvariantViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofMarketInvariantViolation::I1NoDoubleClaim { sid } => {
                write!(f, "I1 violated at slot {sid}: claimer != claimer0")
            }
            ProofMarketInvariantViolation::I2BudgetConservation => write!(
                f,
                "I2 violated: total_payouts > total_deposits + protocol_subsidy"
            ),
            ProofMarketInvariantViolation::I3DeadlineMonotonicity { sid } => {
                write!(f, "I3 violated at slot {sid}: deadline0 > deadline")
            }
            ProofMarketInvariantViolation::I4ObjectiveSlashing { sid } => write!(
                f,
                "I4 violated at slot {sid}: slashed without (deadline < now and no proof)"
            ),
            ProofMarketInvariantViolation::I5NoOverpayout { sid } => {
                write!(f, "I5 violated at slot {sid}: payout > deposit")
            }
            ProofMarketInvariantViolation::I6PayToClaimer { sid } => write!(
                f,
                "I6 violated at slot {sid}: payee != claimer0 for positive payout"
            ),
        }
    }
}

impl std::error::Error for ProofMarketInvariantViolation {}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn action_strategy() -> impl Strategy<Value = Action> {
        prop_oneof![
            (
                any::<SlotId>(),
                any::<ProverId>(),
                0u64..10_000u64,
                0u64..10_000u64,
                any::<Hash32>(),
            )
                .prop_map(|(sid, p, deposit, deadline, job_hash)| Action::Commit {
                    sid,
                    p,
                    deposit,
                    deadline,
                    job_hash,
                }),
            any::<SlotId>().prop_map(|sid| Action::StartProving { sid }),
            (any::<SlotId>(), 0u64..10_000u64, any::<Hash32>()).prop_map(
                |(sid, payout, job_hash)| {
                    Action::Settle {
                        sid,
                        payout,
                        job_hash,
                    }
                }
            ),
            any::<SlotId>().prop_map(|sid| Action::Expire { sid }),
            any::<SlotId>().prop_map(|sid| Action::Slash { sid }),
            (0u64..100u64).prop_map(|dt| Action::Tick { dt }),
        ]
    }

    #[derive(Debug, Clone)]
    struct ByteStream {
        bytes: Vec<u8>,
        idx: usize,
    }

    impl ByteStream {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, idx: 0 }
        }

        fn next(&mut self) -> u8 {
            if self.bytes.is_empty() {
                return 0;
            }
            let b = self.bytes.get(self.idx).copied().unwrap_or(0);
            self.idx = (self.idx + 1) % self.bytes.len();
            b
        }

        fn next_u64(&mut self) -> u64 {
            let mut out: u64 = 0;
            for _ in 0..8 {
                out = (out << 8) | (self.next() as u64);
            }
            out
        }
    }

    proptest! {
        #[test]
        fn invariant_preserved_across_random_action_sequences(
            protocol_subsidy in 0u64..10_000u64,
            actions in proptest::collection::vec(action_strategy(), 0..256),
        ) {
            let mut m = Market::init(protocol_subsidy);
            prop_assert!(m.validate_invariants().is_ok());

            for a in actions {
                let _ = m.step(a);
                prop_assert!(m.validate_invariants().is_ok());
            }
        }

        #[test]
        fn valid_transitions_never_panic_and_preserve_invariants(
            protocol_subsidy in 0u64..10_000u64,
            bytes in proptest::collection::vec(any::<u8>(), 1..512),
        ) {
            let mut bs = ByteStream::new(bytes);
            let mut m = Market::init(protocol_subsidy);
            prop_assert!(m.validate_invariants().is_ok());

            let mut next_sid: SlotId = 0;

            for _ in 0..256 {
                #[derive(Debug, Clone, Copy)]
                enum Kind {
                    Commit,
                    StartProving(SlotId),
                    Settle(SlotId),
                    Expire(SlotId),
                    Slash(SlotId),
                    Tick,
                }

                let mut kinds: Vec<Kind> = vec![Kind::Commit, Kind::Tick];
                for (&sid, slot) in m.slots_iter() {
                    match slot.phase() {
                        SlotPhase::Committed => kinds.push(Kind::StartProving(sid)),
                        SlotPhase::Proving { .. } => {
                            if m.now() <= slot.deadline() {
                                kinds.push(Kind::Settle(sid));
                            }
                            if slot.deadline() < m.now() {
                                kinds.push(Kind::Expire(sid));
                            }
                        }
                        SlotPhase::Expired => {
                            if slot.deadline() < m.now() {
                                kinds.push(Kind::Slash(sid));
                            }
                        }
                        _ => {}
                    }
                }

                let choice = (bs.next() as usize) % kinds.len();
                let action = match kinds[choice] {
                    Kind::Commit => {
                        let sid = next_sid;
                        if let Some(n) = next_sid.checked_add(1) {
                            next_sid = n;
                        }

                        let p: ProverId = bs.next_u64();
                        let deposit: Amount = (bs.next() as u64) % 10_000u64;
                        let delta: Time = 1 + ((bs.next() as u64) % 50u64);
                        let deadline = m.now().checked_add(delta).unwrap_or(u64::MAX);
                        let job_hash: Hash32 = bs.next_u64();

                        Action::Commit {
                            sid,
                            p,
                            deposit,
                            deadline,
                            job_hash,
                        }
                    }
                    Kind::StartProving(sid) => Action::StartProving { sid },
                    Kind::Settle(sid) => {
                        let Some(slot) = m.slot(sid) else {
                            prop_assert!(false, "selected settle sid not found");
                            continue;
                        };
                        let job_hash = slot.job_hash();
                        let payout = if slot.deposit() == 0 {
                            0
                        } else {
                            (bs.next() as u64) % (slot.deposit().saturating_add(1))
                        };
                        Action::Settle {
                            sid,
                            payout,
                            job_hash,
                        }
                    }
                    Kind::Expire(sid) => Action::Expire { sid },
                    Kind::Slash(sid) => Action::Slash { sid },
                    Kind::Tick => {
                        let dt: Time = (bs.next() as u64) % 20u64;
                        Action::Tick { dt }
                    }
                };

                prop_assert!(m.step(action).is_ok());
                prop_assert!(m.validate_invariants().is_ok());
            }
        }
    }
}
