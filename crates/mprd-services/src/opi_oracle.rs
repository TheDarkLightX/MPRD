use crate::types::{
    BoundedMap, CommitmentHasher, ErrorCode, Hash32, HashDomain, OracleRoundConfig,
    MAX_REPORTERS_PER_ROUND,
};

pub type Time = u64;
pub type RoundId = u64;
pub type ReporterId = u64;
pub type MetricValue = u64;
pub type Nonce = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Commit,
    Reveal,
    Aggregated { aggregated_value: Option<MetricValue> },
    Finalized { aggregated_value: MetricValue },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricCommitment {
    Committed {
        commit_hash: Hash32,
        committed_at: Time,
    },
    Revealed {
        commit_hash: Hash32,
        committed_at: Time,
        value: MetricValue,
        nonce: Nonce,
        revealed_at: Time,
    },
}

impl MetricCommitment {
    pub fn commit_hash(&self) -> &Hash32 {
        match self {
            MetricCommitment::Committed { commit_hash, .. }
            | MetricCommitment::Revealed { commit_hash, .. } => commit_hash,
        }
    }

    pub fn revealed_value(&self) -> Option<MetricValue> {
        match self {
            MetricCommitment::Revealed { value, .. } => Some(*value),
            MetricCommitment::Committed { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OPIRound {
    round_id: RoundId,
    now: Time,
    phase: Phase,
    config: OracleRoundConfig,
    commits: BoundedMap<ReporterId, MetricCommitment>,
}

impl OPIRound {
    pub fn new(round_id: RoundId, config: OracleRoundConfig) -> Self {
        Self {
            round_id,
            now: 0,
            phase: Phase::Commit,
            config,
            commits: BoundedMap::new(MAX_REPORTERS_PER_ROUND),
        }
    }

    pub fn new_checked(
        round_id: RoundId,
        commit_deadline: Time,
        reveal_deadline: Time,
        trim_k: usize,
        min_reporters: usize,
    ) -> Result<Self, ErrorCode> {
        let config = OracleRoundConfig::new(commit_deadline, reveal_deadline, trim_k, min_reporters)?;
        Ok(Self::new(round_id, config))
    }

    pub fn round_id(&self) -> RoundId {
        self.round_id
    }

    pub fn now(&self) -> Time {
        self.now
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn config(&self) -> &OracleRoundConfig {
        &self.config
    }

    pub fn aggregated_value(&self) -> Option<MetricValue> {
        match self.phase {
            Phase::Aggregated { aggregated_value } => aggregated_value,
            Phase::Finalized { aggregated_value } => Some(aggregated_value),
            _ => None,
        }
    }

    pub fn commits_len(&self) -> usize {
        self.commits.len()
    }

    pub fn step(&mut self, action: Action, hasher: &impl CommitmentHasher) -> Result<(), ErrorCode> {
        match action {
            Action::Commit { rep, h } => self.commit(rep, h),
            Action::Reveal { rep, v, n } => self.reveal(rep, v, n, hasher),
            Action::Aggregate => self.aggregate(),
            Action::Finalize => self.finalize(),
            Action::Tick { dt } => self.tick(dt),
        }
    }

    pub fn commit(&mut self, rep: ReporterId, h: Hash32) -> Result<(), ErrorCode> {
        if self.phase != Phase::Commit {
            return Err(ErrorCode::RoundWrongPhase);
        }
        if self.now >= self.config.commit_deadline {
            return Err(ErrorCode::CommitDeadlinePassed);
        }
        if self.commits.contains_key(&rep) {
            return Err(ErrorCode::ReporterAlreadyCommitted);
        }

        self.commits
            .insert(
                rep,
                MetricCommitment::Committed {
                    commit_hash: h,
                    committed_at: self.now,
                },
            )
            .map_err(|_| ErrorCode::CapacityExceeded)?;
        Ok(())
    }

    pub fn reveal(
        &mut self,
        rep: ReporterId,
        v: MetricValue,
        n: Nonce,
        hasher: &impl CommitmentHasher,
    ) -> Result<(), ErrorCode> {
        if self.phase != Phase::Reveal {
            return Err(ErrorCode::RoundWrongPhase);
        }
        if self.now >= self.config.reveal_deadline {
            return Err(ErrorCode::RevealDeadlinePassed);
        }

        let mc = self
            .commits
            .get_mut(&rep)
            .ok_or(ErrorCode::ReporterNotCommitted)?;
        match mc {
            MetricCommitment::Committed {
                commit_hash,
                committed_at,
            } => {
                let expected = compute_commitment_hash(self.round_id, rep, v, n, hasher)?;
                if *commit_hash != expected {
                    return Err(ErrorCode::CommitHashMismatch);
                }

                *mc = MetricCommitment::Revealed {
                    commit_hash: *commit_hash,
                    committed_at: *committed_at,
                    value: v,
                    nonce: n,
                    revealed_at: self.now,
                };
                Ok(())
            }
            MetricCommitment::Revealed { .. } => Err(ErrorCode::ReporterAlreadyRevealed),
        }
    }

    pub fn aggregate(&mut self) -> Result<(), ErrorCode> {
        if self.phase != Phase::Reveal {
            return Err(ErrorCode::RoundWrongPhase);
        }
        if self.now < self.config.reveal_deadline {
            return Err(ErrorCode::PreconditionFailed);
        }

        let values = self.revealed_values();
        let aggregated_value = if values.len() < self.config.min_reporters {
            None
        } else {
            robust_aggregate(self.config.trim_k, &values)
        };

        self.phase = Phase::Aggregated { aggregated_value };
        Ok(())
    }

    pub fn finalize(&mut self) -> Result<(), ErrorCode> {
        let aggregated_value = match self.phase {
            Phase::Aggregated { aggregated_value } => aggregated_value,
            _ => return Err(ErrorCode::RoundWrongPhase),
        };

        let Some(a) = aggregated_value else {
            return Err(ErrorCode::AggregationFailed);
        };
        self.phase = Phase::Finalized { aggregated_value: a };
        Ok(())
    }

    pub fn tick(&mut self, dt: Time) -> Result<(), ErrorCode> {
        self.now = self.now.checked_add(dt).ok_or(ErrorCode::ArithmeticOverflow)?;
        if self.phase == Phase::Commit && self.now >= self.config.commit_deadline {
            self.phase = Phase::Reveal;
        }
        Ok(())
    }

    pub fn revealed_values(&self) -> Vec<MetricValue> {
        self.commits
            .iter()
            .filter_map(|(_, mc)| mc.revealed_value())
            .collect()
    }

    pub fn validate_invariants(
        &self,
        hasher: &impl CommitmentHasher,
    ) -> Result<(), OpiOracleInvariantViolation> {
        for (&rep, mc) in self.commits.iter() {
            if let MetricCommitment::Revealed {
                commit_hash,
                value,
                nonce,
                ..
            } = mc
            {
                let expected = compute_commitment_hash(self.round_id, rep, *value, *nonce, hasher)
                    .map_err(|_| OpiOracleInvariantViolation::CommitBeforeReveal)?;
                if *commit_hash != expected {
                    return Err(OpiOracleInvariantViolation::CommitBeforeReveal);
                }
            }
        }

        match self.phase {
            Phase::Aggregated { aggregated_value: Some(a) } => {
                let values = self.revealed_values();
                if !robust_agg_ok(self.config.trim_k, &values, a) {
                    return Err(OpiOracleInvariantViolation::RobustAggregation);
                }
            }
            Phase::Finalized { aggregated_value: a } => {
                let values = self.revealed_values();
                if !robust_agg_ok(self.config.trim_k, &values, a) {
                    return Err(OpiOracleInvariantViolation::RobustAggregation);
                }
            }
            _ => {}
        }

        Ok(())
    }
}

fn compute_commitment_hash(
    round_id: RoundId,
    reporter: ReporterId,
    value: MetricValue,
    nonce: Nonce,
    hasher: &impl CommitmentHasher,
) -> Result<Hash32, ErrorCode> {
    let mut data = [0u8; 32];
    data[0..8].copy_from_slice(&round_id.to_le_bytes());
    data[8..16].copy_from_slice(&reporter.to_le_bytes());
    data[16..24].copy_from_slice(&value.to_le_bytes());
    data[24..32].copy_from_slice(&nonce.to_le_bytes());
    hasher.hash(HashDomain::OPIOracleCommit, &data)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Commit { rep: ReporterId, h: Hash32 },
    Reveal { rep: ReporterId, v: MetricValue, n: Nonce },
    Aggregate,
    Finalize,
    Tick { dt: Time },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpiOracleInvariantViolation {
    CommitBeforeReveal,
    RobustAggregation,
}

impl std::fmt::Display for OpiOracleInvariantViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpiOracleInvariantViolation::CommitBeforeReveal => write!(
                f,
                "commit-before-reveal violated (missing binding or missing commitment)"
            ),
            OpiOracleInvariantViolation::RobustAggregation => write!(
                f,
                "robust aggregation violated (aggregate not within robust bounds)"
            ),
        }
    }
}

impl std::error::Error for OpiOracleInvariantViolation {}

pub fn robust_aggregate(trim_k: usize, values: &[MetricValue]) -> Option<MetricValue> {
    if values.len() <= 2 * trim_k {
        return None;
    }

    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let trimmed = &sorted[trim_k..(sorted.len() - trim_k)];
    let mut sum: u128 = 0;
    for &v in trimmed {
        sum = sum.checked_add(v as u128)?;
    }
    let denom: u128 = u128::try_from(trimmed.len()).ok()?;
    let mean = sum.checked_div(denom)?;
    u64::try_from(mean).ok()
}

pub fn robust_agg_ok(trim_k: usize, values: &[MetricValue], a: MetricValue) -> bool {
    if values.len() <= 2 * trim_k {
        return false;
    }

    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let trimmed = &sorted[trim_k..(sorted.len() - trim_k)];
    let Some(min) = trimmed.first().copied() else {
        return false;
    };
    let Some(max) = trimmed.last().copied() else {
        return false;
    };
    min <= a && a <= max
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Sha256Hasher;
    use proptest::prelude::*;

    #[test]
    fn robust_aggregate_is_trimmed_mean() {
        let values = vec![1u64, 2u64, 100u64, 101u64, 102u64];
        assert_eq!(robust_aggregate(1, &values), Some(67));
        assert_eq!(robust_aggregate(2, &values), Some(100));
        assert_eq!(robust_aggregate(3, &values), None);
    }

    #[test]
    fn end_to_end_round_happy_path() {
        let hasher = Sha256Hasher::new(64);
        let cfg = OracleRoundConfig::new(5, 10, 1, 3).expect("config");
        let mut r = OPIRound::new(7, cfg);

        let reporters = [11u64, 12u64, 13u64, 14u64, 15u64];
        let values = [1u64, 2u64, 100u64, 101u64, 102u64];

        for (rep, v) in reporters.iter().copied().zip(values.iter().copied()) {
            let n = rep.wrapping_add(123);
            let h = compute_commitment_hash(r.round_id(), rep, v, n, &hasher).expect("hash");
            r.commit(rep, h).expect("commit");
        }
        r.validate_invariants(&hasher).expect("invariants");

        r.tick(5).expect("tick to reveal");
        assert_eq!(r.phase(), Phase::Reveal);

        for (rep, v) in reporters.iter().copied().zip(values.iter().copied()) {
            let n = rep.wrapping_add(123);
            r.reveal(rep, v, n, &hasher).expect("reveal");
        }
        r.validate_invariants(&hasher).expect("invariants");

        r.tick(5).expect("tick to reveal_deadline");
        r.aggregate().expect("aggregate");
        assert_eq!(
            r.phase(),
            Phase::Aggregated {
                aggregated_value: Some(67)
            }
        );
        r.validate_invariants(&hasher).expect("invariants");

        r.finalize().expect("finalize");
        assert_eq!(r.phase(), Phase::Finalized { aggregated_value: 67 });
        r.validate_invariants(&hasher).expect("invariants");
    }

    fn valid_config_strategy() -> impl Strategy<Value = OracleRoundConfig> {
        (0u64..20u64, 1u64..40u64, 0usize..5usize).prop_flat_map(|(commit_deadline, dt, trim_k)| {
            let reveal_deadline = commit_deadline.saturating_add(dt.max(1));
            let min_reporters_min = 2 * trim_k + 1;
            (
                Just(commit_deadline),
                Just(reveal_deadline),
                Just(trim_k),
                (min_reporters_min..(min_reporters_min + 8)),
            )
                .prop_map(|(c, r, t, m)| OracleRoundConfig::new(c, r, t, m).expect("valid config"))
        })
    }

    proptest! {
        #[test]
        fn random_actions_never_break_invariants(
            round_id in any::<u64>(),
            cfg in valid_config_strategy(),
            actions in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let hasher = Sha256Hasher::new(64);
            let mut r = OPIRound::new(round_id, cfg);
            prop_assert!(r.validate_invariants(&hasher).is_ok());

            for b in actions {
                let action = match b % 5 {
                    0 => Action::Commit { rep: b as u64, h: [b; 32] },
                    1 => Action::Reveal { rep: b as u64, v: b as u64, n: (b as u64).wrapping_add(1) },
                    2 => Action::Aggregate,
                    3 => Action::Finalize,
                    _ => Action::Tick { dt: (b as u64) % 5 },
                };
                let _ = r.step(action, &hasher);
                prop_assert!(r.validate_invariants(&hasher).is_ok());
            }
        }
    }
}

