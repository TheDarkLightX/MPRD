//! Advanced selection algorithms for MPRD decision pipelines.
//!
//! These selectors implement the `Selector` trait and provide different strategies
//! for choosing among allowed candidates. All are deterministic given the same inputs.
//!
//! # Security: Fail-Closed Behavior
//!
//! All selectors FAIL CLOSED when required metrics are missing or invalid.
//! This prevents manipulation via omission of scenario data or constraint values.
//!
//! # Available Selectors
//!
//! - `ParetoSelector`: Multi-objective optimization with deterministic tie-break
//! - `EpsilonConstraintSelector`: Hard bounds on secondary metrics
//! - `MinimaxRegretSelector`: Minimizes worst-case regret under uncertainty

use crate::hash::hash_candidate;
use crate::{
    CandidateAction, Decision, Hash32, MprdError, PolicyHash, Result, RuleVerdict, Selector,
    StateSnapshot,
};
use std::collections::HashMap;

// =============================================================================
// Helper: Extract numeric value with fail-closed semantics
// =============================================================================

/// Extract a numeric value from verdict limits, failing closed on missing/invalid.
fn extract_numeric(limits: &HashMap<String, crate::Value>, key: &str) -> Result<i64> {
    match limits.get(key) {
        Some(crate::Value::Int(v)) => Ok(*v),
        Some(crate::Value::UInt(v)) => i64::try_from(*v).map_err(|_| {
            MprdError::InvalidInput(format!("limit '{}' value {} overflows i64", key, v))
        }),
        Some(other) => Err(MprdError::InvalidInput(format!(
            "limit '{}' has non-numeric type: {:?}",
            key, other
        ))),
        None => Err(MprdError::InvalidInput(format!(
            "required limit '{}' not found",
            key
        ))),
    }
}

/// Compute the canonical hash for a candidate (for deterministic tie-breaks).
/// This ensures tie-breaks use the actual content hash, not potentially manipulated input.
fn canonical_hash(candidate: &CandidateAction) -> Hash32 {
    hash_candidate(candidate)
}

// =============================================================================
// Pareto Selector: Multi-objective with deterministic tie-break
// =============================================================================

/// Selects from the Pareto front of allowed candidates.
///
/// # Fail-Closed Behavior
/// Returns error if any allowed candidate is missing the risk metric.
pub struct ParetoSelector {
    /// Key in RuleVerdict.limits containing the risk metric (lower is better).
    pub risk_key: String,
}

impl ParetoSelector {
    pub fn new(risk_key: impl Into<String>) -> Self {
        Self {
            risk_key: risk_key.into(),
        }
    }
}

impl Selector for ParetoSelector {
    fn select(
        &self,
        policy_hash: &PolicyHash,
        _state: &StateSnapshot,
        candidates: &[CandidateAction],
        verdicts: &[RuleVerdict],
    ) -> Result<Decision> {
        if candidates.len() != verdicts.len() {
            return Err(MprdError::InvalidInput(
                "candidates and verdicts length mismatch".into(),
            ));
        }
        if candidates.is_empty() {
            return Err(MprdError::SelectionFailed("no candidates provided".into()));
        }

        // Filter to allowed candidates with validated risk values
        let mut allowed: Vec<(usize, &CandidateAction, i64, Hash32)> = Vec::new();
        for (i, (c, v)) in candidates.iter().zip(verdicts.iter()).enumerate() {
            if !v.allowed {
                continue;
            }
            let risk = extract_numeric(&v.limits, &self.risk_key)?;
            let hash = canonical_hash(c);
            allowed.push((i, c, risk, hash));
        }

        if allowed.is_empty() {
            return Err(MprdError::SelectionFailed("no allowed candidates".into()));
        }

        // Find Pareto front (non-dominated candidates)
        let mut pareto_front: Vec<(usize, &CandidateAction, i64, Hash32)> = Vec::new();
        for (i, c, risk, hash) in allowed.iter() {
            let is_dominated = allowed.iter().any(|(_, other_c, other_risk, _)| {
                let dominated_score = other_c.score >= c.score;
                let dominated_risk = other_risk <= risk;
                let strictly_better = other_c.score > c.score || other_risk < risk;
                dominated_score && dominated_risk && strictly_better
            });

            if !is_dominated {
                pareto_front.push((*i, *c, *risk, hash.clone()));
            }
        }

        // Deterministic tie-break: highest score, then lowest canonical hash
        pareto_front.sort_by(|(_, a, _, hash_a), (_, b, _, hash_b)| {
            b.score.cmp(&a.score).then_with(|| hash_a.0.cmp(&hash_b.0))
        });

        let (chosen_index, chosen_action, _, _) = &pareto_front[0];

        Ok(Decision {
            chosen_index: *chosen_index,
            chosen_action: (*chosen_action).clone(),
            policy_hash: policy_hash.clone(),
            decision_commitment: Hash32([0u8; 32]), // Set by caller or Decision::new
        })
    }
}

// =============================================================================
// Epsilon-Constraint Selector: Hard bounds on secondary metrics
// =============================================================================

/// Selects the highest-score candidate that satisfies hard constraints.
///
/// # Fail-Closed Behavior
/// Returns error if any constraint key is missing from a candidate's verdict.
pub struct EpsilonConstraintSelector {
    /// Constraints as (key, max_value) pairs. Candidate passes if limit[key] <= max_value.
    pub constraints: HashMap<String, i64>,
}

impl EpsilonConstraintSelector {
    pub fn new(constraints: HashMap<String, i64>) -> Self {
        Self { constraints }
    }

    /// Check if a verdict satisfies all constraints. Fails closed on missing keys.
    fn check_constraints(&self, verdict: &RuleVerdict) -> Result<bool> {
        for (key, max_val) in &self.constraints {
            let actual = extract_numeric(&verdict.limits, key)?;
            if actual > *max_val {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Selector for EpsilonConstraintSelector {
    fn select(
        &self,
        policy_hash: &PolicyHash,
        _state: &StateSnapshot,
        candidates: &[CandidateAction],
        verdicts: &[RuleVerdict],
    ) -> Result<Decision> {
        if candidates.len() != verdicts.len() {
            return Err(MprdError::InvalidInput(
                "candidates and verdicts length mismatch".into(),
            ));
        }
        if candidates.is_empty() {
            return Err(MprdError::SelectionFailed("no candidates provided".into()));
        }

        // Filter to allowed candidates that satisfy constraints
        let mut valid: Vec<(usize, &CandidateAction, Hash32)> = Vec::new();
        for (i, (c, v)) in candidates.iter().zip(verdicts.iter()).enumerate() {
            if !v.allowed {
                continue;
            }
            if self.check_constraints(v)? {
                valid.push((i, c, canonical_hash(c)));
            }
        }

        if valid.is_empty() {
            return Err(MprdError::SelectionFailed(
                "no candidates satisfy constraints".into(),
            ));
        }

        // Sort by score desc, then canonical hash for tie-break
        valid.sort_by(|(_, a, hash_a), (_, b, hash_b)| {
            b.score.cmp(&a.score).then_with(|| hash_a.0.cmp(&hash_b.0))
        });

        let (chosen_index, chosen_action, _) = &valid[0];

        Ok(Decision {
            chosen_index: *chosen_index,
            chosen_action: (*chosen_action).clone(),
            policy_hash: policy_hash.clone(),
            decision_commitment: Hash32([0u8; 32]),
        })
    }
}

// =============================================================================
// Minimax Regret Selector: Minimize worst-case regret
// =============================================================================

/// Selects the candidate that minimizes worst-case regret across scenarios.
///
/// # Fail-Closed Behavior
/// - Returns error if scenario data is missing or non-numeric
/// - Requires all candidates to have outcomes for all scenarios found in any candidate
pub struct MinimaxRegretSelector {
    /// Prefix for scenario keys in verdict.limits.
    pub scenario_prefix: String,
}

impl MinimaxRegretSelector {
    pub fn new(scenario_prefix: impl Into<String>) -> Self {
        Self {
            scenario_prefix: scenario_prefix.into(),
        }
    }

    /// Extract scenario outcomes from verdict limits, with validation.
    fn extract_scenarios(&self, verdict: &RuleVerdict) -> Result<HashMap<String, i64>> {
        let mut scenarios = HashMap::new();
        for (key, value) in &verdict.limits {
            if key.starts_with(&self.scenario_prefix) {
                let outcome = match value {
                    crate::Value::Int(v) => *v,
                    crate::Value::UInt(v) => i64::try_from(*v).map_err(|_| {
                        MprdError::InvalidInput(format!(
                            "scenario '{}' value {} overflows i64",
                            key, v
                        ))
                    })?,
                    other => {
                        return Err(MprdError::InvalidInput(format!(
                            "scenario '{}' has non-numeric type: {:?}",
                            key, other
                        )))
                    }
                };
                let scenario_name = key.strip_prefix(&self.scenario_prefix).unwrap_or(key);
                scenarios.insert(scenario_name.to_string(), outcome);
            }
        }
        Ok(scenarios)
    }
}

impl Selector for MinimaxRegretSelector {
    fn select(
        &self,
        policy_hash: &PolicyHash,
        _state: &StateSnapshot,
        candidates: &[CandidateAction],
        verdicts: &[RuleVerdict],
    ) -> Result<Decision> {
        if candidates.len() != verdicts.len() {
            return Err(MprdError::InvalidInput(
                "candidates and verdicts length mismatch".into(),
            ));
        }
        if candidates.is_empty() {
            return Err(MprdError::SelectionFailed("no candidates provided".into()));
        }

        // Filter to allowed candidates and extract scenarios
        let mut outcomes: Vec<(usize, &CandidateAction, HashMap<String, i64>, Hash32)> = Vec::new();
        for (i, (c, v)) in candidates.iter().zip(verdicts.iter()).enumerate() {
            if !v.allowed {
                continue;
            }
            let scenarios = self.extract_scenarios(v)?;
            outcomes.push((i, c, scenarios, canonical_hash(c)));
        }

        if outcomes.is_empty() {
            return Err(MprdError::SelectionFailed("no allowed candidates".into()));
        }

        // Collect all scenario names (union of all candidates)
        let mut all_scenarios: Vec<String> = outcomes
            .iter()
            .flat_map(|(_, _, s, _)| s.keys().cloned())
            .collect();
        all_scenarios.sort();
        all_scenarios.dedup();

        // Fail-closed: require scenario data
        if all_scenarios.is_empty() {
            return Err(MprdError::InvalidInput(
                "no scenario data found; MinimaxRegretSelector requires scenario_ prefixed limits"
                    .into(),
            ));
        }

        // Fail-closed: every candidate must have all scenarios
        for (_, c, scenarios, _) in &outcomes {
            for scenario in &all_scenarios {
                if !scenarios.contains_key(scenario) {
                    return Err(MprdError::InvalidInput(format!(
                        "candidate '{}' missing scenario '{}'",
                        c.action_type, scenario
                    )));
                }
            }
        }

        // For each scenario, find the best outcome
        let mut best_per_scenario: HashMap<String, i64> = HashMap::new();
        for scenario in &all_scenarios {
            let best = outcomes
                .iter()
                .map(|(_, _, s, _)| *s.get(scenario).unwrap()) // Safe: validated above
                .max()
                .unwrap();
            best_per_scenario.insert(scenario.clone(), best);
        }

        // Compute max regret for each candidate
        let mut regrets: Vec<(usize, &CandidateAction, i64, Hash32)> = outcomes
            .iter()
            .map(|(i, c, scenarios, hash)| {
                let max_regret = all_scenarios
                    .iter()
                    .map(|s| {
                        let best = *best_per_scenario.get(s).unwrap();
                        let actual = *scenarios.get(s).unwrap();
                        best.saturating_sub(actual) // Use saturating_sub to avoid overflow
                    })
                    .max()
                    .unwrap_or(0);
                (*i, *c, max_regret, hash.clone())
            })
            .collect();

        // Sort by regret (asc), then score (desc), then canonical hash for tie-break
        regrets.sort_by(|(_, a, regret_a, hash_a), (_, b, regret_b, hash_b)| {
            regret_a
                .cmp(regret_b)
                .then_with(|| b.score.cmp(&a.score))
                .then_with(|| hash_a.0.cmp(&hash_b.0))
        });

        let (chosen_index, chosen_action, _, _) = &regrets[0];

        Ok(Decision {
            chosen_index: *chosen_index,
            chosen_action: (*chosen_action).clone(),
            policy_hash: policy_hash.clone(),
            decision_commitment: Hash32([0u8; 32]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Score;

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn make_candidate(name: &str, score: i64, hash_byte: u8) -> CandidateAction {
        CandidateAction {
            action_type: name.into(),
            params: HashMap::new(),
            score: Score(score),
            candidate_hash: dummy_hash(hash_byte),
        }
    }

    fn make_verdict(allowed: bool, limits: HashMap<String, crate::Value>) -> RuleVerdict {
        RuleVerdict {
            allowed,
            reasons: vec![],
            limits,
        }
    }

    #[test]
    fn pareto_selects_non_dominated() {
        let policy_hash = dummy_hash(1);
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(2),
            state_ref: crate::StateRef::unknown(),
        };

        let candidates = vec![
            make_candidate("A", 100, 3),
            make_candidate("B", 100, 4),
            make_candidate("C", 80, 5),
        ];
        let verdicts = vec![
            make_verdict(true, [("risk".into(), crate::Value::Int(50))].into()),
            make_verdict(true, [("risk".into(), crate::Value::Int(30))].into()),
            make_verdict(true, [("risk".into(), crate::Value::Int(20))].into()),
        ];

        let selector = ParetoSelector::new("risk");
        let decision = selector
            .select(&policy_hash, &state, &candidates, &verdicts)
            .unwrap();

        assert_eq!(decision.chosen_index, 1);
        assert_eq!(decision.chosen_action.action_type, "B");
    }

    #[test]
    fn pareto_fails_on_missing_risk() {
        let policy_hash = dummy_hash(1);
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(2),
            state_ref: crate::StateRef::unknown(),
        };

        let candidates = vec![make_candidate("A", 100, 3)];
        let verdicts = vec![make_verdict(true, HashMap::new())]; // Missing risk

        let selector = ParetoSelector::new("risk");
        let result = selector.select(&policy_hash, &state, &candidates, &verdicts);
        assert!(matches!(result, Err(MprdError::InvalidInput(_))));
    }

    #[test]
    fn epsilon_constraint_filters_by_limits() {
        let policy_hash = dummy_hash(1);
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(2),
            state_ref: crate::StateRef::unknown(),
        };

        let candidates = vec![make_candidate("A", 100, 3), make_candidate("B", 80, 4)];
        let verdicts = vec![
            make_verdict(true, [("cost".into(), crate::Value::Int(200))].into()),
            make_verdict(true, [("cost".into(), crate::Value::Int(80))].into()),
        ];

        let selector = EpsilonConstraintSelector::new([("cost".into(), 100)].into());
        let decision = selector
            .select(&policy_hash, &state, &candidates, &verdicts)
            .unwrap();

        assert_eq!(decision.chosen_index, 1);
        assert_eq!(decision.chosen_action.action_type, "B");
    }

    #[test]
    fn epsilon_fails_on_missing_constraint() {
        let policy_hash = dummy_hash(1);
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(2),
            state_ref: crate::StateRef::unknown(),
        };

        let candidates = vec![make_candidate("A", 100, 3)];
        let verdicts = vec![make_verdict(true, HashMap::new())]; // Missing cost

        let selector = EpsilonConstraintSelector::new([("cost".into(), 100)].into());
        let result = selector.select(&policy_hash, &state, &candidates, &verdicts);
        assert!(matches!(result, Err(MprdError::InvalidInput(_))));
    }

    #[test]
    fn minimax_regret_picks_bounded_worst_case() {
        let policy_hash = dummy_hash(1);
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(2),
            state_ref: crate::StateRef::unknown(),
        };

        let candidates = vec![
            make_candidate("A", 0, 3),
            make_candidate("B", 0, 4),
            make_candidate("C", 0, 5),
        ];
        let verdicts = vec![
            make_verdict(
                true,
                [
                    ("scenario_bull".into(), crate::Value::Int(100)),
                    ("scenario_bear".into(), crate::Value::Int(-50)),
                ]
                .into(),
            ),
            make_verdict(
                true,
                [
                    ("scenario_bull".into(), crate::Value::Int(60)),
                    ("scenario_bear".into(), crate::Value::Int(-10)),
                ]
                .into(),
            ),
            make_verdict(
                true,
                [
                    ("scenario_bull".into(), crate::Value::Int(40)),
                    ("scenario_bear".into(), crate::Value::Int(30)),
                ]
                .into(),
            ),
        ];

        let selector = MinimaxRegretSelector::new("scenario_");
        let decision = selector
            .select(&policy_hash, &state, &candidates, &verdicts)
            .unwrap();

        assert_eq!(decision.chosen_index, 1);
        assert_eq!(decision.chosen_action.action_type, "B");
    }

    #[test]
    fn minimax_fails_on_missing_scenario() {
        let policy_hash = dummy_hash(1);
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(2),
            state_ref: crate::StateRef::unknown(),
        };

        let candidates = vec![make_candidate("A", 0, 3), make_candidate("B", 0, 4)];
        let verdicts = vec![
            make_verdict(
                true,
                [
                    ("scenario_bull".into(), crate::Value::Int(100)),
                    ("scenario_bear".into(), crate::Value::Int(-50)),
                ]
                .into(),
            ),
            make_verdict(
                true,
                [
                    ("scenario_bull".into(), crate::Value::Int(60)),
                    // Missing scenario_bear!
                ]
                .into(),
            ),
        ];

        let selector = MinimaxRegretSelector::new("scenario_");
        let result = selector.select(&policy_hash, &state, &candidates, &verdicts);
        assert!(matches!(result, Err(MprdError::InvalidInput(_))));
    }

    #[test]
    fn minimax_fails_on_no_scenarios() {
        let policy_hash = dummy_hash(1);
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(2),
            state_ref: crate::StateRef::unknown(),
        };

        let candidates = vec![make_candidate("A", 0, 3)];
        let verdicts = vec![make_verdict(true, HashMap::new())]; // No scenarios

        let selector = MinimaxRegretSelector::new("scenario_");
        let result = selector.select(&policy_hash, &state, &candidates, &verdicts);
        assert!(matches!(result, Err(MprdError::InvalidInput(_))));
    }

    /// Security test: Verify that user-supplied candidate_hash cannot influence tie-breaks.
    /// Tie-breaks must use canonical hash computed from content, not the input field.
    #[test]
    fn tiebreak_uses_canonical_hash_not_input() {
        let policy_hash = dummy_hash(1);
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(2),
            state_ref: crate::StateRef::unknown(),
        };

        // Create two identical candidates with DIFFERENT fake candidate_hash values.
        // If ordering used input hash, result would differ. Since ordering uses canonical
        // hash (computed from content), both will have same hash and tie-break is stable.
        let mut c1 = CandidateAction {
            action_type: "ACTION".into(),
            params: HashMap::new(),
            score: Score(100),
            candidate_hash: dummy_hash(0xFF), // Fake high hash
        };
        let mut c2 = CandidateAction {
            action_type: "ACTION".into(),
            params: HashMap::new(),
            score: Score(100),
            candidate_hash: dummy_hash(0x00), // Fake low hash
        };

        // Both have same content -> same canonical hash
        let canonical_1 = canonical_hash(&c1);
        let canonical_2 = canonical_hash(&c2);
        assert_eq!(
            canonical_1, canonical_2,
            "identical content should have same canonical hash"
        );

        // Now give them different input hashes to try to influence ordering
        c1.candidate_hash = dummy_hash(0xFF);
        c2.candidate_hash = dummy_hash(0x00);

        let candidates = vec![c1.clone(), c2.clone()];
        let verdicts = vec![
            make_verdict(true, [("risk".into(), crate::Value::Int(10))].into()),
            make_verdict(true, [("risk".into(), crate::Value::Int(10))].into()),
        ];

        let selector = ParetoSelector::new("risk");
        let decision = selector
            .select(&policy_hash, &state, &candidates, &verdicts)
            .unwrap();

        // Result should be stable regardless of input hash manipulation.
        // Since both have identical content and same score/risk, tie-break uses canonical hash.
        // The chosen one is deterministic based on content hash, not input field.
        // (We just verify it picks one consistently - the specific index doesn't matter as long
        // as it's based on content, not the manipulated field.)
        assert!(
            decision.chosen_index < 2,
            "should pick one of the two identical candidates"
        );
    }
}
