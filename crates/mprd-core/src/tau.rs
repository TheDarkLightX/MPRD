use crate::{CandidateAction, MprdError, PolicyEngine, PolicyHash, Result, RuleVerdict, StateSnapshot, MAX_CANDIDATES};

/// Tau-backed policy engine stub.
///
/// This implementation exists only to wire the interface. It deliberately
/// fails on every call to avoid silently running without real Tau
/// integration.
pub struct TauPolicyEngine;

impl PolicyEngine for TauPolicyEngine {
    fn evaluate(
        &self,
        _policy_hash: &PolicyHash,
        _state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<Vec<RuleVerdict>> {
        if candidates.len() > MAX_CANDIDATES {
            return Err(MprdError::BoundedValueExceeded(
                "too many candidates for TauPolicyEngine".into(),
            ));
        }

        Err(MprdError::PolicyEvaluationFailed(
            "TauPolicyEngine not implemented; wire Tau-lang before use".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CandidateHash, Hash32, Score, Value};
    use std::collections::HashMap;

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    #[test]
    fn fails_with_explicit_error() {
        let engine = TauPolicyEngine;
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(1),
        };
        let candidates = vec![CandidateAction {
            action_type: "A".into(),
            params: HashMap::from([("x".into(), Value::Int(1))]),
            score: Score(0),
            candidate_hash: dummy_hash(2),
        }];

        let result = engine.evaluate(&dummy_hash(3), &state, &candidates);
        assert!(matches!(result, Err(MprdError::PolicyEvaluationFailed(_))));
    }
}
