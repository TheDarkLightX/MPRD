use crate::{CandidateAction, Decision, Hash32, StateSnapshot, Value};
use sha2::{Digest, Sha256};

/// Compute a deterministic SHA-256 hash of a byte slice.
pub fn sha256(data: &[u8]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash32(bytes)
}

/// Compute a canonical hash for a `Value`.
pub fn hash_value(value: &Value) -> Vec<u8> {
    match value {
        Value::Bool(b) => vec![0x00, if *b { 1 } else { 0 }],
        Value::Int(i) => {
            let mut buf = vec![0x01];
            buf.extend_from_slice(&i.to_le_bytes());
            buf
        }
        Value::UInt(u) => {
            let mut buf = vec![0x02];
            buf.extend_from_slice(&u.to_le_bytes());
            buf
        }
        Value::String(s) => {
            let mut buf = vec![0x03];
            buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
            buf.extend_from_slice(s.as_bytes());
            buf
        }
        Value::Bytes(b) => {
            let mut buf = vec![0x04];
            buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
            buf.extend_from_slice(b);
            buf
        }
    }
}

/// Compute a deterministic hash for a `CandidateAction`.
pub fn hash_candidate(candidate: &CandidateAction) -> Hash32 {
    let mut buf = Vec::new();

    // action_type
    buf.extend_from_slice(&(candidate.action_type.len() as u32).to_le_bytes());
    buf.extend_from_slice(candidate.action_type.as_bytes());

    // score
    buf.extend_from_slice(&candidate.score.0.to_le_bytes());

    // params (sorted by key for determinism)
    let mut keys: Vec<_> = candidate.params.keys().collect();
    keys.sort();
    for key in keys {
        buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
        buf.extend_from_slice(key.as_bytes());
        buf.extend_from_slice(&hash_value(&candidate.params[key]));
    }

    sha256(&buf)
}

/// Compute a deterministic hash for a `StateSnapshot`.
pub fn hash_state(state: &StateSnapshot) -> Hash32 {
    let mut buf = Vec::new();

    // fields (sorted by key)
    let mut keys: Vec<_> = state.fields.keys().collect();
    keys.sort();
    for key in keys {
        buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
        buf.extend_from_slice(key.as_bytes());
        buf.extend_from_slice(&hash_value(&state.fields[key]));
    }

    // policy_inputs (sorted by key)
    let mut pi_keys: Vec<_> = state.policy_inputs.keys().collect();
    pi_keys.sort();
    for key in pi_keys {
        buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
        buf.extend_from_slice(key.as_bytes());
        let data = &state.policy_inputs[key];
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
    }

    sha256(&buf)
}

/// Compute a deterministic hash for a candidate set.
pub fn hash_candidate_set(candidates: &[CandidateAction]) -> Hash32 {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(candidates.len() as u32).to_le_bytes());
    for c in candidates {
        buf.extend_from_slice(&hash_candidate(c).0);
    }
    sha256(&buf)
}

/// Compute a decision commitment from a `Decision`.
pub fn hash_decision(decision: &Decision) -> Hash32 {
    let mut buf = Vec::new();
    buf.extend_from_slice(&decision.policy_hash.0);
    buf.extend_from_slice(&(decision.chosen_index as u32).to_le_bytes());
    buf.extend_from_slice(&hash_candidate(&decision.chosen_action).0);
    sha256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Score;
    use std::collections::HashMap;

    #[test]
    fn hash_candidate_is_deterministic() {
        let c1 = CandidateAction {
            action_type: "BUY".into(),
            params: HashMap::from([
                ("amount".into(), Value::UInt(100)),
                ("price".into(), Value::UInt(50)),
            ]),
            score: Score(10),
            candidate_hash: Hash32([0u8; 32]),
        };

        let c2 = CandidateAction {
            action_type: "BUY".into(),
            params: HashMap::from([
                ("price".into(), Value::UInt(50)),
                ("amount".into(), Value::UInt(100)),
            ]),
            score: Score(10),
            candidate_hash: Hash32([0u8; 32]),
        };

        assert_eq!(hash_candidate(&c1), hash_candidate(&c2));
    }

    #[test]
    fn different_candidates_have_different_hashes() {
        let c1 = CandidateAction {
            action_type: "BUY".into(),
            params: HashMap::from([("amount".into(), Value::UInt(100))]),
            score: Score(10),
            candidate_hash: Hash32([0u8; 32]),
        };

        let c2 = CandidateAction {
            action_type: "SELL".into(),
            params: HashMap::from([("amount".into(), Value::UInt(100))]),
            score: Score(10),
            candidate_hash: Hash32([0u8; 32]),
        };

        assert_ne!(hash_candidate(&c1), hash_candidate(&c2));
    }
}
