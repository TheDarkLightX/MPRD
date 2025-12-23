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

/// Compute a domain-separated SHA-256 hash: `H(domain || data)`.
pub fn sha256_domain(domain: &[u8], data: &[u8]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(data);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash32(bytes)
}

// =============================================================================
// Domain separation (v1)
// =============================================================================

/// Domain separation tag for hashing Tau policy source bytes.
pub const POLICY_TAU_DOMAIN_V1: &[u8] = b"MPRD_POLICY_TAU_V1";

/// Domain separation tag for hashing canonical state preimages.
pub const STATE_HASH_DOMAIN_V1: &[u8] = b"MPRD_STATE_HASH_V1";

/// Domain separation tag for hashing canonical candidate preimages.
pub const CANDIDATE_HASH_DOMAIN_V1: &[u8] = b"MPRD_CANDIDATE_HASH_V1";

/// Domain separation tag for hashing canonical candidate-set preimages.
pub const CANDIDATE_SET_HASH_DOMAIN_V1: &[u8] = b"MPRD_CANDIDATE_SET_HASH_V1";

/// Domain separation tag for hashing core decision commitments (legacy helper).
pub const DECISION_HASH_DOMAIN_V1: &[u8] = b"MPRD_DECISION_HASH_V1";

/// Hash canonical v1 state preimage bytes into a commitment.
pub fn hash_state_preimage_v1(state_preimage: &[u8]) -> Hash32 {
    sha256_domain(STATE_HASH_DOMAIN_V1, state_preimage)
}

/// Hash canonical v1 candidate preimage bytes into a commitment.
pub fn hash_candidate_preimage_v1(candidate_preimage: &[u8]) -> Hash32 {
    sha256_domain(CANDIDATE_HASH_DOMAIN_V1, candidate_preimage)
}

/// Hash canonical v1 candidate-set preimage bytes into a commitment.
pub fn hash_candidate_set_preimage_v1(candidate_set_preimage: &[u8]) -> Hash32 {
    sha256_domain(CANDIDATE_SET_HASH_DOMAIN_V1, candidate_set_preimage)
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

/// Build the canonical preimage bytes for a `CandidateAction` hash.
///
/// The returned bytes are the exact preimage hashed by `hash_candidate`.
pub fn candidate_hash_preimage(candidate: &CandidateAction) -> Vec<u8> {
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

    buf
}

/// Compute a deterministic hash for a `CandidateAction`.
pub fn hash_candidate(candidate: &CandidateAction) -> Hash32 {
    hash_candidate_preimage_v1(&candidate_hash_preimage(candidate))
}

/// Build the canonical preimage bytes for a `StateSnapshot` hash.
///
/// The returned bytes are the exact preimage hashed by `hash_state`.
pub fn state_hash_preimage(state: &StateSnapshot) -> Vec<u8> {
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

    buf
}

/// Compute a deterministic hash for a `StateSnapshot`.
pub fn hash_state(state: &StateSnapshot) -> Hash32 {
    hash_state_preimage_v1(&state_hash_preimage(state))
}

/// Build the canonical preimage bytes for a candidate set hash.
///
/// Layout (little-endian):
/// - `u32` candidate count
/// - `count * [u8;32]` candidate hashes, in order
pub fn candidate_set_hash_preimage(candidates: &[CandidateAction]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(candidates.len() as u32).to_le_bytes());
    for c in candidates {
        buf.extend_from_slice(&hash_candidate(c).0);
    }
    buf
}

/// Compute a deterministic hash for a candidate set.
pub fn hash_candidate_set(candidates: &[CandidateAction]) -> Hash32 {
    hash_candidate_set_preimage_v1(&candidate_set_hash_preimage(candidates))
}

/// Compute a decision commitment from a `Decision`.
pub fn hash_decision(decision: &Decision) -> Hash32 {
    let mut buf = Vec::new();
    buf.extend_from_slice(&decision.policy_hash.0);
    buf.extend_from_slice(&(decision.chosen_index as u32).to_le_bytes());
    buf.extend_from_slice(&hash_candidate(&decision.chosen_action).0);
    sha256_domain(DECISION_HASH_DOMAIN_V1, &buf)
}

// =============================================================================
// Parallel Hashing (Rayon)
// =============================================================================

use rayon::prelude::*;

/// Hash multiple candidates in parallel using Rayon.
///
/// This provides ~Nx speedup on multi-core systems when hashing many candidates.
/// Useful during candidate set construction or verification.
pub fn hash_candidates_parallel(candidates: &[CandidateAction]) -> Vec<Hash32> {
    candidates
        .par_iter()
        .map(hash_candidate)
        .collect()
}

/// Compute a deterministic hash for a candidate set using parallel hashing.
///
/// Internally hashes each candidate in parallel, then combines into the set hash.
pub fn hash_candidate_set_parallel(candidates: &[CandidateAction]) -> Hash32 {
    let hashes: Vec<Hash32> = hash_candidates_parallel(candidates);
    let mut buf = Vec::with_capacity(4 + candidates.len() * 32);
    buf.extend_from_slice(&(candidates.len() as u32).to_le_bytes());
    for h in hashes {
        buf.extend_from_slice(&h.0);
    }
    hash_candidate_set_preimage_v1(&buf)
}

// =============================================================================
// Cached Candidate (avoid redundant hashing)
// =============================================================================

/// A candidate with its hash pre-computed and cached.
///
/// Use this in hot loops where the same candidate may be hashed multiple times
/// (e.g., building Merkle trees, comparing candidates).
///
/// # Security (CBC)
/// The candidate field is private to prevent mutation that would make the hash stale.
/// Use `candidate()` getter for read access.
#[derive(Clone, Debug)]
pub struct CachedCandidate {
    candidate: CandidateAction, // Private to prevent hash staleness
    hash: Hash32,
}

impl CachedCandidate {
    /// Create a cached candidate by computing and storing its hash.
    pub fn new(candidate: CandidateAction) -> Self {
        let hash = hash_candidate(&candidate);
        Self { candidate, hash }
    }

    /// Get an immutable reference to the candidate.
    pub fn candidate(&self) -> &CandidateAction {
        &self.candidate
    }

    /// Get the pre-computed candidate hash.
    pub fn hash(&self) -> &Hash32 {
        &self.hash
    }

    /// Consume self and return the underlying candidate.
    pub fn into_candidate(self) -> CandidateAction {
        self.candidate
    }

    /// Create multiple cached candidates in parallel.
    pub fn from_candidates_parallel(candidates: Vec<CandidateAction>) -> Vec<Self> {
        candidates
            .into_par_iter()
            .map(Self::new)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Score;
    use proptest::prelude::*;
    use std::collections::HashMap;

    fn value_strategy() -> impl Strategy<Value = Value> {
        prop_oneof![
            any::<bool>().prop_map(Value::Bool),
            (-10_000i64..=10_000).prop_map(Value::Int),
            (0u64..=10_000).prop_map(Value::UInt),
            "[-_a-zA-Z0-9]{0,64}".prop_map(Value::String),
            proptest::collection::vec(any::<u8>(), 0..64).prop_map(Value::Bytes),
        ]
    }

    fn state_with(
        fields: HashMap<String, Value>,
        policy_inputs: HashMap<String, Vec<u8>>,
    ) -> StateSnapshot {
        StateSnapshot {
            fields,
            policy_inputs,
            state_hash: Hash32([0u8; 32]),
            state_ref: crate::StateRef::unknown(),
        }
    }

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

    proptest! {
        #[test]
        fn hash_state_is_order_invariant(
            fields in proptest::collection::btree_map("k[0-9]{1,2}", value_strategy(), 0..32),
            policy_inputs in proptest::collection::btree_map("pi[0-9]{1,2}", proptest::collection::vec(any::<u8>(), 0..64), 0..32),
        ) {
            let mut a_fields = HashMap::new();
            for (k, v) in fields.iter() {
                a_fields.insert(k.clone(), v.clone());
            }

            let mut b_fields = HashMap::new();
            for (k, v) in fields.iter().rev() {
                b_fields.insert(k.clone(), v.clone());
            }

            let mut a_inputs = HashMap::new();
            for (k, v) in policy_inputs.iter() {
                a_inputs.insert(k.clone(), v.clone());
            }

            let mut b_inputs = HashMap::new();
            for (k, v) in policy_inputs.iter().rev() {
                b_inputs.insert(k.clone(), v.clone());
            }

            let s1 = state_with(a_fields, a_inputs);
            let s2 = state_with(b_fields, b_inputs);
            prop_assert_eq!(hash_state(&s1), hash_state(&s2));
        }

        #[test]
        fn hash_candidate_params_is_order_invariant(
            action_type in "[-_a-zA-Z0-9]{1,16}",
            score in (-100i64..=100),
            params in proptest::collection::btree_map("p[0-9]{1,2}", value_strategy(), 0..32),
        ) {
            let mut a = HashMap::new();
            for (k, v) in params.iter() {
                a.insert(k.clone(), v.clone());
            }

            let mut b = HashMap::new();
            for (k, v) in params.iter().rev() {
                b.insert(k.clone(), v.clone());
            }

            let c1 = CandidateAction {
                action_type: action_type.clone(),
                params: a,
                score: Score(score),
                candidate_hash: Hash32([0u8; 32]),
            };
            let c2 = CandidateAction {
                action_type,
                params: b,
                score: c1.score,
                candidate_hash: Hash32([0u8; 32]),
            };

            prop_assert_eq!(hash_candidate(&c1), hash_candidate(&c2));
        }
    }
}
