#![no_main]

use libfuzzer_sys::fuzz_target;
use mprd_core::anti_replay::{AntiReplayConfig, AntiReplayExecutor, DistributedNonceStore, DistributedNonceTracker};
use mprd_core::{DecisionToken, ExecutionResult, ExecutorAdapter, Hash32, MprdError, PolicyRef, ProofBundle, Result, StateRef};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct TestDistributedNonceStore {
    // Keyed by (policy_hash, nonce).
    claimed: Arc<Mutex<HashSet<([u8; 32], [u8; 32])>>>,
}

impl DistributedNonceStore for TestDistributedNonceStore {
    fn try_claim_nonce(
        &self,
        policy_hash: &mprd_core::PolicyHash,
        nonce: &mprd_core::NonceHash,
        _used_at_ms: i64,
        _ttl_ms: i64,
    ) -> Result<bool> {
        let mut set = self.claimed.lock().map_err(|_| {
            MprdError::ExecutionError("distributed nonce store lock poisoned".into())
        })?;
        let key = (policy_hash.0, nonce.0);
        if set.contains(&key) {
            return Ok(false);
        }
        set.insert(key);
        Ok(true)
    }

    fn is_claimed(&self, policy_hash: &mprd_core::PolicyHash, nonce: &mprd_core::NonceHash) -> Result<bool> {
        let set = self.claimed.lock().map_err(|_| {
            MprdError::ExecutionError("distributed nonce store lock poisoned".into())
        })?;
        Ok(set.contains(&(policy_hash.0, nonce.0)))
    }

    fn backend_name(&self) -> &'static str {
        "test_in_memory"
    }
}

#[derive(Clone, Default)]
struct RecordingParityExecutor {
    calls_by_nonce_byte: Arc<Mutex<HashMap<u8, u64>>>,
}

impl RecordingParityExecutor {
    fn calls_for(&self, nonce_byte: u8) -> u64 {
        *self
            .calls_by_nonce_byte
            .lock()
            .expect("lock")
            .get(&nonce_byte)
            .unwrap_or(&0)
    }
}

impl ExecutorAdapter for RecordingParityExecutor {
    fn execute(&self, token: &DecisionToken, _proof: &ProofBundle) -> Result<ExecutionResult> {
        let b = token.nonce_or_tx_hash.0[0];
        let mut map = self.calls_by_nonce_byte.lock().map_err(|_| {
            MprdError::ExecutionError("recording executor lock poisoned".into())
        })?;
        *map.entry(b).or_insert(0) += 1;

        // Deterministic success/failure: parity of timestamp.
        let success = (token.timestamp_ms % 2) == 0;
        Ok(ExecutionResult {
            success,
            message: None,
        })
    }
}

fn proof_for(token: &DecisionToken) -> ProofBundle {
    ProofBundle {
        policy_hash: token.policy_hash.clone(),
        state_hash: token.state_hash.clone(),
        candidate_set_hash: Hash32([4u8; 32]),
        chosen_action_hash: token.chosen_action_hash.clone(),
        limits_hash: Hash32([5u8; 32]),
        limits_bytes: vec![],
        chosen_action_preimage: vec![],
        risc0_receipt: vec![1],
        attestation_metadata: HashMap::new(),
    }
}

fn token_for(nonce_byte: u8, timestamp_ms: i64) -> DecisionToken {
    DecisionToken {
        policy_hash: Hash32([1u8; 32]),
        policy_ref: PolicyRef {
            policy_epoch: 1,
            registry_root: Hash32([9u8; 32]),
        },
        state_hash: Hash32([2u8; 32]),
        state_ref: StateRef::unknown(),
        chosen_action_hash: Hash32([3u8; 32]),
        nonce_or_tx_hash: Hash32([nonce_byte; 32]),
        timestamp_ms,
        signature: vec![],
    }
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    HighTrust,
    LowTrust,
}

#[derive(Clone, Copy, Debug)]
struct Step {
    node: u8,
    nonce_byte: u8,
    timestamp_ms: i64,
}

fn parse_steps(input: &[u8]) -> (Mode, Vec<Step>) {
    if input.is_empty() {
        return (Mode::HighTrust, Vec::new());
    }

    let mode = if (input[0] & 1) == 0 {
        Mode::HighTrust
    } else {
        Mode::LowTrust
    };

    let mut steps = Vec::new();
    let mut i = 1usize;

    // Bounded length to keep fuzz runs cheap and avoid quadratic behavior.
    while i + 2 < input.len() && steps.len() < 256 {
        let node = input[i] & 1;
        let nonce_byte = input[i + 1];
        let t = input[i + 2] as i8;
        steps.push(Step {
            node,
            nonce_byte,
            timestamp_ms: t as i64,
        });
        i += 3;
    }

    (mode, steps)
}

fuzz_target!(|data: &[u8]| {
    let (mode, steps) = parse_steps(data);

    let inner = RecordingParityExecutor::default();

    // This target focuses on nonce-claim/idempotency semantics. Use permissive timestamp bounds so
    // inputs don't get filtered out as expired/future and so failures remain reproducible.
    let config = AntiReplayConfig {
        max_token_age_ms: i64::MAX / 2,
        nonce_retention_ms: i64::MAX / 2,
        max_future_skew_ms: i64::MAX / 2,
        max_tracked_nonces: 10_000,
    };
    let base_ms = 0i64;

    match mode {
        Mode::HighTrust => {
            let tracker = mprd_core::anti_replay::InMemoryNonceTracker::with_config(config);
            let exec = AntiReplayExecutor::new(inner.clone(), tracker);

            // Model: nonce is consumed only after a success.
            let mut succeeded: HashSet<u8> = HashSet::new();
            for step in steps {
                let token = token_for(step.nonce_byte, base_ms + step.timestamp_ms);
                let proof = proof_for(&token);

                let expect_replay = succeeded.contains(&step.nonce_byte);
                let result = exec.execute(&token, &proof);

                if expect_replay {
                    // If the nonce was successfully used before, any further attempt must fail
                    // before reaching inner side effects.
                    if !matches!(result, Err(MprdError::NonceReplay { .. })) {
                        panic!("expected NonceReplay for already-successful nonce");
                    }
                    continue;
                }

                match result {
                    Ok(r) => {
                        if r.success {
                            succeeded.insert(step.nonce_byte);
                        }
                    }
                    Err(MprdError::NonceReplay { .. }) => {
                        // Allowed only if the nonce had a prior success, which we checked above.
                        panic!("NonceReplay without prior success in model");
                    }
                    Err(_) => {
                        // Expiry/skew/config failures are ok and must be fail-closed.
                    }
                }
            }
        }
        Mode::LowTrust => {
            let store = TestDistributedNonceStore::default();

            // Two executors ("nodes") sharing the same distributed nonce state.
            let exec0 = AntiReplayExecutor::new(
                inner.clone(),
                DistributedNonceTracker::new(store.clone(), config.clone()),
            );
            let exec1 = AntiReplayExecutor::new(inner.clone(), DistributedNonceTracker::new(store, config));

            // Model: the first attempt claims the nonce and executes (success or fail);
            // all further attempts are replay and must not reach side effects.
            let mut claimed: HashSet<u8> = HashSet::new();
            for step in steps {
                let token = token_for(step.nonce_byte, base_ms + step.timestamp_ms);
                let proof = proof_for(&token);
                let executor = if step.node == 0 { &exec0 } else { &exec1 };

                let expect_replay = claimed.contains(&step.nonce_byte);
                let result = executor.execute(&token, &proof);
                if expect_replay {
                    // For a claimed nonce, any failure is acceptable (fail-closed). The key
                    // security property is: it must not reach side effects.
                    if matches!(result, Ok(_)) {
                        panic!("expected fail-closed for claimed nonce");
                    }
                } else {
                    // First claim can still fail for timestamp issues; but if it reaches claim,
                    // it must be considered claimed thereafter.
                    if matches!(result, Ok(_)) || matches!(result, Err(MprdError::NonceReplay { .. })) {
                        // Ok is normal; NonceReplay shouldn't happen on first claim but if it does,
                        // it's safe (fail-closed).
                    }
                    claimed.insert(step.nonce_byte);
                }
            }

            // Strong invariant: each nonce_byte can cause at most one inner side-effect call.
            for b in 0u8..=255 {
                let calls = inner.calls_for(b);
                if calls > 1 {
                    panic!("nonce_byte={} executed {} times (expected <= 1)", b, calls);
                }
            }
        }
    }
});
