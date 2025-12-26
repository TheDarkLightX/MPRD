use mprd_core::egress::validate_outbound_url;
use mprd_core::hash::hash_candidate;
use mprd_core::validation::validate_candidate_action_v1;
use mprd_core::{
    CandidateAction, MprdError, PolicyHash, Proposer, Result, StateSnapshot, MAX_CANDIDATES,
};
use mprd_models_market::{
    deterministic_shuffle_v1, router_seed_v1, MinerScoreEntryV1, SignedModelsMarketSnapshotV1,
};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};

use crate::proposers::{HttpProposer, HttpProposerConfig};

#[derive(Debug, Clone)]
pub struct ModelsMarketRoutingConfig {
    /// Total proposers to query per decision cycle (exploit + explore).
    pub n_total: usize,
    /// How many to take from the top-ranked miners (deterministic).
    pub n_exploit: usize,
    /// Per-endpoint candidate cap.
    pub max_candidates_per_endpoint: usize,
}

impl Default for ModelsMarketRoutingConfig {
    fn default() -> Self {
        Self {
            n_total: 4,
            n_exploit: 2,
            max_candidates_per_endpoint: MAX_CANDIDATES,
        }
    }
}

pub trait ModelsMarketSnapshotProvider: Send + Sync {
    fn get_verified(&self) -> Result<SignedModelsMarketSnapshotV1>;
}

pub struct FileModelsMarketSnapshotProvider {
    path: String,
    verifying_key: mprd_core::crypto::TokenVerifyingKey,
}

impl FileModelsMarketSnapshotProvider {
    pub fn new(
        path: impl Into<String>,
        verifying_key: mprd_core::crypto::TokenVerifyingKey,
    ) -> Self {
        Self {
            path: path.into(),
            verifying_key,
        }
    }
}

impl ModelsMarketSnapshotProvider for FileModelsMarketSnapshotProvider {
    fn get_verified(&self) -> Result<SignedModelsMarketSnapshotV1> {
        let bytes = fs::read(&self.path).map_err(|e| {
            MprdError::ExecutionError(format!(
                "failed to read models market snapshot {}: {}",
                self.path, e
            ))
        })?;
        let signed: SignedModelsMarketSnapshotV1 = serde_json::from_slice(&bytes).map_err(|e| {
            MprdError::InvalidInput(format!("invalid models market snapshot JSON: {}", e))
        })?;
        signed.verify_with_key(&self.verifying_key)?;
        Ok(signed)
    }
}

trait EndpointProposerFactory: Send + Sync {
    fn proposer_for_endpoint(&self, endpoint: &str) -> Result<Box<dyn Proposer>>;
}

struct HttpEndpointProposerFactory {
    policy_hash: PolicyHash,
    endpoint_path: String,
    timeout: std::time::Duration,
    max_candidates: usize,
}

impl EndpointProposerFactory for HttpEndpointProposerFactory {
    fn proposer_for_endpoint(&self, endpoint: &str) -> Result<Box<dyn Proposer>> {
        let config = HttpProposerConfig {
            base_url: endpoint.to_string(),
            endpoint_path: self.endpoint_path.clone(),
            timeout: self.timeout,
            max_candidates: self.max_candidates,
        };
        Ok(Box::new(HttpProposer::new(
            self.policy_hash.clone(),
            config,
        )?))
    }
}

/// A proposer that routes to multiple untrusted proposers (miners) based on a signed models market snapshot.
///
/// This is advisory-only: it only affects which proposers are queried, never authorization.
pub struct MarketRoutedProposer {
    policy_hash: PolicyHash,
    provider: Arc<dyn ModelsMarketSnapshotProvider>,
    routing: ModelsMarketRoutingConfig,
    factory: Arc<dyn EndpointProposerFactory>,
    proposer_cache: Mutex<HashMap<String, Arc<dyn Proposer>>>,
}

impl MarketRoutedProposer {
    pub fn new_http(
        provider: Arc<dyn ModelsMarketSnapshotProvider>,
        policy_hash: PolicyHash,
        routing: ModelsMarketRoutingConfig,
        endpoint_path: impl Into<String>,
        timeout: std::time::Duration,
    ) -> Result<Self> {
        if routing.n_total == 0 {
            return Err(MprdError::InvalidInput("n_total must be > 0".into()));
        }
        if routing.n_exploit > routing.n_total {
            return Err(MprdError::InvalidInput(
                "n_exploit must be <= n_total".into(),
            ));
        }
        if routing.max_candidates_per_endpoint == 0
            || routing.max_candidates_per_endpoint > MAX_CANDIDATES
        {
            return Err(MprdError::InvalidInput(format!(
                "max_candidates_per_endpoint out of range ({}; max {})",
                routing.max_candidates_per_endpoint, MAX_CANDIDATES
            )));
        }

        let factory = HttpEndpointProposerFactory {
            policy_hash: policy_hash.clone(),
            endpoint_path: endpoint_path.into(),
            timeout,
            max_candidates: routing.max_candidates_per_endpoint,
        };
        Ok(Self {
            policy_hash,
            provider,
            routing,
            factory: Arc::new(factory),
            proposer_cache: Mutex::new(HashMap::new()),
        })
    }

    fn select_endpoints(&self, miners: &[MinerScoreEntryV1], seed: [u8; 32]) -> Vec<String> {
        let mut miners_filtered: Vec<&MinerScoreEntryV1> = miners
            .iter()
            .filter(|m| validate_outbound_url(&m.endpoint).is_ok())
            .collect();

        // Rank deterministically: score desc, then miner_pubkey asc.
        miners_filtered.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| a.miner_pubkey.cmp(&b.miner_pubkey))
        });

        let n_total = self.routing.n_total.min(miners_filtered.len());
        let n_exploit = self.routing.n_exploit.min(n_total);
        let n_explore = n_total.saturating_sub(n_exploit);

        let mut out: Vec<String> = Vec::with_capacity(n_total);
        for m in miners_filtered.iter().take(n_exploit) {
            out.push(m.endpoint.clone());
        }

        if n_explore == 0 {
            return out;
        }

        let mut remaining: Vec<&MinerScoreEntryV1> =
            miners_filtered.into_iter().skip(n_exploit).collect();
        deterministic_shuffle_v1(&mut remaining, seed);
        for m in remaining.into_iter().take(n_explore) {
            out.push(m.endpoint.clone());
        }

        out
    }

    fn proposer_for_endpoint(&self, endpoint: &str) -> Result<Box<dyn Proposer>> {
        self.factory.proposer_for_endpoint(endpoint)
    }

    fn merge_and_bound_candidates(
        &self,
        mut candidates: Vec<CandidateAction>,
    ) -> Vec<CandidateAction> {
        // Fail-closed per-candidate: drop invalid ones rather than failing the whole proposer call.
        candidates.retain(|c| validate_candidate_action_v1(c).is_ok());

        // Recompute hashes (untrusted proposers)
        for c in &mut candidates {
            c.candidate_hash = hash_candidate(c);
        }

        // Deduplicate by candidate_hash (prevent duplicates from crowding out diversity)
        let mut seen = std::collections::HashSet::new();
        candidates.retain(|c| seen.insert(c.candidate_hash.0));

        // Sort deterministically and cap; tie-break by candidate_hash.
        candidates.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| a.candidate_hash.0.cmp(&b.candidate_hash.0))
        });
        if candidates.len() > MAX_CANDIDATES {
            candidates.truncate(MAX_CANDIDATES);
        }
        candidates
    }
}

impl Proposer for MarketRoutedProposer {
    fn propose(&self, state: &StateSnapshot) -> Result<Vec<CandidateAction>> {
        let signed = self.provider.get_verified()?;
        let snapshot = &signed.snapshot;

        let seed = router_seed_v1(
            self.policy_hash.clone(),
            state.state_hash.clone(),
            snapshot.epoch_id,
        );
        let endpoints = self.select_endpoints(&snapshot.miners, seed);

        let mut all_candidates: Vec<CandidateAction> = Vec::new();
        for endpoint in endpoints {
            let proposer: Arc<dyn Proposer> = {
                let mut cache = self.proposer_cache.lock().map_err(|_| {
                    MprdError::ExecutionError("proposer cache lock poisoned".into())
                })?;
                if let Some(p) = cache.get(&endpoint) {
                    p.clone()
                } else {
                    let created = self.proposer_for_endpoint(&endpoint)?;
                    let p: Arc<dyn Proposer> = Arc::from(created);
                    cache.insert(endpoint.clone(), p.clone());
                    p
                }
            };

            match proposer.propose(state) {
                Ok(mut cs) => all_candidates.append(&mut cs),
                Err(_) => continue,
            }
        }

        Ok(self.merge_and_bound_candidates(all_candidates))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mprd_core::Hash32;
    use mprd_core::Score;
    use mprd_models_market::{ModelsMarketSnapshotV1, MODELS_MARKET_SNAPSHOT_VERSION_V1};
    use std::collections::HashMap as StdHashMap;

    struct StaticProvider {
        signed: SignedModelsMarketSnapshotV1,
        vk: mprd_core::crypto::TokenVerifyingKey,
    }

    impl ModelsMarketSnapshotProvider for StaticProvider {
        fn get_verified(&self) -> Result<SignedModelsMarketSnapshotV1> {
            self.signed.verify_with_key(&self.vk)?;
            Ok(self.signed.clone())
        }
    }

    #[derive(Clone)]
    struct DummyFactory {
        by_endpoint: Arc<StdHashMap<String, Vec<CandidateAction>>>,
    }

    impl EndpointProposerFactory for DummyFactory {
        fn proposer_for_endpoint(&self, endpoint: &str) -> Result<Box<dyn Proposer>> {
            let candidates = self.by_endpoint.get(endpoint).cloned().unwrap_or_default();
            Ok(Box::new(mprd_core::components::SimpleProposer::new(
                candidates,
            )))
        }
    }

    #[test]
    fn selects_exploit_and_explore_deterministically() {
        let sk = mprd_core::crypto::TokenSigningKey::from_seed(&[1u8; 32]);
        let vk = sk.verifying_key();

        let snapshot = ModelsMarketSnapshotV1 {
            snapshot_version: MODELS_MARKET_SNAPSHOT_VERSION_V1,
            epoch_id: 10,
            challenge_set_hash: [1u8; 32],
            scope_id: [2u8; 32],
            miners: vec![
                MinerScoreEntryV1 {
                    miner_pubkey: [1u8; 32],
                    model_version_id: [8u8; 32],
                    endpoint: "http://localhost:1111".into(),
                    score: 100,
                },
                MinerScoreEntryV1 {
                    miner_pubkey: [2u8; 32],
                    model_version_id: [8u8; 32],
                    endpoint: "http://localhost:2222".into(),
                    score: 90,
                },
                MinerScoreEntryV1 {
                    miner_pubkey: [3u8; 32],
                    model_version_id: [8u8; 32],
                    endpoint: "http://localhost:3333".into(),
                    score: 80,
                },
            ],
        };

        let signed = mprd_models_market::SignedModelsMarketSnapshotV1::sign(&sk, 123, snapshot)
            .expect("sign");
        let provider = Arc::new(StaticProvider { signed, vk });

        let policy_hash = Hash32([9u8; 32]);
        let routing = ModelsMarketRoutingConfig {
            n_total: 2,
            n_exploit: 1,
            max_candidates_per_endpoint: 10,
        };

        let mut candidates_by_endpoint: StdHashMap<String, Vec<CandidateAction>> =
            StdHashMap::new();
        candidates_by_endpoint.insert(
            "http://localhost:1111".into(),
            vec![CandidateAction {
                action_type: "a".into(),
                params: HashMap::new(),
                score: Score(5),
                candidate_hash: Hash32([0u8; 32]),
            }],
        );
        candidates_by_endpoint.insert(
            "http://localhost:2222".into(),
            vec![CandidateAction {
                action_type: "b".into(),
                params: HashMap::new(),
                score: Score(6),
                candidate_hash: Hash32([0u8; 32]),
            }],
        );
        candidates_by_endpoint.insert(
            "http://localhost:3333".into(),
            vec![CandidateAction {
                action_type: "c".into(),
                params: HashMap::new(),
                score: Score(7),
                candidate_hash: Hash32([0u8; 32]),
            }],
        );

        let routed = MarketRoutedProposer {
            policy_hash: policy_hash.clone(),
            provider,
            routing,
            factory: Arc::new(DummyFactory {
                by_endpoint: Arc::new(candidates_by_endpoint),
            }),
            proposer_cache: Mutex::new(HashMap::new()),
        };

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: Hash32([3u8; 32]),
            state_ref: mprd_core::StateRef::unknown(),
        };

        let out1 = routed.propose(&state).expect("propose");
        let out2 = routed.propose(&state).expect("propose");
        assert_eq!(out1, out2);
        assert!(out1.len() <= MAX_CANDIDATES);
    }

    #[test]
    fn merge_bounds_and_orders_by_score_then_hash() {
        let _candidates = vec![
            CandidateAction {
                action_type: "x".into(),
                params: HashMap::new(),
                score: Score(1),
                candidate_hash: Hash32([0u8; 32]),
            },
            CandidateAction {
                action_type: "y".into(),
                params: HashMap::new(),
                score: Score(2),
                candidate_hash: Hash32([0u8; 32]),
            },
        ];

        let sk = mprd_core::crypto::TokenSigningKey::from_seed(&[2u8; 32]);
        let vk = sk.verifying_key();
        let signed = mprd_models_market::SignedModelsMarketSnapshotV1::sign(
            &sk,
            1,
            ModelsMarketSnapshotV1 {
                snapshot_version: MODELS_MARKET_SNAPSHOT_VERSION_V1,
                epoch_id: 1,
                challenge_set_hash: [0u8; 32],
                scope_id: [0u8; 32],
                miners: vec![],
            },
        )
        .unwrap();

        let routed = MarketRoutedProposer {
            policy_hash: Hash32([1u8; 32]),
            provider: Arc::new(StaticProvider { signed, vk }),
            routing: ModelsMarketRoutingConfig::default(),
            factory: Arc::new(DummyFactory {
                by_endpoint: Arc::new(StdHashMap::new()),
            }),
            proposer_cache: Mutex::new(HashMap::new()),
        };

        let merged = routed.merge_and_bound_candidates(_candidates);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].action_type, "y");
        assert_eq!(merged[1].action_type, "x");
    }
}
