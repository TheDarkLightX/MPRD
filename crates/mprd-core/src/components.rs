//! Concrete implementations of MPRD core traits.
//!
//! This module provides production-ready implementations of the core
//! interfaces defined in lib.rs, enabling real MPRD pipelines.

use crate::anti_replay::{
    AntiReplayConfig as CoreAntiReplayConfig, DistributedNonceTracker, FileNonceStore,
    InMemoryNonceTracker, NonceValidator, PersistentNonceTracker, RedisDistributedNonceStore,
    SharedFsDistributedNonceStore,
};
use crate::orchestrator::DecisionTokenFactory;
use crate::{
    hash::candidate_hash_preimage,
    hash::{hash_candidate, hash_decision, hash_state},
    CandidateAction, Decision, DecisionToken, ExecutionResult, ExecutorAdapter, Hash32, NonceHash,
    PolicyRef, ProofBundle, Proposer, Result, Score, StateProvider, StateSnapshot, Value,
    VerificationStatus, ZkAttestor, ZkLocalVerifier,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// =============================================================================
// SimpleStateProvider
// =============================================================================

/// A configurable state provider that returns a fixed or computed state.
///
/// Useful for testing, simulation, and simple integration scenarios.
pub struct SimpleStateProvider {
    fields: HashMap<String, Value>,
    policy_inputs: HashMap<String, Vec<u8>>,
}

impl SimpleStateProvider {
    /// Create a new provider with the given fields.
    pub fn new(fields: HashMap<String, Value>) -> Self {
        Self {
            fields,
            policy_inputs: HashMap::new(),
        }
    }

    /// Create provider with both fields and policy inputs.
    pub fn with_policy_inputs(
        fields: HashMap<String, Value>,
        policy_inputs: HashMap<String, Vec<u8>>,
    ) -> Self {
        Self {
            fields,
            policy_inputs,
        }
    }

    /// Update a field value.
    pub fn set_field(&mut self, key: impl Into<String>, value: Value) {
        self.fields.insert(key.into(), value);
    }
}

impl StateProvider for SimpleStateProvider {
    fn snapshot(&self) -> Result<StateSnapshot> {
        let state = StateSnapshot {
            fields: self.fields.clone(),
            policy_inputs: self.policy_inputs.clone(),
            state_hash: Hash32([0u8; 32]), // Placeholder, computed below
            state_ref: crate::StateRef::unknown(),
        };
        let state_hash = hash_state(&state);
        Ok(StateSnapshot {
            state_hash,
            ..state
        })
    }
}

// =============================================================================
// SimpleProposer
// =============================================================================

/// A proposer that generates candidates from a fixed list or a generator function.
pub struct SimpleProposer {
    candidates: Vec<CandidateAction>,
}

impl SimpleProposer {
    /// Create a proposer with a fixed list of candidates.
    pub fn new(candidates: Vec<CandidateAction>) -> Self {
        Self { candidates }
    }

    /// Create a single candidate with the given action type and params.
    pub fn single(
        action_type: impl Into<String>,
        params: HashMap<String, Value>,
        score: i64,
    ) -> Self {
        let mut candidate = CandidateAction {
            action_type: action_type.into(),
            params,
            score: Score(score),
            candidate_hash: Hash32([0u8; 32]),
        };
        candidate.candidate_hash = hash_candidate(&candidate);
        Self {
            candidates: vec![candidate],
        }
    }
}

impl Proposer for SimpleProposer {
    fn propose(&self, _state: &StateSnapshot) -> Result<Vec<CandidateAction>> {
        // Ensure all candidates have valid hashes
        let candidates: Vec<CandidateAction> = self
            .candidates
            .iter()
            .map(|c| {
                let mut cloned = c.clone();
                if cloned.candidate_hash == Hash32([0u8; 32]) {
                    cloned.candidate_hash = hash_candidate(&cloned);
                }
                cloned
            })
            .collect();
        Ok(candidates)
    }
}

// =============================================================================
// SignedDecisionTokenFactory
// =============================================================================

/// Factory that creates decision tokens with deterministic hashing.
///
/// In production, this would use a real signing key. For now, the signature
/// is a stub that binds the token contents.
pub struct SignedDecisionTokenFactory {
    /// Stub signing key (in production, this would be a real key).
    signing_key: [u8; 32],
}

impl SignedDecisionTokenFactory {
    /// Create a factory with the given signing key.
    pub fn new(signing_key: [u8; 32]) -> Self {
        Self { signing_key }
    }

    /// Create a factory with a default key (for testing).
    pub fn default_for_testing() -> Self {
        Self {
            signing_key: [0xABu8; 32],
        }
    }

    fn generate_nonce() -> NonceHash {
        // SECURITY: Use cryptographic RNG for nonce generation
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Hash32(bytes)
    }

    fn stub_sign(&self, data: &[u8]) -> Vec<u8> {
        // Stub signature: HMAC-like binding of data with key
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.signing_key);
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

impl DecisionTokenFactory for SignedDecisionTokenFactory {
    fn create(
        &self,
        decision: &Decision,
        state: &StateSnapshot,
        nonce_or_tx_hash: Option<NonceHash>,
        policy_ref: &PolicyRef,
    ) -> Result<DecisionToken> {
        let nonce = nonce_or_tx_hash.unwrap_or_else(Self::generate_nonce);
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crate::MprdError::ExecutionError("System clock error".into()))?
            .as_millis();
        let timestamp_ms: i64 = timestamp_ms
            .try_into()
            .map_err(|_| crate::MprdError::ExecutionError("System clock overflow".into()))?;

        let decision_commitment = hash_decision(decision);

        // Construct token binding data for signature
        let mut binding = Vec::new();
        binding.extend_from_slice(&decision.policy_hash.0);
        binding.extend_from_slice(&policy_ref.policy_epoch.to_le_bytes());
        binding.extend_from_slice(&policy_ref.registry_root.0);
        binding.extend_from_slice(&state.state_hash.0);
        binding.extend_from_slice(&state.state_ref.state_source_id.0);
        binding.extend_from_slice(&state.state_ref.state_epoch.to_le_bytes());
        binding.extend_from_slice(&state.state_ref.state_attestation_hash.0);
        binding.extend_from_slice(&decision_commitment.0);
        binding.extend_from_slice(&nonce.0);
        binding.extend_from_slice(&timestamp_ms.to_le_bytes());

        let signature = self.stub_sign(&binding);

        Ok(DecisionToken {
            policy_hash: decision.policy_hash.clone(),
            policy_ref: policy_ref.clone(),
            state_hash: state.state_hash.clone(),
            state_ref: state.state_ref.clone(),
            chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
            nonce_or_tx_hash: nonce,
            timestamp_ms,
            signature,
        })
    }
}

// =============================================================================
// CryptoDecisionTokenFactory (Production)
// =============================================================================

/// Production token factory using ed25519 signatures.
///
/// This factory creates decision tokens with real cryptographic signatures
/// that can be verified by any party with the public key.
pub struct CryptoDecisionTokenFactory {
    signing_key: crate::crypto::TokenSigningKey,
}

impl CryptoDecisionTokenFactory {
    /// Create a factory with the given signing key.
    pub fn new(signing_key: crate::crypto::TokenSigningKey) -> Self {
        Self { signing_key }
    }

    /// Create a factory with a randomly generated key.
    ///
    /// # Security
    /// Only use for testing. Production should load keys from secure storage.
    pub fn generate() -> Self {
        Self {
            signing_key: crate::crypto::TokenSigningKey::generate(),
        }
    }

    /// Create a factory from a hex-encoded seed.
    pub fn from_hex(hex_seed: &str) -> Result<Self> {
        let signing_key = crate::crypto::TokenSigningKey::from_hex(hex_seed)?;
        Ok(Self { signing_key })
    }

    /// Get the public verifying key for distribution.
    pub fn verifying_key(&self) -> crate::crypto::TokenVerifyingKey {
        self.signing_key.verifying_key()
    }

    fn generate_nonce() -> NonceHash {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Hash32(bytes)
    }
}

impl DecisionTokenFactory for CryptoDecisionTokenFactory {
    fn create(
        &self,
        decision: &Decision,
        state: &StateSnapshot,
        nonce_or_tx_hash: Option<NonceHash>,
        policy_ref: &PolicyRef,
    ) -> Result<DecisionToken> {
        let nonce = nonce_or_tx_hash.unwrap_or_else(Self::generate_nonce);
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crate::MprdError::ExecutionError("System clock error".into()))?
            .as_millis();
        let timestamp_ms: i64 = timestamp_ms
            .try_into()
            .map_err(|_| crate::MprdError::ExecutionError("System clock overflow".into()))?;

        // Create unsigned token for signing
        let mut token = DecisionToken {
            policy_hash: decision.policy_hash.clone(),
            policy_ref: policy_ref.clone(),
            state_hash: state.state_hash.clone(),
            state_ref: state.state_ref.clone(),
            chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
            nonce_or_tx_hash: nonce,
            timestamp_ms,
            signature: vec![],
        };

        // Sign the token
        let signature = self.signing_key.sign_token(&token);
        token.signature = signature.to_vec();

        Ok(token)
    }
}

// =============================================================================
// StubZkAttestor
// =============================================================================

/// Stub ZK attestor that creates proof bundles without real proofs.
///
/// In production, this would invoke Risc0 to generate a receipt.
pub struct StubZkAttestor;

impl StubZkAttestor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StubZkAttestor {
    fn default() -> Self {
        Self::new()
    }
}

impl ZkAttestor for StubZkAttestor {
    fn attest(
        &self,
        token: &DecisionToken,
        decision: &Decision,
        state: &StateSnapshot,
        candidates: &[CandidateAction],
    ) -> Result<ProofBundle> {
        use crate::hash::hash_candidate_set;

        let candidate_set_hash = hash_candidate_set(candidates);
        let chosen_action_preimage = candidate_hash_preimage(&decision.chosen_action);

        // Stub receipt: in production, this would be a real Risc0 receipt
        let stub_receipt = b"STUB_RISC0_RECEIPT_V1".to_vec();

        let mut metadata = HashMap::new();
        metadata.insert("attestor_version".into(), "stub_v1".into());
        metadata.insert("risc0_image_id".into(), "placeholder".into());
        metadata.insert(
            "nonce_or_tx_hash".into(),
            hex::encode(token.nonce_or_tx_hash.0),
        );

        Ok(ProofBundle {
            policy_hash: decision.policy_hash.clone(),
            state_hash: state.state_hash.clone(),
            candidate_set_hash,
            chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
            limits_hash: crate::limits::limits_hash_v1(&[]),
            limits_bytes: vec![],
            chosen_action_preimage,
            risc0_receipt: stub_receipt,
            attestation_metadata: metadata,
        })
    }
}

// =============================================================================
// StubZkLocalVerifier
// =============================================================================

/// Stub ZK verifier that checks proof bundle structure without real verification.
///
/// In production, this would verify the Risc0 receipt.
pub struct StubZkLocalVerifier;

impl StubZkLocalVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StubZkLocalVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ZkLocalVerifier for StubZkLocalVerifier {
    fn verify(&self, token: &DecisionToken, proof: &ProofBundle) -> VerificationStatus {
        // Structural checks
        if token.policy_hash != proof.policy_hash {
            return VerificationStatus::Failure("policy_hash mismatch".into());
        }
        if token.state_hash != proof.state_hash {
            return VerificationStatus::Failure("state_hash mismatch".into());
        }
        if token.chosen_action_hash != proof.chosen_action_hash {
            return VerificationStatus::Failure("chosen_action_hash mismatch".into());
        }
        if proof.risc0_receipt.is_empty() {
            return VerificationStatus::Failure("empty receipt".into());
        }

        // In production: verify the Risc0 receipt here
        VerificationStatus::Success
    }
}

// =============================================================================
// LoggingExecutorAdapter
// =============================================================================

/// Executor that logs actions instead of performing real side effects.
///
/// Useful for testing, dry runs, and audit trails.
pub struct LoggingExecutorAdapter {
    /// Accumulated log of executed actions.
    log: std::sync::Mutex<Vec<ExecutedAction>>,
}

/// Record of an executed action.
#[derive(Clone, Debug)]
pub struct ExecutedAction {
    pub policy_hash: Hash32,
    pub state_hash: Hash32,
    pub action_hash: Hash32,
    pub timestamp_ms: i64,
}

impl LoggingExecutorAdapter {
    pub fn new() -> Self {
        Self {
            log: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Get a copy of the execution log.
    pub fn get_log(&self) -> Vec<ExecutedAction> {
        match self.log.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Clear the execution log.
    pub fn clear_log(&self) {
        match self.log.lock() {
            Ok(mut guard) => guard.clear(),
            Err(poisoned) => poisoned.into_inner().clear(),
        }
    }
}

impl Default for LoggingExecutorAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutorAdapter for LoggingExecutorAdapter {
    fn execute(&self, verified: &crate::VerifiedBundle<'_>) -> Result<ExecutionResult> {
        let token = verified.token();
        let action = ExecutedAction {
            policy_hash: token.policy_hash.clone(),
            state_hash: token.state_hash.clone(),
            action_hash: token.chosen_action_hash.clone(),
            timestamp_ms: token.timestamp_ms,
        };

        let mut log = self
            .log
            .lock()
            .map_err(|_| crate::MprdError::ExecutionError("Execution log lock poisoned".into()))?;
        log.push(action);

        Ok(ExecutionResult {
            success: true,
            message: Some("action logged".into()),
        })
    }
}

// =============================================================================
// SignatureVerifyingExecutor (Production)
// =============================================================================

/// Executor wrapper that verifies token signatures before execution.
///
/// This provides an additional security layer by ensuring that only
/// tokens signed by the authorized key are executed.
pub struct SignatureVerifyingExecutor<E: ExecutorAdapter> {
    inner: E,
    verifying_key: crate::crypto::TokenVerifyingKey,
}

impl<E: ExecutorAdapter> SignatureVerifyingExecutor<E> {
    /// Create a new signature-verifying executor.
    pub fn new(inner: E, verifying_key: crate::crypto::TokenVerifyingKey) -> Self {
        Self {
            inner,
            verifying_key,
        }
    }
}

impl<E: ExecutorAdapter> ExecutorAdapter for SignatureVerifyingExecutor<E> {
    fn execute(&self, verified: &crate::VerifiedBundle<'_>) -> Result<ExecutionResult> {
        let token = verified.token();
        // Verify signature before executing
        self.verifying_key.verify_token(token, &token.signature)?;

        // Signature valid, proceed with execution
        self.inner.execute(verified)
    }
}

pub struct SignatureVerifyingBoxedExecutor {
    inner: Box<dyn ExecutorAdapter + Send + Sync>,
    verifying_key: crate::crypto::TokenVerifyingKey,
}

impl SignatureVerifyingBoxedExecutor {
    pub fn new(
        inner: Box<dyn ExecutorAdapter + Send + Sync>,
        verifying_key: crate::crypto::TokenVerifyingKey,
    ) -> Self {
        Self {
            inner,
            verifying_key,
        }
    }
}

impl ExecutorAdapter for SignatureVerifyingBoxedExecutor {
    fn execute(&self, verified: &crate::VerifiedBundle<'_>) -> Result<ExecutionResult> {
        let token = verified.token();
        // SECURITY: fail closed on invalid/missing signatures. This must run before any side
        // effects (including nonce tracking) to prevent unauthenticated probing.
        self.verifying_key.verify_token(token, &token.signature)?;
        self.inner.execute(verified)
    }
}

pub struct StateProvenanceBoxedExecutor {
    inner: Box<dyn ExecutorAdapter + Send + Sync>,
    allowed_state_source_ids: Vec<Hash32>,
}

impl StateProvenanceBoxedExecutor {
    pub fn new(
        inner: Box<dyn ExecutorAdapter + Send + Sync>,
        allowed_state_source_ids: Vec<Hash32>,
    ) -> Self {
        Self {
            inner,
            allowed_state_source_ids,
        }
    }
}

impl ExecutorAdapter for StateProvenanceBoxedExecutor {
    fn execute(&self, verified: &crate::VerifiedBundle<'_>) -> Result<ExecutionResult> {
        let token = verified.token();
        let state_ref = &token.state_ref;
        if state_ref.state_source_id == Hash32([0u8; 32])
            || state_ref.state_attestation_hash == Hash32([0u8; 32])
        {
            return Err(crate::MprdError::InvalidInput(
                "missing state provenance (state_ref)".into(),
            ));
        }

        if !self
            .allowed_state_source_ids
            .iter()
            .any(|h| h == &state_ref.state_source_id)
        {
            return Err(crate::MprdError::InvalidInput(
                "unallowlisted state provenance scheme (state_source_id)".into(),
            ));
        }

        self.inner.execute(verified)
    }
}

pub struct AntiReplayBoxedExecutor {
    inner: Box<dyn ExecutorAdapter + Send + Sync>,
    nonce_validator: Arc<dyn NonceValidator>,
}

impl AntiReplayBoxedExecutor {
    pub fn new(
        inner: Box<dyn ExecutorAdapter + Send + Sync>,
        nonce_validator: Arc<dyn NonceValidator>,
    ) -> Self {
        Self {
            inner,
            nonce_validator,
        }
    }
}

impl ExecutorAdapter for AntiReplayBoxedExecutor {
    fn execute(&self, verified: &crate::VerifiedBundle<'_>) -> Result<ExecutionResult> {
        let token = verified.token();
        // SECURITY: Checks-Effects-Interactions
        // - Check: validate that the nonce has not been replayed and timestamp is acceptable.
        // - Interaction: execute the inner action.
        // - Effect:
        //   - If the nonce was not claimed before execution, mark it used only on success.
        //   - If the nonce was claimed before execution (low-trust multi-node), do not re-claim.
        let claim = self.nonce_validator.validate_and_claim(token)?;
        let result = self.inner.execute(verified)?;

        if !result.success {
            return Ok(result);
        }

        if claim == crate::anti_replay::NonceClaim::NotClaimed {
            self.nonce_validator.mark_used(token)?;
        }
        Ok(result)
    }
}

fn nonce_tracker_from_config(config: &crate::MprdConfig) -> Result<Arc<dyn NonceValidator>> {
    // SECURITY: translate the user-provided anti-replay settings into the core nonce tracker.
    // Any omitted fields use the core defaults; this must remain conservative (fail-closed)
    // relative to replay protection.
    let tracker_config = CoreAntiReplayConfig::new(
        config.anti_replay.max_token_age_ms,
        config.anti_replay.nonce_retention_ms,
        config.anti_replay.max_future_skew_ms,
        config.anti_replay.max_tracked_nonces,
    )?;

    if config.trust_mode == crate::config::TrustMode::LowTrust {
        match config.low_trust.nonce_store_backend {
            crate::config::DistributedNonceBackend::SharedFs => {
                let Some(ref dir) = config.anti_replay.nonce_store_dir else {
                    return Err(crate::MprdError::ConfigError(
                        "LowTrust requires anti_replay.nonce_store_dir for SharedFs nonce coordination".into(),
                    ));
                };
                let store = SharedFsDistributedNonceStore::new(dir)?;
                return Ok(Arc::new(DistributedNonceTracker::new(
                    store,
                    tracker_config,
                )));
            }
            crate::config::DistributedNonceBackend::Redis => {
                let Some(ref redis_url) = config.low_trust.redis_url else {
                    return Err(crate::MprdError::ConfigError(
                        "LowTrust Redis requires low_trust.redis_url".into(),
                    ));
                };
                let store = RedisDistributedNonceStore::new(
                    redis_url,
                    &config.low_trust.redis_key_prefix,
                    std::time::Duration::from_millis(config.low_trust.redis_timeout_ms),
                )?;
                return Ok(Arc::new(DistributedNonceTracker::new(
                    store,
                    tracker_config,
                )));
            }
            crate::config::DistributedNonceBackend::PostgreSql
            | crate::config::DistributedNonceBackend::Etcd
            | crate::config::DistributedNonceBackend::OnChain => {
                return Err(crate::MprdError::ConfigError(
                    "LowTrust distributed nonce backend not implemented in this build; use redis (recommended) or shared_fs for pre-testnet".into(),
                ));
            }
        }
    }

    if let Some(ref dir) = config.anti_replay.nonce_store_dir {
        // HighTrust: fail closed if persistence is configured but cannot be initialized.
        let store = FileNonceStore::new(dir)?;
        return Ok(Arc::new(PersistentNonceTracker::new(store, tracker_config)));
    }

    Ok(Arc::new(InMemoryNonceTracker::with_config(tracker_config)))
}

fn verifying_key_from_config(
    config: &crate::config::CryptoConfig,
) -> Result<crate::crypto::TokenVerifyingKey> {
    // SECURITY: signatures are only meaningful if key material is configured correctly.
    // This function must stay fail-closed: missing or malformed keys must produce Err.
    let Some(ref signing_key_hex) = config.signing_key_hex else {
        return Err(crate::MprdError::ConfigError(
            "signing_key_hex is required when require_signatures=true".into(),
        ));
    };

    let signing_key = crate::crypto::TokenSigningKey::from_hex(signing_key_hex)?;
    Ok(signing_key.verifying_key())
}

fn state_provenance_allowlist_from_config(
    config: &crate::config::StateProvenanceConfig,
) -> Result<Vec<Hash32>> {
    let mut out = Vec::with_capacity(config.allowed_state_source_ids_hex.len());
    for id in &config.allowed_state_source_ids_hex {
        let bytes = hex::decode(id.trim()).map_err(|_| {
            crate::MprdError::ConfigError(
                "allowed_state_source_ids_hex contains invalid hex".into(),
            )
        })?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            crate::MprdError::ConfigError(
                "allowed_state_source_ids_hex entries must be 32 bytes".into(),
            )
        })?;
        out.push(Hash32(arr));
    }
    Ok(out)
}

pub fn wrap_executor_with_guards(
    inner: Box<dyn ExecutorAdapter + Send + Sync>,
    config: &crate::MprdConfig,
) -> Result<Box<dyn ExecutorAdapter + Send + Sync>> {
    // SECURITY BOUNDARY: this function is the canonical composition point for runtime execution
    // guards. It must stay fail-closed: any inability to enforce configured checks returns Err.
    //
    // Invariants:
    // - If `require_signatures=true`, then every accepted token MUST have a valid signature.
    // - Every successful execution MUST be replay-protected (nonce marked used once).
    // - High-trust: unsuccessful executions MUST NOT consume the nonce (prevents
    //   attacker-induced nonce exhaustion).
    // - Low-trust: the distributed nonce tracker claims the nonce before execution to prevent
    //   multi-node replay races. This may consume the nonce even if execution fails; deployments
    //   should require downstream idempotency keyed by `nonce_or_tx_hash`.
    //
    // Guard ordering (outermost first):
    // - Signature verification (when enabled) runs before anti-replay to avoid an attacker using
    //   unauthenticated traffic to probe nonce-tracker state.
    // - State provenance checks (when enabled) run before anti-replay; they are side-effect free
    //   and prevent accepting tokens bound to unknown/untrusted state sources.
    // - Anti-replay performs Checks-Effects-Interactions: validate -> execute -> mark_used.
    let nonce_validator = nonce_tracker_from_config(config)?;
    let mut executor: Box<dyn ExecutorAdapter + Send + Sync> =
        Box::new(AntiReplayBoxedExecutor::new(inner, nonce_validator));

    if config.state_provenance.require_provenance {
        let allowlisted = state_provenance_allowlist_from_config(&config.state_provenance)?;
        executor = Box::new(StateProvenanceBoxedExecutor::new(executor, allowlisted));
    }

    if !config.crypto.require_signatures {
        return Ok(executor);
    }

    // Fail closed if signatures are required but key material is not configured.
    let verifying_key = verifying_key_from_config(&config.crypto)?;
    executor = Box::new(SignatureVerifyingBoxedExecutor::new(
        executor,
        verifying_key,
    ));
    Ok(executor)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn dummy_policy_ref() -> PolicyRef {
        PolicyRef {
            policy_epoch: 1,
            registry_root: dummy_hash(99),
        }
    }

    #[test]
    fn simple_state_provider_creates_snapshot_with_hash() {
        let fields = HashMap::from([
            ("balance".into(), Value::UInt(1000)),
            ("risk_level".into(), Value::Int(5)),
        ]);
        let provider = SimpleStateProvider::new(fields);
        let snapshot = provider.snapshot().expect("snapshot should succeed");

        assert_eq!(snapshot.fields.len(), 2);
        assert_ne!(snapshot.state_hash, Hash32([0u8; 32]));
    }

    #[test]
    fn simple_proposer_generates_candidates_with_hashes() {
        let proposer = SimpleProposer::single(
            "BUY",
            HashMap::from([("amount".into(), Value::UInt(100))]),
            10,
        );

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(1),
            state_ref: crate::StateRef::unknown(),
        };

        let candidates = proposer.propose(&state).expect("propose should succeed");
        assert_eq!(candidates.len(), 1);
        assert_ne!(candidates[0].candidate_hash, Hash32([0u8; 32]));
    }

    #[test]
    fn signed_token_factory_creates_valid_token() {
        let factory = SignedDecisionTokenFactory::default_for_testing();

        let decision = Decision {
            chosen_index: 0,
            chosen_action: CandidateAction {
                action_type: "BUY".into(),
                params: HashMap::new(),
                score: Score(10),
                candidate_hash: dummy_hash(2),
            },
            policy_hash: dummy_hash(3),
            decision_commitment: dummy_hash(4),
        };

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(5),
            state_ref: crate::StateRef::unknown(),
        };

        let token = factory
            .create(&decision, &state, None, &dummy_policy_ref())
            .expect("create should succeed");

        assert_eq!(token.policy_hash, decision.policy_hash);
        assert_eq!(token.state_hash, state.state_hash);
        assert!(!token.signature.is_empty());
    }

    #[test]
    fn stub_attestor_creates_proof_bundle() {
        let attestor = StubZkAttestor::new();

        let decision = Decision {
            chosen_index: 0,
            chosen_action: CandidateAction {
                action_type: "BUY".into(),
                params: HashMap::new(),
                score: Score(10),
                candidate_hash: dummy_hash(2),
            },
            policy_hash: dummy_hash(3),
            decision_commitment: dummy_hash(4),
        };

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(5),
            state_ref: crate::StateRef::unknown(),
        };

        let candidates = vec![decision.chosen_action.clone()];
        let token = DecisionToken {
            policy_hash: decision.policy_hash.clone(),
            policy_ref: dummy_policy_ref(),
            state_hash: state.state_hash.clone(),
            state_ref: state.state_ref.clone(),
            chosen_action_hash: decision.chosen_action.candidate_hash.clone(),
            nonce_or_tx_hash: dummy_hash(9),
            timestamp_ms: 0,
            signature: vec![],
        };

        let proof = attestor
            .attest(&token, &decision, &state, &candidates)
            .expect("attest should succeed");

        assert_eq!(proof.policy_hash, decision.policy_hash);
        assert!(!proof.risc0_receipt.is_empty());
    }

    #[test]
    fn stub_verifier_checks_hash_consistency() {
        let verifier = StubZkLocalVerifier::new();

        let token = DecisionToken {
            policy_hash: dummy_hash(1),
            policy_ref: dummy_policy_ref(),
            state_hash: dummy_hash(2),
            state_ref: crate::StateRef::unknown(),
            chosen_action_hash: dummy_hash(3),
            nonce_or_tx_hash: dummy_hash(4),
            timestamp_ms: 0,
            signature: vec![],
        };

        let proof = ProofBundle {
            policy_hash: dummy_hash(1),
            state_hash: dummy_hash(2),
            candidate_set_hash: dummy_hash(5),
            chosen_action_hash: dummy_hash(3),
            limits_hash: dummy_hash(6),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![1, 2, 3],
            attestation_metadata: HashMap::new(),
        };

        assert_eq!(verifier.verify(&token, &proof), VerificationStatus::Success);

        // Mismatch should fail
        let bad_proof = ProofBundle {
            policy_hash: dummy_hash(99), // Wrong
            ..proof.clone()
        };
        assert!(matches!(
            verifier.verify(&token, &bad_proof),
            VerificationStatus::Failure(_)
        ));
    }

    #[test]
    fn logging_executor_records_actions() {
        let executor = LoggingExecutorAdapter::new();

        let token = DecisionToken {
            policy_hash: dummy_hash(1),
            policy_ref: dummy_policy_ref(),
            state_hash: dummy_hash(2),
            state_ref: crate::StateRef::unknown(),
            chosen_action_hash: dummy_hash(3),
            nonce_or_tx_hash: dummy_hash(4),
            timestamp_ms: 12345,
            signature: vec![],
        };

        let proof = ProofBundle {
            policy_hash: dummy_hash(1),
            state_hash: dummy_hash(2),
            candidate_set_hash: dummy_hash(5),
            chosen_action_hash: dummy_hash(3),
            limits_hash: dummy_hash(6),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![1, 2, 3],
            attestation_metadata: HashMap::new(),
        };

        let verified = crate::VerifiedBundle::new(&token, &proof);
        let result = executor.execute(&verified).expect("execute should succeed");
        assert!(result.success);

        let log = executor.get_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].action_hash, dummy_hash(3));
    }

    #[test]
    fn crypto_token_factory_creates_verifiable_tokens() {
        let factory = CryptoDecisionTokenFactory::generate();
        let verifying_key = factory.verifying_key();

        let decision = Decision {
            chosen_index: 0,
            chosen_action: CandidateAction {
                action_type: "BUY".into(),
                params: HashMap::new(),
                score: Score(10),
                candidate_hash: dummy_hash(2),
            },
            policy_hash: dummy_hash(3),
            decision_commitment: dummy_hash(4),
        };

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(5),
            state_ref: crate::StateRef::unknown(),
        };

        let token = factory
            .create(&decision, &state, None, &dummy_policy_ref())
            .expect("create should succeed");

        // Verify signature
        let result = verifying_key.verify_token(&token, &token.signature);
        assert!(result.is_ok());
    }

    #[test]
    fn signature_verifying_executor_accepts_valid_signature() {
        let factory = CryptoDecisionTokenFactory::generate();
        let verifying_key = factory.verifying_key();
        let inner = LoggingExecutorAdapter::new();
        let executor = SignatureVerifyingExecutor::new(inner, verifying_key);

        let decision = Decision {
            chosen_index: 0,
            chosen_action: CandidateAction {
                action_type: "BUY".into(),
                params: HashMap::new(),
                score: Score(10),
                candidate_hash: dummy_hash(2),
            },
            policy_hash: dummy_hash(3),
            decision_commitment: dummy_hash(4),
        };

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(5),
            state_ref: crate::StateRef::unknown(),
        };

        let token = factory
            .create(&decision, &state, None, &dummy_policy_ref())
            .unwrap();

        let proof = ProofBundle {
            policy_hash: token.policy_hash.clone(),
            state_hash: token.state_hash.clone(),
            candidate_set_hash: dummy_hash(6),
            chosen_action_hash: token.chosen_action_hash.clone(),
            limits_hash: dummy_hash(7),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![1, 2, 3],
            attestation_metadata: HashMap::new(),
        };

        let verified = crate::VerifiedBundle::new(&token, &proof);
        let result = executor.execute(&verified);
        assert!(result.is_ok());
    }

    #[test]
    fn signature_verifying_executor_rejects_invalid_signature() {
        let factory = CryptoDecisionTokenFactory::generate();
        let wrong_factory = CryptoDecisionTokenFactory::generate(); // Different key
        let verifying_key = wrong_factory.verifying_key();
        let inner = LoggingExecutorAdapter::new();
        let executor = SignatureVerifyingExecutor::new(inner, verifying_key);

        let decision = Decision {
            chosen_index: 0,
            chosen_action: CandidateAction {
                action_type: "BUY".into(),
                params: HashMap::new(),
                score: Score(10),
                candidate_hash: dummy_hash(2),
            },
            policy_hash: dummy_hash(3),
            decision_commitment: dummy_hash(4),
        };

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(5),
            state_ref: crate::StateRef::unknown(),
        };

        // Token signed with wrong key
        let token = factory
            .create(&decision, &state, None, &dummy_policy_ref())
            .unwrap();

        let proof = ProofBundle {
            policy_hash: token.policy_hash.clone(),
            state_hash: token.state_hash.clone(),
            candidate_set_hash: dummy_hash(6),
            chosen_action_hash: token.chosen_action_hash.clone(),
            limits_hash: dummy_hash(7),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![1, 2, 3],
            attestation_metadata: HashMap::new(),
        };

        let verified = crate::VerifiedBundle::new(&token, &proof);
        let result = executor.execute(&verified);
        assert!(result.is_err());
    }

    struct CountingExecutor {
        calls: Arc<AtomicUsize>,
    }

    impl ExecutorAdapter for CountingExecutor {
        fn execute(&self, _verified: &crate::VerifiedBundle<'_>) -> Result<ExecutionResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ExecutionResult {
                success: true,
                message: None,
            })
        }
    }

    fn now_ms_for_tests() -> i64 {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis();
        ms as i64
    }

    #[test]
    fn wrap_executor_with_guards_rejects_invalid_signature_without_side_effects() {
        let seed_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let factory = CryptoDecisionTokenFactory::from_hex(seed_hex).expect("factory");
        let config = crate::MprdConfig::builder()
            .signing_key_hex(seed_hex)
            .require_signatures(true)
            .build()
            .expect("config");

        let decision = Decision {
            chosen_index: 0,
            chosen_action: CandidateAction {
                action_type: "BUY".into(),
                params: HashMap::new(),
                score: Score(10),
                candidate_hash: dummy_hash(2),
            },
            policy_hash: dummy_hash(3),
            decision_commitment: dummy_hash(4),
        };

        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(5),
            state_ref: crate::StateRef::unknown(),
        };

        let mut token = factory
            .create(&decision, &state, None, &dummy_policy_ref())
            .expect("token");
        token.signature = vec![0u8; 64];
        token.timestamp_ms = now_ms_for_tests();

        let proof = ProofBundle {
            policy_hash: token.policy_hash.clone(),
            state_hash: token.state_hash.clone(),
            candidate_set_hash: dummy_hash(6),
            chosen_action_hash: token.chosen_action_hash.clone(),
            limits_hash: dummy_hash(7),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![1],
            attestation_metadata: HashMap::new(),
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let inner: Box<dyn ExecutorAdapter + Send + Sync> = Box::new(CountingExecutor {
            calls: calls.clone(),
        });
        let guarded = wrap_executor_with_guards(inner, &config).expect("wrap");

        let verified = crate::VerifiedBundle::new(&token, &proof);
        let result = guarded.execute(&verified);
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn wrap_executor_with_guards_rejects_nonce_replay() {
        let config = crate::MprdConfig::builder()
            .require_signatures(false)
            .build()
            .expect("config");

        let token = DecisionToken {
            policy_hash: dummy_hash(10),
            policy_ref: dummy_policy_ref(),
            state_hash: dummy_hash(11),
            state_ref: crate::StateRef::unknown(),
            chosen_action_hash: dummy_hash(12),
            nonce_or_tx_hash: dummy_hash(13),
            timestamp_ms: now_ms_for_tests(),
            signature: vec![],
        };

        let proof = ProofBundle {
            policy_hash: token.policy_hash.clone(),
            state_hash: token.state_hash.clone(),
            candidate_set_hash: dummy_hash(14),
            chosen_action_hash: token.chosen_action_hash.clone(),
            limits_hash: dummy_hash(15),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![1],
            attestation_metadata: HashMap::new(),
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let inner: Box<dyn ExecutorAdapter + Send + Sync> = Box::new(CountingExecutor {
            calls: calls.clone(),
        });
        let guarded = wrap_executor_with_guards(inner, &config).expect("wrap");

        let verified = crate::VerifiedBundle::new(&token, &proof);
        let first = guarded.execute(&verified);
        assert!(first.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let second = guarded.execute(&verified);
        assert!(matches!(second, Err(crate::MprdError::NonceReplay { .. })));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn low_trust_nonce_claims_before_execute_prevent_double_execution() {
        let dir = std::env::temp_dir().join(format!(
            "mprd_low_trust_nonces_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create dir");

        let mut config = crate::MprdConfig::default();
        config.crypto.require_signatures = false;
        config.trust_mode = crate::config::TrustMode::LowTrust;
        config.anti_replay.nonce_store_dir = Some(dir.to_string_lossy().to_string());
        config.low_trust.registry_quorum_threshold = 1;
        config.low_trust.registry_trusted_signers_hex =
            vec!["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into()];
        config.low_trust.state_quorum_threshold = 1;
        config.low_trust.state_trusted_attestors_hex =
            vec!["abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into()];
        config.low_trust.max_state_staleness_ms = 60_000;
        config.low_trust.ipfs_gateways =
            vec!["https://gw1.invalid".into(), "https://gw2.invalid".into()];
        config.validate().expect("config validate");

        let token = DecisionToken {
            policy_hash: dummy_hash(10),
            policy_ref: dummy_policy_ref(),
            state_hash: dummy_hash(11),
            state_ref: crate::StateRef::unknown(),
            chosen_action_hash: dummy_hash(12),
            nonce_or_tx_hash: dummy_hash(13),
            timestamp_ms: now_ms_for_tests(),
            signature: vec![],
        };

        let proof = ProofBundle {
            policy_hash: token.policy_hash.clone(),
            state_hash: token.state_hash.clone(),
            candidate_set_hash: dummy_hash(14),
            chosen_action_hash: token.chosen_action_hash.clone(),
            limits_hash: dummy_hash(15),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![1],
            attestation_metadata: HashMap::new(),
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let inner: Box<dyn ExecutorAdapter + Send + Sync> = Box::new(CountingExecutor {
            calls: calls.clone(),
        });
        let guarded = Arc::new(wrap_executor_with_guards(inner, &config).expect("wrap"));

        let g1 = guarded.clone();
        let t1 = token.clone();
        let p1 = proof.clone();
        let h1 = std::thread::spawn(move || {
            let verified = crate::VerifiedBundle::new(&t1, &p1);
            g1.execute(&verified)
        });

        let g2 = guarded.clone();
        let t2 = token.clone();
        let p2 = proof.clone();
        let h2 = std::thread::spawn(move || {
            let verified = crate::VerifiedBundle::new(&t2, &p2);
            g2.execute(&verified)
        });

        let r1 = h1.join().expect("join");
        let r2 = h2.join().expect("join");

        assert!(
            matches!(r1, Ok(_)) || matches!(r2, Ok(_)),
            "at least one execution should succeed"
        );
        assert!(
            matches!(r1, Err(crate::MprdError::NonceReplay { .. }))
                || matches!(r2, Err(crate::MprdError::NonceReplay { .. }))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn wrap_executor_with_guards_rejects_unknown_state_provenance_when_required() {
        let allowlisted = vec![hex::encode(
            crate::state_provenance::state_source_id_signed_snapshot_v1().0,
        )];
        let config = crate::MprdConfig::builder()
            .require_signatures(false)
            .require_state_provenance(true)
            .allowed_state_source_ids_hex(allowlisted)
            .build()
            .expect("config");

        let token = DecisionToken {
            policy_hash: dummy_hash(10),
            policy_ref: dummy_policy_ref(),
            state_hash: dummy_hash(11),
            state_ref: crate::StateRef::unknown(),
            chosen_action_hash: dummy_hash(12),
            nonce_or_tx_hash: dummy_hash(13),
            timestamp_ms: now_ms_for_tests(),
            signature: vec![],
        };

        let proof = ProofBundle {
            policy_hash: token.policy_hash.clone(),
            state_hash: token.state_hash.clone(),
            candidate_set_hash: dummy_hash(14),
            chosen_action_hash: token.chosen_action_hash.clone(),
            limits_hash: dummy_hash(15),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![1],
            attestation_metadata: HashMap::new(),
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let inner: Box<dyn ExecutorAdapter + Send + Sync> = Box::new(CountingExecutor {
            calls: calls.clone(),
        });
        let guarded = wrap_executor_with_guards(inner, &config).expect("wrap");

        let verified = crate::VerifiedBundle::new(&token, &proof);
        let result = guarded.execute(&verified);
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn wrap_executor_with_guards_accepts_allowlisted_state_provenance() {
        let state_source_id = crate::state_provenance::state_source_id_signed_snapshot_v1();
        let allowlisted = vec![hex::encode(state_source_id.0)];
        let config = crate::MprdConfig::builder()
            .require_signatures(false)
            .require_state_provenance(true)
            .allowed_state_source_ids_hex(allowlisted)
            .build()
            .expect("config");

        let token = DecisionToken {
            policy_hash: dummy_hash(10),
            policy_ref: dummy_policy_ref(),
            state_hash: dummy_hash(11),
            state_ref: crate::StateRef {
                state_source_id,
                state_epoch: 7,
                state_attestation_hash: dummy_hash(33),
            },
            chosen_action_hash: dummy_hash(12),
            nonce_or_tx_hash: dummy_hash(99),
            timestamp_ms: now_ms_for_tests(),
            signature: vec![],
        };

        let proof = ProofBundle {
            policy_hash: token.policy_hash.clone(),
            state_hash: token.state_hash.clone(),
            candidate_set_hash: dummy_hash(14),
            chosen_action_hash: token.chosen_action_hash.clone(),
            limits_hash: dummy_hash(15),
            limits_bytes: vec![],
            chosen_action_preimage: vec![],
            risc0_receipt: vec![1],
            attestation_metadata: HashMap::new(),
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let inner: Box<dyn ExecutorAdapter + Send + Sync> = Box::new(CountingExecutor {
            calls: calls.clone(),
        });
        let guarded = wrap_executor_with_guards(inner, &config).expect("wrap");

        let verified = crate::VerifiedBundle::new(&token, &proof);
        let result = guarded.execute(&verified);
        assert!(result.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
