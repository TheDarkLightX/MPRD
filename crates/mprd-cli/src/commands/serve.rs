//! `mprd serve` command implementation

use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::http::header;
use axum::response::IntoResponse;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    middleware,
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::process::Command;

use crate::operator;
use crate::operator::api as op_api;
use crate::operator::store as op_store;
use mprd_core::components::{
    LoggingExecutorAdapter, SignedDecisionTokenFactory, SimpleProposer, SimpleStateProvider,
    StubZkAttestor, StubZkLocalVerifier,
};
use mprd_core::orchestrator::{self};
use mprd_core::{DefaultSelector, PolicyEngine, PolicyHash, RuleVerdict, StateSnapshot, Value};

type CoreResult<T> = mprd_core::Result<T>;

mod events;
mod http_middleware;
mod util;

use self::util::{
    build_state_fields, env_opt, fingerprint_hex, is_decision_id, is_placeholder_hex64,
    is_safe_path_id, now_ms, page_bounds, parse_hash32,
};

#[cfg(test)]
mod incidents_tests;
#[cfg(test)]
mod router_tests;
#[cfg(test)]
mod status_tests;

fn map_chosen_action_preimage_storage(
    mode: op_store::OperatorChosenActionPreimageStorageModeV1,
) -> op_api::ChosenActionPreimageStorage {
    match mode {
        op_store::OperatorChosenActionPreimageStorageModeV1::NotStored => {
            op_api::ChosenActionPreimageStorage::NotStored
        }
        op_store::OperatorChosenActionPreimageStorageModeV1::InlineBlob => {
            op_api::ChosenActionPreimageStorage::InlineBlob
        }
        op_store::OperatorChosenActionPreimageStorageModeV1::DerivedFromReceipt => {
            op_api::ChosenActionPreimageStorage::DerivedFromReceipt
        }
    }
}

fn map_governance_update_kind(
    kind: mprd_core::GovernanceUpdateKindV1,
) -> op_api::GovernanceUpdateKind {
    match kind {
        mprd_core::GovernanceUpdateKindV1::PolicyTweak => op_api::GovernanceUpdateKind::PolicyTweak,
        mprd_core::GovernanceUpdateKindV1::SafetyRuleChange => {
            op_api::GovernanceUpdateKind::SafetyRuleChange
        }
        mprd_core::GovernanceUpdateKindV1::AgentCapabilityExpand => {
            op_api::GovernanceUpdateKind::AgentCapabilityExpand
        }
    }
}

fn governance_attestation_from_metadata(
    metadata: &HashMap<String, String>,
) -> CoreResult<Option<op_api::GovernanceAttestation>> {
    Ok(
        mprd_core::governance_admission_witness_from_attestation_metadata_v1(metadata)?.map(
            |governance| op_api::GovernanceAttestation {
                update_kind: map_governance_update_kind(governance.update_kind()),
                profile_app_ok: governance.profile_app_ok(),
                profile_safety_ok: governance.profile_safety_ok(),
                link_ok: governance.link_ok(),
            },
        ),
    )
}

fn registry_authorization_from_metadata(
    metadata: &HashMap<String, String>,
) -> CoreResult<Option<op_api::RegistryAuthorizationAttestation>> {
    Ok(
        mprd_zk::registry_state::registry_authorization_attestation_metadata_from_metadata_v1(
            metadata,
        )?
        .map(|registry| op_api::RegistryAuthorizationAttestation {
            resolution_hash: hex::encode(registry.resolution_hash.0),
            exec_kind_id: hex::encode(registry.exec_kind_id),
            exec_version_id: hex::encode(registry.exec_version_id),
            image_id: hex::encode(registry.image_id),
            policy_source_kind_id: registry.policy_source_kind_id.map(hex::encode),
            policy_source_hash: registry.policy_source_hash.map(|hash| hex::encode(hash.0)),
        }),
    )
}

struct CliAllowAllPolicyEngine;

impl PolicyEngine for CliAllowAllPolicyEngine {
    fn evaluate(
        &self,
        _policy_hash: &PolicyHash,
        _state: &StateSnapshot,
        candidates: &[mprd_core::CandidateAction],
    ) -> CoreResult<Vec<RuleVerdict>> {
        let verdicts = candidates
            .iter()
            .map(|_| RuleVerdict {
                allowed: true,
                reasons: Vec::new(),
                limits: HashMap::new(),
            })
            .collect();
        Ok(verdicts)
    }
}

#[derive(Clone)]
struct AppState {
    store: op_store::OperatorStore,
    store_dir: PathBuf,
    policy_dir: PathBuf,
    insecure_demo: bool,
    live_tx: tokio::sync::broadcast::Sender<String>,
    config: super::MprdConfigFile,
    cegis_metrics: Arc<RwLock<mprd_core::cegis::ProposerMetrics>>,
}

#[derive(Clone)]
struct SignedRegistryExecutionReadyBridge {
    signed_registry_state: mprd_zk::registry_state::SignedRegistryStateV1,
    registry_state_verifying_key: mprd_core::crypto::TokenVerifyingKey,
    manifest_verifying_key: mprd_core::crypto::TokenVerifyingKey,
}

impl orchestrator::ExecutionReadyBridge for SignedRegistryExecutionReadyBridge {
    fn prepare_execution_ready<'a>(
        &self,
        verified: mprd_core::VerifiedBundle<'a>,
        state: &'a mprd_core::StateSnapshot,
        governance: Option<mprd_core::GovernanceAdmissionWitnessV1>,
    ) -> mprd_core::Result<mprd_core::ExecutionReadyBundle<'a>> {
        if governance.is_some() {
            return Err(mprd_core::MprdError::InvalidInput(
                "production serve ready bridge requires a concrete governance gate packet".into(),
            ));
        }

        // The production serve path has the verifier-trusted registry checkpoint but not a
        // concrete GovernanceGateInput packet. The zk bridge still re-derives and checks the
        // canonical state-prepared governance rails fail-closed.
        mprd_zk::prepare_execution_ready_from_signed_registry_and_governance_v1(
            verified,
            state,
            self.signed_registry_state.clone(),
            self.registry_state_verifying_key.clone(),
            self.manifest_verifying_key.clone(),
            None,
        )
    }
}

#[derive(Deserialize)]
struct RunRequest {
    #[serde(default)]
    state: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Serialize)]
struct RunResponse {
    success: bool,
    message: Option<String>,
}

fn require_no_request_state_in_production(
    request_state: Option<&HashMap<String, serde_json::Value>>,
) -> CoreResult<()> {
    if request_state.is_some() {
        return Err(mprd_core::MprdError::InvalidInput(
            "production serve requires configured signed state snapshot; request-supplied state is demo-only".into(),
        ));
    }
    Ok(())
}

fn load_signed_state_provider_from_config(
    config: &super::MprdConfigFile,
) -> CoreResult<mprd_core::state_provenance::SignedSnapshotStateProvider> {
    use mprd_core::crypto::TokenVerifyingKey;
    use mprd_core::state_provenance::{SignedSnapshotStateProvider, SignedStateSnapshotV1};

    let snapshot_path = config.state_snapshot_path.as_ref().ok_or_else(|| {
        mprd_core::MprdError::ConfigError("Missing state_snapshot_path for production serve".into())
    })?;
    let state_key_hex = config.state_verifying_key_hex.as_ref().ok_or_else(|| {
        mprd_core::MprdError::ConfigError(
            "Missing state_verifying_key_hex for production serve".into(),
        )
    })?;

    let state_vk = TokenVerifyingKey::from_hex(state_key_hex)
        .map_err(|e| mprd_core::MprdError::ExecutionError(e.to_string()))?;
    let json = std::fs::read_to_string(snapshot_path).map_err(|e| {
        mprd_core::MprdError::ExecutionError(format!("Failed to read signed state snapshot: {}", e))
    })?;
    let signed: SignedStateSnapshotV1 = serde_json::from_str(&json).map_err(|e| {
        mprd_core::MprdError::ExecutionError(format!("Invalid signed state snapshot JSON: {}", e))
    })?;

    Ok(SignedSnapshotStateProvider::new(signed, state_vk))
}

fn build_production_core_config(
    config: &super::MprdConfigFile,
) -> CoreResult<mprd_core::MprdConfig> {
    let signing_key_hex = config
        .token_signing_key_hex
        .clone()
        .ok_or_else(|| mprd_core::MprdError::ConfigError("Missing token_signing_key_hex".into()))?;

    let mut core_config = mprd_core::MprdConfig::default();
    core_config.crypto.require_signatures = true;
    core_config.crypto.signing_key_hex = Some(signing_key_hex);
    core_config.execution.circuit_breaker.enabled = true;
    core_config.state_provenance.require_provenance = true;
    core_config.state_provenance.allowed_state_source_ids_hex = vec![hex::encode(
        mprd_core::state_provenance::state_source_id_signed_snapshot_v1().0,
    )];
    core_config.anti_replay.nonce_store_dir = config
        .anti_replay
        .as_ref()
        .and_then(|ar| ar.nonce_store_dir.as_ref())
        .map(|p| p.to_string_lossy().to_string());

    core_config.validate_production()?;
    Ok(core_config)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn run_handler(
    State(state): State<AppState>,
    Json(req): Json<RunRequest>,
) -> Json<RunResponse> {
    if !state.insecure_demo
        && !trust_anchors_configured_with(
            state.config.registry_state_path.as_deref(),
            state.config.registry_verifying_key_hex.as_deref(),
            state.config.state_snapshot_path.as_deref(),
            state.config.state_verifying_key_hex.as_deref(),
        )
    {
        return Json(RunResponse {
            success: false,
            message: Some(
                "Production mode requires configured trust anchors (registry checkpoint + signed state snapshot + keys). Check your config.".into()
            ),
        });
    }

    if !state.insecure_demo {
        if let Err(e) = require_no_request_state_in_production(req.state.as_ref()) {
            return Json(RunResponse {
                success: false,
                message: Some(e.to_string()),
            });
        }
    }

    let request_state = req.state;

    let store = state.store.clone();
    let live_tx = state.live_tx.clone();
    let config = state.config.clone();
    let insecure_demo = state.insecure_demo;

    let join = tokio::task::spawn_blocking(move || {
        if insecure_demo {
            // Keep the demo pipeline running, but record operator-facing detail so the UI can be wired.
            let fields = build_state_fields(request_state)
                .map_err(|e| mprd_core::MprdError::ExecutionError(e.to_string()))?;
            let state_provider = SimpleStateProvider::new(fields);

            let proposer = SimpleProposer::single(
                "DEMO_ACTION",
                HashMap::from([("amount".into(), Value::UInt(10))]),
                100,
            );

            let policy_engine = CliAllowAllPolicyEngine;
            let selector = DefaultSelector;
            let token_factory = SignedDecisionTokenFactory::default_for_testing();
            let attestor = StubZkAttestor::new();
            let verifier = StubZkLocalVerifier::new();

            struct StoreAuditRecorder {
                store: op_store::OperatorStore,
                live_tx: tokio::sync::broadcast::Sender<String>,
            }

            impl mprd_core::orchestrator::DecisionAuditRecorder for StoreAuditRecorder {
                fn record_verified_decision(
                    &self,
                    token: &mprd_core::DecisionToken,
                    proof: &mprd_core::ProofBundle,
                    state: &mprd_core::StateSnapshot,
                    candidates: &[mprd_core::CandidateAction],
                    verdicts: &[mprd_core::RuleVerdict],
                    decision: &mprd_core::Decision,
                ) -> mprd_core::Result<()> {
                    let id = self
                        .store
                        .write_verified_decision(token, proof, state, candidates, verdicts, decision)
                        .map_err(|e| mprd_core::MprdError::ExecutionError(e.to_string()))?;
                    let binding_hash = mprd_core::execution_binding_vector_hash_v1(
                        token, proof, state, candidates, verdicts, decision,
                    )?;
                    self.store
                        .write_execution_binding_vector_hash(&id, &binding_hash)
                        .map_err(|e| mprd_core::MprdError::ExecutionError(e.to_string()))?;

                    let _ = self.live_tx.send(
                        serde_json::json!({
                            "type": "decision_completed",
                            "decisionId": id,
                        })
                        .to_string(),
                    );

                    Ok(())
                }

                fn record_execution_ready(
                    &self,
                    ready: &mprd_core::ExecutionReadyBundle<'_>,
                ) -> mprd_core::Result<()> {
                    let decision_id_hex = hex::encode(op_store::decision_id_v1(ready.token()).0);
                    let ready_hash = mprd_core::execution_ready_packet_hash_v1(ready.packet());
                    let refinement_hash =
                        mprd_core::execution_boundary_refinement_hash_v1(ready);
                    self.store
                        .write_execution_ready_packet_hash(&decision_id_hex, &ready_hash)
                        .and_then(|()| {
                            self.store.write_execution_boundary_refinement_hash(
                                &decision_id_hex,
                                &refinement_hash,
                            )
                        })
                        .map_err(|e| mprd_core::MprdError::ExecutionError(e.to_string()))
                }
            }

            struct RecordingExecutor<E: mprd_core::ExecutorAdapter> {
                inner: E,
                store: op_store::OperatorStore,
                executor_name: String,
            }

            impl<E: mprd_core::ExecutorAdapter> mprd_core::ExecutorAdapter for RecordingExecutor<E> {
                fn execute(
                    &self,
                    verified: &mprd_core::VerifiedBundle<'_>,
                ) -> mprd_core::Result<mprd_core::ExecutionResult> {
                    let started = Instant::now();
                    let result = self.inner.execute(verified)?;
                    let decision_id_hex = hex::encode(op_store::decision_id_v1(verified.token()).0);
                    let _ = self.store.write_execution_result(
                        &decision_id_hex,
                        result.success,
                        result.message.clone(),
                        self.executor_name.clone(),
                        started.elapsed().as_millis() as u64,
                    );
                    Ok(result)
                }

                fn execute_ready(
                    &self,
                    ready: &mprd_core::ExecutionReadyBundle<'_>,
                ) -> mprd_core::Result<mprd_core::ExecutionResult> {
                    let started = Instant::now();
                    let result = self.inner.execute_ready(ready)?;
                    let decision_id_hex = hex::encode(op_store::decision_id_v1(ready.token()).0);
                    let _ = self.store.write_execution_result(
                        &decision_id_hex,
                        result.success,
                        result.message.clone(),
                        self.executor_name.clone(),
                        started.elapsed().as_millis() as u64,
                    );
                    Ok(result)
                }
            }

            let audit = StoreAuditRecorder {
                store: store.clone(),
                live_tx: live_tx.clone(),
            };
            let inner_executor = LoggingExecutorAdapter::new();
            let executor = RecordingExecutor {
                inner: inner_executor,
                store: store.clone(),
                executor_name: "logging".into(),
            };

            orchestrator::run_once(orchestrator::RunOnceInputs {
                state_provider: &state_provider,
                proposer: &proposer,
                policy_engine: &policy_engine,
                selector: &selector,
                token_factory: &token_factory,
                attestor: &attestor,
                verifier: &verifier,
                executor: &executor,
                policy_hash: &mprd_core::Hash32([1u8; 32]),
                policy_ref: mprd_core::PolicyRef {
                    policy_epoch: 0,
                    registry_root: mprd_core::Hash32([0u8; 32]),
                },
                nonce_or_tx_hash: None,
                metrics: None,
                audit_recorder: Some(&audit),
            })
        } else {
             // Production Pipeline Wiring
            use mprd_core::crypto::{TokenSigningKey, TokenVerifyingKey};
            use mprd_zk::policy_fetch::DirPolicyArtifactStore;
            use mprd_zk::registry_state::{SignedRegistryStateV1, SignedStaticRegistryStateProvider};
            use mprd_risc0_shared::MPB_FUEL_LIMIT_V1;

            // 1. Load Trust Anchors
            let registry_path = config.registry_state_path.clone().ok_or_else(|| anyhow::anyhow!("Missing registry_state_path")).map_err(|e| mprd_core::MprdError::ExecutionError(e.to_string()))?;
            let registry_vk_hex = config.registry_verifying_key_hex.clone().ok_or_else(|| anyhow::anyhow!("Missing registry_verifying_key_hex")).map_err(|e| mprd_core::MprdError::ExecutionError(e.to_string()))?;
            let signing_key_hex = config.token_signing_key_hex.clone().ok_or_else(|| anyhow::anyhow!("Missing token_signing_key_hex")).map_err(|e| mprd_core::MprdError::ExecutionError(e.to_string()))?;
            let artifacts_dir = config.policy_artifacts_dir.clone().ok_or_else(|| anyhow::anyhow!("Missing policy_artifacts_dir")).map_err(|e| mprd_core::MprdError::ExecutionError(e.to_string()))?;

            let registry_vk = TokenVerifyingKey::from_hex(&registry_vk_hex).map_err(|e| mprd_core::MprdError::ExecutionError(e.to_string()))?;
            let signing_key = TokenSigningKey::from_hex(&signing_key_hex).map_err(|e| mprd_core::MprdError::ExecutionError(e.to_string()))?;

            // 2. Load Registry State
            let json = std::fs::read_to_string(&registry_path).map_err(|e| mprd_core::MprdError::ExecutionError(format!("Failed to read registry state: {}", e)))?;
            let signed_registry: SignedRegistryStateV1 = serde_json::from_str(&json).map_err(|e| mprd_core::MprdError::ExecutionError(format!("Invalid registry state JSON: {}", e)))?;

            // 3. Setup Policy/State Provider (Registry Bound)
            // Note: In a real long-running node, we would use a dynamic registry provider.
            // For now, we use the static provider loaded from the checkpoint.
             let registry_provider = Arc::new(if insecure_demo {
                 // Should be unreachable due to if check, but safe fallback
                  SignedStaticRegistryStateProvider::new(signed_registry.clone(), registry_vk.clone())
             } else {
                  SignedStaticRegistryStateProvider::new(signed_registry.clone(), registry_vk.clone())
             });

            // 4. Setup Policy Engine (MPB + Registry)
            // We use the MPB engine which enforces resource limits and deterministic execution.
            // It needs the artifact store to load bytecode for approved policies.
            let artifact_store = DirPolicyArtifactStore::new(artifacts_dir.clone());
            // TODO: Wire up MpbPolicyEngine (it's in mprd-mpb or mprd-core).
            // For this 'wire-up' task, we will stick to the Orchestrator's expected PolicyEngine trait.
            // Since MpbPolicyEngine isn't strictly exported as a standalone trait impl in core yet,
            // we will use the `Risc0` attested execution path which effectively *is* the policy engine
            // in the ZK context.
            //
            // However, the orchestrator needs a host-side `PolicyEngine` to compute the *proposed* verdict
            // before proving it.
            // We'll use a `RegistryBoundPolicyEngine` if available, or fall back to a simple logic
            // that mimics the guest logic for now.
            //
            // CRITICAL: The *Attestor* is what provides safety. The PolicyEngine is just for liveness/optimistic execution.
            // Let's use the AllowAll engine for the *host* hint, but the strictly verified Attestor for the proof.
            // The Attestor will fail if the policy (loaded from registry) actually denies it.
            let policy_engine = CliAllowAllPolicyEngine; // HOST HINT ONLY.

             // 5. Setup Proposer & State (from signed production snapshot)
            let state_provider = load_signed_state_provider_from_config(&config)?;
            // Propose a schema-valid v1 action type so the executor boundary can enforce
            // preimage/limits/schema binding (fail-closed).
            let proposer = SimpleProposer::single("noop", HashMap::new(), 0);

            // 6. Setup Attestor (Real Risc0)
            // This is the heavy lifter. It proves (Policy(State, Candidate) -> Verdict)
            // using the *actual* bytecode authorized by the registry.
            let (policy_ref, attestor) = mprd_zk::create_registry_bound_mpb_v1_attestor_from_signed_registry_state(
                signed_registry.clone(),
                registry_vk.clone(),
                registry_vk.clone(), // Manifest key same as registry for now
                artifact_store,
                MPB_FUEL_LIMIT_V1,
            ).map_err(|e| mprd_core::MprdError::ExecutionError(format!("Failed to create production attestor: {}", e)))?;

            // 7. Setup Token Factory (Real Signing)
            let token_factory = mprd_core::components::CryptoDecisionTokenFactory::new(signing_key);

            // 8. Setup Audit/Executor
             struct StoreAuditRecorder {
                store: op_store::OperatorStore,
                live_tx: tokio::sync::broadcast::Sender<String>,
            }

            impl mprd_core::orchestrator::DecisionAuditRecorder for StoreAuditRecorder {
                fn record_verified_decision(
                    &self,
                    token: &mprd_core::DecisionToken,
                    proof: &mprd_core::ProofBundle,
                    state: &mprd_core::StateSnapshot,
                    candidates: &[mprd_core::CandidateAction],
                    verdicts: &[mprd_core::RuleVerdict],
                    decision: &mprd_core::Decision,
                ) -> mprd_core::Result<()> {
                    let id = self
                        .store
                        .write_verified_decision(token, proof, state, candidates, verdicts, decision)
                        .map_err(|e| mprd_core::MprdError::ExecutionError(e.to_string()))?;
                    let binding_hash = mprd_core::execution_binding_vector_hash_v1(
                        token, proof, state, candidates, verdicts, decision,
                    )?;
                    self.store
                        .write_execution_binding_vector_hash(&id, &binding_hash)
                        .map_err(|e| mprd_core::MprdError::ExecutionError(e.to_string()))?;

                     // Notify UI
                    let _ = self.live_tx.send(
                        serde_json::json!({
                            "type": "decision_completed",
                            "decisionId": id,
                        })
                        .to_string(),
                    );
                    Ok(())
                }

                fn record_execution_ready(
                    &self,
                    ready: &mprd_core::ExecutionReadyBundle<'_>,
                ) -> mprd_core::Result<()> {
                    let decision_id_hex = hex::encode(op_store::decision_id_v1(ready.token()).0);
                    let ready_hash = mprd_core::execution_ready_packet_hash_v1(ready.packet());
                    let refinement_hash =
                        mprd_core::execution_boundary_refinement_hash_v1(ready);
                    self.store
                        .write_execution_ready_packet_hash(&decision_id_hex, &ready_hash)
                        .and_then(|()| {
                            self.store.write_execution_boundary_refinement_hash(
                                &decision_id_hex,
                                &refinement_hash,
                            )
                        })
                        .map_err(|e| mprd_core::MprdError::ExecutionError(e.to_string()))
                }
            }

             let audit = StoreAuditRecorder {
                store: store.clone(),
                live_tx: live_tx.clone(),
            };

            // Production path must verify the locally-generated proof against the verifier-trusted
            // signed registry checkpoint before any side effects happen.
             let verifier = mprd_zk::create_production_verifier_from_signed_registry_state_with_manifest_key(
                 signed_registry.clone(),
                 &registry_vk,
                 &registry_vk,
             ).map_err(|e| {
                 mprd_core::MprdError::ExecutionError(format!(
                     "Failed to create production verifier: {}",
                     e
                 ))
             })?;

             // Executor (wrapped with production guards).
             //
             // SECURITY: the executor is the side-effect chokepoint. Even in this single-process
             // node, wrap with the same fail-closed guards that production deployments require.
             let core_config = build_production_core_config(&config)?;

             // Inner executor selection (side effects):
             // - `noop` => logs only
             // - `file` => append-only JSONL audit sink (local/demo only)
             // - `idempotent_file` => one-record-per-idempotency-key file sink
             // - `idempotent_http` => remote HTTP side effects with a fail-closed local barrier
             let executor_typ = config.execution.executor_type.trim().to_ascii_lowercase();
             let inner_executor: Box<dyn mprd_core::ExecutorAdapter + Send + Sync> =
                 match executor_typ.as_str() {
                     "noop" => Box::new(LoggingExecutorAdapter::new()),
                     "file" => {
                         return Err(mprd_core::MprdError::ConfigError(
                             "production serve requires executor_type=idempotent_file for file-based side effects"
                                 .into(),
                         ))
                     }
                     "idempotent_file" => {
                         let path = config.execution.audit_file.clone().ok_or_else(|| {
                             mprd_core::MprdError::ConfigError(
                                 "executor_type=idempotent_file requires execution.audit_file"
                                     .into(),
                             )
                         })?;
                         Box::new(mprd_adapters::executors::IdempotentFileExecutor::new(path)?)
                     }
                     "http" => {
                         return Err(mprd_core::MprdError::ConfigError(
                             "production serve requires executor_type=idempotent_http for remote side effects"
                                 .into(),
                         ))
                     }
                     "idempotent_http" => {
                         let url = config.execution.http_url.clone().ok_or_else(|| {
                             mprd_core::MprdError::ConfigError(
                                 "executor_type=idempotent_http requires execution.http_url".into(),
                             )
                         })?;
                         let effect_journal_root =
                             config.execution.effect_journal_dir.clone().ok_or_else(|| {
                                 mprd_core::MprdError::ConfigError(
                                     "executor_type=idempotent_http requires execution.effect_journal_dir"
                                         .into(),
                                 )
                             })?;
                         let api_key = env_opt("MPRD_EXECUTOR_API_KEY");
                         let http_cfg = mprd_adapters::executors::HttpExecutorConfig {
                             base_url: url,
                             api_key,
                             effect_journal_root: Some(effect_journal_root),
                             ..Default::default()
                         };
                         Box::new(mprd_adapters::executors::IdempotentHttpExecutor::new(
                             http_cfg,
                         )?)
                     }
                     other => {
                         return Err(mprd_core::MprdError::ConfigError(format!(
                             "unknown executor_type: {other} (expected noop|file|idempotent_file|http|idempotent_http)"
                         )))
                     }
                 };
             let guarded_executor =
                 mprd_core::components::wrap_executor_with_guards(inner_executor, &core_config)?;

             struct BoxedExecutor(Box<dyn mprd_core::ExecutorAdapter + Send + Sync>);
             impl mprd_core::ExecutorAdapter for BoxedExecutor {
                 fn execute(
                     &self,
                     verified: &mprd_core::VerifiedBundle<'_>,
                 ) -> mprd_core::Result<mprd_core::ExecutionResult> {
                     self.0.execute(verified)
                 }

                 fn execute_ready(
                     &self,
                     ready: &mprd_core::ExecutionReadyBundle<'_>,
                 ) -> mprd_core::Result<mprd_core::ExecutionResult> {
                     self.0.execute_ready(ready)
                 }
             }

             let executor = BoxedExecutor(guarded_executor);
             let ready_bridge = SignedRegistryExecutionReadyBridge {
                 signed_registry_state: signed_registry.clone(),
                 registry_state_verifying_key: registry_vk.clone(),
                 manifest_verifying_key: registry_vk.clone(),
             };

             // Wrapper for Box<dyn ZkAttestor> to satisfy ZkAttestor trait bound
             struct BoxedZkAttestor(Box<dyn mprd_core::ZkAttestor>);
             impl mprd_core::ZkAttestor for BoxedZkAttestor {
                 fn attest_ready(
                     &self,
                     ready: &mprd_core::AttestationReadyBundle<'_>,
                     candidates: &[mprd_core::CandidateAction],
                 ) -> mprd_core::Result<mprd_core::ProofBundle> {
                     self.0.attest_ready(ready, candidates)
                 }

                 fn attest(
                     &self,
                     token: &mprd_core::DecisionToken,
                     decision: &mprd_core::Decision,
                     state: &mprd_core::StateSnapshot,
                     candidates: &[mprd_core::CandidateAction],
                 ) -> mprd_core::Result<mprd_core::ProofBundle> {
                     self.0.attest(token, decision, state, candidates)
                 }
             }
             let attestor = BoxedZkAttestor(attestor);

             struct BoxedLocalVerifier(Box<dyn mprd_core::ZkLocalVerifier>);
             impl mprd_core::ZkLocalVerifier for BoxedLocalVerifier {
                 fn verify(
                     &self,
                     token: &mprd_core::DecisionToken,
                     proof: &mprd_core::ProofBundle,
                 ) -> mprd_core::VerificationStatus {
                     self.0.verify(token, proof)
                 }
             }
             let verifier = BoxedLocalVerifier(verifier);

             // RUN IT
             // This shipped production serve path is currently MPB-specific because it wires
             // the registry-bound MPB attestor above. Select the first authorized MPB policy
             // explicitly instead of assuming the first authorized policy matches.
             let registry_state =
                 mprd_zk::registry_state::RegistryStateProvider::get(registry_provider.as_ref())
                     .unwrap();
             let target_policy = select_production_serve_policy(&registry_state)?;

             orchestrator::run_once_with_ready_bridge(orchestrator::RunOnceInputs {
                state_provider: &state_provider,
                proposer: &proposer,
                policy_engine: &policy_engine, // Host hint
                selector: &DefaultSelector,
                token_factory: &token_factory,
                attestor: &attestor, // REAL PROOF GENERATED HERE
                verifier: &verifier,
                executor: &executor,
                policy_hash: &target_policy.policy_hash,
                policy_ref,
                nonce_or_tx_hash: None, // Generated internally if None
                metrics: None,
                audit_recorder: Some(&audit),
            }, &ready_bridge)
        }
    })
    .await;

    match join {
        Ok(Ok(result)) => Json(RunResponse {
            success: result.success,
            message: result.message,
        }),
        Ok(Err(e)) => Json(RunResponse {
            success: false,
            message: Some(e.to_string()),
        }),
        Err(e) => Json(RunResponse {
            success: false,
            message: Some(format!("Internal task failure: {}", e)),
        }),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecisionsQuery {
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    page: Option<u32>,
    #[serde(default)]
    page_size: Option<u32>,
    #[serde(default)]
    start_date: Option<i64>,
    #[serde(default)]
    end_date: Option<i64>,
    #[serde(default)]
    policy_hash: Option<String>,
    #[serde(default)]
    action_type: Option<String>,
    #[serde(default)]
    verdict: Option<String>,
    #[serde(default)]
    proof_status: Option<String>,
    #[serde(default)]
    execution_status: Option<String>,
    #[serde(default)]
    q: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecisionFilter {
    All,
    Allowed,
    Denied,
    Executed,
    Failed,
    Pending,
}

impl TryFrom<&str> for DecisionFilter {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "all" => Ok(Self::All),
            "allowed" => Ok(Self::Allowed),
            "denied" => Ok(Self::Denied),
            "executed" => Ok(Self::Executed),
            "failed" => Ok(Self::Failed),
            "pending" => Ok(Self::Pending),
            _ => Err("unsupported decision filter"),
        }
    }
}

impl DecisionFilter {
    fn matches(self, decision: &op_api::DecisionSummary) -> bool {
        match self {
            DecisionFilter::All => true,
            DecisionFilter::Allowed => matches!(decision.verdict, op_api::Verdict::Allowed),
            DecisionFilter::Denied => matches!(decision.verdict, op_api::Verdict::Denied),
            DecisionFilter::Executed => {
                !matches!(decision.execution_status, op_api::ExecutionStatus::Skipped)
            }
            DecisionFilter::Failed => {
                matches!(decision.proof_status, op_api::ProofStatus::Failed)
                    || matches!(decision.execution_status, op_api::ExecutionStatus::Failed)
            }
            DecisionFilter::Pending => {
                matches!(decision.proof_status, op_api::ProofStatus::Pending)
            }
        }
    }
}

struct Pagination {
    page: u32,
    page_size: u32,
}

impl Pagination {
    fn from_query(q: &DecisionsQuery) -> Self {
        let page = q.page.unwrap_or(1).max(1);
        let page_size = q.page_size.unwrap_or(50).clamp(1, 200);
        Self { page, page_size }
    }

    fn paginate<T: Clone>(&self, items: &[T]) -> op_api::PaginatedResponse<T> {
        let total = items.len() as u64;
        let (start_idx, end_idx) = page_bounds(items.len(), self.page, self.page_size);
        let data = if start_idx >= items.len() {
            Vec::new()
        } else {
            items[start_idx..end_idx].to_vec()
        };

        op_api::PaginatedResponse {
            data,
            page: self.page,
            page_size: self.page_size,
            total,
            has_more: end_idx < items.len(),
        }
    }
}

impl DecisionsQuery {
    fn decision_filter(&self) -> Result<DecisionFilter, StatusCode> {
        self.filter
            .as_deref()
            .map(DecisionFilter::try_from)
            .transpose()
            .map_err(|_| StatusCode::BAD_REQUEST)
            .map(|filter| filter.unwrap_or(DecisionFilter::All))
    }

    fn apply_filters(&self, filter: DecisionFilter, items: &mut Vec<op_api::DecisionSummary>) {
        if !matches!(filter, DecisionFilter::All) {
            items.retain(|d| filter.matches(d));
        }

        if let Some(start) = self.start_date {
            items.retain(|d| d.timestamp >= start);
        }
        if let Some(end) = self.end_date {
            items.retain(|d| d.timestamp <= end);
        }
        if let Some(ref ph) = self.policy_hash {
            items.retain(|d| d.policy_hash == *ph);
        }
        if let Some(ref at) = self.action_type {
            items.retain(|d| d.action_type == *at);
        }
        if let Some(ref v) = self.verdict {
            items.retain(|d| format!("{:?}", d.verdict).eq_ignore_ascii_case(v));
        }
        if let Some(ref ps) = self.proof_status {
            items.retain(|d| format!("{:?}", d.proof_status).eq_ignore_ascii_case(ps));
        }
        if let Some(ref es) = self.execution_status {
            items.retain(|d| format!("{:?}", d.execution_status).eq_ignore_ascii_case(es));
        }
        if let Some(ref query) = self.q {
            let needle = query.trim().to_lowercase();
            if !needle.is_empty() {
                items.retain(|d| {
                    d.id.to_lowercase().contains(&needle)
                        || d.policy_hash.to_lowercase().contains(&needle)
                        || d.action_type.to_lowercase().contains(&needle)
                });
            }
        }
    }
}

async fn api_settings(State(state): State<AppState>) -> Json<op_api::OperatorSettings> {
    let api_key_required = env_opt("MPRD_OPERATOR_API_KEY").is_some();
    let registry_state_path = state
        .config
        .registry_state_path
        .as_ref()
        .map(|p| p.to_string_lossy().to_string());
    let registry_key_hex = state.config.registry_verifying_key_hex.clone();
    let manifest_key_hex = registry_key_hex.clone();
    let state_snapshot_path = state
        .config
        .state_snapshot_path
        .as_ref()
        .map(|p| p.to_string_lossy().to_string());
    let state_key_hex = state.config.state_verifying_key_hex.clone();
    let store_sensitive_enabled = state.store.store_sensitive_enabled();
    let decision_retention_days = state.store.decision_retention_days();
    let decision_max = state.store.decision_max();

    let deployment_mode = match state.config.mode.trim().to_ascii_lowercase().as_str() {
        "local" => op_api::DeploymentMode::Local,
        "private" => op_api::DeploymentMode::Private,
        _ => op_api::DeploymentMode::Trustless,
    };

    let registry_key_fingerprint = registry_key_hex
        .as_deref()
        .and_then(|hex_key| hex::decode(hex_key).ok())
        .map(|b| fingerprint_hex(&b));
    let manifest_key_fingerprint = manifest_key_hex
        .as_deref()
        .and_then(|hex_key| hex::decode(hex_key).ok())
        .map(|b| fingerprint_hex(&b));
    let state_key_fingerprint = state_key_hex
        .as_deref()
        .and_then(|hex_key| hex::decode(hex_key).ok())
        .map(|b| fingerprint_hex(&b));

    let trust_anchors_configured = trust_anchors_configured_with(
        state.config.registry_state_path.as_deref(),
        registry_key_hex.as_deref(),
        state.config.state_snapshot_path.as_deref(),
        state_key_hex.as_deref(),
    );

    Json(op_api::OperatorSettings {
        version: env!("CARGO_PKG_VERSION").to_string(),
        deployment_mode,
        api_key_required,
        insecure_demo_enabled: state.insecure_demo,
        store_dir: state.store_dir.to_string_lossy().to_string(),
        policy_dir: state.policy_dir.to_string_lossy().to_string(),
        store_sensitive_enabled,
        decision_retention_days,
        decision_max,
        trust_anchors_configured,
        trust_anchors: op_api::TrustAnchors {
            registry_state_path,
            registry_key_fingerprint,
            manifest_key_fingerprint,
            state_snapshot_path,
            state_key_fingerprint,
        },
    })
}

async fn api_settings_update(
    State(state): State<AppState>,
    Json(req): Json<op_api::OperatorSettingsUpdate>,
) -> Result<Json<op_api::OperatorSettings>, StatusCode> {
    if req.decision_retention_days.is_none() && req.decision_max.is_none() {
        return Ok(api_settings(State(state)).await);
    }

    if validate_retention_update(&req).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }

    state
        .store
        .update_retention_settings(req.decision_retention_days, req.decision_max)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = state.store.prune_decisions();

    Ok(api_settings(State(state)).await)
}

fn ms_since(ts_ms: i64, now_ms: i64) -> i64 {
    now_ms.saturating_sub(ts_ms)
}

fn verify_fail_rate_24h(store: &op_store::OperatorStore, now: i64) -> f64 {
    let Ok(items) = store.list_summaries(Duration::from_millis(250)) else {
        return 1.0;
    };
    let cutoff = now - 24 * 60 * 60 * 1000;
    let mut total: u64 = 0;
    let mut failed: u64 = 0;
    for d in items {
        if d.timestamp < cutoff {
            continue;
        }
        total += 1;
        if matches!(d.proof_status, op_api::ProofStatus::Failed) {
            failed += 1;
        }
    }
    if total == 0 {
        0.0
    } else {
        (failed as f64) / (total as f64)
    }
}

fn has_unacked_critical_alerts(state: &AppState) -> bool {
    let Ok(alerts) = build_alerts(state, 200, true) else {
        return true;
    };
    alerts
        .iter()
        .any(|a| matches!(a.severity, op_api::AlertSeverity::Critical) && !a.acknowledged)
}

fn autopilot_transition_allowed(
    state: &AppState,
    current: &op_store::AutopilotStateFileV1,
) -> bool {
    let mode = state.config.mode.trim().to_ascii_lowercase();
    let trustless = mode == "trustless" || mode == "private";
    if trustless
        && !trust_anchors_configured_with(
            state.config.registry_state_path.as_deref(),
            state.config.registry_verifying_key_hex.as_deref(),
            state.config.state_snapshot_path.as_deref(),
            state.config.state_verifying_key_hex.as_deref(),
        )
    {
        return false;
    }
    let now = now_ms();
    if ms_since(current.last_human_ack, now) > 4 * 60 * 60 * 1000 {
        return false;
    }
    if verify_fail_rate_24h(&state.store, now) > 0.05 {
        return false;
    }
    if has_unacked_critical_alerts(state) {
        return false;
    }
    true
}

fn autopilot_degradation_target(
    state: &AppState,
    current: &op_store::AutopilotStateFileV1,
    now: i64,
) -> Option<(op_api::AutopilotMode, String)> {
    let mode = state.config.mode.trim().to_ascii_lowercase();
    let trustless = mode == "trustless" || mode == "private";
    if trustless
        && !trust_anchors_configured_with(
            state.config.registry_state_path.as_deref(),
            state.config.registry_verifying_key_hex.as_deref(),
            state.config.state_snapshot_path.as_deref(),
            state.config.state_verifying_key_hex.as_deref(),
        )
    {
        return Some((
            op_api::AutopilotMode::Manual,
            "trust_anchors_missing".into(),
        ));
    }

    let verify_fail = verify_fail_rate_24h(&state.store, now);
    if verify_fail > 0.20 {
        return Some((
            op_api::AutopilotMode::Manual,
            format!("verify_fail_rate={:.3}", verify_fail),
        ));
    }

    if matches!(current.mode, op_api::AutopilotMode::Autopilot)
        && ms_since(current.last_human_ack, now) > 8 * 60 * 60 * 1000
    {
        return Some((op_api::AutopilotMode::Assisted, "ack_timeout".into()));
    }

    if matches!(current.mode, op_api::AutopilotMode::Autopilot)
        && has_unacked_critical_alerts(state)
    {
        return Some((op_api::AutopilotMode::Assisted, "unacked_critical".into()));
    }

    None
}

async fn autopilot_guard(state: AppState) {
    loop {
        let current = state.store.read_autopilot_state();
        let now = now_ms();
        let Some((to, reason)) = autopilot_degradation_target(&state, &current, now) else {
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        };

        if to == current.mode {
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }

        let from = current.mode;
        if state.store.set_autopilot_mode(to).is_ok() {
            let seed = format!("auto_degrade:{}:{:?}:{:?}:{reason}", now, from, to);
            let digest = sha2::Sha256::digest(seed.as_bytes());
            let audit_id = hex::encode(&digest[..8]);
            let action_id = format!("auto_degrade_{now}_{audit_id}");
            let _ = state.store.append_autopilot_action(op_api::AutoAction {
                id: action_id,
                action_type: op_api::AutoActionType::AutoDegrade,
                target: "autopilot_mode".into(),
                timestamp: now,
                explanation: op_api::Explanation {
                    summary: format!("Auto-degraded from {:?} to {:?}", from, to),
                    evidence: reason.clone(),
                    confidence: 1.0,
                    counterfactual: "Restore invariants to re-enable autopilot".into(),
                    audit_id: audit_id.clone(),
                    timestamp: now,
                    operator_can_override: false,
                },
                reversible: false,
            });

            let _ = state.live_tx.send(
                serde_json::json!({
                    "type": "mode_changed",
                    "from": format!("{:?}", from).to_lowercase(),
                    "to": format!("{:?}", to).to_lowercase(),
                    "reason": format!("auto_degrade:{reason}"),
                })
                .to_string(),
            );
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn can_transition_to(
    state: &AppState,
    current: &op_store::AutopilotStateFileV1,
) -> Vec<op_api::AutopilotMode> {
    let mut out = vec![
        op_api::AutopilotMode::Manual,
        op_api::AutopilotMode::Assisted,
    ];
    if autopilot_transition_allowed(state, current) {
        out.push(op_api::AutopilotMode::Autopilot);
    }
    out
}

async fn api_autopilot(
    State(state): State<AppState>,
) -> Result<Json<op_api::AutopilotState>, StatusCode> {
    let current = state.store.read_autopilot_state();
    Ok(Json(op_api::AutopilotState {
        mode: current.mode,
        last_human_ack: current.last_human_ack,
        pending_review_count: current.pending_review_count,
        auto_handled_24h: current.auto_handled_24h,
        can_transition_to: can_transition_to(&state, &current),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AutopilotModeRequest {
    pub mode: op_api::AutopilotMode,
    #[serde(default)]
    pub reason: Option<String>,
}

async fn api_autopilot_mode(
    State(state): State<AppState>,
    Json(req): Json<AutopilotModeRequest>,
) -> Result<Json<op_api::AutopilotState>, StatusCode> {
    let current = state.store.read_autopilot_state();
    if matches!(req.mode, op_api::AutopilotMode::Autopilot)
        && !autopilot_transition_allowed(&state, &current)
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let from = current.mode;
    let updated = state
        .store
        .set_autopilot_mode(req.mode)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let _ = state.live_tx.send(
        serde_json::json!({
            "type": "mode_changed",
            "from": format!("{:?}", from).to_lowercase(),
            "to": format!("{:?}", updated.mode).to_lowercase(),
            "reason": req.reason.unwrap_or_else(|| "operator_requested".into()),
        })
        .to_string(),
    );

    Ok(Json(op_api::AutopilotState {
        mode: updated.mode,
        last_human_ack: updated.last_human_ack,
        pending_review_count: updated.pending_review_count,
        auto_handled_24h: updated.auto_handled_24h,
        can_transition_to: can_transition_to(&state, &updated),
    }))
}

async fn api_autopilot_ack(
    State(state): State<AppState>,
) -> Result<Json<op_api::AutopilotState>, StatusCode> {
    let updated = state
        .store
        .autopilot_ack()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(op_api::AutopilotState {
        mode: updated.mode,
        last_human_ack: updated.last_human_ack,
        pending_review_count: updated.pending_review_count,
        auto_handled_24h: updated.auto_handled_24h,
        can_transition_to: can_transition_to(&state, &updated),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AutopilotActivityQuery {
    #[serde(default)]
    limit: Option<u32>,
}

async fn api_autopilot_activity(
    State(state): State<AppState>,
    Query(q): Query<AutopilotActivityQuery>,
) -> Result<Json<Vec<op_api::AutoAction>>, StatusCode> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200) as usize;
    let actions = state
        .store
        .list_autopilot_actions(limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(actions))
}

async fn api_autopilot_override(
    State(_state): State<AppState>,
    Path(_id): Path<String>,
) -> StatusCode {
    // Override/undo depends on the specific auto-action type and is not implemented in the CLI server yet.
    StatusCode::NOT_IMPLEMENTED
}

async fn api_prune_decisions(
    State(state): State<AppState>,
) -> Result<Json<op_api::RetentionPruneResult>, StatusCode> {
    let removed = state
        .store
        .prune_decisions()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(op_api::RetentionPruneResult {
        removed: removed as u64,
        now_ms: now_ms(),
        decision_retention_days: state.store.decision_retention_days(),
        decision_max: state.store.decision_max(),
    }))
}

fn validate_retention_update(req: &op_api::OperatorSettingsUpdate) -> Result<(), ()> {
    if let Some(days) = req.decision_retention_days {
        if days != 0 {
            let ms = (days as u128).saturating_mul(24 * 60 * 60 * 1000);
            if ms > i64::MAX as u128 {
                return Err(());
            }
        }
    }
    if let Some(max) = req.decision_max {
        if max != 0 && max > usize::MAX as u64 {
            return Err(());
        }
    }
    Ok(())
}

async fn tau_component_health(tau_binary: &str) -> op_api::ComponentHealth {
    let now = now_ms();
    let out = tokio::time::timeout(
        Duration::from_secs(1),
        Command::new(tau_binary)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output(),
    )
    .await;

    match out {
        Ok(Ok(output)) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            op_api::ComponentHealth {
                status: op_api::HealthLevel::Healthy,
                version: if version.is_empty() {
                    None
                } else {
                    Some(version)
                },
                last_check: now,
                message: None,
                effect_barrier_summary: None,
            }
        }
        Ok(Ok(_)) => op_api::ComponentHealth {
            status: op_api::HealthLevel::Degraded,
            version: None,
            last_check: now,
            message: Some(format!(
                "tau binary `{tau_binary}` returned non-zero status"
            )),
            effect_barrier_summary: None,
        },
        _ => op_api::ComponentHealth {
            status: op_api::HealthLevel::Unavailable,
            version: None,
            last_check: now,
            message: Some(format!("tau binary `{tau_binary}` not available")),
            effect_barrier_summary: None,
        },
    }
}

fn ipfs_component_health(config: &super::MprdConfigFile) -> op_api::ComponentHealth {
    let now = now_ms();
    let storage_type = config
        .policy_storage
        .storage_type
        .trim()
        .to_ascii_lowercase();
    if storage_type != "ipfs" {
        return op_api::ComponentHealth {
            status: op_api::HealthLevel::Healthy,
            version: None,
            last_check: now,
            message: Some(format!("disabled (policy storage = {storage_type})")),
            effect_barrier_summary: None,
        };
    }

    let Some(url) = config.policy_storage.ipfs_url.as_deref() else {
        return op_api::ComponentHealth {
            status: op_api::HealthLevel::Unavailable,
            version: None,
            last_check: now,
            message: Some("ipfs storage selected but ipfs_url is not configured".into()),
            effect_barrier_summary: None,
        };
    };

    if let Err(e) = mprd_adapters::egress::validate_outbound_url(url) {
        return op_api::ComponentHealth {
            status: op_api::HealthLevel::Unavailable,
            version: None,
            last_check: now,
            message: Some(format!("invalid ipfs_url: {e}")),
            effect_barrier_summary: None,
        };
    }

    op_api::ComponentHealth {
        status: op_api::HealthLevel::Degraded,
        version: None,
        last_check: now,
        message: Some(format!("configured ({url}); connectivity not checked")),
        effect_barrier_summary: None,
    }
}

fn risc0_component_health(config: &super::MprdConfigFile) -> op_api::ComponentHealth {
    let now = now_ms();
    let Some(image_id) = config.risc0_image_id.as_deref() else {
        return op_api::ComponentHealth {
            status: op_api::HealthLevel::Unavailable,
            version: None,
            last_check: now,
            message: Some("risc0_image_id not configured".into()),
            effect_barrier_summary: None,
        };
    };
    if is_placeholder_hex64(image_id) {
        return op_api::ComponentHealth {
            status: op_api::HealthLevel::Degraded,
            version: Some("risc0".into()),
            last_check: now,
            message: Some("placeholder image id (not production ready)".into()),
            effect_barrier_summary: None,
        };
    }
    op_api::ComponentHealth {
        status: op_api::HealthLevel::Healthy,
        version: Some("risc0".into()),
        last_check: now,
        message: Some("configured".into()),
        effect_barrier_summary: None,
    }
}

fn executor_component_health(config: &super::MprdConfigFile) -> op_api::ComponentHealth {
    let now = now_ms();
    let typ = config.execution.executor_type.trim().to_ascii_lowercase();
    match typ.as_str() {
        "noop" => op_api::ComponentHealth {
            status: op_api::HealthLevel::Degraded,
            version: None,
            last_check: now,
            message: Some("noop executor (no side effects)".into()),
            effect_barrier_summary: None,
        },
        "http" => {
            let Some(url) = config.execution.http_url.as_deref() else {
                return op_api::ComponentHealth {
                    status: op_api::HealthLevel::Unavailable,
                    version: None,
                    last_check: now,
                    message: Some("http executor selected but http_url is not configured".into()),
                    effect_barrier_summary: None,
                };
            };
            if let Err(e) = mprd_adapters::egress::validate_outbound_url(url) {
                return op_api::ComponentHealth {
                    status: op_api::HealthLevel::Unavailable,
                    version: None,
                    last_check: now,
                    message: Some(format!("invalid http_url: {e}")),
                    effect_barrier_summary: None,
                };
            }
            op_api::ComponentHealth {
                status: op_api::HealthLevel::Degraded,
                version: None,
                last_check: now,
                message: Some(format!("configured ({url}); connectivity not checked")),
                effect_barrier_summary: None,
            }
        }
        "idempotent_http" => {
            let Some(url) = config.execution.http_url.as_deref() else {
                return op_api::ComponentHealth {
                    status: op_api::HealthLevel::Unavailable,
                    version: None,
                    last_check: now,
                    message: Some(
                        "idempotent_http executor selected but http_url is not configured".into(),
                    ),
                    effect_barrier_summary: None,
                };
            };
            if let Err(e) = mprd_adapters::egress::validate_outbound_url(url) {
                return op_api::ComponentHealth {
                    status: op_api::HealthLevel::Unavailable,
                    version: None,
                    last_check: now,
                    message: Some(format!("invalid http_url: {e}")),
                    effect_barrier_summary: None,
                };
            }
            let Some(path) = config.execution.effect_journal_dir.as_ref() else {
                return op_api::ComponentHealth {
                    status: op_api::HealthLevel::Unavailable,
                    version: None,
                    last_check: now,
                    message: Some(
                        "idempotent_http executor selected but effect_journal_dir is not configured"
                            .into(),
                    ),
                    effect_barrier_summary: None,
                };
            };
            let summary = match mprd_adapters::executors::summarize_http_effect_journal_root(path) {
                Ok(summary) => summary,
                Err(e) => {
                    return op_api::ComponentHealth {
                        status: op_api::HealthLevel::Unavailable,
                        version: None,
                        last_check: now,
                        message: Some(format!(
                            "failed to inspect effect journal root {}: {e}",
                            path.display()
                        )),
                        effect_barrier_summary: None,
                    };
                }
            };
            let status = if summary.pending_entries > 0 {
                op_api::HealthLevel::Degraded
            } else {
                op_api::HealthLevel::Healthy
            };
            op_api::ComponentHealth {
                status,
                version: None,
                last_check: now,
                message: Some(format!(
                    "idempotent http executor: {url}; effect journal root: {}; pending barriers: {}; committed barriers: {} (automatic: {}, manual_promote: {}, legacy: {})",
                    path.display(),
                    summary.pending_entries,
                    summary.committed_entries,
                    summary.committed_automatic_entries,
                    summary.committed_manual_promote_entries,
                    summary.committed_legacy_entries
                )),
                effect_barrier_summary: Some(op_api::EffectBarrierSummary {
                    root_path: Some(path.display().to_string()),
                    pending_entries: summary.pending_entries,
                    committed_entries: summary.committed_entries,
                    committed_automatic_entries: summary.committed_automatic_entries,
                    committed_manual_promote_entries: summary.committed_manual_promote_entries,
                    committed_legacy_entries: summary.committed_legacy_entries,
                }),
            }
        }
        "file" => {
            let Some(path) = config.execution.audit_file.as_ref() else {
                return op_api::ComponentHealth {
                    status: op_api::HealthLevel::Degraded,
                    version: None,
                    last_check: now,
                    message: Some("file executor selected but audit_file not configured".into()),
                    effect_barrier_summary: None,
                };
            };
            op_api::ComponentHealth {
                status: op_api::HealthLevel::Healthy,
                version: None,
                last_check: now,
                message: Some(format!("audit file: {}", path.display())),
                effect_barrier_summary: None,
            }
        }
        "idempotent_file" => {
            let Some(path) = config.execution.audit_file.as_ref() else {
                return op_api::ComponentHealth {
                    status: op_api::HealthLevel::Degraded,
                    version: None,
                    last_check: now,
                    message: Some(
                        "idempotent_file executor selected but audit_file not configured".into(),
                    ),
                    effect_barrier_summary: None,
                };
            };
            op_api::ComponentHealth {
                status: op_api::HealthLevel::Healthy,
                version: None,
                last_check: now,
                message: Some(format!("idempotent audit root: {}", path.display())),
                effect_barrier_summary: None,
            }
        }
        other => op_api::ComponentHealth {
            status: op_api::HealthLevel::Degraded,
            version: None,
            last_check: now,
            message: Some(format!("unknown executor_type: {other}")),
            effect_barrier_summary: None,
        },
    }
}

fn trust_anchors_configured_with(
    registry_state_path: Option<&std::path::Path>,
    registry_key_hex: Option<&str>,
    state_snapshot_path: Option<&std::path::Path>,
    state_key_hex: Option<&str>,
) -> bool {
    let registry_path_ok = registry_state_path.is_some_and(|p| p.exists());
    let registry_key_ok = registry_key_hex
        .and_then(|hex_key| hex::decode(hex_key).ok())
        .is_some();
    let state_path_ok = state_snapshot_path.is_some_and(|p| p.exists());
    let state_key_ok = state_key_hex
        .and_then(|hex_key| hex::decode(hex_key).ok())
        .is_some();
    registry_path_ok && registry_key_ok && state_path_ok && state_key_ok
}

fn select_production_serve_policy(
    state: &mprd_zk::registry_state::RegistryStateV1,
) -> mprd_core::Result<&mprd_zk::registry_state::AuthorizedPolicyV1> {
    state
        .authorized_policies
        .iter()
        .find(|policy| {
            policy.policy_exec_kind_id == mprd_risc0_shared::policy_exec_kind_mpb_id_v1()
                && policy.policy_exec_version_id == mprd_risc0_shared::policy_exec_version_id_v1()
        })
        .ok_or_else(|| {
            mprd_core::MprdError::ExecutionError(
                "Registry has no authorized mpb-v1 policy for production serve".into(),
            )
        })
}

fn validate_serve_startup_config(
    config: &super::MprdConfigFile,
    insecure_demo: bool,
) -> anyhow::Result<()> {
    use mprd_core::crypto::TokenVerifyingKey;
    use mprd_zk::registry_state::{
        PolicyAuthorizationProvider, RegistryStatePolicyAuthorizationProvider,
        RegistryStateProvider, SignedRegistryStateV1, SignedStaticRegistryStateProvider,
    };

    if insecure_demo {
        return Ok(());
    }

    let mode = config.mode.trim().to_ascii_lowercase();
    let trustless = mode == "trustless" || mode == "private";
    if !trustless {
        return Ok(());
    }

    if trustless
        && !trust_anchors_configured_with(
            config.registry_state_path.as_deref(),
            config.registry_verifying_key_hex.as_deref(),
            config.state_snapshot_path.as_deref(),
            config.state_verifying_key_hex.as_deref(),
        )
    {
        anyhow::bail!(
            "production serve startup requires configured trust anchors (registry checkpoint + signed state snapshot + keys)"
        );
    }

    let registry_path = config.registry_state_path.as_ref().expect("checked above");
    let registry_vk = TokenVerifyingKey::from_hex(
        config
            .registry_verifying_key_hex
            .as_deref()
            .expect("checked above"),
    )?;
    let registry_json = std::fs::read_to_string(registry_path)?;
    let signed_registry: SignedRegistryStateV1 = serde_json::from_str(&registry_json)?;
    let registry_provider: Arc<dyn RegistryStateProvider> = Arc::new(
        SignedStaticRegistryStateProvider::new(signed_registry.clone(), registry_vk.clone()),
    );
    let state = RegistryStateProvider::get(registry_provider.as_ref())?;

    let state_provider = load_signed_state_provider_from_config(config)?;
    mprd_core::StateProvider::snapshot(&state_provider)?;
    let core_config = build_production_core_config(config)?;
    let _ = mprd_core::components::wrap_executor_with_guards(
        Box::new(mprd_core::components::LoggingExecutorAdapter::new()),
        &core_config,
    )?;

    if trustless {
        let executor_typ = config.execution.executor_type.trim().to_ascii_lowercase();
        match executor_typ.as_str() {
            "noop" => {}
            "http" => {
                anyhow::bail!(
                    "trustless/private production serve requires execution.executor_type=idempotent_http for remote side effects"
                );
            }
            "idempotent_http" => {
                let url = config.execution.http_url.clone().ok_or_else(|| {
                    anyhow::anyhow!("executor_type=idempotent_http requires execution.http_url")
                })?;
                let effect_journal_root =
                    config.execution.effect_journal_dir.clone().ok_or_else(|| {
                        anyhow::anyhow!(
                            "executor_type=idempotent_http requires execution.effect_journal_dir"
                        )
                    })?;
                let http_cfg = mprd_adapters::executors::HttpExecutorConfig {
                    base_url: url,
                    api_key: None,
                    effect_journal_root: Some(effect_journal_root.clone()),
                    ..Default::default()
                };
                let _ = mprd_adapters::executors::IdempotentHttpExecutor::new(http_cfg)?;
                let summary = mprd_adapters::executors::summarize_http_effect_journal_root(
                    &effect_journal_root,
                )?;
                if summary.pending_entries > 0 {
                    anyhow::bail!(
                        "trustless/private production serve refuses startup with {} unresolved idempotent_http pending barrier(s) in {}",
                        summary.pending_entries,
                        effect_journal_root.display()
                    );
                }
            }
            "idempotent_file" => {
                let path = config.execution.audit_file.clone().ok_or_else(|| {
                    anyhow::anyhow!("executor_type=idempotent_file requires execution.audit_file")
                })?;
                let _ = mprd_adapters::executors::IdempotentFileExecutor::new(path)?;
            }
            "file" => {
                anyhow::bail!(
                    "trustless/private production serve requires execution.executor_type=idempotent_file for file-based side effects"
                );
            }
            other => {
                anyhow::bail!(
                    "unknown executor_type: {other} (expected noop|file|idempotent_file|http|idempotent_http)"
                );
            }
        }

        let artifacts_dir = config
            .policy_artifacts_dir
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Missing policy_artifacts_dir"))?;
        super::deploy::check_bundle_quiet(
            registry_path.to_path_buf(),
            config
                .registry_verifying_key_hex
                .clone()
                .expect("checked above"),
            None,
            artifacts_dir,
        )?;

        let policy_ref = mprd_core::PolicyRef {
            policy_epoch: state.policy_epoch,
            registry_root: state.registry_root,
        };
        select_production_serve_policy(&state)?;
        let authorization = RegistryStatePolicyAuthorizationProvider::new(
            Arc::clone(&registry_provider),
            registry_vk.clone(),
        )
        .with_required_policy_source_mapping(true);
        for authorized in &state.authorized_policies {
            authorization.resolve(&authorized.policy_hash, &policy_ref)?;
        }

        let artifact_store = mprd_zk::policy_fetch::DirPolicyArtifactStore::new(
            config.policy_artifacts_dir.clone().expect("checked above"),
        );
        let _ = mprd_zk::create_registry_bound_mpb_v1_attestor_from_signed_registry_state(
            signed_registry.clone(),
            registry_vk.clone(),
            registry_vk.clone(),
            artifact_store,
            mprd_risc0_shared::MPB_FUEL_LIMIT_V1,
        )?;
        let _ = mprd_zk::create_production_verifier_from_signed_registry_state_with_manifest_key(
            signed_registry,
            &registry_vk,
            &registry_vk,
        )?;
    }

    Ok(())
}

fn compute_system_status(
    config: &super::MprdConfigFile,
    now: i64,
    mut components: op_api::SystemComponents,
    anchors_ok: bool,
) -> op_api::SystemStatus {
    let mode = config.mode.trim().to_ascii_lowercase();
    let trustless = mode == "trustless" || mode == "private";

    let executor_unavailable =
        matches!(components.executor.status, op_api::HealthLevel::Unavailable);
    let executor_effectively_degraded = executor_unavailable
        || (trustless && matches!(components.executor.status, op_api::HealthLevel::Degraded));
    let tau_required_unavailable =
        matches!(components.tau.status, op_api::HealthLevel::Unavailable)
            && config.tau_binary.is_some();

    let overall = if !anchors_ok
        || (trustless && matches!(components.risc0.status, op_api::HealthLevel::Unavailable))
    {
        op_api::OverallStatus::Critical
    } else if executor_effectively_degraded || tau_required_unavailable {
        op_api::OverallStatus::Degraded
    } else {
        op_api::OverallStatus::Operational
    };

    if !anchors_ok {
        components.risc0.message = Some("trust anchors missing (fail-closed)".into());
        components.risc0.last_check = now;
    }

    op_api::SystemStatus {
        overall,
        components,
    }
}

async fn api_status(State(state): State<AppState>) -> Json<op_api::SystemStatus> {
    let config = &state.config;
    let now = now_ms();

    let tau_binary = config.tau_binary.as_deref().unwrap_or("tau");
    let tau = tau_component_health(tau_binary).await;
    let ipfs = ipfs_component_health(config);
    let risc0 = risc0_component_health(config);
    let executor = executor_component_health(config);

    let mode = config.mode.trim().to_ascii_lowercase();
    let trustless = mode == "trustless" || mode == "private";
    let anchors_ok = !trustless
        || trust_anchors_configured_with(
            config.registry_state_path.as_deref(),
            config.registry_verifying_key_hex.as_deref(),
            config.state_snapshot_path.as_deref(),
            config.state_verifying_key_hex.as_deref(),
        );

    let components = op_api::SystemComponents {
        tau,
        ipfs,
        risc0,
        executor,
    };

    Json(compute_system_status(config, now, components, anchors_ok))
}

fn is_hex64_path_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn pending_http_effect_journal_root(
    config: &super::MprdConfigFile,
) -> Result<&std::path::Path, StatusCode> {
    if !config
        .execution
        .executor_type
        .trim()
        .eq_ignore_ascii_case("idempotent_http")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    config
        .execution
        .effect_journal_dir
        .as_deref()
        .ok_or(StatusCode::BAD_REQUEST)
}

fn map_pending_effect_barrier(
    barrier: mprd_adapters::executors::PendingHttpEffectBarrier,
) -> op_api::PendingEffectBarrier {
    op_api::PendingEffectBarrier {
        barrier_path: barrier.barrier_path.display().to_string(),
        policy_hash: barrier.policy_hash_hex,
        idempotency_key_v1: barrier.idempotency_key_v1,
        state_hash: barrier.state_hash_hex,
        action_hash: barrier.action_hash_hex,
        nonce_or_tx_hash: barrier.nonce_or_tx_hash_hex,
        timestamp_ms: barrier.timestamp_ms,
    }
}

fn map_committed_effect_barrier(
    barrier: mprd_adapters::executors::CommittedHttpEffectBarrier,
) -> op_api::CommittedEffectBarrier {
    op_api::CommittedEffectBarrier {
        barrier_path: barrier.barrier_path.display().to_string(),
        policy_hash: barrier.policy_hash_hex,
        idempotency_key_v1: barrier.idempotency_key_v1,
        state_hash: barrier.state_hash_hex,
        action_hash: barrier.action_hash_hex,
        nonce_or_tx_hash: barrier.nonce_or_tx_hash_hex,
        timestamp_ms: barrier.timestamp_ms,
        resolution_kind: barrier.resolution_kind.map(|kind| match kind {
            mprd_adapters::executors::CommittedHttpEffectBarrierResolutionKind::Automatic => {
                op_api::CommittedEffectBarrierResolutionKind::Automatic
            }
            mprd_adapters::executors::CommittedHttpEffectBarrierResolutionKind::ManualPromote => {
                op_api::CommittedEffectBarrierResolutionKind::ManualPromote
            }
        }),
    }
}

fn map_pending_http_effect_barrier_error(err: &mprd_core::MprdError) -> StatusCode {
    let message = err.to_string();
    if message.contains("not found") {
        StatusCode::NOT_FOUND
    } else if message.contains("already exists") {
        StatusCode::CONFLICT
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

fn load_pending_http_effect_barriers(
    config: &super::MprdConfigFile,
) -> Result<Vec<op_api::PendingEffectBarrier>, StatusCode> {
    let executor_type = config.execution.executor_type.trim().to_ascii_lowercase();
    if executor_type != "idempotent_http" {
        return Ok(Vec::new());
    }
    let Some(root) = config.execution.effect_journal_dir.as_ref() else {
        return Ok(Vec::new());
    };

    let mut barriers = mprd_adapters::executors::list_pending_http_effect_barriers(root)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .map(map_pending_effect_barrier)
        .collect::<Vec<_>>();
    barriers.sort_by(|a, b| {
        b.timestamp_ms
            .cmp(&a.timestamp_ms)
            .then_with(|| a.barrier_path.cmp(&b.barrier_path))
    });
    Ok(barriers)
}

fn load_committed_http_effect_barriers(
    config: &super::MprdConfigFile,
) -> Result<Vec<op_api::CommittedEffectBarrier>, StatusCode> {
    let executor_type = config.execution.executor_type.trim().to_ascii_lowercase();
    if executor_type != "idempotent_http" {
        return Ok(Vec::new());
    }
    let Some(root) = config.execution.effect_journal_dir.as_ref() else {
        return Ok(Vec::new());
    };

    let mut barriers = mprd_adapters::executors::list_committed_http_effect_barriers(root)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .map(map_committed_effect_barrier)
        .collect::<Vec<_>>();
    barriers.sort_by(|a, b| {
        b.timestamp_ms
            .cmp(&a.timestamp_ms)
            .then_with(|| a.barrier_path.cmp(&b.barrier_path))
    });
    Ok(barriers)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EffectBarriersQuery {
    #[serde(default)]
    limit: Option<u32>,
}

async fn api_pending_effect_barriers(
    State(state): State<AppState>,
    Query(q): Query<EffectBarriersQuery>,
) -> Result<Json<Vec<op_api::PendingEffectBarrier>>, StatusCode> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500) as usize;
    let mut barriers = load_pending_http_effect_barriers(&state.config)?;
    barriers.truncate(limit);
    Ok(Json(barriers))
}

async fn api_committed_effect_barriers(
    State(state): State<AppState>,
    Query(q): Query<EffectBarriersQuery>,
) -> Result<Json<Vec<op_api::CommittedEffectBarrier>>, StatusCode> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500) as usize;
    let mut barriers = load_committed_http_effect_barriers(&state.config)?;
    barriers.truncate(limit);
    Ok(Json(barriers))
}

async fn api_resolve_pending_effect_barrier(
    State(state): State<AppState>,
    Path((policy_hash, idempotency_key_v1)): Path<(String, String)>,
    Json(req): Json<op_api::ResolvePendingEffectBarrierRequest>,
) -> Result<Json<op_api::ResolvePendingEffectBarrierResult>, StatusCode> {
    if !is_safe_path_id(&policy_hash, 64)
        || !is_hex64_path_id(&policy_hash)
        || !is_safe_path_id(&idempotency_key_v1, 64)
        || !is_hex64_path_id(&idempotency_key_v1)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let root = pending_http_effect_journal_root(&state.config)?;
    let resolution = match req.resolution {
        op_api::PendingEffectBarrierResolution::Clear => {
            mprd_adapters::executors::PendingHttpEffectBarrierResolution::Clear
        }
        op_api::PendingEffectBarrierResolution::PromoteToCommitted => {
            mprd_adapters::executors::PendingHttpEffectBarrierResolution::PromoteToCommitted
        }
    };

    if req.dry_run {
        let barrier = mprd_adapters::executors::get_pending_http_effect_barrier(
            root,
            &policy_hash,
            &idempotency_key_v1,
        )
        .map_err(|err| map_pending_http_effect_barrier_error(&err))?;
        let committed_barrier_path = matches!(
            req.resolution,
            op_api::PendingEffectBarrierResolution::PromoteToCommitted
        )
        .then(|| {
            root.join(&policy_hash)
                .join(format!("{idempotency_key_v1}.committed.json"))
                .display()
                .to_string()
        });
        return Ok(Json(op_api::ResolvePendingEffectBarrierResult {
            success: true,
            dry_run: true,
            resolution: req.resolution,
            barrier: map_pending_effect_barrier(barrier),
            committed_barrier_path,
            message: format!(
                "Dry run: pending HTTP effect barrier {} is eligible for {:?}",
                idempotency_key_v1, req.resolution
            ),
        }));
    }

    let resolved = mprd_adapters::executors::resolve_pending_http_effect_barrier(
        root,
        &policy_hash,
        &idempotency_key_v1,
        resolution,
    )
    .map_err(|err| map_pending_http_effect_barrier_error(&err))?;
    Ok(Json(op_api::ResolvePendingEffectBarrierResult {
        success: true,
        dry_run: false,
        resolution: req.resolution,
        barrier: map_pending_effect_barrier(resolved.barrier),
        committed_barrier_path: resolved
            .committed_barrier_path
            .map(|path| path.display().to_string()),
        message: match req.resolution {
            op_api::PendingEffectBarrierResolution::Clear => {
                "Cleared pending HTTP effect barrier".into()
            }
            op_api::PendingEffectBarrierResolution::PromoteToCommitted => {
                "Promoted pending HTTP effect barrier to committed".into()
            }
        },
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AlertsQuery {
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    unacknowledged: Option<bool>,
}

async fn api_alerts(
    State(state): State<AppState>,
    Query(q): Query<AlertsQuery>,
) -> Result<Json<Vec<op_api::Alert>>, StatusCode> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200) as usize;
    let unack_only = q.unacknowledged.unwrap_or(false);
    Ok(Json(build_alerts(&state, limit, unack_only)?))
}

async fn api_alert_ack(State(state): State<AppState>, Path(id): Path<String>) -> StatusCode {
    if !is_safe_path_id(&id, 128) {
        return StatusCode::BAD_REQUEST;
    }
    let _ = state.store.acknowledge_alert(&id);
    StatusCode::NO_CONTENT
}

fn build_alerts(
    state: &AppState,
    limit: usize,
    unack_only: bool,
) -> Result<Vec<op_api::Alert>, StatusCode> {
    let decisions = state
        .store
        .list_summaries(Duration::from_millis(250))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut alerts: Vec<op_api::Alert> = Vec::new();
    for d in decisions {
        if alerts.len() >= limit {
            break;
        }
        let decision_id = d.id.clone();

        if matches!(d.proof_status, op_api::ProofStatus::Failed) {
            let id = format!("verification_failure:{decision_id}");
            let acknowledged = state.store.is_alert_acknowledged(&id);
            if !(unack_only && acknowledged) {
                alerts.push(op_api::Alert {
                    id,
                    timestamp: d.timestamp,
                    severity: op_api::AlertSeverity::Critical,
                    alert_type: op_api::AlertType::VerificationFailure,
                    message: format!("Proof verification failed for decision {decision_id}"),
                    decision_id: Some(decision_id.clone()),
                    acknowledged,
                });
            }
        }

        if alerts.len() >= limit {
            break;
        }

        if matches!(d.execution_status, op_api::ExecutionStatus::Failed) {
            let id = format!("execution_error:{decision_id}");
            let acknowledged = state.store.is_alert_acknowledged(&id);
            if !(unack_only && acknowledged) {
                alerts.push(op_api::Alert {
                    id,
                    timestamp: d.timestamp,
                    severity: op_api::AlertSeverity::Warning,
                    alert_type: op_api::AlertType::ExecutionError,
                    message: format!("Execution failed for decision {decision_id}"),
                    decision_id: Some(decision_id.clone()),
                    acknowledged,
                });
            }
        }
    }

    if alerts.len() < limit {
        let mode = state.config.mode.trim().to_ascii_lowercase();
        let trustless = mode == "trustless" || mode == "private";
        for barrier in load_pending_http_effect_barriers(&state.config)? {
            if alerts.len() >= limit {
                break;
            }
            let id = format!("pending_http_effect_barrier:{}", barrier.idempotency_key_v1);
            let acknowledged = state.store.is_alert_acknowledged(&id);
            if unack_only && acknowledged {
                continue;
            }
            alerts.push(op_api::Alert {
                id,
                timestamp: barrier.timestamp_ms,
                severity: if trustless {
                    op_api::AlertSeverity::Critical
                } else {
                    op_api::AlertSeverity::Warning
                },
                alert_type: op_api::AlertType::Anomaly,
                message: format!(
                    "Unresolved idempotent_http pending barrier at {}",
                    barrier.barrier_path
                ),
                decision_id: None,
                acknowledged,
            });
        }
    }

    Ok(alerts)
}

fn severity_score(severity: &op_api::AlertSeverity) -> u32 {
    match severity {
        op_api::AlertSeverity::Critical => 3,
        op_api::AlertSeverity::Warning => 2,
        op_api::AlertSeverity::Info => 1,
    }
}

fn normalize_incident_message(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut chars = lower.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '0' && chars.peek() == Some(&'x') {
            // Replace long hex-ish 0x... sequences.
            out.push_str("0x…");
            let _ = chars.next(); // consume 'x'
            while let Some(n) = chars.peek() {
                if n.is_ascii_hexdigit() {
                    let _ = chars.next();
                } else {
                    break;
                }
            }
            continue;
        }

        if c.is_ascii_hexdigit() {
            // Collapse long raw hex sequences (hashes).
            let mut run = String::new();
            run.push(c);
            while let Some(n) = chars.peek() {
                if n.is_ascii_hexdigit() {
                    run.push(*n);
                    let _ = chars.next();
                } else {
                    break;
                }
            }
            if run.len() >= 16 {
                out.push('…');
            } else {
                out.push_str(&run);
            }
            continue;
        }

        if c.is_ascii_digit() {
            out.push('n');
            while let Some(n) = chars.peek() {
                if n.is_ascii_digit() {
                    let _ = chars.next();
                } else {
                    break;
                }
            }
            continue;
        }

        if c.is_whitespace() {
            out.push(' ');
            while let Some(n) = chars.peek() {
                if n.is_whitespace() {
                    let _ = chars.next();
                } else {
                    break;
                }
            }
            continue;
        }

        out.push(c);
    }

    out.trim().to_string()
}

fn incident_id_for(alert_type: &op_api::AlertType, normalized_message: &str) -> String {
    let key = format!("{alert_type:?}:{normalized_message}");
    let digest = sha2::Sha256::digest(key.as_bytes());
    format!("inc_{}", hex::encode(&digest[..16]))
}

fn incident_title_for(alert: &op_api::Alert) -> String {
    let mut title = format!("{:?}: {}", alert.alert_type, alert.message);
    if title.len() > 120 {
        title.truncate(119);
        title.push('…');
    }
    title
}

fn build_incidents(
    state: &AppState,
    alerts: Vec<op_api::Alert>,
    include_snoozed: bool,
) -> Vec<(op_api::IncidentSummary, Vec<op_api::Alert>)> {
    let mut groups: HashMap<String, Vec<op_api::Alert>> = HashMap::new();
    for alert in alerts {
        let norm = normalize_incident_message(&alert.message);
        let id = incident_id_for(&alert.alert_type, &norm);
        groups.entry(id).or_default().push(alert);
    }

    let now = now_ms();
    let mut out: Vec<(op_api::IncidentSummary, Vec<op_api::Alert>)> = Vec::new();

    for (id, mut group) in groups {
        group.sort_by_key(|a| std::cmp::Reverse(a.timestamp));

        let snoozed_until = state.store.incident_snoozed_until(&id);
        let is_snoozed = snoozed_until.is_some_and(|t| t > now);
        if is_snoozed && !include_snoozed {
            continue;
        }

        let primary = group
            .iter()
            .find(|a| !a.acknowledged)
            .cloned()
            .unwrap_or_else(|| group[0].clone());
        let severity = group.iter().fold(op_api::AlertSeverity::Info, |acc, a| {
            if severity_score(&a.severity) > severity_score(&acc) {
                a.severity.clone()
            } else {
                acc
            }
        });

        let unacked = group.iter().any(|a| !a.acknowledged);
        let first_seen = group.iter().map(|a| a.timestamp).min().unwrap_or(now);
        let last_seen = group.iter().map(|a| a.timestamp).max().unwrap_or(now);
        let count = group.len() as u64;
        let flapping = Some(count >= 3 && (last_seen - first_seen) <= 10 * 60 * 1000);

        let summary = op_api::IncidentSummary {
            id: id.clone(),
            severity,
            title: incident_title_for(&primary),
            primary_alert_id: primary.id.clone(),
            alert_ids: group.iter().map(|a| a.id.clone()).collect(),
            unacked,
            first_seen,
            last_seen,
            count,
            flapping,
            recommended_action: if is_snoozed {
                Some("Snoozed".into())
            } else {
                None
            },
        };
        out.push((summary, group));
    }

    out.sort_by_key(|(s, _)| {
        (
            std::cmp::Reverse(severity_score(&s.severity)),
            std::cmp::Reverse(s.unacked),
            std::cmp::Reverse(s.last_seen),
        )
    });
    out
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IncidentsQuery {
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    unacknowledged: Option<bool>,
    #[serde(default)]
    include_snoozed: Option<bool>,
}

async fn api_incidents(
    State(state): State<AppState>,
    Query(q): Query<IncidentsQuery>,
) -> Result<Json<Vec<op_api::IncidentSummary>>, StatusCode> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200) as usize;
    let unack_only = q.unacknowledged.unwrap_or(false);
    let include_snoozed = q.include_snoozed.unwrap_or(false);

    let alerts = build_alerts(&state, 500, unack_only)?;
    let incidents = build_incidents(&state, alerts, include_snoozed);
    Ok(Json(
        incidents.into_iter().map(|(s, _)| s).take(limit).collect(),
    ))
}

async fn api_incident_detail(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<op_api::IncidentDetail>, StatusCode> {
    if !is_safe_path_id(&id, 128) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let alerts = build_alerts(&state, 500, false)?;
    let incidents = build_incidents(&state, alerts, true);
    let Some((summary, group)) = incidents.into_iter().find(|(s, _)| s.id == id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok(Json(op_api::IncidentDetail {
        summary,
        alerts: group,
        actions: suggested_actions_for_incident(),
    }))
}

fn suggested_actions_for_incident() -> Vec<op_api::SuggestedAction> {
    vec![op_api::SuggestedAction {
        id: "check_status".into(),
        title: "Run safe check: fetch /api/status".into(),
        risk: op_api::ActionRisk::Safe,
        dry_run_supported: true,
        runbook_url: None,
    }]
}

async fn api_incident_ack(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    if !is_safe_path_id(&id, 128) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let alerts = build_alerts(&state, 500, false)?;
    let incidents = build_incidents(&state, alerts, true);
    let Some((_summary, group)) = incidents.into_iter().find(|(s, _)| s.id == id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    for alert in &group {
        let _ = state.store.acknowledge_alert(&alert.id);
    }
    let _ = state.store.clear_incident_snooze(&id);
    Ok(StatusCode::NO_CONTENT)
}

async fn api_incident_snooze(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<op_api::SnoozeRequest>,
) -> Result<Json<op_api::SnoozeResult>, StatusCode> {
    if !is_safe_path_id(&id, 128) {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Cap at 7 days.
    let ttl_ms = req.ttl_ms.min(7 * 24 * 60 * 60 * 1000);
    let until = now_ms() + ttl_ms as i64;
    state
        .store
        .snooze_incident(&id, until)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(op_api::SnoozeResult {
        snoozed_until: until,
    }))
}

async fn api_incident_actions(
    Path(id): Path<String>,
) -> Result<Json<Vec<op_api::SuggestedAction>>, StatusCode> {
    if !is_safe_path_id(&id, 128) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Json(suggested_actions_for_incident()))
}

async fn api_incident_action_run(
    State(state): State<AppState>,
    Path((id, action_id)): Path<(String, String)>,
    Json(req): Json<op_api::ActionRunRequest>,
) -> Result<Json<op_api::ActionRunResult>, StatusCode> {
    if !is_safe_path_id(&id, 128) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !is_safe_path_id(&action_id, 64) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if action_id == "check_status" {
        let _ = req;
        let seed = format!("check_status:{}", now_ms());
        let digest = sha2::Sha256::digest(seed.as_bytes());
        let audit_id = hex::encode(&digest[..8]);
        let _status = api_status(State(state)).await;
        return Ok(Json(op_api::ActionRunResult {
            success: true,
            message: Some("Fetched /api/status".into()),
            audit_id: Some(audit_id),
        }));
    }
    Ok(Json(op_api::ActionRunResult {
        success: false,
        message: Some("Unknown action".into()),
        audit_id: None,
    }))
}

async fn api_decisions(
    State(state): State<AppState>,
    Query(q): Query<DecisionsQuery>,
) -> Result<Json<op_api::PaginatedResponse<op_api::DecisionSummary>>, StatusCode> {
    let pagination = Pagination::from_query(&q);
    let filter = q.decision_filter()?;
    let mut items = state
        .store
        .list_summaries(Duration::from_millis(250))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    q.apply_filters(filter, &mut items);

    Ok(Json(pagination.paginate(&items)))
}

async fn api_decision_detail(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<op_api::DecisionDetail>, StatusCode> {
    if !is_decision_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let record = state
        .store
        .read_record(&id)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let governance = governance_attestation_from_metadata(&record.proof.attestation_metadata)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let registry_authorization =
        registry_authorization_from_metadata(&record.proof.attestation_metadata)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let chosen_action_preimage_storage = record
        .proof
        .chosen_action_preimage_storage_mode
        .clone()
        .map(map_chosen_action_preimage_storage);

    let summary = op_api::DecisionSummary {
        id: id.clone(),
        timestamp: record.token.timestamp_ms,
        policy_hash: record.token.policy_hash.clone(),
        action_type: record
            .candidates
            .iter()
            .find(|c| c.selected)
            .map(|c| c.action_type.clone())
            .unwrap_or_else(|| "UNKNOWN".into()),
        verdict: record.summary.verdict.clone(),
        proof_status: record.summary.proof_status.clone(),
        execution_status: record.summary.execution_status.clone(),
        latency_ms: record.summary.latency_ms,
        chosen_action_preimage_storage: chosen_action_preimage_storage.clone(),
    };

    Ok(Json(op_api::DecisionDetail {
        summary,
        token: op_api::DecisionToken {
            policy_hash: record.token.policy_hash,
            policy_epoch: record.token.policy_epoch,
            registry_root: record.token.registry_root,
            state_hash: record.token.state_hash,
            chosen_action_hash: record.token.chosen_action_hash,
            nonce_or_tx_hash: record.token.nonce_or_tx_hash,
            timestamp_ms: record.token.timestamp_ms,
            signature: record.token.signature_hex,
        },
        proof: op_api::ProofBundle {
            candidate_set_hash: record.proof.candidate_set_hash,
            limits_hash: record.proof.limits_hash,
            receipt_size: record.proof.receipt_size,
            verified_at: record.proof.verified_at_ms,
            attestation_metadata_hash: hex::encode(
                mprd_core::decision_log::attestation_metadata_hash_v1(
                    &record.proof.attestation_metadata,
                )
                .0,
            ),
            registry_authorization_hash: record
                .proof
                .attestation_metadata
                .get(mprd_zk::registry_state::REGISTRY_AUTH_METADATA_RESOLUTION_HASH_V1)
                .cloned(),
            registry_checkpoint_attestation_hash: record
                .proof
                .attestation_metadata
                .get(mprd_zk::registry_state::REGISTRY_AUTH_METADATA_CHECKPOINT_ATTESTATION_HASH_V1)
                .cloned(),
            registry_authorization,
            execution_authorization_hash: record
                .proof
                .attestation_metadata
                .get(mprd_core::EXECUTION_AUTH_ATTESTATION_METADATA_HASH_V1)
                .cloned(),
            execution_ready_packet_hash: record.proof.execution_ready_packet_hash.clone(),
            execution_binding_vector_hash: record.proof.execution_binding_vector_hash.clone(),
            execution_boundary_refinement_hash: record
                .proof
                .execution_boundary_refinement_hash
                .clone(),
            governance,
            chosen_action_preimage_storage,
        },
        state: op_api::StateSnapshot {
            fields: record.state.fields_json,
            state_hash: record.state.state_hash,
        },
        candidates: record
            .candidates
            .into_iter()
            .map(|c| op_api::CandidateWithVerdict {
                index: c.index,
                action_type: c.action_type,
                params: c.params_json,
                score: c.score,
                verdict: c.verdict,
                selected: c.selected,
                reasons: c.reasons,
            })
            .collect(),
        execution_result: record.execution.map(|e| op_api::ExecutionResult {
            success: e.success,
            message: e.message,
            executor: e.executor,
            duration_ms: e.duration_ms,
        }),
    }))
}

async fn api_decision_export(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<op_api::DecisionExport>, StatusCode> {
    if !is_decision_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let record = state
        .store
        .read_record(&id)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let base = format!("/api/decisions/{id}/blob");
    let chosen_action_preimage_storage = record
        .proof
        .chosen_action_preimage_storage_mode
        .map(map_chosen_action_preimage_storage)
        .unwrap_or(op_api::ChosenActionPreimageStorage::NotStored);
    Ok(Json(op_api::DecisionExport {
        decision_id: id.clone(),
        record_url: format!("{base}/record.json"),
        receipt_url: format!("{base}/receipt.bin"),
        limits_url: format!("{base}/limits.bin"),
        chosen_action_preimage_url: match chosen_action_preimage_storage {
            op_api::ChosenActionPreimageStorage::NotStored => None,
            op_api::ChosenActionPreimageStorage::InlineBlob
            | op_api::ChosenActionPreimageStorage::DerivedFromReceipt => {
                Some(format!("{base}/chosen_action_preimage.bin"))
            }
        },
        chosen_action_preimage_storage,
    }))
}

async fn api_decision_blob(
    State(state): State<AppState>,
    Path((id, name)): Path<(String, String)>,
) -> Result<Response, StatusCode> {
    if !is_decision_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let record = state
        .store
        .read_record(&id)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let dir = state.store.decision_dir(&id);

    fn read_bounded(path: &std::path::Path, max_payload_bytes: u64) -> Result<Vec<u8>, StatusCode> {
        let max_total = max_payload_bytes.saturating_add(mprd_core::wire::MAX_HEADER_BYTES as u64);
        let len = std::fs::metadata(path)
            .map_err(|_| StatusCode::NOT_FOUND)?
            .len();
        if len > max_total {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let bytes = std::fs::read(path).map_err(|_| StatusCode::NOT_FOUND)?;
        if (bytes.len() as u64) > max_total {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        Ok(bytes)
    }

    const MAX_LIMITS_BYTES: u64 = 4 * 1024;

    let (bytes, content_type) = match name.as_str() {
        "record.json" => (
            serde_json::to_vec_pretty(&record).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            "application/json",
        ),
        "receipt.bin" if record.proof.receipt_path == "receipt.bin" => (
            read_bounded(
                &dir.join("receipt.bin"),
                mprd_zk::bounded_deser::MAX_RECEIPT_BYTES,
            )?,
            "application/octet-stream",
        ),
        "limits.bin" if record.proof.limits_bytes_path == "limits.bin" => (
            read_bounded(&dir.join("limits.bin"), MAX_LIMITS_BYTES)?,
            "application/octet-stream",
        ),
        "chosen_action_preimage.bin"
            if !record.proof.chosen_action_preimage_path.trim().is_empty() =>
        {
            (
                state
                    .store
                    .chosen_action_preimage_for_record(&id, &record)
                    .map_err(|_| StatusCode::NOT_FOUND)?,
                "application/octet-stream",
            )
        }
        _ => return Err(StatusCode::NOT_FOUND),
    };
    let mut resp = Response::new(Body::from(bytes));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(content_type),
    );
    let cd = format!("attachment; filename=\"{}\"", name);
    let cd_val =
        header::HeaderValue::from_str(&cd).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    resp.headers_mut()
        .insert(header::CONTENT_DISPOSITION, cd_val);
    Ok(resp)
}

async fn api_live(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    let rx = state.live_tx.subscribe();
    ws.on_upgrade(move |socket| live_socket(socket, rx))
}

async fn live_socket<S, E>(mut socket: S, mut rx: tokio::sync::broadcast::Receiver<String>)
where
    S: futures_util::Sink<Message, Error = E>
        + futures_util::Stream<Item = Result<Message, E>>
        + Unpin,
{
    use futures_util::{SinkExt, StreamExt};

    loop {
        tokio::select! {
            msg = rx.recv() => {
                let Ok(payload) = msg else {
                    continue;
                };
                if socket.send(Message::Text(payload)).await.is_err() {
                    break;
                }
            }
            incoming = socket.next() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    // Ignore any client messages (this channel is server->client only).
                    _ => {}
                }
            },
        }
    }
}

async fn api_policies(
    State(state): State<AppState>,
) -> Result<Json<Vec<op_api::PolicySummary>>, StatusCode> {
    use mprd_adapters::storage::{LocalPolicyStorage, PolicyStorage};

    let storage = LocalPolicyStorage::new(&state.policy_dir)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let hashes = storage
        .list()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let decisions = state
        .store
        .list_summaries(Duration::from_millis(250))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut usage: HashMap<String, u64> = HashMap::new();
    for d in decisions {
        *usage.entry(d.policy_hash).or_default() += 1;
    }

    let mut out = Vec::with_capacity(hashes.len());
    for h in hashes {
        let hash_hex = hex::encode(h.0);
        let created_at = std::fs::metadata(state.policy_dir.join(format!("{hash_hex}.policy")))
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64)
            .unwrap_or_else(now_ms);
        out.push(op_api::PolicySummary {
            hash: hash_hex.clone(),
            name: None,
            status: op_api::PolicyStatus::Active,
            created_at,
            usage_count: *usage.get(&hash_hex).unwrap_or(&0),
        });
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyUploadRequest {
    spec: String,
    #[serde(default)]
    name: Option<String>,
}

async fn api_policy_upload(
    State(state): State<AppState>,
    Json(req): Json<PolicyUploadRequest>,
) -> Result<Json<op_api::PolicyHashResponse>, StatusCode> {
    use mprd_adapters::storage::{LocalPolicyStorage, PolicyStorage};
    let _ = req.name;
    if req.spec.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let storage = LocalPolicyStorage::new(&state.policy_dir)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let hash = storage
        .store(req.spec.as_bytes())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(op_api::PolicyHashResponse {
        hash: hex::encode(hash.0),
    }))
}

fn validate_policy_text(policy_text: &str) -> op_api::ValidationResult {
    let text = policy_text.trim();
    if text.is_empty() {
        return op_api::ValidationResult {
            valid: false,
            errors: vec!["Policy is empty".into()],
        };
    }

    let has_tau_keywords = text.contains("forall")
        || text.contains("exists")
        || text.contains("=>")
        || text.contains("&&")
        || text.contains("||");

    if !has_tau_keywords {
        return op_api::ValidationResult {
            valid: true,
            errors: vec![
                "No Tau keywords detected (heuristic warning). Expected: forall, exists, =>, &&, ||"
                    .into(),
            ],
        };
    }

    op_api::ValidationResult {
        valid: true,
        errors: Vec::new(),
    }
}

async fn api_policy_detail(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Result<Json<op_api::PolicyDetail>, StatusCode> {
    if !is_decision_id(&hash) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let path = state.policy_dir.join(format!("{hash}.policy"));
    let bytes = std::fs::read(&path).map_err(|_| StatusCode::NOT_FOUND)?;
    let spec = String::from_utf8(bytes).ok();

    let usage_count = state
        .store
        .list_summaries(Duration::from_millis(250))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .filter(|d| d.policy_hash == hash)
        .count() as u64;

    let created_at = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or_else(now_ms);

    let validation =
        spec.as_deref()
            .map(validate_policy_text)
            .unwrap_or(op_api::ValidationResult {
                valid: true,
                errors: vec!["Policy is not UTF-8; cannot validate".into()],
            });

    Ok(Json(op_api::PolicyDetail {
        summary: op_api::PolicySummary {
            hash: hash.clone(),
            name: None,
            status: op_api::PolicyStatus::Active,
            created_at,
            usage_count,
        },
        spec,
        validation_errors: if validation.errors.is_empty() {
            None
        } else {
            Some(validation.errors)
        },
    }))
}

async fn api_policy_validate(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Result<Json<op_api::ValidationResult>, StatusCode> {
    if !is_decision_id(&hash) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let path = state.policy_dir.join(format!("{hash}.policy"));
    let bytes = std::fs::read(&path).map_err(|_| StatusCode::NOT_FOUND)?;
    let spec = String::from_utf8(bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(validate_policy_text(&spec)))
}

async fn api_metrics(
    State(state): State<AppState>,
) -> Result<Json<op_api::MetricsSummary>, StatusCode> {
    let now = now_ms();
    let start = now - 24 * 60 * 60 * 1000;
    let prev_start = start - 24 * 60 * 60 * 1000;
    let decisions = state
        .store
        .list_summaries(Duration::from_millis(250))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    fn accumulate(
        decisions: &[op_api::DecisionSummary],
        window_start: i64,
        window_end: i64,
    ) -> (u64, u64, u64, u64, u64) {
        let mut total = 0u64;
        let mut allowed = 0u64;
        let mut denied = 0u64;
        let mut success = 0u64;
        let mut latency_sum = 0u64;

        for d in decisions
            .iter()
            .filter(|d| d.timestamp >= window_start && d.timestamp <= window_end)
        {
            total += 1;
            match d.verdict {
                op_api::Verdict::Allowed => allowed += 1,
                op_api::Verdict::Denied => denied += 1,
            }
            if matches!(d.execution_status, op_api::ExecutionStatus::Success) {
                success += 1;
            }
            latency_sum += d.latency_ms;
        }

        (total, allowed, denied, success, latency_sum)
    }

    let (total, allowed, denied, success, latency_sum) = accumulate(&decisions, start, now);
    let (prev_total, _prev_allowed, _prev_denied, prev_success, prev_latency_sum) =
        accumulate(&decisions, prev_start, start);

    let success_rate = if total == 0 {
        0.0
    } else {
        (success as f64) * 100.0 / (total as f64)
    };
    let prev_success_rate = if prev_total == 0 {
        0.0
    } else {
        (prev_success as f64) * 100.0 / (prev_total as f64)
    };

    let avg_latency = if total == 0 { 0 } else { latency_sum / total };
    let prev_avg_latency = if prev_total == 0 {
        0
    } else {
        prev_latency_sum / prev_total
    };

    let decisions_change = if prev_total == 0 {
        0.0
    } else {
        ((total as f64) - (prev_total as f64)) * 100.0 / (prev_total as f64)
    };
    let success_rate_change = success_rate - prev_success_rate;
    let avg_latency_change = if prev_avg_latency == 0 {
        0.0
    } else {
        ((avg_latency as f64) - (prev_avg_latency as f64)) * 100.0 / (prev_avg_latency as f64)
    };

    let active_policies = {
        use mprd_adapters::storage::{LocalPolicyStorage, PolicyStorage};
        LocalPolicyStorage::new(&state.policy_dir)
            .ok()
            .and_then(|s| s.list().ok())
            .map(|v| v.len() as u64)
            .unwrap_or(0)
    };

    Ok(Json(op_api::MetricsSummary {
        period: op_api::MetricsPeriod { start, end: now },
        decisions: op_api::DecisionsMetrics {
            total,
            allowed,
            denied,
            change: decisions_change,
        },
        success_rate: op_api::MetricWithChange {
            value: success_rate,
            change: success_rate_change,
        },
        avg_latency_ms: op_api::MetricWithChangeU64 {
            value: avg_latency,
            change: avg_latency_change,
        },
        active_policies,
    }))
}

async fn api_cegis_metrics(
    State(state): State<AppState>,
) -> Result<Json<op_api::CegisMetricsSummary>, StatusCode> {
    let metrics = state
        .cegis_metrics
        .read()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(op_api::CegisMetricsSummary {
        proposals_total: metrics.proposals_total,
        proposals_valid: metrics.proposals_valid,
        proposals_invalid: metrics.proposals_invalid,
        counterexamples_captured: metrics.counterexamples_captured,
        time_to_first_valid_ms: metrics.time_to_first_valid_ms,
    }))
}

fn verifier_from_env() -> Result<Box<dyn mprd_core::ZkLocalVerifier>, String> {
    let path = std::env::var("MPRD_OPERATOR_REGISTRY_STATE_PATH").map_err(|_| {
        "registry_state unavailable: set MPRD_OPERATOR_REGISTRY_STATE_PATH".to_string()
    })?;
    let registry_key_hex = std::env::var("MPRD_OPERATOR_REGISTRY_KEY_HEX").map_err(|_| {
        "registry_state unavailable: set MPRD_OPERATOR_REGISTRY_KEY_HEX".to_string()
    })?;
    let manifest_key_hex = std::env::var("MPRD_OPERATOR_MANIFEST_KEY_HEX").ok();

    let registry_vk = mprd_core::TokenVerifyingKey::from_hex(&registry_key_hex)
        .map_err(|e| format!("invalid registry verifying key: {e}"))?;
    let manifest_vk = match manifest_key_hex.as_deref() {
        None => registry_vk.clone(),
        Some(hex) => mprd_core::TokenVerifyingKey::from_hex(hex)
            .map_err(|e| format!("invalid manifest verifying key: {e}"))?,
    };

    let json = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read registry_state: {e}"))?;
    let signed: mprd_zk::registry_state::SignedRegistryStateV1 =
        serde_json::from_str(&json).map_err(|e| format!("failed to parse registry_state: {e}"))?;

    mprd_zk::create_production_verifier_from_signed_registry_state_with_manifest_key(
        signed,
        &registry_vk,
        &manifest_vk,
    )
    .map_err(|e| format!("{e}"))
}

async fn api_verify_decision(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !is_decision_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let record = state
        .store
        .read_record(&id)
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let (receipt, limits_bytes, chosen_action_preimage) =
        match state.store.blobs_for_proof(&id, &record) {
            Ok(v) => v,
            Err(e) => {
                return Ok(Json(serde_json::json!({
                    "verified": false,
                    "error": e.to_string(),
                })));
            }
        };

    let token = mprd_core::DecisionToken {
        policy_hash: parse_hash32(&record.token.policy_hash)
            .map_err(|_| StatusCode::BAD_REQUEST)?,
        policy_ref: mprd_core::PolicyRef {
            policy_epoch: record.token.policy_epoch,
            registry_root: parse_hash32(&record.token.registry_root)
                .map_err(|_| StatusCode::BAD_REQUEST)?,
        },
        state_hash: parse_hash32(&record.token.state_hash).map_err(|_| StatusCode::BAD_REQUEST)?,
        state_ref: mprd_core::StateRef {
            state_source_id: parse_hash32(&record.token.state_source_id)
                .map_err(|_| StatusCode::BAD_REQUEST)?,
            state_epoch: record.token.state_epoch,
            state_attestation_hash: parse_hash32(&record.token.state_attestation_hash)
                .map_err(|_| StatusCode::BAD_REQUEST)?,
        },
        chosen_action_hash: parse_hash32(&record.token.chosen_action_hash)
            .map_err(|_| StatusCode::BAD_REQUEST)?,
        nonce_or_tx_hash: parse_hash32(&record.token.nonce_or_tx_hash)
            .map_err(|_| StatusCode::BAD_REQUEST)?,
        timestamp_ms: record.token.timestamp_ms,
        signature: hex::decode(&record.token.signature_hex).map_err(|_| StatusCode::BAD_REQUEST)?,
    };

    let proof = mprd_core::ProofBundle {
        policy_hash: parse_hash32(&record.proof.policy_hash)
            .map_err(|_| StatusCode::BAD_REQUEST)?,
        state_hash: parse_hash32(&record.proof.state_hash).map_err(|_| StatusCode::BAD_REQUEST)?,
        candidate_set_hash: parse_hash32(&record.proof.candidate_set_hash)
            .map_err(|_| StatusCode::BAD_REQUEST)?,
        chosen_action_hash: parse_hash32(&record.proof.chosen_action_hash)
            .map_err(|_| StatusCode::BAD_REQUEST)?,
        limits_hash: parse_hash32(&record.proof.limits_hash)
            .map_err(|_| StatusCode::BAD_REQUEST)?,
        limits_bytes,
        chosen_action_preimage,
        risc0_receipt: receipt,
        attestation_metadata: record.proof.attestation_metadata.clone(),
    };

    let verifier = match verifier_from_env() {
        Ok(v) => v,
        Err(e) => {
            return Ok(Json(serde_json::json!({ "verified": false, "error": e })));
        }
    };
    let status = verifier.verify(&token, &proof);

    match status {
        mprd_core::VerificationStatus::Success => {
            let _ = state
                .store
                .write_proof_status(&id, op_api::ProofStatus::Verified, now_ms());
            Ok(Json(serde_json::json!({ "verified": true })))
        }
        mprd_core::VerificationStatus::Failure(reason) => {
            let _ = state
                .store
                .write_proof_status(&id, op_api::ProofStatus::Failed, now_ms());
            Ok(Json(
                serde_json::json!({ "verified": false, "error": reason }),
            ))
        }
    }
}

async fn start_server(addr: SocketAddr, state: AppState) -> anyhow::Result<()> {
    tokio::spawn(autopilot_guard(state.clone()));
    tokio::spawn(events::poll_store_events(
        state.store.clone(),
        state.live_tx.clone(),
    ));

    let api_key = operator::auth::api_key_from_env();
    let app = build_app(state, api_key);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_app(state: AppState, api_key: operator::auth::ApiKeyConfig) -> Router {
    use axum::extract::DefaultBodyLimit;

    let api = Router::new()
        .route("/settings", get(api_settings).post(api_settings_update))
        .route("/settings/prune", post(api_prune_decisions))
        .route("/autopilot", get(api_autopilot))
        .route("/autopilot/mode", post(api_autopilot_mode))
        .route("/autopilot/ack", post(api_autopilot_ack))
        .route("/autopilot/activity", get(api_autopilot_activity))
        .route(
            "/autopilot/activity/:id/override",
            post(api_autopilot_override),
        )
        .route("/status", get(api_status))
        .route("/effect-barriers/pending", get(api_pending_effect_barriers))
        .route(
            "/effect-barriers/committed",
            get(api_committed_effect_barriers),
        )
        .route(
            "/effect-barriers/pending/:policy_hash/:idempotency_key_v1/resolve",
            post(api_resolve_pending_effect_barrier),
        )
        .route("/metrics", get(api_metrics))
        .route("/cegis/metrics", get(api_cegis_metrics))
        .route("/alerts", get(api_alerts))
        .route("/alerts/:id/acknowledge", post(api_alert_ack))
        .route("/incidents", get(api_incidents))
        .route("/incidents/:id", get(api_incident_detail))
        .route("/incidents/:id/acknowledge", post(api_incident_ack))
        .route("/incidents/:id/snooze", post(api_incident_snooze))
        .route("/incidents/:id/actions", get(api_incident_actions))
        .route(
            "/incidents/:id/actions/:action_id/run",
            post(api_incident_action_run),
        )
        .route("/decisions", get(api_decisions))
        .route("/decisions/:id", get(api_decision_detail))
        .route("/decisions/:id/export", get(api_decision_export))
        .route("/decisions/:id/blob/:name", get(api_decision_blob))
        .route("/decisions/:id/verify", post(api_verify_decision))
        .route("/policies", get(api_policies).post(api_policy_upload))
        .route("/policies/:hash", get(api_policy_detail))
        .route("/policies/:hash/validate", post(api_policy_validate))
        .route("/live", get(api_live));

    let protected = Router::new()
        .route("/api/v1/run", post(run_handler))
        .nest("/api", api)
        .layer(middleware::from_fn_with_state(
            api_key,
            operator::auth::require_api_key,
        ));

    Router::new()
        .route("/health", get(health))
        .merge(protected)
        .layer(DefaultBodyLimit::max(256 * 1024))
        .layer(middleware::from_fn(http_middleware::cors_middleware))
        .with_state(state)
}

pub fn run(
    bind: String,
    policy_dir: Option<PathBuf>,
    insecure_demo: bool,
    config: Option<super::MprdConfigFile>,
) -> Result<()> {
    // Stay tolerant for local/demo modes, but do not let trustless/private production serve
    // start in a configuration that can never satisfy the live fail-closed trust-anchor boundary.
    let config = config.unwrap_or_default();
    validate_serve_startup_config(&config, insecure_demo)?;

    let policy_dir = policy_dir.unwrap_or_else(|| {
        config
            .policy_storage
            .local_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(".mprd/policies"))
    });
    let store_dir = std::env::var("MPRD_OPERATOR_STORE_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".mprd/operator"));

    let store = op_store::OperatorStore::new(store_dir.clone())?;
    let (live_tx, _live_rx) = tokio::sync::broadcast::channel::<String>(256);
    let state = AppState {
        store,
        store_dir,
        policy_dir,
        insecure_demo,
        live_tx,
        config,
        cegis_metrics: Arc::new(RwLock::new(mprd_core::cegis::ProposerMetrics::default())),
    };

    let addr: SocketAddr = bind.parse()?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(start_server(addr, state))?;

    Ok(())
}
