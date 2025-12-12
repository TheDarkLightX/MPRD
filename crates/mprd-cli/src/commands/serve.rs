//! `mprd serve` command implementation

use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use axum::{routing::{get, post}, Json, Router};
use serde::{Deserialize, Serialize};

use mprd_core::{
    DefaultSelector, PolicyEngine, PolicyHash, RuleVerdict, StateSnapshot, Value,
};
use mprd_core::components::{
    SimpleStateProvider, SimpleProposer, SignedDecisionTokenFactory,
    StubZkAttestor, StubZkLocalVerifier, LoggingExecutorAdapter,
};
use mprd_core::orchestrator::{self};
use mprd_zk::decentralization::{
    LocalOnChainRegistry, LocalTimestampAnchorStore, RegistryRecorder,
};

type CoreResult<T> = mprd_core::Result<T>;

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

fn json_to_value(v: serde_json::Value) -> Option<Value> {
    match v {
        serde_json::Value::Bool(b) => Some(Value::Bool(b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i < 0 {
                    return Some(Value::Int(i));
                }
                if let Some(u) = n.as_u64() {
                    return Some(Value::UInt(u));
                }
                return Some(Value::Int(i));
            }
            n.as_u64().map(Value::UInt)
        }
        serde_json::Value::String(s) => Some(Value::String(s)),
        _ => None,
    }
}

fn build_state_fields(
    input: Option<HashMap<String, serde_json::Value>>,
) -> anyhow::Result<HashMap<String, Value>> {
    let Some(input) = input else {
        return Ok(HashMap::from([("balance".into(), Value::UInt(1_000))]));
    };

    let mut rejected_keys = Vec::new();
    let mut fields: HashMap<String, Value> = HashMap::new();

    for (key, value) in input {
        match json_to_value(value) {
            Some(v) => {
                fields.insert(key, v);
            }
            None => {
                rejected_keys.push(key);
            }
        }
    }

    if !rejected_keys.is_empty() && fields.is_empty() {
        return Err(anyhow::anyhow!(
            "All provided state fields were invalid: {:?}",
            rejected_keys
        ));
    }

    if fields.is_empty() {
        return Ok(HashMap::from([("balance".into(), Value::UInt(1_000))]));
    }

    Ok(fields)
}

fn run_anchored_demo(demo_fields: HashMap<String, Value>) -> CoreResult<mprd_core::ExecutionResult> {
    let state_provider = SimpleStateProvider::new(demo_fields);

    let proposer = SimpleProposer::single(
        "DEMO_ACTION",
        HashMap::from([
            ("amount".into(), Value::UInt(10)),
        ]),
        100,
    );

    let policy_engine = CliAllowAllPolicyEngine;
    let selector = DefaultSelector;
    let token_factory = SignedDecisionTokenFactory::default_for_testing();
    let attestor = StubZkAttestor::new();
    let verifier = StubZkLocalVerifier::new();
    let executor = LoggingExecutorAdapter::new();

    let anchor_store = Box::new(LocalTimestampAnchorStore::new());
    let registry = LocalOnChainRegistry::new(anchor_store);
    let recorder = RegistryRecorder::new(registry);

    let policy_hash = mprd_core::Hash32([1u8; 32]);

    orchestrator::run_once_with_recorder(
        &state_provider,
        &proposer,
        &policy_engine,
        &selector,
        &token_factory,
        &attestor,
        &verifier,
        &executor,
        &recorder,
        &policy_hash,
    )
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn run_handler(Json(req): Json<RunRequest>) -> Json<RunResponse> {
    let fields = match build_state_fields(req.state) {
        Ok(f) => f,
        Err(e) => {
            return Json(RunResponse {
                success: false,
                message: Some(e.to_string()),
            });
        }
    };

    let join = tokio::task::spawn_blocking(move || run_anchored_demo(fields)).await;

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

async fn start_server(addr: SocketAddr) -> anyhow::Result<()> {
    use axum::extract::DefaultBodyLimit;

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/run", post(run_handler))
        .layer(DefaultBodyLimit::max(256 * 1024));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn run(
    bind: String,
    policy_dir: Option<PathBuf>,
    config_path: Option<PathBuf>,
) -> Result<()> {
    println!("🌐 MPRD HTTP Server");
    println!();
    println!("   Bind: {}", bind);
    if let Some(ref dir) = policy_dir {
        println!("   Policy dir: {}", dir.display());
    }
    println!();
    
    // For now, just print the planned API
    println!("📡 API Endpoints (planned):");
    println!();
    println!("   POST /api/v1/propose");
    println!("        Submit state and get candidate actions");
    println!();
    println!("   POST /api/v1/evaluate");
    println!("        Evaluate candidates against policy");
    println!();
    println!("   POST /api/v1/select");
    println!("        Select best allowed action");
    println!();
    println!("   POST /api/v1/attest");
    println!("        Generate ZK proof for decision");
    println!();
    println!("   POST /api/v1/verify");
    println!("        Verify proof bundle");
    println!();
    println!("   POST /api/v1/execute");
    println!("        Execute verified action");
    println!();
    println!("   GET  /api/v1/policies");
    println!("        List stored policies");
    println!();
    println!("   POST /api/v1/policies");
    println!("        Store a new policy");
    println!();
    println!("   GET  /health");
    println!("        Health check");
    println!();
    
    println!("⚠️  HTTP server not yet implemented.");
    println!("    This will be added in a future update.");
    println!();
    println!("For now, use the CLI commands directly:");
    println!("    mprd run --policy <hash> --state state.json --candidates candidates.json");
    println!();

    let _ = config_path;

    let addr: SocketAddr = bind.parse()?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(start_server(addr))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{build_state_fields, json_to_value};
    use mprd_core::Value;
    use std::collections::HashMap;

    #[test]
    fn json_to_value_supports_bool_int_uint_and_string() {
        assert_eq!(json_to_value(serde_json::json!(true)), Some(Value::Bool(true)));
        assert_eq!(json_to_value(serde_json::json!(-1)), Some(Value::Int(-1)));
        assert_eq!(json_to_value(serde_json::json!(1)), Some(Value::UInt(1)));
        assert_eq!(
            json_to_value(serde_json::json!("x")),
            Some(Value::String("x".to_string()))
        );
        assert_eq!(json_to_value(serde_json::json!([1, 2, 3])), None);
    }

    #[test]
    fn build_state_fields_defaults_when_missing() {
        let fields = build_state_fields(None).expect("should default");
        assert_eq!(fields.get("balance"), Some(&Value::UInt(1_000)));
    }

    #[test]
    fn build_state_fields_fails_closed_when_all_fields_invalid() {
        let mut input = HashMap::new();
        input.insert("nested".to_string(), serde_json::json!({"x": 1}));
        let err = build_state_fields(Some(input)).expect_err("should fail closed");
        assert!(err.to_string().contains("All provided state fields were invalid"));
    }

    #[test]
    fn build_state_fields_accepts_partial_valid_input() {
        let mut input = HashMap::new();
        input.insert("balance".to_string(), serde_json::json!(7));
        input.insert("nested".to_string(), serde_json::json!({"x": 1}));
        let fields = build_state_fields(Some(input)).expect("should succeed");
        assert_eq!(fields.get("balance"), Some(&Value::UInt(7)));
    }
}
