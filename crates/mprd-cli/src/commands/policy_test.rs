//! `mprd policy test` command implementation

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use mprd_core::mpb::{MpbPolicy, MpbPolicyEngine};
use mprd_core::validation::{canonicalize_candidates_v1, canonicalize_state_snapshot_v1};
use mprd_core::wire::{parse_or_legacy_bounded, ParsedPayload, WireKind};
use mprd_core::{
    CandidateAction, DefaultSelector, Hash32, PolicyEngine, Score, Selector, StateRef, StateSnapshot, Value,
    MAX_CANDIDATES,
};
use mprd_zk::bounded_deser::MAX_MPB_ARTIFACT_BYTES;
use mprd_zk::policy_artifacts::decode_mpb_policy_artifact_bytes_v1;

pub fn run(policy_path: PathBuf, tests_path: PathBuf) -> Result<()> {
    let (engine, policy_hash) = load_policy(&policy_path)?;
    let cases = load_test_cases(&tests_path)?;

    if cases.is_empty() {
        println!("No test cases found in {}", tests_path.display());
        return Ok(());
    }

    println!("Policy test");
    println!();
    println!("  Policy: {}", policy_path.display());
    println!("  Policy hash: {}", hex::encode(policy_hash.0));
    println!("  Test cases: {}", cases.len());
    println!();

    let mut failures = Vec::new();
    for (idx, case) in cases.into_iter().enumerate() {
        let label = case
            .name
            .clone()
            .unwrap_or_else(|| format!("case_{}", idx + 1));
        let expected_action = case.expected_action.clone();

        match run_case(&engine, &policy_hash, case) {
            Ok(actual_action) => {
                if actual_action == expected_action {
                    println!("  [OK] {}", label);
                } else {
                    println!(
                        "  [FAIL] {}: expected {}, got {}",
                        label, expected_action, actual_action
                    );
                    failures.push(label);
                }
            }
            Err(err) => {
                println!("  [FAIL] {}: {}", label, err);
                failures.push(label);
            }
        }
    }

    if failures.is_empty() {
        println!();
        println!("All test cases passed.");
        return Ok(());
    }

    println!();
    println!("{} test case(s) failed.", failures.len());
    std::process::exit(1);
}

fn load_policy(path: &Path) -> Result<(MpbPolicyEngine, Hash32)> {
    let bytes =
        fs::read(path).with_context(|| format!("Failed to read policy file: {}", path.display()))?;

    let payload = match parse_or_legacy_bounded(
        &bytes,
        Some(WireKind::MpbArtifactBincode),
        MAX_MPB_ARTIFACT_BYTES,
    ) {
        Ok(ParsedPayload::Enveloped(env)) => env.payload,
        Ok(ParsedPayload::Legacy(payload)) => payload,
        Err(err) => {
            return Err(anyhow::anyhow!(
                "Failed to parse policy file envelope: {err}"
            ))
        }
    };

    let artifact = decode_mpb_policy_artifact_bytes_v1(payload)
        .context("Policy file is not a valid mpb-v1 artifact")?;

    let variables: HashMap<String, u8> = artifact.variables.into_iter().collect();
    let policy = MpbPolicy::new(artifact.bytecode, variables);
    let mut engine = MpbPolicyEngine::new();
    let policy_hash = engine.register(policy);

    Ok((engine, policy_hash))
}

fn run_case(
    engine: &MpbPolicyEngine,
    policy_hash: &Hash32,
    case: PolicyTestCaseInput,
) -> Result<String> {
    if case.expected_action.trim().is_empty() {
        anyhow::bail!("expected_action must be non-empty");
    }

    let state = build_state_snapshot(case.state)?;
    let candidates = build_candidates(case.candidates)?;

    let verdicts = engine
        .evaluate(policy_hash, &state, &candidates)
        .context("Policy evaluation failed")?;

    let selector = DefaultSelector;
    let decision = selector
        .select(policy_hash, &state, &candidates, &verdicts)
        .context("Selection failed")?;

    Ok(decision.chosen_action.action_type)
}

fn build_state_snapshot(state: HashMap<String, serde_json::Value>) -> Result<StateSnapshot> {
    let mut fields = HashMap::with_capacity(state.len());
    for (key, value) in state {
        let value = json_to_value(value).with_context(|| format!("Invalid state value for {key}"))?;
        fields.insert(key, value);
    }

    let state = StateSnapshot {
        fields,
        policy_inputs: HashMap::new(),
        state_hash: Hash32([0u8; 32]),
        state_ref: StateRef::unknown(),
    };
    canonicalize_state_snapshot_v1(state).context("Invalid state snapshot")
}

fn build_candidates(inputs: Vec<CandidateInput>) -> Result<Vec<CandidateAction>> {
    if inputs.len() > MAX_CANDIDATES {
        anyhow::bail!(
            "Too many candidates ({} > {})",
            inputs.len(),
            MAX_CANDIDATES
        );
    }

    let mut candidates = Vec::with_capacity(inputs.len());
    for input in inputs {
        let mut params = HashMap::with_capacity(input.params.len());
        for (key, value) in input.params {
            let value =
                json_to_value(value).with_context(|| format!("Invalid param value for {key}"))?;
            params.insert(key, value);
        }

        candidates.push(CandidateAction {
            action_type: input.action_type,
            params,
            score: Score(input.score),
            candidate_hash: Hash32([0u8; 32]),
        });
    }

    canonicalize_candidates_v1(candidates).context("Invalid candidates")
}

fn json_to_value(value: serde_json::Value) -> Result<Value> {
    match value {
        serde_json::Value::Bool(b) => Ok(Value::Bool(b)),
        serde_json::Value::Number(n) => json_number_to_value(&n),
        serde_json::Value::String(s) => Ok(Value::String(s)),
        _ => anyhow::bail!("Unsupported JSON value type"),
    }
}

fn json_number_to_value(n: &serde_json::Number) -> Result<Value> {
    if let Some(i) = n.as_i64() {
        if i < 0 {
            return Ok(Value::Int(i));
        }
        if let Some(u) = n.as_u64() {
            return Ok(Value::UInt(u));
        }
        return Ok(Value::Int(i));
    }

    if let Some(u) = n.as_u64() {
        return Ok(Value::UInt(u));
    }

    anyhow::bail!("Number must be an integer")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateInput {
    action_type: String,
    params: HashMap<String, serde_json::Value>,
    score: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTestCaseInput {
    #[serde(default)]
    name: Option<String>,
    state: HashMap<String, serde_json::Value>,
    candidates: Vec<CandidateInput>,
    expected_action: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTestCases {
    cases: Vec<PolicyTestCaseInput>,
}

fn load_test_cases(path: &Path) -> Result<Vec<PolicyTestCaseInput>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read test cases file: {}", path.display()))?;
    let cases = parse_test_cases(&raw)
        .with_context(|| format!("Failed to parse test cases file: {}", path.display()))?;
    Ok(cases)
}

fn parse_test_cases(raw: &str) -> Result<Vec<PolicyTestCaseInput>> {
    if let Ok(wrapper) = serde_json::from_str::<PolicyTestCases>(raw) {
        return Ok(wrapper.cases);
    }

    if let Ok(cases) = serde_json::from_str::<Vec<PolicyTestCaseInput>>(raw) {
        return Ok(cases);
    }

    let wrapped_err = serde_json::from_str::<PolicyTestCases>(raw)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    let list_err = serde_json::from_str::<Vec<PolicyTestCaseInput>>(raw)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    anyhow::bail!(
        "Test cases must be a JSON array or object with 'cases'. Errors: {} | {}",
        wrapped_err,
        list_err
    );
}
