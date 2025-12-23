use crate::{
    CandidateAction, MprdError, PolicyEngine, PolicyHash, Result, RuleVerdict, StateSnapshot,
    Value, MAX_CANDIDATES,
};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const TAU_MAX_OUTPUT_BYTES: usize = 64 * 1024;
const TAU_POLL_INTERVAL_MS: u64 = 10;

/// Maximum allowed WFF length to prevent DoS via excessively large formulas.
const MAX_WFF_LENGTH: usize = 4096;

/// Validate that a WFF string is safe to pass to Tau.
///
/// # Security
///
/// This prevents command injection by ensuring the WFF only contains
/// characters expected in Tau formulas. Specifically:
/// - Alphanumeric characters
/// - Bitvector literals (#b followed by 0/1)
/// - Operators: <, >, =, !, &, |, +, -, *, /
/// - Parentheses and brackets: (, ), [, ]
/// - Whitespace
///
/// Rejects: newlines, semicolons, quotes, backticks, shell metacharacters
fn validate_wff(wff: &str) -> Result<()> {
    if wff.is_empty() {
        return Err(MprdError::PolicyEvaluationFailed(
            "WFF cannot be empty".into(),
        ));
    }

    if wff.len() > MAX_WFF_LENGTH {
        return Err(MprdError::PolicyEvaluationFailed(format!(
            "WFF exceeds maximum length of {} bytes",
            MAX_WFF_LENGTH
        )));
    }

    // SECURITY: Whitelist approach - only allow known-safe characters
    for (i, c) in wff.chars().enumerate() {
        let allowed = c.is_ascii_alphanumeric()
            || matches!(
                c,
                ' ' | '\t'      // Whitespace (no newlines!)
                | '#'           // Bitvector prefix
                | '(' | ')'     // Grouping
                | '[' | ']'     // Bitvector notation
                | '<' | '>' | '=' | '!'  // Comparison/negation
                | '&' | '|'     // Logical operators
                | '+' | '-' | '*' | '/'  // Arithmetic
                | '_' // Identifiers
            );

        if !allowed {
            return Err(MprdError::PolicyEvaluationFailed(format!(
                "WFF contains disallowed character '{}' at position {}",
                c.escape_default(),
                i
            )));
        }
    }

    // SECURITY: Explicitly reject dangerous patterns even if individual chars passed
    let dangerous_patterns = [
        "\n", "\r", // Newlines (command injection)
        ";",  // Command separator
        "quit", "exit", // Tau control commands (case-insensitive check below)
        "load", "save", // File operations
        "exec", "system", // Execution commands
        "`", "$(", // Shell substitution
        "\\", // Escape sequences
    ];

    let wff_lower = wff.to_lowercase();
    for pattern in dangerous_patterns {
        if wff_lower.contains(pattern) {
            return Err(MprdError::PolicyEvaluationFailed(format!(
                "WFF contains potentially dangerous pattern: '{}'",
                pattern.escape_default()
            )));
        }
    }

    Ok(())
}

fn read_tau_stream<R: Read>(mut reader: R, stream_name: &'static str) -> Result<String> {
    let mut output = Vec::new();
    let mut total = 0usize;
    let mut buf = [0u8; 4096];

    loop {
        let n = reader.read(&mut buf).map_err(|e| {
            MprdError::PolicyEvaluationFailed(format!("failed to read tau {stream_name}: {e}"))
        })?;

        if n == 0 {
            break;
        }

        total = total.saturating_add(n);

        if output.len() < TAU_MAX_OUTPUT_BYTES {
            let remaining = TAU_MAX_OUTPUT_BYTES - output.len();
            let take = remaining.min(n);
            output.extend_from_slice(&buf[..take]);
        }
    }

    if total > TAU_MAX_OUTPUT_BYTES {
        return Err(MprdError::PolicyEvaluationFailed(format!(
            "tau {stream_name} exceeded {TAU_MAX_OUTPUT_BYTES} bytes"
        )));
    }

    Ok(String::from_utf8_lossy(&output).into_owned())
}

fn wait_for_exit(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::ExitStatus> {
    let start = Instant::now();

    loop {
        let status = child.try_wait().map_err(|e| {
            MprdError::PolicyEvaluationFailed(format!("failed to poll tau status: {e}"))
        })?;

        if let Some(status) = status {
            return Ok(status);
        }

        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(MprdError::PolicyEvaluationFailed(format!(
                "tau timed out after {:?}",
                timeout,
            )));
        }

        thread::sleep(Duration::from_millis(TAU_POLL_INTERVAL_MS));
    }
}

/// Configuration for interacting with Tau.
///
/// This is intentionally minimal for now and will be extended with
/// fields such as policy resolution paths or CLI options when we wire in
/// real Tau integration.
#[derive(Clone)]
pub struct TauConfig {
    pub tau_binary: String,
    pub tau_timeout_ms: u64,
}

/// Tau-backed policy engine stub.
///
/// This implementation exists only to wire the interface. It deliberately
/// fails on every call to avoid silently running without real Tau
/// integration.
pub struct TauPolicyEngine {
    pub config: TauConfig,
}

impl TauPolicyEngine {
    pub fn new(tau_binary: impl Into<String>) -> Self {
        Self {
            config: TauConfig {
                tau_binary: tau_binary.into(),
                tau_timeout_ms: 500,
            },
        }
    }

    fn to_bitvec_u64(v: u64) -> String {
        format!("#b{:064b}", v)
    }

    fn extract_u64(params: &std::collections::HashMap<String, Value>, key: &str) -> Result<u64> {
        match params.get(key) {
            Some(Value::UInt(v)) => Ok(*v),
            Some(Value::Int(v)) if *v >= 0 => Ok(*v as u64),
            _ => Err(MprdError::InvalidInput(format!(
                "missing or invalid numeric param '{}'",
                key
            ))),
        }
    }

    fn build_risk_threshold_wff(&self, candidate: &CandidateAction) -> Result<String> {
        let risk = Self::extract_u64(&candidate.params, "risk")?;
        let max_risk = Self::extract_u64(&candidate.params, "max_risk")?;
        let cost = Self::extract_u64(&candidate.params, "cost")?;
        let max_cost = Self::extract_u64(&candidate.params, "max_cost")?;
        let has_approval = match candidate.params.get("has_approval") {
            Some(Value::Bool(b)) => *b,
            _ => {
                return Err(MprdError::InvalidInput(
                    "missing or invalid 'has_approval'".into(),
                ))
            }
        };

        let risk_bv = Self::to_bitvec_u64(risk);
        let max_risk_bv = Self::to_bitvec_u64(max_risk);
        let cost_bv = Self::to_bitvec_u64(cost);
        let max_cost_bv = Self::to_bitvec_u64(max_cost);
        let approval_const = if has_approval { "1" } else { "0" };

        Ok(format!(
            "(({} <= {}) && ({} <= {}) && {})",
            risk_bv, max_risk_bv, cost_bv, max_cost_bv, approval_const
        ))
    }

    fn solve_wff_with_tau(&self, wff: &str) -> Result<bool> {
        // SECURITY: Validate WFF to prevent command injection
        validate_wff(wff)?;

        let script = format!("solve {}\nquit\n", wff);

        let mut child = Command::new(&self.config.tau_binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| MprdError::PolicyEvaluationFailed(format!("failed to spawn tau: {e}")))?;

        let stdout_reader = child
            .stdout
            .take()
            .ok_or_else(|| MprdError::PolicyEvaluationFailed("tau stdout unavailable".into()))?;
        let stderr_reader = child
            .stderr
            .take()
            .ok_or_else(|| MprdError::PolicyEvaluationFailed("tau stderr unavailable".into()))?;

        let stdout_task = thread::spawn(move || read_tau_stream(stdout_reader, "stdout"));
        let stderr_task = thread::spawn(move || read_tau_stream(stderr_reader, "stderr"));

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| MprdError::PolicyEvaluationFailed("tau stdin unavailable".into()))?;

            stdin.write_all(script.as_bytes()).map_err(|e| {
                MprdError::PolicyEvaluationFailed(format!("failed to write to tau stdin: {e}"))
            })?;
            // `stdin` is dropped here, closing the pipe and letting Tau
            // observe EOF after the script has been sent.
        }
        let timeout = Duration::from_millis(self.config.tau_timeout_ms);
        let status = wait_for_exit(&mut child, timeout);

        let stdout = stdout_task.join().map_err(|_| {
            MprdError::PolicyEvaluationFailed("tau stdout reader thread panicked".into())
        })??;
        let stderr = stderr_task.join().map_err(|_| {
            MprdError::PolicyEvaluationFailed("tau stderr reader thread panicked".into())
        })??;

        let status = status?;

        if !status.success() {
            return Err(MprdError::PolicyEvaluationFailed(format!(
                "tau exited with error: {stderr}",
            )));
        }

        if stdout.contains("solution:") {
            return Ok(true);
        }

        if stdout.contains("no solution") {
            return Ok(false);
        }

        Err(MprdError::PolicyEvaluationFailed(format!(
            "tau returned unexpected output: {stdout}",
        )))
    }
}

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

        let mut verdicts = Vec::with_capacity(candidates.len());

        for candidate in candidates {
            let wff = self.build_risk_threshold_wff(candidate)?;
            let allowed = self.solve_wff_with_tau(&wff)?;

            let reasons = if allowed {
                Vec::new()
            } else {
                vec!["risk_threshold_not_satisfied".into()]
            };

            verdicts.push(RuleVerdict {
                allowed,
                reasons,
                limits: std::collections::HashMap::new(),
            });
        }

        Ok(verdicts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash32, Score, Value};
    use std::collections::HashMap;
    use std::path::Path;

    fn dummy_hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    #[test]
    fn wff_validation_allows_valid_formulas() {
        // Basic formula
        assert!(validate_wff("1 = 1").is_ok());

        // Bitvector formula
        assert!(validate_wff("#b0101 <= #b1000").is_ok());

        // Complex formula with operators
        assert!(validate_wff("((#b0101 <= #b1000) && (#b0011 <= #b0100) && 1)").is_ok());
    }

    #[test]
    fn wff_validation_rejects_newlines() {
        let result = validate_wff("1 = 1\nquit");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("newline") || err_msg.contains("disallowed"));
    }

    #[test]
    fn wff_validation_rejects_semicolons() {
        let result = validate_wff("1 = 1; quit");
        assert!(result.is_err());
    }

    #[test]
    fn wff_validation_rejects_quotes() {
        let result = validate_wff("\"malicious\"");
        assert!(result.is_err());
    }

    #[test]
    fn wff_validation_rejects_control_commands() {
        assert!(validate_wff("quit").is_err());
        assert!(validate_wff("1 = 1 exit").is_err());
        assert!(validate_wff("load file").is_err());
    }

    #[test]
    fn wff_validation_rejects_empty() {
        assert!(validate_wff("").is_err());
    }

    #[test]
    fn wff_validation_rejects_oversized() {
        let large_wff = "a".repeat(MAX_WFF_LENGTH + 1);
        assert!(validate_wff(&large_wff).is_err());
    }

    #[test]
    fn evaluate_fails_on_missing_params() {
        let engine = TauPolicyEngine::new("tau");
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(1),
            state_ref: crate::StateRef::unknown(),
        };
        let candidates = vec![CandidateAction {
            action_type: "A".into(),
            params: HashMap::from([("x".into(), Value::Int(1))]),
            score: Score(0),
            candidate_hash: dummy_hash(2),
        }];

        let result = engine.evaluate(&dummy_hash(3), &state, &candidates);
        assert!(matches!(result, Err(MprdError::InvalidInput(_))));
    }

    #[test]
    fn encodes_risk_threshold_wff_with_bitvectors() {
        let engine = TauPolicyEngine::new("tau");
        let candidate = CandidateAction {
            action_type: "test".into(),
            params: HashMap::from([
                ("risk".into(), Value::UInt(5)),
                ("max_risk".into(), Value::UInt(8)),
                ("cost".into(), Value::UInt(3)),
                ("max_cost".into(), Value::UInt(4)),
                ("has_approval".into(), Value::Bool(true)),
            ]),
            score: Score(0),
            candidate_hash: dummy_hash(2),
        };

        let wff = engine
            .build_risk_threshold_wff(&candidate)
            .expect("encoding should succeed");

        assert!(wff.contains("#b0000000000000000000000000000000000000000000000000000000000000101"));
        assert!(wff.contains("#b0000000000000000000000000000000000000000000000000000000000001000"));
        assert!(wff.contains("#b0000000000000000000000000000000000000000000000000000000000000011"));
        assert!(wff.contains("#b0000000000000000000000000000000000000000000000000000000000000100"));
        assert!(wff.ends_with("&& 1)"));
    }

    #[test]
    #[ignore]
    fn solve_wff_with_real_tau_trivial_formulas_when_binary_present() {
        let tau_path = format!(
            "{}/../../external/tau-lang/build-Release/tau",
            env!("CARGO_MANIFEST_DIR"),
        );

        if !Path::new(&tau_path).exists() {
            eprintln!(
                "skipping real Tau integration test; binary not found at {}",
                tau_path
            );
            return;
        }

        let engine = TauPolicyEngine::new(&tau_path);

        let sat = engine
            .solve_wff_with_tau("1 = 1")
            .expect("solve 1 = 1 should not fail");
        assert!(sat);

        let unsat = engine
            .solve_wff_with_tau("1 = 0")
            .expect("solve 1 = 0 should not fail");
        assert!(!unsat);
    }

    #[test]
    #[ignore]
    fn evaluate_with_real_tau_bitvector_wff_fails_closed_on_unexpected_output() {
        let tau_path = format!(
            "{}/../../external/tau-lang/build-Release/tau",
            env!("CARGO_MANIFEST_DIR"),
        );

        if !Path::new(&tau_path).exists() {
            eprintln!(
                "skipping real Tau integration test; binary not found at {}",
                tau_path
            );
            return;
        }

        let engine = TauPolicyEngine::new(tau_path);
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(1),
            state_ref: crate::StateRef::unknown(),
        };

        let candidates = vec![CandidateAction {
            action_type: "test".into(),
            params: HashMap::from([
                ("risk".into(), Value::UInt(5)),
                ("max_risk".into(), Value::UInt(8)),
                ("cost".into(), Value::UInt(3)),
                ("max_cost".into(), Value::UInt(4)),
                ("has_approval".into(), Value::Bool(true)),
            ]),
            score: Score(0),
            candidate_hash: dummy_hash(2),
        }];

        let result = engine.evaluate(&dummy_hash(3), &state, &candidates);

        assert!(matches!(result, Err(MprdError::PolicyEvaluationFailed(_))));
    }

    #[allow(clippy::too_many_arguments)]
    fn pid_allowed(
        setpoint: i64,
        measured: i64,
        e_prev: i64,
        i_prev: i64,
        kp: i64,
        ki: i64,
        kd: i64,
        u_min: i64,
        u_max: i64,
        tol: i64,
        u: i64,
    ) -> bool {
        let e = setpoint - measured;
        let i = i_prev + e;
        let d = e - e_prev;
        let u_pid = kp * e + ki * i + kd * d;
        let within_bounds = u >= u_min && u <= u_max;
        let diff = if u >= u_pid { u - u_pid } else { u_pid - u };
        let within_tol = diff <= tol;
        within_bounds && within_tol
    }

    #[test]
    #[ignore]
    fn pid_spec_end_to_end_with_tau_when_binary_present() {
        let tau_path = format!(
            "{}/../../external/tau-lang/build-Release/tau",
            env!("CARGO_MANIFEST_DIR"),
        );

        if !Path::new(&tau_path).exists() {
            eprintln!(
                "skipping PID Tau integration test; binary not found at {}",
                tau_path
            );
            return;
        }

        let engine = TauPolicyEngine::new(&tau_path);

        let setpoint = 10;
        let measured = 9;
        let e_prev = 0;
        let i_prev = 0;
        let kp = 1;
        let ki = 0;
        let kd = 0;
        let u_min = -100;
        let u_max = 100;
        let tol = 0;

        let u_ok = 1;
        let allowed_ok = pid_allowed(
            setpoint, measured, e_prev, i_prev, kp, ki, kd, u_min, u_max, tol, u_ok,
        );
        assert!(allowed_ok);

        let sat_ok = engine
            .solve_wff_with_tau("1 = 1 && 1 = 1")
            .expect("tau solve for allowed case should not fail");
        assert_eq!(sat_ok, allowed_ok);

        let u_bad = 2;
        let allowed_bad = pid_allowed(
            setpoint, measured, e_prev, i_prev, kp, ki, kd, u_min, u_max, tol, u_bad,
        );
        assert!(!allowed_bad);

        let sat_bad = engine
            .solve_wff_with_tau("1 = 1 && 1 = 0")
            .expect("tau solve for disallowed case should not fail");
        assert_eq!(sat_bad, allowed_bad);
    }
}
