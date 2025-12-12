use crate::{CandidateAction, MprdError, PolicyEngine, PolicyHash, Result, RuleVerdict, StateSnapshot, Value, MAX_CANDIDATES};
use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

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

    fn extract_u64(
        params: &std::collections::HashMap<String, Value>,
        key: &str,
    ) -> Result<u64> {
        match params.get(key) {
            Some(Value::UInt(v)) => Ok(*v),
            Some(Value::Int(v)) if *v >= 0 => Ok(*v as u64),
            _ => Err(MprdError::InvalidInput(format!(
                "missing or invalid numeric param '{}'",
                key
            ))),
        }
    }

    fn build_risk_threshold_wff(
        &self,
        candidate: &CandidateAction,
    ) -> Result<String> {
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
        let script = format!("solve {}\nquit\n", wff);

        let mut child = Command::new(&self.config.tau_binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                MprdError::PolicyEvaluationFailed(format!(
                    "failed to spawn tau: {e}",
                ))
            })?;

        {
            let mut stdin = child.stdin.take().ok_or_else(|| {
                MprdError::PolicyEvaluationFailed("tau stdin unavailable".into())
            })?;

            stdin
                .write_all(script.as_bytes())
                .map_err(|e| {
                    MprdError::PolicyEvaluationFailed(format!(
                        "failed to write to tau stdin: {e}",
                    ))
                })?;
            // `stdin` is dropped here, closing the pipe and letting Tau
            // observe EOF after the script has been sent.
        }
        let timeout = Duration::from_millis(self.config.tau_timeout_ms);
        let start = Instant::now();

        loop {
            match child.try_wait().map_err(|e| {
                MprdError::PolicyEvaluationFailed(format!(
                    "failed to poll tau status: {e}",
                ))
            })? {
                Some(_status) => {
                    let output = child.wait_with_output().map_err(|e| {
                        MprdError::PolicyEvaluationFailed(format!(
                            "failed to collect tau output: {e}",
                        ))
                    })?;

                    let stdout =
                        String::from_utf8_lossy(&output.stdout).into_owned();
                    let stderr =
                        String::from_utf8_lossy(&output.stderr).into_owned();

                    if !output.status.success() {
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

                    return Err(MprdError::PolicyEvaluationFailed(format!(
                        "tau returned unexpected output: {stdout}",
                    )));
                }
                None => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(MprdError::PolicyEvaluationFailed(format!(
                            "tau timed out after {:?}",
                            timeout,
                        )));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
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
    fn evaluate_fails_on_missing_params() {
        let engine = TauPolicyEngine::new("tau");
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
            eprintln!("skipping real Tau integration test; binary not found at {}", tau_path);
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
            eprintln!("skipping real Tau integration test; binary not found at {}", tau_path);
            return;
        }

        let engine = TauPolicyEngine::new(tau_path);
        let state = StateSnapshot {
            fields: HashMap::new(),
            policy_inputs: HashMap::new(),
            state_hash: dummy_hash(1),
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
