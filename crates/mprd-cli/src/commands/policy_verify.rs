//! `mprd policy verify` command implementation

use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::load_config;

const MAX_WFF_LENGTH: usize = 4096;
const TAU_MAX_OUTPUT_BYTES: usize = 64 * 1024;
const TAU_TIMEOUT_MS: u64 = 500;
const TAU_POLL_INTERVAL_MS: u64 = 10;

pub fn run(
    policy_path: PathBuf,
    cases_path: Option<PathBuf>,
    config_path: Option<PathBuf>,
) -> Result<()> {
    let config = load_config(config_path)?;
    let tau_binary = config.tau_binary.as_deref().unwrap_or("tau");

    let policy_raw = fs::read_to_string(&policy_path)
        .with_context(|| format!("Failed to read policy file: {}", policy_path.display()))?;
    let policy_wff = TauWff::parse(&policy_raw)
        .with_context(|| format!("Invalid Tau WFF in policy file: {}", policy_path.display()))?;

    let solver = TauSolver::new(tau_binary);
    let policy_sat = solver
        .solve(&policy_wff)
        .context("Tau failed to parse policy WFF")?;

    println!("Policy verification");
    println!();
    println!("  Policy: {}", policy_path.display());
    println!("  WFF length: {} bytes", policy_wff.len());
    println!("  Tau parse: {}", if policy_sat { "SAT" } else { "UNSAT" });
    println!();

    let Some(cases_path) = cases_path else {
        println!("No test cases provided.");
        return Ok(());
    };

    let cases = load_test_cases(&cases_path)?;
    if cases.is_empty() {
        println!("No test cases found in {}", cases_path.display());
        return Ok(());
    }

    println!("Test cases: {}", cases.len());

    let mut failures = Vec::new();
    for (idx, case) in cases.into_iter().enumerate() {
        let label = case.name.unwrap_or_else(|| format!("case_{}", idx + 1));
        let combined = TauWff::conjoin(&policy_wff, &case.wff)
            .with_context(|| format!("Failed to combine WFF for {}", label))?;

        match solver.solve(&combined) {
            Ok(actual) => {
                if actual == case.expect_sat {
                    println!("  [OK] {}", label);
                } else {
                    let expected_str = if case.expect_sat { "SAT" } else { "UNSAT" };
                    let actual_str = if actual { "SAT" } else { "UNSAT" };
                    println!(
                        "  [FAIL] {}: expected {}, got {}",
                        label, expected_str, actual_str
                    );
                    failures.push(label);
                }
            }
            Err(err) => {
                println!("  [FAIL] {}: tau error: {}", label, err);
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

#[derive(Clone, Debug)]
struct TauWff(String);

impl TauWff {
    fn parse(raw: &str) -> Result<Self> {
        let normalized: String = raw
            .chars()
            .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
            .collect();
        let trimmed = normalized.trim();

        if trimmed.is_empty() {
            anyhow::bail!("WFF cannot be empty");
        }

        if trimmed.len() > MAX_WFF_LENGTH {
            anyhow::bail!("WFF exceeds maximum length of {} bytes", MAX_WFF_LENGTH);
        }

        // Reject potentially dangerous tokens/patterns *before* character-class validation so
        // test failures are categorized as "dangerous" rather than merely "disallowed".
        let dangerous_patterns = [
            "\n", "\r", ";", "quit", "exit", "load", "save", "exec", "system", "`", "$(", "\\",
        ];
        let wff_lower = trimmed.to_lowercase();
        for pattern in dangerous_patterns {
            if wff_lower.contains(pattern) {
                anyhow::bail!(
                    "WFF contains potentially dangerous pattern: '{}'",
                    pattern.escape_default()
                );
            }
        }

        for (i, c) in trimmed.chars().enumerate() {
            if !c.is_ascii() {
                anyhow::bail!("WFF contains non-ASCII character at position {}", i);
            }

            let allowed = c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    ' ' | '\t' // Whitespace
                    | '#' // Bitvector prefix
                    | '(' | ')' // Grouping
                    | '[' | ']' // Indexing / bitvector
                    | '{' | '}' // Typed literals
                    | '<' | '>' | '=' | '!' // Comparisons/negation
                    | '&' | '|' // Logical operators
                    | '+' | '-' | '*' | '/' // Arithmetic
                    | '_' // Identifiers
                    | ':' | '?' // Ternary
                    | '\'' // Temporal/prime
                    | '.' | ',' // Selector separators
                );

            if !allowed {
                anyhow::bail!(
                    "WFF contains disallowed character '{}' at position {}",
                    c.escape_default(),
                    i
                );
            }
        }

        Ok(Self(trimmed.to_string()))
    }

    fn conjoin(left: &TauWff, right: &TauWff) -> Result<Self> {
        TauWff::parse(&format!("({}) && ({})", left.0, right.0))
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug)]
struct PolicyTestCase {
    name: Option<String>,
    wff: TauWff,
    expect_sat: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTestCaseInput {
    #[serde(default)]
    name: Option<String>,
    wff: String,
    #[serde(alias = "expected", alias = "expect")]
    expect_sat: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTestCases {
    cases: Vec<PolicyTestCaseInput>,
}

fn load_test_cases(path: &Path) -> Result<Vec<PolicyTestCase>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read test cases file: {}", path.display()))?;
    let cases = parse_test_cases(&raw)
        .with_context(|| format!("Failed to parse test cases file: {}", path.display()))?;

    cases
        .into_iter()
        .enumerate()
        .map(|(idx, input)| {
            let wff = TauWff::parse(&input.wff).with_context(|| {
                let label = input.name.as_deref().unwrap_or("unnamed");
                format!("Invalid WFF in test case {} ({})", idx + 1, label)
            })?;

            Ok(PolicyTestCase {
                name: input.name,
                wff,
                expect_sat: input.expect_sat,
            })
        })
        .collect()
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

struct TauSolver {
    tau_binary: PathBuf,
    timeout: Duration,
}

impl TauSolver {
    fn new(tau_binary: impl Into<PathBuf>) -> Self {
        Self {
            tau_binary: tau_binary.into(),
            timeout: Duration::from_millis(TAU_TIMEOUT_MS),
        }
    }

    fn solve(&self, wff: &TauWff) -> Result<bool> {
        let script = format!("solve {}\nquit\n", wff.0);

        let mut child = Command::new(&self.tau_binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == ErrorKind::NotFound {
                    anyhow::anyhow!(
                        "Tau binary not found: {:?}. Configure it in the MPRD config or install Tau.",
                        self.tau_binary
                    )
                } else {
                    anyhow::anyhow!("Failed to spawn tau binary {:?}: {}", self.tau_binary, e)
                }
            })?;

        let stdout_reader = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("Tau stdout unavailable"))?;
        let stderr_reader = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("Tau stderr unavailable"))?;

        let stdout_task = thread::spawn(move || read_tau_stream(stdout_reader, "stdout"));
        let stderr_task = thread::spawn(move || read_tau_stream(stderr_reader, "stderr"));

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow::anyhow!("Tau stdin unavailable"))?;
            stdin
                .write_all(script.as_bytes())
                .context("Failed to write to tau stdin")?;
        }

        let status = wait_for_exit(&mut child, self.timeout)?;
        let stdout = stdout_task
            .join()
            .map_err(|_| anyhow::anyhow!("Tau stdout reader thread panicked"))??;
        let stderr = stderr_task
            .join()
            .map_err(|_| anyhow::anyhow!("Tau stderr reader thread panicked"))??;

        if !status.success() {
            anyhow::bail!("Tau exited with error: {}", stderr.trim());
        }

        if stdout.contains("solution:") {
            return Ok(true);
        }
        if stdout.contains("no solution") {
            return Ok(false);
        }

        anyhow::bail!("Tau returned unexpected output: {}", stdout.trim());
    }
}

fn read_tau_stream<R: Read>(mut reader: R, stream_name: &'static str) -> Result<String> {
    let mut output = Vec::new();
    let mut total = 0usize;
    let mut buf = [0u8; 4096];

    loop {
        let n = reader
            .read(&mut buf)
            .with_context(|| format!("Failed to read tau {}", stream_name))?;
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
        anyhow::bail!(
            "Tau {} exceeded {} bytes",
            stream_name,
            TAU_MAX_OUTPUT_BYTES
        );
    }

    Ok(String::from_utf8_lossy(&output).into_owned())
}

fn wait_for_exit(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::ExitStatus> {
    let start = Instant::now();

    loop {
        let status = child.try_wait().context("Failed to poll tau status")?;
        if let Some(status) = status {
            return Ok(status);
        }

        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Tau timed out after {:?}", timeout);
        }

        thread::sleep(Duration::from_millis(TAU_POLL_INTERVAL_MS));
    }
}

#[cfg(test)]
mod tests {
    use super::TauWff;

    #[test]
    fn wff_parse_accepts_basic_formula() {
        let wff = TauWff::parse("1 = 1").expect("valid wff");
        assert_eq!(wff.len(), "1 = 1".len());
    }

    #[test]
    fn wff_parse_rejects_empty() {
        let err = TauWff::parse("").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn wff_parse_rejects_dangerous_tokens() {
        let err = TauWff::parse("1 = 1; quit").unwrap_err();
        assert!(err.to_string().contains("dangerous"));
    }

    #[test]
    fn wff_parse_normalizes_newlines() {
        let wff = TauWff::parse("1 = 1\n&& 1 = 1").expect("valid wff");
        assert!(wff.len() > 0);
    }
}
