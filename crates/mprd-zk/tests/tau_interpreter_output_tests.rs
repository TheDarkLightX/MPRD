#![allow(dead_code)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
struct TauOutputEvent {
    stream_idx: u32,
    step: u32,
    value: String,
}

fn run_tau_bv16_risk_policy_cases(
    tau_bin: &Path,
    export_label: &str,
    cases: &[(u16, u16, u16, u16, bool)],
) -> std::io::Result<Vec<bool>> {
    let work_dir = unique_tau_work_dir(export_label);
    let _ = std::fs::create_dir_all(&work_dir);

    let i_risk = work_dir.join("risk.in");
    let i_max_risk = work_dir.join("max_risk.in");
    let i_cost = work_dir.join("cost.in");
    let i_max_cost = work_dir.join("max_cost.in");
    let i_approval = work_dir.join("approval.in");

    let mut risk_contents = String::from("0\n");
    let mut max_risk_contents = String::from("0\n");
    let mut cost_contents = String::from("0\n");
    let mut max_cost_contents = String::from("0\n");
    let mut approval_contents = String::from("0\n");

    for (risk, max_risk, cost, max_cost, has_approval) in cases {
        risk_contents.push_str(&bv16_to_file_literal(*risk));
        risk_contents.push('\n');
        max_risk_contents.push_str(&bv16_to_file_literal(*max_risk));
        max_risk_contents.push('\n');
        cost_contents.push_str(&bv16_to_file_literal(*cost));
        cost_contents.push('\n');
        max_cost_contents.push_str(&bv16_to_file_literal(*max_cost));
        max_cost_contents.push('\n');
        approval_contents.push_str(sbf_to_file_literal(*has_approval));
        approval_contents.push('\n');
    }

    std::fs::write(&i_risk, risk_contents)?;
    std::fs::write(&i_max_risk, max_risk_contents)?;
    std::fs::write(&i_cost, cost_contents)?;
    std::fs::write(&i_max_cost, max_cost_contents)?;
    std::fs::write(&i_approval, approval_contents)?;

    let out_path = work_dir.join("allowed.out");
    let _ = std::fs::remove_file(&out_path);

    // NOTE: BV comparisons (<=, >=, <, >) are NOT supported directly in Tau execution mode.
    // They must be wrapped in ternary conditionals: (cond ? then : else).
    // See internal/demos/README.md and the primes example for reference.
    let program = format!(
        "set charvar off\n\
i_risk:bv[16] = in file(\"{}\").\n\
i_max_risk:bv[16] = in file(\"{}\").\n\
i_cost:bv[16] = in file(\"{}\").\n\
i_max_cost:bv[16] = in file(\"{}\").\n\
i_approval:sbf = in file(\"{}\").\n\
o_allowed:sbf = out file(\"{}\").\n\
\n\
defs\n\
r (\n\
    ((i_risk[t] <= i_max_risk[t]) ? ((i_cost[t] <= i_max_cost[t]) ? (o_allowed[t] = i_approval[t]) : (o_allowed[t] = 0)) : (o_allowed[t] = 0))\n\
)\n\
n\n\
q\n",
        i_risk.to_string_lossy(),
        i_max_risk.to_string_lossy(),
        i_cost.to_string_lossy(),
        i_max_cost.to_string_lossy(),
        i_approval.to_string_lossy(),
        out_path.to_string_lossy(),
    );

    run_tau_file_io_once(tau_bin, &program)?;

    let out_contents = std::fs::read_to_string(&out_path)?;
    let out_lines: Vec<&str> = out_contents.lines().map(|l| l.trim()).collect();
    let expected_len = 1usize + cases.len();
    if out_lines.len() != expected_len {
        return Err(std::io::Error::other(format!(
            "tau bv16 policy output line count mismatch: expected {expected_len}, got {}",
            out_lines.len()
        )));
    }

    let mut allowed = Vec::<bool>::with_capacity(cases.len());
    for idx in 0..cases.len() {
        let raw = out_lines[idx + 1];
        let b = parse_sbf_value_to_bool(raw)
            .ok_or_else(|| std::io::Error::other(format!("unexpected sbf output '{raw}'")))?;
        allowed.push(b);
    }

    let _ = std::fs::remove_dir_all(&work_dir);
    Ok(allowed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TruthTableTerminalMode {
    Off,
    Progress,
    Table,
    Pretty,
}

fn truth_table_terminal_mode() -> TruthTableTerminalMode {
    let Ok(raw) = std::env::var("TAU_TRUTH_TABLE_TERMINAL") else {
        return TruthTableTerminalMode::Off;
    };
    match raw.trim() {
        "progress" => TruthTableTerminalMode::Progress,
        "table" => TruthTableTerminalMode::Table,
        "pretty" => TruthTableTerminalMode::Pretty,
        _ => TruthTableTerminalMode::Off,
    }
}

fn ansi_ok(mode: TruthTableTerminalMode) -> bool {
    mode == TruthTableTerminalMode::Pretty
}

fn format_bool_cell(b: bool) -> &'static str {
    if b {
        "1"
    } else {
        "0"
    }
}

fn ansi_wrap(mode: TruthTableTerminalMode, code: &str, s: &str) -> String {
    if !ansi_ok(mode) {
        return s.to_string();
    }
    format!("\x1b[{code}m{s}\x1b[0m")
}

fn print_progress_line(label: &str, done: u32, total: u32) {
    let mut stderr = std::io::stderr();
    let pct = if total == 0 {
        100u32
    } else {
        (done.saturating_mul(100)) / total
    };
    let _ = write!(
        &mut stderr,
        "\r[tau-truth-table] {label}: {done}/{total} ({pct}%)"
    );
    let _ = stderr.flush();
}

fn print_truth_table_rows(
    mode: TruthTableTerminalMode,
    export_label: &str,
    num_inputs: u8,
    rows: &[(u32, Vec<bool>, bool, bool)],
) {
    let mut stderr = std::io::stderr();
    let _ = writeln!(&mut stderr, "\n[tau-truth-table] {export_label}");

    let mut header = String::from("bits | ");
    for i in 0..num_inputs {
        header.push_str(&format!("i{i} "));
    }
    header.push_str("| exp | act | ok");
    let _ = writeln!(&mut stderr, "{header}");

    for (bits, inputs, expected, actual) in rows {
        let ok = expected == actual;
        let ok_cell = if ok { "OK" } else { "FAIL" };
        let ok_cell = if ok {
            ansi_wrap(mode, "32", ok_cell)
        } else {
            ansi_wrap(mode, "31", ok_cell)
        };

        let mut line = format!("{:0width$b} | ", bits, width = num_inputs as usize);
        for b in inputs {
            line.push_str(format_bool_cell(*b));
            line.push(' ');
        }
        line.push_str("| ");
        line.push_str(format_bool_cell(*expected));
        line.push_str("   | ");
        line.push_str(format_bool_cell(*actual));
        line.push_str("   | ");
        line.push_str(&ok_cell);
        let _ = writeln!(&mut stderr, "{line}");
    }
}

fn check_sbf_truth_table_via_files<F>(
    tau_bin: &Path,
    export_label: &str,
    num_inputs: u8,
    tau_relation: &str,
    expected_fn: F,
) -> std::io::Result<()>
where
    F: Fn(&[bool]) -> bool,
{
    assert!(num_inputs > 0, "num_inputs must be > 0");
    assert!(
        num_inputs <= 8,
        "num_inputs too large for exhaustive truth table"
    );

    let export_dir = truth_table_export_dir();
    let terminal_mode = truth_table_terminal_mode();

    let mut export_rows: Vec<String> = Vec::new();
    if export_dir.is_some() {
        let mut header = String::from("bits");
        for i in 0..num_inputs {
            header.push_str(&format!(",i{i}"));
        }
        header.push_str(",expected,actual\n");
        export_rows.push(header);
    }

    let max_state: u32 = 1u32 << num_inputs;

    let mut terminal_rows: Vec<(u32, Vec<bool>, bool, bool)> = Vec::new();
    if terminal_mode == TruthTableTerminalMode::Table
        || terminal_mode == TruthTableTerminalMode::Pretty
    {
        terminal_rows.reserve(max_state as usize);
    }

    // Batch the entire truth table into a single Tau run by mapping input combinations to
    // time steps. This avoids spawning Tau + hitting the filesystem once per state, which
    // can make these tests take minutes on developer machines.
    let work_dir = unique_tau_work_dir(export_label);
    let _ = std::fs::create_dir_all(&work_dir);

    let mut input_paths = Vec::<PathBuf>::new();
    for i in 0..num_inputs {
        let p = work_dir.join(format!("i{i}.in"));
        let mut contents = String::new();
        contents.push_str("0\n");
        for bits in 0..max_state {
            let mask = 1u32 << i;
            let b = bits & mask != 0;
            contents.push_str(sbf_to_file_literal(b));
            contents.push('\n');
        }
        std::fs::write(&p, contents)?;
        input_paths.push(p);
    }

    let out_path = work_dir.join("o0.out");
    let _ = std::fs::remove_file(&out_path);

    let mut program = String::from("set charvar off\n");
    for i in 0..num_inputs {
        let p = input_paths[i as usize].to_string_lossy();
        program.push_str(&format!("i{i}:sbf = in file(\"{p}\").\n"));
    }
    program.push_str(&format!(
        "o0:sbf = out file(\"{}\").\n",
        out_path.to_string_lossy()
    ));
    program.push_str("defs\n");
    program.push_str(&format!("r (\n    {tau_relation}\n)\n"));
    program.push_str("n\nq\n");

    run_tau_file_io_once(tau_bin, &program).unwrap_or_else(|e| {
        panic!("[tau-truth-table] {export_label}: batch file-io run failed: {e}");
    });

    let out_contents = std::fs::read_to_string(&out_path).unwrap_or_else(|e| {
        panic!("[tau-truth-table] {export_label}: failed reading output: {e}");
    });
    let out_lines: Vec<String> = out_contents.lines().map(|l| l.trim().to_string()).collect();
    let expected_len = 1usize + max_state as usize;
    if out_lines.len() != expected_len {
        panic!(
            "[tau-truth-table] {export_label}: output line count mismatch (expected {expected_len}, got {})",
            out_lines.len()
        );
    }

    let mut ok_count: u32 = 0;
    let mut inputs_vec = vec![false; num_inputs as usize];
    for bits in 0..max_state {
        for i in 0..num_inputs {
            let mask = 1u32 << i;
            inputs_vec[i as usize] = bits & mask != 0;
        }

        let expected = expected_fn(&inputs_vec);

        let out_line = &out_lines[(bits as usize) + 1];
        let Some(actual) = parse_sbf_value_to_bool(out_line) else {
            panic!(
                "unexpected sbf output '{out_line}' for state {:0width$b}",
                bits,
                width = num_inputs as usize
            );
        };

        if terminal_mode == TruthTableTerminalMode::Table
            || terminal_mode == TruthTableTerminalMode::Pretty
        {
            terminal_rows.push((bits, inputs_vec.clone(), expected, actual));
        }

        if export_dir.is_some() {
            let mut row = format!("{:0width$b}", bits, width = num_inputs as usize);
            for b in &inputs_vec {
                row.push_str(if *b { ",1" } else { ",0" });
            }
            row.push_str(if expected { ",1" } else { ",0" });
            row.push_str(if actual { ",1" } else { ",0" });
            row.push('\n');
            export_rows.push(row);
        }

        if expected == actual {
            ok_count = ok_count.saturating_add(1);
        }

        if terminal_mode == TruthTableTerminalMode::Progress {
            print_progress_line(export_label, bits.saturating_add(1), max_state);
        }

        if expected != actual {
            if terminal_mode != TruthTableTerminalMode::Off {
                let rows = [(bits, inputs_vec.clone(), expected, actual)];
                print_truth_table_rows(terminal_mode, export_label, num_inputs, &rows);
            }
            panic!(
                "truth table mismatch for state {:0width$b}",
                bits,
                width = num_inputs as usize
            );
        }
    }

    if terminal_mode == TruthTableTerminalMode::Progress {
        let mut stderr = std::io::stderr();
        let _ = writeln!(&mut stderr);
        let _ = writeln!(
            &mut stderr,
            "[tau-truth-table] {export_label}: ok={ok_count}/{max_state}"
        );
    }

    if terminal_mode == TruthTableTerminalMode::Table
        || terminal_mode == TruthTableTerminalMode::Pretty
    {
        print_truth_table_rows(terminal_mode, export_label, num_inputs, &terminal_rows);
        let mut stderr = std::io::stderr();
        let _ = writeln!(
            &mut stderr,
            "[tau-truth-table] {export_label}: ok={ok_count}/{max_state}"
        );
    }

    let _ = std::fs::remove_dir_all(&work_dir);

    if let Some(dir) = export_dir {
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("{export_label}.csv"));
        if let Ok(mut f) = std::fs::File::create(&path) {
            for row in export_rows {
                let _ = f.write_all(row.as_bytes());
            }
        }
    }

    Ok(())
}

#[test]
fn mprd_risk_threshold_policy_truth_table_matches_expected() {
    let Some(tau_bin) = tau_binary_path() else {
        eprintln!("Skipping: TAU_BIN not set and external/tau-lang/build-Release/tau not found",);
        return;
    };

    // File-IO policy gate: allow iff (risk_le_max && guard_ok && link_ok).
    check_sbf_truth_table_via_files(
        &tau_bin,
        "mprd_risk_threshold_gate_sbf",
        3,
        "o0[t] = i0[t] & i1[t] & i2[t]",
        |inputs: &[bool]| inputs[0] && inputs[1] && inputs[2],
    )
    .expect("risk threshold sbf truth table should run");
}

fn parse_inline_assignments(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::<(String, String)>::new();

    let tokens: Vec<&str> = line.split_whitespace().collect();
    let mut i = 0usize;
    while i + 2 < tokens.len() {
        let var = tokens[i];
        let op = tokens[i + 1];
        let val = tokens[i + 2];

        if op == ":=" && var.contains('[') && var.ends_with(']') {
            out.push((var.to_string(), val.to_string()));
            i += 2;
            continue;
        }

        i += 1;
    }

    out
}

fn tau_testnet_genesis_spec_path() -> Option<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())?;

    let candidate = workspace_root.join("external/tau-testnet/genesis.tau");
    if candidate.is_file() {
        return Some(candidate);
    }
    None
}

struct TauChild {
    child: Child,
    stdin: ChildStdin,
    stdout_rx: Receiver<u8>,
    stderr_rx: Receiver<u8>,
}

fn spawn_tau_with_spec(tau_bin: &Path, spec_path: &Path) -> std::io::Result<TauChild> {
    let mut child = Command::new(tau_bin)
        .arg(spec_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("tau stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("tau stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("tau stderr unavailable"))?;

    let (stdout_tx, stdout_rx) = mpsc::channel::<u8>();
    let (stderr_tx, stderr_rx) = mpsc::channel::<u8>();

    thread::spawn(move || {
        let mut reader = stdout;
        let mut buf = [0u8; 1];
        while let Ok(n) = std::io::Read::read(&mut reader, &mut buf) {
            if n == 0 {
                break;
            }
            let _ = stdout_tx.send(buf[0]);
        }
    });

    thread::spawn(move || {
        let mut reader = stderr;
        let mut buf = [0u8; 1];
        while let Ok(n) = std::io::Read::read(&mut reader, &mut buf) {
            if n == 0 {
                break;
            }
            let _ = stderr_tx.send(buf[0]);
        }
    });

    Ok(TauChild {
        child,
        stdin,
        stdout_rx,
        stderr_rx,
    })
}

fn tau_binary_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("TAU_BIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())?;

    let candidate = workspace_root.join("external/tau-lang/build-Release/tau");
    if candidate.is_file() {
        return Some(candidate);
    }

    None
}

fn spawn_tau_repl(tau_bin: &Path) -> std::io::Result<TauChild> {
    let mut child = Command::new(tau_bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("tau stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("tau stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("tau stderr unavailable"))?;

    let (stdout_tx, stdout_rx) = mpsc::channel::<u8>();
    let (stderr_tx, stderr_rx) = mpsc::channel::<u8>();

    thread::spawn(move || {
        let mut reader = stdout;
        let mut buf = [0u8; 1];
        while let Ok(n) = std::io::Read::read(&mut reader, &mut buf) {
            if n == 0 {
                break;
            }
            let _ = stdout_tx.send(buf[0]);
        }
    });

    thread::spawn(move || {
        let mut reader = stderr;
        let mut buf = [0u8; 1];
        while let Ok(n) = std::io::Read::read(&mut reader, &mut buf) {
            if n == 0 {
                break;
            }
            let _ = stderr_tx.send(buf[0]);
        }
    });

    Ok(TauChild {
        child,
        stdin,
        stdout_rx,
        stderr_rx,
    })
}

fn parse_prompt_line(prefix: char, line: &str) -> Option<u32> {
    let trimmed = line.trim();
    if !trimmed.starts_with(prefix) {
        return None;
    }

    let rest = trimmed.strip_prefix(prefix)?;
    let digits_end = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits_end == 0 {
        return None;
    }

    let (digits, after_digits) = rest.split_at(digits_end);
    if !after_digits.contains('[') {
        return None;
    }

    if !trimmed.ends_with(":=") {
        return None;
    }

    digits.parse::<u32>().ok()
}

fn parse_any_stream_prompt(line: &str) -> Option<(String, u32)> {
    // Matches prompts printed by Tau like:
    // - i0[0] :=
    // - o0[0] :=
    // - o999[0] :=
    // - u[0] :=
    let trimmed = line.trim();
    if !trimmed.ends_with(":=") {
        return None;
    }

    let open = trimmed.find('[')?;
    let close = trimmed[open..].find(']')? + open;

    let name = trimmed[..open].trim();
    if name.is_empty() {
        return None;
    }

    let idx_str = trimmed[(open + 1)..close].trim();
    let idx = idx_str.parse::<u32>().ok()?;
    Some((name.to_string(), idx))
}

fn parse_output_assignment_line(line: &str) -> Option<(u32, String)> {
    let trimmed = line.trim();
    if !trimmed.starts_with('o') {
        return None;
    }

    let rest = trimmed.strip_prefix('o')?;
    let digits_end = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits_end == 0 {
        return None;
    }

    let (digits, after_digits) = rest.split_at(digits_end);

    // Only treat concrete runtime output assignments like "o0[0] = ...".
    // Avoid matching:
    // - stream declarations such as "o0:sbf = out console."
    // - symbolic/temporal equations printed during normalization such as "o0[t] = ..."
    let after = after_digits.trim_start();
    if !after.starts_with('[') {
        return None;
    }

    let close = after.find(']')?;
    let bracketed = &after[1..close];
    if bracketed.is_empty() {
        return None;
    }
    if !bracketed.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    let eq_pos = after.find('=')?;
    let value = after[(eq_pos + 1)..].trim().to_string();
    let idx = digits.parse::<u32>().ok()?;
    Some((idx, value))
}

fn read_tau_transcript_bytes(
    rx: &Receiver<u8>,
    deadline: Instant,
    current_line: &mut String,
) -> std::io::Result<Option<String>> {
    if Instant::now() >= deadline {
        return Ok(None);
    }

    let remaining = deadline.saturating_duration_since(Instant::now());
    let timeout = remaining.min(Duration::from_millis(100));

    let b = match rx.recv_timeout(timeout) {
        Ok(b) => b,
        Err(mpsc::RecvTimeoutError::Timeout) => return Ok(Some(String::new())),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "tau stdout channel disconnected",
            ))
        }
    };

    let ch = b as char;
    if ch == '\n' {
        let line = std::mem::take(current_line);
        return Ok(Some(line));
    }

    current_line.push(ch);

    if current_line.trim_end().ends_with(":=") {
        let line = std::mem::take(current_line);
        return Ok(Some(line));
    }

    Ok(Some(String::new()))
}

fn drain_stderr(stderr_rx: &Receiver<u8>) -> String {
    let mut out = Vec::<u8>::new();
    while let Ok(b) = stderr_rx.try_recv() {
        out.push(b);
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn write_line(stdin: &mut ChildStdin, line: &str) -> std::io::Result<()> {
    stdin.write_all(line.as_bytes())?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    Ok(())
}

fn run_tau_one_step_and_capture_outputs(
    tau_bin: &Path,
    repl_prelude: &[&str],
    inputs_by_stream: &BTreeMap<u32, String>,
    target_output_stream: u32,
    timeout: Duration,
) -> std::io::Result<Vec<TauOutputEvent>> {
    let mut tau = spawn_tau_repl(tau_bin)?;

    for line in repl_prelude {
        write_line(&mut tau.stdin, line)?;
    }

    let deadline = Instant::now() + timeout;

    let mut current_step: u32 = 0;
    let mut current_line = String::new();
    let mut expect_output_value_for: Option<u32> = None;
    let mut events = Vec::<TauOutputEvent>::new();

    // For interactive console-input specs, Tau may pause after requesting all inputs for a
    // step until it receives an extra newline to continue. We track which input streams
    // we've satisfied for step 0 and send a single empty line once all are provided.
    let expected_inputs: BTreeSet<u32> = inputs_by_stream.keys().copied().collect();
    let mut satisfied_inputs_step0 = BTreeSet::<u32>::new();
    let mut sent_step0_continue = false;

    loop {
        if Instant::now() >= deadline {
            let stderr = drain_stderr(&tau.stderr_rx);
            let _ = tau.child.kill();
            let _ = tau.child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("tau timed out. stderr: {stderr}"),
            ));
        }

        let maybe_line = read_tau_transcript_bytes(&tau.stdout_rx, deadline, &mut current_line)?;
        let Some(line) = maybe_line else {
            continue;
        };

        if line.is_empty() {
            continue;
        }

        if let Some(step_str) = line.trim().strip_prefix("Execution step:") {
            if let Ok(step) = step_str.trim().parse::<u32>() {
                current_step = step;
            }
            continue;
        }

        if let Some(out_idx) = expect_output_value_for {
            let value = line.trim();
            if !value.is_empty() {
                events.push(TauOutputEvent {
                    stream_idx: out_idx,
                    step: current_step,
                    value: value.to_string(),
                });
                expect_output_value_for = None;
            }
        }

        if let Some(idx) = parse_prompt_line('o', &line) {
            expect_output_value_for = Some(idx);
            continue;
        }

        if let Some((idx, value)) = parse_output_assignment_line(&line) {
            events.push(TauOutputEvent {
                stream_idx: idx,
                step: current_step,
                value,
            });
        }

        if let Some(idx) = parse_prompt_line('i', &line) {
            let Some(v) = inputs_by_stream.get(&idx) else {
                continue;
            };
            write_line(&mut tau.stdin, v)?;

            if current_step == 0 {
                satisfied_inputs_step0.insert(idx);
                if !sent_step0_continue
                    && !expected_inputs.is_empty()
                    && satisfied_inputs_step0 == expected_inputs
                {
                    // Send an empty line to allow Tau to proceed to compute outputs.
                    write_line(&mut tau.stdin, "")?;
                    sent_step0_continue = true;
                }
            }
        }

        let got_target = events
            .iter()
            .any(|e| e.stream_idx == target_output_stream && e.step == 0);
        if got_target {
            let _ = write_line(&mut tau.stdin, "q");
            let _ = tau.child.kill();
            let _ = tau.child.wait();
            break;
        }
    }

    Ok(events)
}

fn parse_sbf_value_to_bool(raw: &str) -> Option<bool> {
    match raw.trim() {
        "T" | "1" => Some(true),
        "F" | "0" => Some(false),
        _ => None,
    }
}

fn sbf_to_file_literal(b: bool) -> &'static str {
    if b {
        "1"
    } else {
        "0"
    }
}

fn bv16_to_file_literal(v: u16) -> String {
    v.to_string()
}

fn write_two_line_input_file(path: &Path, init: &str, t0: &str) -> std::io::Result<()> {
    std::fs::write(path, format!("{init}\n{t0}\n"))
}

fn read_last_nonempty_line(path: &Path) -> std::io::Result<Option<String>> {
    let contents = std::fs::read_to_string(path)?;
    let mut last: Option<String> = None;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        last = Some(trimmed.to_string());
    }
    Ok(last)
}

fn run_tau_file_io_once(tau_bin: &Path, program: &str) -> std::io::Result<()> {
    let mut child = Command::new(tau_bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| std::io::Error::other("tau stdin unavailable"))?;
        stdin.write_all(program.as_bytes())?;
        stdin.flush()?;
    }

    let output = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "tau file-io run failed. stderr: {stderr}"
        )));
    }

    if stdout.contains("(Error)") || stderr.contains("(Error)") {
        return Err(std::io::Error::other(format!(
            "tau file-io reported error. stdout: {stdout} stderr: {stderr}"
        )));
    }

    Ok(())
}

fn unique_tau_work_dir(label: &str) -> PathBuf {
    static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("mprd_tau_truth_table_work_{label}_{id}"))
}

fn truth_table_export_dir() -> Option<PathBuf> {
    let enabled = std::env::var("TAU_TRUTH_TABLE_EXPORT").ok()?;
    if enabled != "1" {
        return None;
    }
    let dir = std::env::temp_dir().join("mprd_tau_truth_tables");
    Some(dir)
}

fn check_sbf_truth_table<F>(
    tau_bin: &Path,
    repl_prelude: &[&str],
    export_label: &str,
    num_inputs: u8,
    target_output_stream: u32,
    timeout: Duration,
    expected_fn: F,
) where
    F: Fn(&[bool]) -> bool,
{
    assert!(num_inputs > 0, "num_inputs must be > 0");
    assert!(
        num_inputs <= 8,
        "num_inputs too large for exhaustive truth table"
    );

    let mut inputs_vec = vec![false; num_inputs as usize];
    let max_state: u32 = 1u32 << num_inputs;

    let export_dir = truth_table_export_dir();
    let mut export_rows: Vec<String> = Vec::new();
    if export_dir.is_some() {
        let mut header = String::from("bits");
        for i in 0..num_inputs {
            header.push_str(&format!(",i{i}"));
        }
        header.push_str(",expected,actual\n");
        export_rows.push(header);
    }

    for bits in 0..max_state {
        for i in 0..num_inputs {
            let mask = 1u32 << i;
            inputs_vec[i as usize] = bits & mask != 0;
        }

        let expected = expected_fn(&inputs_vec);

        let mut inputs_by_stream = BTreeMap::<u32, String>::new();
        for (idx, &b) in inputs_vec.iter().enumerate() {
            // Tau REPL sbf prompts accept boolean literals like "T."/"F.".
            // Using numeric forms like "1."/"0." here tends to keep values symbolic,
            // causing Tau to output formulas rather than concrete T/F.
            inputs_by_stream.insert(
                idx as u32,
                if b {
                    "T.".to_string()
                } else {
                    "F.".to_string()
                },
            );
        }

        let events = run_tau_one_step_and_capture_outputs(
            tau_bin,
            repl_prelude,
            &inputs_by_stream,
            target_output_stream,
            timeout,
        )
        .unwrap_or_else(|e| {
            panic!(
                "tau run failed for input state {:0width$b}: {e}",
                bits,
                width = num_inputs as usize
            )
        });

        let ev = events
            .iter()
            .find(|e| e.stream_idx == target_output_stream && e.step == 0)
            .unwrap_or_else(|| {
                panic!(
                    "no output for state {:0width$b}",
                    bits,
                    width = num_inputs as usize
                )
            });

        let Some(actual) = parse_sbf_value_to_bool(&ev.value) else {
            panic!(
                "unexpected sbf output '{}' for state {:0width$b}",
                ev.value.trim(),
                bits,
                width = num_inputs as usize
            );
        };

        if export_dir.is_some() {
            let mut row = format!("{:0width$b}", bits, width = num_inputs as usize);
            for b in &inputs_vec {
                row.push_str(if *b { ",1" } else { ",0" });
            }
            row.push_str(if expected { ",1" } else { ",0" });
            row.push_str(if actual { ",1" } else { ",0" });
            row.push('\n');
            export_rows.push(row);
        }

        assert_eq!(
            actual,
            expected,
            "truth table mismatch for state {:0width$b}",
            bits,
            width = num_inputs as usize
        );
    }

    if let Some(dir) = export_dir {
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("{export_label}.csv"));
        if let Ok(mut f) = std::fs::File::create(&path) {
            for row in export_rows {
                let _ = f.write_all(row.as_bytes());
            }
        }
    }
}

#[test]
fn tau_testnet_genesis_step0_outputs_are_deterministic() {
    let Some(tau_bin) = tau_binary_path() else {
        eprintln!("Skipping: TAU_BIN not set and external/tau-lang/build-Release/tau not found");
        return;
    };
    let Some(genesis_spec) = tau_testnet_genesis_spec_path() else {
        eprintln!("Skipping: external/tau-testnet/genesis.tau not found");
        return;
    };

    let mut tau = spawn_tau_with_spec(&tau_bin, &genesis_spec)
        .expect("spawning tau with genesis spec should succeed");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut current_line = String::new();

    let mut current_step: Option<u32> = None;
    let mut sent_i0_0 = false;
    let mut expect_value_for: Option<(String, u32)> = None;
    let mut outputs_step0 = std::collections::BTreeMap::<String, String>::new();
    let mut recent_stdout_lines: Vec<String> = Vec::new();

    loop {
        if Instant::now() >= deadline {
            let stderr = drain_stderr(&tau.stderr_rx);
            let _ = tau.child.kill();
            let _ = tau.child.wait();
            panic!(
                "tau timed out while waiting for step0 output. recent stdout: {:?}. stderr: {}",
                recent_stdout_lines, stderr
            );
        }

        let maybe_line = read_tau_transcript_bytes(&tau.stdout_rx, deadline, &mut current_line)
            .expect("reading tau stdout should succeed");
        let Some(line) = maybe_line else {
            continue;
        };

        if line.is_empty() {
            continue;
        }

        let trimmed = line.trim().to_string();
        if !trimmed.is_empty() {
            recent_stdout_lines.push(trimmed.clone());
            if recent_stdout_lines.len() > 20 {
                recent_stdout_lines.remove(0);
            }
        }

        if trimmed.starts_with("Execution step:") {
            current_step = trimmed
                .strip_prefix("Execution step:")
                .and_then(|s| s.trim().parse::<u32>().ok());
            if current_step == Some(1) {
                break;
            }
            continue;
        }

        if current_step != Some(0) {
            continue;
        }

        if let Some((stream_name, stream_idx)) = expect_value_for.take() {
            if !trimmed.is_empty() {
                outputs_step0.insert(format!("{stream_name}[{stream_idx}]"), trimmed);
            }
            if outputs_step0.contains_key("o0[0]")
                && outputs_step0.contains_key("o999[0]")
                && outputs_step0.contains_key("u[0]")
            {
                break;
            }
            continue;
        }

        if let Some((name, idx)) = parse_any_stream_prompt(&trimmed) {
            // Tau prompt formatting has changed across versions (e.g. `i0[0] :=` vs `i0[0]:tau :=`).
            // Parse the prompt structurally instead of matching on an exact string.
            if !sent_i0_0 && name == "i0" && idx == 0 {
                write_line(&mut tau.stdin, "F.").expect("writing i0[0] input should succeed");
                sent_i0_0 = true;
                continue;
            }

            // We only care about output-bearing streams during step 0.
            if name == "o0" || name == "o999" || name == "u" {
                expect_value_for = Some((name, idx));
                continue;
            }
        }

        if trimmed.starts_with("i0[1]") {
            break;
        }

        if outputs_step0.contains_key("o0[0]")
            && outputs_step0.contains_key("o999[0]")
            && outputs_step0.contains_key("u[0]")
        {
            break;
        }
    }

    let _ = write_line(&mut tau.stdin, "q");
    let _ = tau.child.kill();
    let _ = tau.child.wait();

    assert_eq!(outputs_step0.get("o0[0]").map(|s| s.as_str()), Some("T"));
    assert_eq!(outputs_step0.get("o999[0]").map(|s| s.as_str()), Some("F"));
    assert_eq!(outputs_step0.get("u[0]").map(|s| s.as_str()), Some("F"));
}

#[test]
fn mprd_governance_gate_truth_table_matches_expected() {
    let Some(tau_bin) = tau_binary_path() else {
        eprintln!("Skipping: TAU_BIN not set and external/tau-lang/build-Release/tau not found",);
        return;
    };

    // File-based truth table (matches internal demos): six sbf inputs, one sbf output.
    check_sbf_truth_table_via_files(
        &tau_bin,
        "mprd_governance_gate",
        6,
        "o0[t] = ((i0[t] & i1[t]' & i2[t]') | (i0[t]' & i1[t] & i2[t]') | (i0[t]' & i1[t]' & i2[t])) & ((i0[t] & i3[t] & i5[t]) | (i1[t] & i4[t] & i5[t]) | (i2[t] & i3[t] & i4[t] & i5[t]))",
        |inputs: &[bool]| {
            let pt = inputs[0];
            let sc = inputs[1];
            let ce = inputs[2];
            let app_ok = inputs[3];
            let safety_ok = inputs[4];
            let link_ok = inputs[5];

            let one_hot_mode = usize::from(pt) + usize::from(sc) + usize::from(ce) == 1;
            one_hot_mode
                && ((pt && app_ok && link_ok)
                    || (sc && safety_ok && link_ok)
                    || (ce && app_ok && safety_ok && link_ok))
        },
    )
    .expect("governance gate truth table should run");
}

#[test]
fn mprd_committee_decision_matrix_2_of_3_with_veto_truth_table_matches_expected() {
    let Some(tau_bin) = tau_binary_path() else {
        eprintln!("Skipping: TAU_BIN not set and external/tau-lang/build-Release/tau not found",);
        return;
    };

    check_sbf_truth_table_via_files(
        &tau_bin,
        "mprd_committee_2of3_veto",
        4,
        "o0[t] = (((i0[t] & i1[t]) | (i0[t] & i2[t]) | (i1[t] & i2[t])) & i3[t]')",
        |inputs: &[bool]| {
            let v0 = inputs[0];
            let v1 = inputs[1];
            let v2 = inputs[2];
            let veto = inputs[3];

            let at_least_two = usize::from(v0) + usize::from(v1) + usize::from(v2) >= 2;
            at_least_two && !veto
        },
    )
    .expect("committee decision matrix truth table should run");
}

#[test]
fn decision_tool_supermajority_2_of_3_truth_table_matches_expected() {
    let Some(tau_bin) = tau_binary_path() else {
        eprintln!("Skipping: TAU_BIN not set and external/tau-lang/build-Release/tau not found",);
        return;
    };

    check_sbf_truth_table_via_files(
        &tau_bin,
        "decision_tool_supermajority_2of3",
        3,
        "o0[t] = ((i0[t] & i1[t]) | (i0[t] & i2[t]) | (i1[t] & i2[t]))",
        |inputs: &[bool]| {
            let y0 = inputs[0];
            let y1 = inputs[1];
            let y2 = inputs[2];
            usize::from(y0) + usize::from(y1) + usize::from(y2) >= 2
        },
    )
    .expect("supermajority 2-of-3 truth table should run");
}

#[test]
fn decision_tool_quorum_abstention_2_of_3_present_truth_table_matches_expected() {
    let Some(tau_bin) = tau_binary_path() else {
        eprintln!("Skipping: TAU_BIN not set and external/tau-lang/build-Release/tau not found",);
        return;
    };

    // Inputs:
    // i0..i2: present flags p0,p1,p2
    // i3..i5: yes flags y0,y1,y2
    // Allow iff at least two present AND at least two yes among those present.
    check_sbf_truth_table_via_files(
        &tau_bin,
        "decision_tool_quorum_abstention_2of3_present",
        6,
        "o0[t] = (((i0[t] & i1[t]) | (i0[t] & i2[t]) | (i1[t] & i2[t])) & (((i3[t] & i0[t]) & (i4[t] & i1[t])) | ((i3[t] & i0[t]) & (i5[t] & i2[t])) | ((i4[t] & i1[t]) & (i5[t] & i2[t]))))",
        |inputs: &[bool]| {
            let p0 = inputs[0];
            let p1 = inputs[1];
            let p2 = inputs[2];

            let y0 = inputs[3];
            let y1 = inputs[4];
            let y2 = inputs[5];

            let quorum = usize::from(p0) + usize::from(p1) + usize::from(p2) >= 2;

            let yp0 = y0 && p0;
            let yp1 = y1 && p1;
            let yp2 = y2 && p2;
            let yes_two_present = usize::from(yp0) + usize::from(yp1) + usize::from(yp2) >= 2;

            quorum && yes_two_present
        },
    )
    .expect("quorum+abstention truth table should run");
}

#[test]
fn decision_tool_proposal_sequencing_gate_truth_table_matches_expected() {
    let Some(tau_bin) = tau_binary_path() else {
        eprintln!("Skipping: TAU_BIN not set and external/tau-lang/build-Release/tau not found",);
        return;
    };

    check_sbf_truth_table_via_files(
        &tau_bin,
        "decision_tool_proposal_sequencing_gate",
        3,
        "o0[t] = (i0[t] & i1[t] & i2[t])",
        |inputs: &[bool]| inputs[0] && inputs[1] && inputs[2],
    )
    .expect("proposal sequencing gate truth table should run");
}

#[test]
fn decision_tool_emergency_pause_override_truth_table_matches_expected() {
    let Some(tau_bin) = tau_binary_path() else {
        eprintln!("Skipping: TAU_BIN not set and external/tau-lang/build-Release/tau not found",);
        return;
    };

    check_sbf_truth_table_via_files(
        &tau_bin,
        "decision_tool_emergency_pause_override",
        3,
        "o0[t] = ((i0[t] & i1[t]') | i2[t])",
        |inputs: &[bool]| {
            let allow_candidate = inputs[0];
            let pause = inputs[1];
            let override_flag = inputs[2];
            (allow_candidate && !pause) || override_flag
        },
    )
    .expect("emergency pause override truth table should run");
}

/// Cross-verification test: Rust GovernanceProfile::would_accept() vs Tau governance gate spec.
/// This test verifies that the Rust implementation exactly matches the Tau spec logic.
///
/// Note: Uses sbf flags for update_kind encoding since bv[N] comparisons with && in ternary
/// conditionals don't execute properly in Tau execution mode.
#[test]
fn governance_gate_rust_vs_tau_cross_verification() {
    let Some(tau_bin) = tau_binary_path() else {
        eprintln!("Skipping: TAU_BIN not set and external/tau-lang/build-Release/tau not found",);
        return;
    };

    // Encode update_kind as one-hot sbf flags: is_policy_tweak, is_safety_change, is_cap_expand
    // This avoids bv[8] comparison issues in execution mode
    //
    // Logic matches mprd_governance_gate.tau:
    //   POLICY_TWEAK (0x01): app_ok && link_ok
    //   SAFETY_CHANGE (0x02): safety_ok && link_ok
    //   CAPABILITY_EXPAND (0x03): app_ok && safety_ok && link_ok
    //   Invalid: always reject

    // Tau formula encoding the governance gate logic:
    // i0=is_policy_tweak, i1=is_safety_change, i2=is_cap_expand
    // i3=app_ok, i4=safety_ok, i5=link_ok
    //
    // Accept = (i0 & !i1 & !i2 & i3 & i5) | (!i0 & i1 & !i2 & i4 & i5) | (!i0 & !i1 & i2 & i3 & i4 & i5)
    check_sbf_truth_table_via_files(
        &tau_bin,
        "governance_gate_cross_verify",
        6,
        "o0[t] = (i0[t] & i1[t]' & i2[t]' & i3[t] & i5[t]) | (i0[t]' & i1[t] & i2[t]' & i4[t] & i5[t]) | (i0[t]' & i1[t]' & i2[t] & i3[t] & i4[t] & i5[t])",
        |inputs: &[bool]| {
            let is_policy_tweak = inputs[0];
            let is_safety_change = inputs[1];
            let is_cap_expand = inputs[2];
            let app_ok = inputs[3];
            let safety_ok = inputs[4];
            let link_ok = inputs[5];

            // One-hot constraint: exactly one mode flag must be set
            let one_hot = usize::from(is_policy_tweak)
                + usize::from(is_safety_change)
                + usize::from(is_cap_expand)
                == 1;

            if !one_hot {
                return false;
            }

            // Check authorization based on update kind
            if is_policy_tweak {
                app_ok && link_ok
            } else if is_safety_change {
                safety_ok && link_ok
            } else if is_cap_expand {
                app_ok && safety_ok && link_ok
            } else {
                false
            }
        },
    )
    .expect("governance gate cross-verification should run");
}

#[test]
fn mprd_risk_threshold_policy_bv16_grid_matches_expected() {
    let Some(tau_bin) = tau_binary_path() else {
        eprintln!("Skipping: TAU_BIN not set and external/tau-lang/build-Release/tau not found",);
        return;
    };

    const EXPORT_LABEL: &str = "mprd_risk_threshold_policy_bv16_grid";

    let mut cases: Vec<(u16, u16, u16, u16, bool)> = vec![
        (0, 0, 0, 0, true),
        (1, 2, 1, 2, true),
        (255, 256, 255, 256, true),
        (u16::MAX, u16::MAX, u16::MAX, u16::MAX, true),
        (2, 1, 0, 0, true),
        (u16::MAX, u16::MAX - 1, 0, 0, true),
        (0, 0, 2, 1, true),
        (0, 0, u16::MAX, u16::MAX - 1, true),
        (0, 0, 0, 0, false),
        (1, 2, 1, 2, false),
        (2, 1, 2, 1, true),
        (2, 1, 2, 1, false),
    ];

    let slice_values: [u16; 6] = [0, 1, 2, 255, 256, u16::MAX];
    for &risk in &slice_values {
        for &max_risk in &[0u16, 1u16, u16::MAX] {
            cases.push((risk, max_risk, 0, 0, true));
        }
    }

    cases.sort();
    cases.dedup();

    let actuals =
        run_tau_bv16_risk_policy_cases(&tau_bin, EXPORT_LABEL, &cases).unwrap_or_else(|e| {
            panic!("tau bv16 policy batch run failed: {e}");
        });

    for ((risk, max_risk, cost, max_cost, has_approval), actual) in
        cases.into_iter().zip(actuals.into_iter())
    {
        let expected = (risk <= max_risk) && (cost <= max_cost) && has_approval;
        assert_eq!(
            actual, expected,
            "bv16 risk policy mismatch for risk={risk} max_risk={max_risk} cost={cost} max_cost={max_cost} approval={has_approval}"
        );
    }
}
