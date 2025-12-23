//! `mprd panel` command implementation
//!
//! High-signal operator "control panel" output intended for SSH/tmux use.

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::operator::api as op_api;
use crate::operator::store::OperatorStore;

fn now_ms() -> i64 {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_millis(0))
        .as_millis();
    i64::try_from(ms).unwrap_or(0)
}

fn env_opt(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn fingerprint_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(bytes);
    hex::encode(&digest[..8])
}

fn fmt_ts(ms: i64) -> String {
    if ms <= 0 {
        return "unknown".into();
    }
    let secs = (ms / 1000) as u64;
    let rem = (ms % 1000).unsigned_abs();
    format!("{secs}.{rem:03}s")
}

fn status_tag_ok(ok: bool) -> &'static str {
    if ok {
        "[OK ]"
    } else {
        "[FAIL]"
    }
}

fn status_tag_warn() -> &'static str {
    "[WARN]"
}

fn box_line(width: usize) -> String {
    let w = width.max(10);
    format!("+{}+", "-".repeat(w.saturating_sub(2)))
}

fn box_title(width: usize, title: &str) -> String {
    let w = width.max(10);
    let inner = w.saturating_sub(2);
    let t = title.trim();
    let mut s = String::with_capacity(w + 2);
    s.push('|');
    if inner == 0 {
        s.push('|');
        return s;
    }
    let label = format!(" {t} ");
    if label.len() >= inner {
        s.push_str(&label[..inner]);
    } else {
        s.push_str(&label);
        s.push_str(&" ".repeat(inner - label.len()));
    }
    s.push('|');
    s
}

fn box_kv(width: usize, k: &str, v: &str) -> String {
    let w = width.max(10);
    let inner = w.saturating_sub(2);
    let mut line = format!("{k}: {v}");
    if line.len() > inner {
        line.truncate(inner.saturating_sub(3));
        line.push_str("...");
    }
    format!("|{:<inner$}|", line, inner = inner)
}

fn box_text(width: usize, text: &str) -> String {
    let w = width.max(10);
    let inner = w.saturating_sub(2);
    let mut line = text.to_string();
    if line.len() > inner {
        line.truncate(inner.saturating_sub(3));
        line.push_str("...");
    }
    format!("|{:<inner$}|", line, inner = inner)
}

#[derive(Clone)]
struct AlertRow {
    severity: op_api::AlertSeverity,
    message: String,
    ts: i64,
    acknowledged: bool,
}

fn derive_alerts(store: &OperatorStore, limit: usize) -> Result<Vec<AlertRow>> {
    let decisions = store.list_summaries(Duration::from_millis(250))?;
    let mut alerts = Vec::new();
    for d in decisions {
        if alerts.len() >= limit {
            break;
        }
        let decision_id = d.id.clone();

        if matches!(d.proof_status, op_api::ProofStatus::Failed) {
            let id = format!("verification_failure:{decision_id}");
            let acknowledged = store.is_alert_acknowledged(&id);
            alerts.push(AlertRow {
                severity: op_api::AlertSeverity::Critical,
                message: format!("Proof verification failed ({decision_id})"),
                ts: d.timestamp,
                acknowledged,
            });
        }

        if alerts.len() >= limit {
            break;
        }

        if matches!(d.execution_status, op_api::ExecutionStatus::Failed) {
            let id = format!("execution_error:{decision_id}");
            let acknowledged = store.is_alert_acknowledged(&id);
            alerts.push(AlertRow {
                severity: op_api::AlertSeverity::Warning,
                message: format!("Execution failed ({decision_id})"),
                ts: d.timestamp,
                acknowledged,
            });
        }
    }
    Ok(alerts)
}

fn clear_screen() {
    // ANSI clear + home (works in most terminals).
    print!("\x1b[2J\x1b[H");
}

fn render_panel(
    width: usize,
    store: &OperatorStore,
    store_dir: &Path,
    policy_dir: &Path,
) -> Result<String> {
    let mut out = String::new();
    let now = now_ms();

    let registry_state_path = env_opt("MPRD_OPERATOR_REGISTRY_STATE_PATH");
    let registry_key_fp = env_opt("MPRD_OPERATOR_REGISTRY_KEY_HEX")
        .and_then(|hex_key| hex::decode(hex_key).ok())
        .map(|b| fingerprint_hex(&b));
    let manifest_key_fp = env_opt("MPRD_OPERATOR_MANIFEST_KEY_HEX")
        .or_else(|| env_opt("MPRD_OPERATOR_REGISTRY_KEY_HEX"))
        .and_then(|hex_key| hex::decode(hex_key).ok())
        .map(|b| fingerprint_hex(&b));

    let decisions = store.list_summaries(Duration::from_millis(250))?;
    let alerts = derive_alerts(store, 8)?;
    let unacked = alerts.iter().filter(|a| !a.acknowledged).count();

    out.push_str(&format!(
        "MPRD OPERATOR PANEL  time={}  decisions={}  alerts_unacked={}\n",
        fmt_ts(now),
        decisions.len(),
        unacked
    ));

    // TRUST ANCHORS
    out.push_str(&box_line(width));
    out.push('\n');
    out.push_str(&box_title(width, "TRUST ANCHORS"));
    out.push('\n');
    let anchors_ok = registry_state_path.is_some()
        && registry_key_fp.as_deref().is_some_and(|s| !s.is_empty())
        && manifest_key_fp.as_deref().is_some_and(|s| !s.is_empty());
    out.push_str(&box_text(
        width,
        &format!(
            "{} registry_state configured",
            if anchors_ok {
                status_tag_ok(true)
            } else {
                status_tag_warn()
            }
        ),
    ));
    out.push('\n');
    out.push_str(&box_kv(
        width,
        "registry_state",
        registry_state_path.as_deref().unwrap_or("(unset)"),
    ));
    out.push('\n');
    out.push_str(&box_kv(
        width,
        "registry_key_fp",
        registry_key_fp.as_deref().unwrap_or("(unset)"),
    ));
    out.push('\n');
    out.push_str(&box_kv(
        width,
        "manifest_key_fp",
        manifest_key_fp.as_deref().unwrap_or("(unset)"),
    ));
    out.push('\n');
    out.push_str(&box_line(width));
    out.push('\n');

    // STORE
    out.push_str(&box_line(width));
    out.push('\n');
    out.push_str(&box_title(width, "STORE"));
    out.push('\n');
    out.push_str(&box_kv(width, "store_dir", &store_dir.to_string_lossy()));
    out.push('\n');
    out.push_str(&box_kv(width, "policy_dir", &policy_dir.to_string_lossy()));
    out.push('\n');
    out.push_str(&box_kv(
        width,
        "sensitive_store",
        if store.store_sensitive_enabled() {
            "ENABLED"
        } else {
            "DISABLED"
        },
    ));
    out.push('\n');
    out.push_str(&box_line(width));
    out.push('\n');

    // ALERTS
    out.push_str(&box_line(width));
    out.push('\n');
    out.push_str(&box_title(width, &format!("ALERTS (unacked={})", unacked)));
    out.push('\n');
    if alerts.is_empty() {
        out.push_str(&box_text(width, "[OK ] no active alerts"));
        out.push('\n');
    } else {
        for a in alerts.iter().take(6) {
            let sev = match a.severity {
                op_api::AlertSeverity::Critical => "CRIT",
                op_api::AlertSeverity::Warning => "WARN",
                op_api::AlertSeverity::Info => "INFO",
            };
            let ack = if a.acknowledged { "ack" } else { "UNACK" };
            out.push_str(&box_text(
                width,
                &format!("[{sev}] {ack} t={} {}", fmt_ts(a.ts), a.message),
            ));
            out.push('\n');
        }
    }
    out.push_str(&box_line(width));
    out.push('\n');

    // DECISIONS
    out.push_str(&box_line(width));
    out.push('\n');
    out.push_str(&box_title(width, "RECENT DECISIONS"));
    out.push('\n');
    if decisions.is_empty() {
        out.push_str(&box_text(width, "no decisions recorded yet"));
        out.push('\n');
    } else {
        out.push_str(&box_text(
            width,
            "time        verdict  proof    exec     policy_hash_prefix  action",
        ));
        out.push('\n');
        for d in decisions.iter().take(8) {
            let verdict = match d.verdict {
                op_api::Verdict::Allowed => "ALLOW",
                op_api::Verdict::Denied => "DENY ",
            };
            let proof = match d.proof_status {
                op_api::ProofStatus::Verified => "OK  ",
                op_api::ProofStatus::Failed => "FAIL",
                op_api::ProofStatus::Pending => "PEND",
            };
            let exec = match d.execution_status {
                op_api::ExecutionStatus::Success => "OK  ",
                op_api::ExecutionStatus::Failed => "FAIL",
                op_api::ExecutionStatus::Skipped => "SKIP",
            };
            let policy_prefix = if d.policy_hash.len() >= 12 {
                &d.policy_hash[..12]
            } else {
                &d.policy_hash
            };
            out.push_str(&box_text(
                width,
                &format!(
                    "{:>10}  {verdict}  {proof}  {exec}  {}  {}",
                    fmt_ts(d.timestamp),
                    policy_prefix,
                    d.action_type
                ),
            ));
            out.push('\n');
        }
    }
    out.push_str(&box_line(width));
    out.push('\n');

    Ok(out)
}

pub fn run(
    watch_ms: Option<u64>,
    width: usize,
    policy_dir: Option<PathBuf>,
    store_dir: Option<PathBuf>,
) -> Result<()> {
    let policy_dir = policy_dir.unwrap_or_else(|| PathBuf::from(".mprd/policies"));
    let store_dir = store_dir
        .or_else(|| env_opt("MPRD_OPERATOR_STORE_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(".mprd/operator"));

    let store = OperatorStore::new(store_dir.clone())?;

    loop {
        clear_screen();
        let panel = render_panel(width, &store, &store_dir, &policy_dir)?;
        print!("{panel}");

        let Some(ms) = watch_ms else {
            break;
        };
        thread::sleep(Duration::from_millis(ms.max(250)));
    }

    Ok(())
}
