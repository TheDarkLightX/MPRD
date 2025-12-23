use crate::operator::api as op_api;
use crate::operator::store as op_store;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::util;

pub(super) async fn poll_store_events(
    store: op_store::OperatorStore,
    tx: tokio::sync::broadcast::Sender<String>,
) {
    let mut known_decisions: HashMap<String, i64> = HashMap::new();
    let mut known_alerts: HashMap<String, i64> = HashMap::new();
    let mut last_prune = Instant::now() - Duration::from_secs(60);

    loop {
        if last_prune.elapsed() >= Duration::from_secs(60) {
            let _ = store.prune_decisions();
            last_prune = Instant::now();
        }

        let summaries = store.list_summaries(Duration::from_millis(0));
        if let Ok(items) = summaries {
            for d in items {
                if !known_decisions.contains_key(&d.id) {
                    known_decisions.insert(d.id.clone(), d.timestamp);
                    if let Ok(record) = store.read_record(&d.id) {
                        let event = serde_json::json!({
                            "type": "decision_completed",
                            "decisionId": d.id,
                            "policyHash": record.token.policy_hash,
                            "stateHash": record.token.state_hash,
                            "candidateCount": record.candidates.len(),
                            "verdict": format!("{:?}", record.summary.verdict).to_lowercase(),
                            "proofStatus": format!("{:?}", record.summary.proof_status).to_lowercase(),
                            "executionStatus": format!("{:?}", record.summary.execution_status).to_lowercase(),
                        })
                        .to_string();
                        let _ = tx.send(event);

                        // Emit alert events for high-signal failures (unacknowledged only).
                        if matches!(record.summary.proof_status, op_api::ProofStatus::Failed) {
                            let alert_id =
                                format!("verification_failure:{}", record.decision_id_hex);
                            if !known_alerts.contains_key(&alert_id)
                                && !store.is_alert_acknowledged(&alert_id)
                            {
                                known_alerts.insert(alert_id.clone(), record.token.timestamp_ms);
                                let _ = tx.send(
                                    serde_json::json!({
                                        "type": "alert_raised",
                                        "alert": {
                                            "id": alert_id,
                                            "timestamp": record.token.timestamp_ms,
                                            "severity": "critical",
                                            "type": "verification_failure",
                                            "message": format!("Proof verification failed for decision {}", record.decision_id_hex),
                                            "decisionId": record.decision_id_hex,
                                            "acknowledged": false,
                                        }
                                    })
                                    .to_string(),
                                );
                            }
                        }

                        if matches!(
                            record.summary.execution_status,
                            op_api::ExecutionStatus::Failed
                        ) {
                            let alert_id = format!("execution_error:{}", record.decision_id_hex);
                            if !known_alerts.contains_key(&alert_id)
                                && !store.is_alert_acknowledged(&alert_id)
                            {
                                known_alerts.insert(alert_id.clone(), record.token.timestamp_ms);
                                let _ = tx.send(
                                    serde_json::json!({
                                        "type": "alert_raised",
                                        "alert": {
                                            "id": alert_id,
                                            "timestamp": record.token.timestamp_ms,
                                            "severity": "warning",
                                            "type": "execution_error",
                                            "message": format!("Execution failed for decision {}", record.decision_id_hex),
                                            "decisionId": record.decision_id_hex,
                                            "acknowledged": false,
                                        }
                                    })
                                    .to_string(),
                                );
                            }
                        }
                    }
                }
            }
        }

        let retention_ms = store.decision_retention_ms();
        let max_decisions = store.max_decisions();
        let max_alerts = max_decisions.map(|v| v.saturating_mul(2));
        util::prune_seen(&mut known_decisions, retention_ms, max_decisions);
        util::prune_seen(&mut known_alerts, retention_ms, max_alerts);

        tokio::time::sleep(Duration::from_millis(750)).await;
    }
}
