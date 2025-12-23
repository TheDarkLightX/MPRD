use serde::{Deserialize, Serialize};

// These mirror `tools/operator-ui/src/api/types.ts`.

pub type HashHex = String;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthLevel {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallStatus {
    Operational,
    Degraded,
    Critical,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    Local,
    Trustless,
    Private,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentHealth {
    pub status: HealthLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub last_check: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemStatus {
    pub overall: OverallStatus,
    pub components: SystemComponents,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemComponents {
    pub tau: ComponentHealth,
    pub ipfs: ComponentHealth,
    pub risc0: ComponentHealth,
    pub executor: ComponentHealth,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allowed,
    Denied,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Verified,
    Failed,
    Pending,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Success,
    Failed,
    Skipped,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionSummary {
    pub id: String,
    pub timestamp: i64,
    pub policy_hash: HashHex,
    pub action_type: String,
    pub verdict: Verdict,
    pub proof_status: ProofStatus,
    pub execution_status: ExecutionStatus,
    pub latency_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateWithVerdict {
    pub index: u32,
    pub action_type: String,
    pub params: serde_json::Value,
    pub score: i64,
    pub verdict: Verdict,
    pub selected: bool,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionToken {
    pub policy_hash: HashHex,
    pub policy_epoch: u64,
    pub registry_root: HashHex,
    pub state_hash: HashHex,
    pub chosen_action_hash: HashHex,
    pub nonce_or_tx_hash: HashHex,
    pub timestamp_ms: i64,
    pub signature: HashHex,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofBundle {
    pub candidate_set_hash: HashHex,
    pub limits_hash: HashHex,
    pub receipt_size: u64,
    pub verified_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateSnapshot {
    pub fields: serde_json::Value,
    pub state_hash: HashHex,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub executor: String,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionDetail {
    #[serde(flatten)]
    pub summary: DecisionSummary,
    pub token: DecisionToken,
    pub proof: ProofBundle,
    pub state: StateSnapshot,
    pub candidates: Vec<CandidateWithVerdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_result: Option<ExecutionResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Active,
    Deprecated,
    Invalid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySummary {
    pub hash: HashHex,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub status: PolicyStatus,
    pub created_at: i64,
    pub usage_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Critical,
    Warning,
    Info,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    VerificationFailure,
    ExecutionError,
    ComponentDown,
    Anomaly,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    pub id: String,
    pub timestamp: i64,
    pub severity: AlertSeverity,
    #[serde(rename = "type")]
    pub alert_type: AlertType,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    pub acknowledged: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustAnchors {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_state_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_key_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_key_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorSettings {
    pub version: String,
    pub deployment_mode: DeploymentMode,
    pub api_key_required: bool,
    pub insecure_demo_enabled: bool,
    pub store_dir: String,
    pub policy_dir: String,
    pub store_sensitive_enabled: bool,
    pub decision_retention_days: u64,
    pub decision_max: u64,
    pub trust_anchors_configured: bool,
    pub trust_anchors: TrustAnchors,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorSettingsUpdate {
    #[serde(default)]
    pub decision_retention_days: Option<u64>,
    #[serde(default)]
    pub decision_max: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionPruneResult {
    pub removed: u64,
    pub now_ms: i64,
    pub decision_retention_days: u64,
    pub decision_max: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionExport {
    pub decision_id: String,
    pub record_url: String,
    pub receipt_url: String,
    pub limits_url: String,
    pub chosen_action_preimage_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricsSummary {
    pub period: MetricsPeriod,
    pub decisions: DecisionsMetrics,
    pub success_rate: MetricWithChange,
    pub avg_latency_ms: MetricWithChangeU64,
    pub active_policies: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricsPeriod {
    pub start: i64,
    pub end: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionsMetrics {
    pub total: u64,
    pub allowed: u64,
    pub denied: u64,
    pub change: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricWithChange {
    pub value: f64,
    pub change: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricWithChangeU64 {
    pub value: u64,
    pub change: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub page: u32,
    pub page_size: u32,
    pub total: u64,
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDetail {
    #[serde(flatten)]
    pub summary: PolicySummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_errors: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyHashResponse {
    pub hash: HashHex,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionRisk {
    Safe,
    RequiresConfirmation,
    Dangerous,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuggestedAction {
    pub id: String,
    pub title: String,
    pub risk: ActionRisk,
    pub dry_run_supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runbook_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentSummary {
    pub id: String,
    pub severity: AlertSeverity,
    pub title: String,
    pub primary_alert_id: String,
    pub alert_ids: Vec<String>,
    pub unacked: bool,
    pub first_seen: i64,
    pub last_seen: i64,
    pub count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flapping: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_action: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentDetail {
    #[serde(flatten)]
    pub summary: IncidentSummary,
    pub alerts: Vec<Alert>,
    #[serde(default)]
    pub actions: Vec<SuggestedAction>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnoozeRequest {
    pub ttl_ms: u64,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnoozeResult {
    pub snoozed_until: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionRunRequest {
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionRunResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_id: Option<String>,
}

// =============================================================================
// Autopilot & Attention Types (Algorithms 10-11)
// =============================================================================

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AutopilotMode {
    Manual,
    Assisted,
    Autopilot,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoActionType {
    AutoDismiss,
    AutoCorrelate,
    AutoExecute,
    AutoDegrade,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Explanation {
    pub summary: String,
    pub evidence: String,
    pub confidence: f64,
    pub counterfactual: String,
    pub audit_id: String,
    pub timestamp: i64,
    pub operator_can_override: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoAction {
    pub id: String,
    #[serde(rename = "type")]
    pub action_type: AutoActionType,
    pub target: String,
    pub timestamp: i64,
    pub explanation: Explanation,
    pub reversible: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutopilotState {
    pub mode: AutopilotMode,
    pub last_human_ack: i64,
    pub pending_review_count: u32,
    pub auto_handled_24h: u32,
    pub can_transition_to: Vec<AutopilotMode>,
}
