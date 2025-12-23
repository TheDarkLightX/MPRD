/**
 * MPRD Operator UI - API Types
 * 
 * These types mirror the backend API responses and follow the spec from operator_ui_ux_spec.md
 * 
 * @invariant All hash fields are 64-character hex strings
 * @invariant All timestamp fields are Unix milliseconds
 */

// =============================================================================
// Health & Status Types
// =============================================================================

export type HealthLevel = 'healthy' | 'degraded' | 'unavailable';
export type OverallStatus = 'operational' | 'degraded' | 'critical';

export interface ComponentHealth {
    status: HealthLevel;
    version?: string;
    lastCheck: number; // Unix ms
    message?: string;
}

export interface SystemStatus {
    overall: OverallStatus;
    components: {
        tau: ComponentHealth;
        ipfs: ComponentHealth;
        risc0: ComponentHealth;
        executor: ComponentHealth;
    };
}

// =============================================================================
// Decision Types
// =============================================================================

export type Verdict = 'allowed' | 'denied';
export type ProofStatus = 'verified' | 'failed' | 'pending';
export type ExecutionStatus = 'success' | 'failed' | 'skipped';

export interface DecisionSummary {
    id: string;
    timestamp: number; // Unix ms
    policyHash: string;
    actionType: string;
    verdict: Verdict;
    proofStatus: ProofStatus;
    executionStatus: ExecutionStatus;
    latencyMs: number;
}

export interface CandidateWithVerdict {
    index: number;
    actionType: string;
    params: Record<string, unknown>;
    score: number;
    verdict: Verdict;
    selected: boolean;
    reasons: string[];
}

export interface DecisionToken {
    policyHash: string;
    policyEpoch: number;
    registryRoot: string;
    stateHash: string;
    chosenActionHash: string;
    nonceOrTxHash: string;
    timestampMs: number;
    signature: string;
}

export interface ProofBundle {
    candidateSetHash: string;
    limitsHash: string;
    receiptSize: number;
    verifiedAt: number;
}

export interface StateSnapshot {
    fields: Record<string, unknown>;
    stateHash: string;
}

export interface ExecutionResult {
    success: boolean;
    message?: string;
    executor: string;
    durationMs: number;
}

export interface DecisionDetail extends DecisionSummary {
    token: DecisionToken;
    proof: ProofBundle;
    state: StateSnapshot;
    candidates: CandidateWithVerdict[];
    executionResult?: ExecutionResult;
}

// =============================================================================
// Policy Types
// =============================================================================

export type PolicyStatus = 'active' | 'deprecated' | 'invalid';

export interface PolicySummary {
    hash: string;
    name?: string;
    status: PolicyStatus;
    createdAt: number;
    usageCount: number;
}

export interface PolicyDetail extends PolicySummary {
    spec?: string; // Tau specification content
    validationErrors?: string[];
}

// =============================================================================
// Alert Types
// =============================================================================

export type AlertSeverity = 'critical' | 'warning' | 'info';
export type AlertType = 'verification_failure' | 'execution_error' | 'component_down' | 'anomaly';

export interface Alert {
    id: string;
    timestamp: number;
    severity: AlertSeverity;
    type: AlertType;
    message: string;
    decisionId?: string;
    acknowledged: boolean;
}

// =============================================================================
// Metrics Types
// =============================================================================

export interface MetricsSummary {
    period: {
        start: number;
        end: number;
    };
    decisions: {
        total: number;
        allowed: number;
        denied: number;
        change: number; // percentage vs previous period
    };
    successRate: {
        value: number;
        change: number;
    };
    avgLatencyMs: {
        value: number;
        change: number;
    };
    activePolicies: number;
}

// =============================================================================
// Pipeline Types (for live visualization)
// =============================================================================

export type PipelineStage =
    | 'state'
    | 'propose'
    | 'evaluate'
    | 'select'
    | 'token'
    | 'attest'
    | 'verify'
    | 'execute';

export type StageStatus = 'pending' | 'active' | 'complete' | 'failed';

export interface PipelineStageInfo {
    stage: PipelineStage;
    status: StageStatus;
    durationMs?: number;
    error?: string;
}

export interface LivePipelineState {
    decisionId?: string;
    policyHash?: string;
    stateHash?: string;
    candidateCount?: number;
    stages: PipelineStageInfo[];
    startedAt?: number;
}

export type PipelineEventType =
    | 'stage_started'
    | 'stage_completed'
    | 'decision_completed'
    | 'alert_raised';

export interface PipelineEvent {
    type: PipelineEventType;
    decisionId?: string;
    policyHash?: string;
    stateHash?: string;
    candidateCount?: number;
    verdict?: string;
    proofStatus?: string;
    executionStatus?: string;
    stage?: string;
    durationMs?: number;
    error?: string;
    alert?: Alert;
}

export type PipelineEventHandler = (event: PipelineEvent) => void;

// =============================================================================
// API Request/Response Types
// =============================================================================

export interface PaginatedResponse<T> {
    data: T[];
    page: number;
    pageSize: number;
    total: number;
    hasMore: boolean;
}

export interface DecisionFilter {
    startDate?: number;
    endDate?: number;
    policyHash?: string;
    actionType?: string;
    verdict?: Verdict;
    proofStatus?: ProofStatus;
    executionStatus?: ExecutionStatus;
    query?: string;
}

// =============================================================================
// Operator Settings / Trust Anchors
// =============================================================================

export interface TrustAnchors {
    registryStatePath?: string;
    registryKeyFingerprint?: string;
    manifestKeyFingerprint?: string;
}

export interface OperatorSettings {
    version: string;
    deploymentMode: DeploymentMode;
    apiKeyRequired: boolean;
    insecureDemoEnabled: boolean;
    storeDir: string;
    policyDir: string;
    storeSensitiveEnabled: boolean;
    decisionRetentionDays: number;
    decisionMax: number;
    trustAnchorsConfigured: boolean;
    trustAnchors: TrustAnchors;
}

export interface OperatorSettingsUpdate {
    decisionRetentionDays?: number;
    decisionMax?: number;
}

export interface RetentionPruneResult {
    removed: number;
    nowMs: number;
    decisionRetentionDays: number;
    decisionMax: number;
}

export interface DecisionExport {
    decisionId: string;
    recordUrl: string;
    receiptUrl: string;
    limitsUrl: string;
    chosenActionPreimageUrl: string;
}

// =============================================================================
// Autopilot & Attention Types (Algorithms 5, 10-12)
// =============================================================================

export type AutopilotMode = 'manual' | 'assisted' | 'autopilot';
export type Severity = 'critical' | 'warning' | 'info' | 'ok';
export type TrendDirection = 'up' | 'down' | 'stable';
export type DeploymentMode = 'local' | 'trustless' | 'private';

export interface AutopilotState {
    mode: AutopilotMode;
    lastHumanAck: number;  // Unix timestamp ms
    pendingReviewCount: number;
    autoHandled24h: number;
    canTransitionTo: AutopilotMode[];
}

export interface AttentionDemand {
    itemsNeedingAction: number;
    estimatedMinutes: number;
    withinBudget: boolean;
    trend: TrendDirection;
}

export interface PrescriptiveAction {
    label: string;
    route: string;
    urgency: Severity;
    estimatedTimeMinutes: number;
}

export interface TrendSet {
    decisions: TrendDirection;
    success: TrendDirection;
    latency: TrendDirection;
    autopilotActivity?: number[]; // Sparkline data (bins)
}

export interface AutopilotBadge {
    mode: AutopilotMode;
    autoHandled24h: number;
    pendingReview: number;
    nextAckRequired: number; // Unix timestamp ms
}

export interface GlanceableView {
    headline: string;
    headlineSeverity: Severity;
    trendNarrative: string; // v1.2 requirement
    attentionDemand: AttentionDemand;
    nextAction: PrescriptiveAction | null;
    trends: TrendSet;
    autopilotBadge: AutopilotBadge | null;
}

// =============================================================================
// Explainability Types (Algorithm 11)
// =============================================================================

export type AutoActionType = 'auto_dismiss' | 'auto_correlate' | 'auto_execute' | 'auto_degrade';

export interface Explanation {
    summary: string;
    evidence: string;
    confidence: number;  // 0-1
    counterfactual: string;
    auditId: string;
    timestamp: number;
    operatorCanOverride: boolean;
}

export interface AutoAction {
    id: string;
    type: AutoActionType;
    target: string;
    timestamp: number;
    explanation: Explanation;
    reversible: boolean;
}

// =============================================================================
// Security Posture Types (Algorithms 1, 2)
// =============================================================================

export type TrustLevel = 'critical' | 'degraded' | 'healthy';
export type AvailabilityLevel = 'critical' | 'degraded' | 'healthy';

export interface SecurityPosture {
    trustLevel: TrustLevel;
    availabilityLevel: AvailabilityLevel;
    reasons: string[];
    metrics: {
        failRate: number;
        verifyFailRate: number;
        execFailRate: number;
        decisionRate: number; // per minute
    };
}

export type DisclosurePolicy =
    | 'HashFirstStrict'
    | 'HashFirstWithTimedReveal'
    | 'HashFirstWithTimedRevealAndRedaction';

export interface UIRenderConfig {
    visibleSections: string[];
    disabledActions: string[];
    warnings: string[];
    disclosurePolicy: DisclosurePolicy;
}

// =============================================================================
// Incident Extended Types (Algorithm 4)
// =============================================================================

export type IncidentState = 'open' | 'acknowledged' | 'snoozed' | 'resolved';

export interface IncidentExtended {
    id: string;
    severity: AlertSeverity;
    title: string;
    count: number;
    unacked: boolean;
    firstSeen: number;
    lastSeen: number;
    primary: Alert;
    state: IncidentState;
    flapping: boolean;
    priority: number;
}

export interface IncidentSummary {
    id: string;
    severity: AlertSeverity;
    title: string;
    primaryAlertId: string;
    alertIds: string[];
    unacked: boolean;
    firstSeen: number;
    lastSeen: number;
    count: number;
    flapping?: boolean;
    recommendedAction?: string;
}

export interface IncidentDetail {
    summary: IncidentSummary;
    alerts: Alert[];
}

export type IncidentActionRisk = 'safe' | 'requires_confirmation' | 'dangerous';

export interface IncidentSuggestedAction {
    id: string;
    title: string;
    risk: IncidentActionRisk;
    dryRunSupported: boolean;
    runbookUrl?: string;
}

export interface IncidentDetailWithActions {
    summary: IncidentSummary;
    alerts: Alert[];
    actions: IncidentSuggestedAction[];
}

export interface SnoozeRequest {
    ttlMs: number;
    reason?: string;
}

export interface SnoozeResult {
    snoozedUntil: number;
}

// =============================================================================
// Attention Budget Types (Algorithm 5)
// =============================================================================

export interface AttentionBudgetResult {
    banner: string | null;
    bannerSeverity: Severity | null;
    toasts: string[];
    badgeCounts: {
        incidentsUnacked: number;
        alertsTotal: number;
        verifyFailures24h: number;
    };
    workQueue: IncidentExtended[];
    digests: string[];
}

// =============================================================================
// Autopilot WebSocket Events (Algorithm 10)
// =============================================================================

export type AutopilotEvent =
    | { type: 'mode_changed'; from: AutopilotMode; to: AutopilotMode; reason: string }
    | { type: 'auto_action'; actionId: string; explanation: Explanation }
    | { type: 'ack_warning'; minutesUntilDegrade: number }
    | { type: 'attention_budget_warning'; activeCritical: number; budget: number };

// =============================================================================
// Suggested Actions Types (Algorithm 8)
// =============================================================================

export type ActionRisk = 'low' | 'medium' | 'high';

export interface SuggestedAction {
    id: string;
    label: string;
    description: string;
    risk: ActionRisk;
    dryRun: boolean;
    requiresConfirmation: boolean;
    runbookLink?: string;
    estimatedTimeSeconds: number;
}
