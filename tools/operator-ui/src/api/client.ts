/**
 * MPRD Operator UI - API Client
 * 
 * Provides a type-safe interface to the MPRD backend API.
 * All methods handle errors consistently and return typed responses.
 * 
 * @precondition API_BASE_URL must be configured
 * @postcondition All returned data matches the declared types
 */

import type {
  SystemStatus,
  DecisionSummary,
  DecisionDetail,
  DecisionFilter,
  PolicySummary,
  Alert,
  MetricsSummary,
  PaginatedResponse,
  OperatorSettings,
  OperatorSettingsUpdate,
  RetentionPruneResult,
  DecisionExport,
  IncidentSummary,
  IncidentDetailWithActions,
  SnoozeRequest,
  SnoozeResult,
  AutopilotState,
  AutopilotMode,
  AutoAction,
  PipelineEvent,
  PipelineEventHandler,
} from './types';

// =============================================================================
// Configuration
// =============================================================================

import { getApiBaseUrl, getApiKey } from '../config';

// =============================================================================
// Error Handling
// =============================================================================

export class ApiError extends Error {
    public status: number;
    public code?: string;

    constructor(
        message: string,
        status: number,
        code?: string
    ) {
        super(message);
        this.name = 'ApiError';
        this.status = status;
        this.code = code;
    }
}

function toNetworkApiError(err: unknown): ApiError {
    const message =
        err instanceof Error && err.name === 'AbortError'
            ? 'Request aborted'
            : 'Backend unreachable (network error)';
    return new ApiError(message, 0, 'NETWORK_ERROR');
}

async function safeFetch(url: string, init?: RequestInit): Promise<Response> {
    try {
        return await fetch(url, init);
    } catch (e) {
        throw toNetworkApiError(e);
    }
}

async function handleResponse<T>(response: Response): Promise<T> {
    if (!response.ok) {
        const errorBody = await response.text();
        let message = `API Error: ${response.status}`;
        let code: string | undefined;

        try {
            const parsed = JSON.parse(errorBody);
            message = parsed.message || message;
            code = parsed.code;
        } catch {
            message = errorBody || message;
        }

        throw new ApiError(message, response.status, code);
    }

    // Avoid throwing on empty bodies (common for 204 or some POST endpoints).
    if (response.status === 204) {
        return undefined as T;
    }

    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
        const text = await response.text();
        if (!text.trim()) return undefined as T;
        try {
            return JSON.parse(text) as T;
        } catch {
            throw new ApiError('Backend returned invalid JSON', response.status, 'INVALID_JSON');
        }
    }

    // Best-effort fallback for non-JSON responses.
    const text = await response.text();
    return text as unknown as T;
}

function buildHeaders(): HeadersInit {
    const headers: HeadersInit = {
        'Content-Type': 'application/json',
    };

    const apiKey = getApiKey();
    if (apiKey) {
        headers['X-API-Key'] = apiKey;
    }

    return headers;
}

// =============================================================================
// API Client
// =============================================================================

export const apiClient = {
    async getHealth(): Promise<{ status: string; version: string }> {
        const response = await safeFetch(`${getApiBaseUrl()}/health`, {
            headers: { 'Content-Type': 'application/json' },
        });
        return handleResponse<{ status: string; version: string }>(response);
    },

    /**
     * Get system health status.
     * 
     * @returns SystemStatus with component health indicators
     */
    async getStatus(): Promise<SystemStatus> {
        const response = await safeFetch(`${getApiBaseUrl()}/api/status`, {
            headers: buildHeaders(),
        });
        return handleResponse<SystemStatus>(response);
    },

    /**
     * Get operator settings and trust anchors.
     */
    async getSettings(): Promise<OperatorSettings> {
        const response = await safeFetch(`${getApiBaseUrl()}/api/settings`, {
            headers: buildHeaders(),
        });
        return handleResponse<OperatorSettings>(response);
    },

    /**
     * Update operator settings (retention and limits).
     */
    async updateSettings(update: OperatorSettingsUpdate): Promise<OperatorSettings> {
        const response = await safeFetch(`${getApiBaseUrl()}/api/settings`, {
            method: 'POST',
            headers: buildHeaders(),
            body: JSON.stringify(update),
        });
        return handleResponse<OperatorSettings>(response);
    },

    /**
     * Trigger an immediate retention prune.
     */
    async pruneDecisions(): Promise<RetentionPruneResult> {
        const response = await safeFetch(`${getApiBaseUrl()}/api/settings/prune`, {
            method: 'POST',
            headers: buildHeaders(),
        });
        return handleResponse<RetentionPruneResult>(response);
    },

    // -------------------------------------------------------------------------
    // Autopilot
    // -------------------------------------------------------------------------

    async getAutopilot(): Promise<AutopilotState> {
        const response = await safeFetch(`${getApiBaseUrl()}/api/autopilot`, {
            headers: buildHeaders(),
        });
        return handleResponse<AutopilotState>(response);
    },

    async setAutopilotMode(mode: AutopilotMode, reason?: string): Promise<AutopilotState> {
        const response = await safeFetch(`${getApiBaseUrl()}/api/autopilot/mode`, {
            method: 'POST',
            headers: buildHeaders(),
            body: JSON.stringify({ mode, reason }),
        });
        return handleResponse<AutopilotState>(response);
    },

    async ackAutopilot(): Promise<AutopilotState> {
        const response = await safeFetch(`${getApiBaseUrl()}/api/autopilot/ack`, {
            method: 'POST',
            headers: buildHeaders(),
        });
        return handleResponse<AutopilotState>(response);
    },

    async listAutopilotActivity(limit = 50): Promise<AutoAction[]> {
        const params = new URLSearchParams({ limit: String(limit) });
        const response = await safeFetch(`${getApiBaseUrl()}/api/autopilot/activity?${params}`, {
            headers: buildHeaders(),
        });
        return handleResponse<AutoAction[]>(response);
    },

    /**
     * List decisions with pagination and optional filters.
     * 
     * @param page - 1-indexed page number
     * @param pageSize - Number of items per page (default: 50)
     * @param filter - Optional filter criteria
     */
    async listDecisions(
        page = 1,
        pageSize = 50,
        filter?: DecisionFilter
    ): Promise<PaginatedResponse<DecisionSummary>> {
        const params = new URLSearchParams({
            page: String(page),
            pageSize: String(pageSize),
        });

        if (filter) {
            if (filter.startDate) params.set('startDate', String(filter.startDate));
            if (filter.endDate) params.set('endDate', String(filter.endDate));
            if (filter.policyHash) params.set('policyHash', filter.policyHash);
            if (filter.actionType) params.set('actionType', filter.actionType);
            if (filter.verdict) params.set('verdict', filter.verdict);
            if (filter.proofStatus) params.set('proofStatus', filter.proofStatus);
            if (filter.executionStatus) params.set('executionStatus', filter.executionStatus);
            if (filter.query) params.set('q', filter.query);
        }

        const response = await safeFetch(`${getApiBaseUrl()}/api/decisions?${params}`, {
            headers: buildHeaders(),
        });
        return handleResponse<PaginatedResponse<DecisionSummary>>(response);
    },

    /**
     * Get full decision detail by ID.
     * 
     * @param id - Decision ID
     */
    async getDecision(id: string): Promise<DecisionDetail> {
        const response = await safeFetch(`${getApiBaseUrl()}/api/decisions/${encodeURIComponent(id)}`, {
            headers: buildHeaders(),
        });
        return handleResponse<DecisionDetail>(response);
    },

    /**
     * Get export URLs for a decision.
     */
    async getDecisionExport(id: string): Promise<DecisionExport> {
        const response = await safeFetch(`${getApiBaseUrl()}/api/decisions/${encodeURIComponent(id)}/export`, {
            headers: buildHeaders(),
        });
        return handleResponse<DecisionExport>(response);
    },

    /**
     * Download a decision blob (record.json, receipt.bin, etc.) as a Blob.
     */
    async downloadDecisionBlob(id: string, name: string): Promise<Blob> {
        const response = await safeFetch(
            `${getApiBaseUrl()}/api/decisions/${encodeURIComponent(id)}/blob/${encodeURIComponent(name)}`,
            { headers: buildHeaders() },
        );
        if (!response.ok) {
            throw new ApiError(`API Error: ${response.status}`, response.status);
        }
        return response.blob();
    },

    /**
     * Re-verify a decision's proof.
     * 
     * @param id - Decision ID
     * @returns Verification result
     */
    async verifyDecision(id: string): Promise<{ verified: boolean; error?: string }> {
        const response = await safeFetch(`${getApiBaseUrl()}/api/decisions/${encodeURIComponent(id)}/verify`, {
            method: 'POST',
            headers: buildHeaders(),
        });
        return handleResponse(response);
    },

    /**
     * List policies.
     */
    async listPolicies(): Promise<PolicySummary[]> {
        const response = await safeFetch(`${getApiBaseUrl()}/api/policies`, {
            headers: buildHeaders(),
        });
        return handleResponse<PolicySummary[]>(response);
    },

    /**
     * List alerts.
     * 
     * @param limit - Maximum number of alerts to return
     * @param unacknowledgedOnly - Only return unacknowledged alerts
     */
    async listAlerts(limit = 50, unacknowledgedOnly = false): Promise<Alert[]> {
        const params = new URLSearchParams({
            limit: String(limit),
        });
        if (unacknowledgedOnly) {
            params.set('unacknowledged', 'true');
        }

        const response = await safeFetch(`${getApiBaseUrl()}/api/alerts?${params}`, {
            headers: buildHeaders(),
        });
        return handleResponse<Alert[]>(response);
    },

    /**
     * Acknowledge an alert.
     * 
     * @param id - Alert ID
     */
    async acknowledgeAlert(id: string): Promise<void> {
        const response = await safeFetch(`${getApiBaseUrl()}/api/alerts/${encodeURIComponent(id)}/acknowledge`, {
            method: 'POST',
            headers: buildHeaders(),
        });
        await handleResponse(response);
    },

    /**
     * List incidents (grouped alerts).
     *
     * @param limit - Max number of incidents (clamped server-side)
     * @param unacknowledgedOnly - Only return incidents that have unacked alerts
     * @param includeSnoozed - Include snoozed incidents
     */
    async listIncidents(
        limit = 50,
        unacknowledgedOnly = false,
        includeSnoozed = false
    ): Promise<IncidentSummary[]> {
        const params = new URLSearchParams({
            limit: String(limit),
        });
        if (unacknowledgedOnly) {
            params.set('unacknowledged', 'true');
        }
        if (includeSnoozed) {
            params.set('includeSnoozed', 'true');
        }

        const response = await safeFetch(`${getApiBaseUrl()}/api/incidents?${params}`, {
            headers: buildHeaders(),
        });
        return handleResponse<IncidentSummary[]>(response);
    },

    /**
     * Get incident detail (alerts + suggested actions).
     */
    async getIncident(id: string): Promise<IncidentDetailWithActions> {
        const response = await safeFetch(`${getApiBaseUrl()}/api/incidents/${encodeURIComponent(id)}`, {
            headers: buildHeaders(),
        });
        return handleResponse<IncidentDetailWithActions>(response);
    },

    /**
     * Acknowledge an incident (acks all included alerts + clears snooze).
     */
    async acknowledgeIncident(id: string): Promise<void> {
        const response = await safeFetch(`${getApiBaseUrl()}/api/incidents/${encodeURIComponent(id)}/acknowledge`, {
            method: 'POST',
            headers: buildHeaders(),
        });
        await handleResponse(response);
    },

    /**
     * Snooze an incident.
     */
    async snoozeIncident(id: string, request: SnoozeRequest): Promise<SnoozeResult> {
        const response = await safeFetch(`${getApiBaseUrl()}/api/incidents/${encodeURIComponent(id)}/snooze`, {
            method: 'POST',
            headers: buildHeaders(),
            body: JSON.stringify(request),
        });
        return handleResponse<SnoozeResult>(response);
    },

    /**
     * Get metrics summary for the dashboard.
     */
    async getMetrics(): Promise<MetricsSummary> {
        const response = await safeFetch(`${getApiBaseUrl()}/api/metrics`, {
            headers: buildHeaders(),
        });
        return handleResponse<MetricsSummary>(response);
    },
};

// =============================================================================
// WebSocket Client for Live Pipeline
// =============================================================================

export function createPipelineWebSocket(onEvent: PipelineEventHandler): WebSocket | null {
    const baseHttp = getApiBaseUrl();
    const baseWs = baseHttp.replace(/^http/, 'ws') + '/api/live';
    const apiKey = getApiKey();
    const wsUrl = apiKey ? `${baseWs}?api_key=${encodeURIComponent(apiKey)}` : baseWs;

    try {
        const ws = new WebSocket(wsUrl);

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data) as PipelineEvent;
                onEvent(data);
            } catch (e) {
                console.error('Failed to parse pipeline event:', e);
            }
        };

        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };

        return ws;
    } catch (e) {
        console.error('Failed to create WebSocket:', e);
        return null;
    }
}

export type { PipelineEvent, PipelineEventHandler } from './types';
