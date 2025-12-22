/**
 * Mock Data Hooks
 * 
 * Provides realistic mock data for development and demo purposes.
 * These will be replaced with real API hooks when the backend is ready.
 */

import { useState, useEffect } from 'react';
import type {
    SystemStatus,
    MetricsSummary,
    Alert,
    LivePipelineState,
    DecisionSummary,
    DecisionDetail,
    DecisionFilter,
    PolicySummary,
    IncidentSummary,
} from '../api/types';
import { clusterAlerts } from '../components/incidents/cluster';

// =============================================================================
// Mock Data Generators
// =============================================================================

function generateHash(): string {
    return Array.from({ length: 64 }, () =>
        Math.floor(Math.random() * 16).toString(16)
    ).join('');
}

function generateMockSystemStatus(): SystemStatus {
    return {
        overall: 'operational',
        components: {
            tau: {
                status: 'healthy',
                version: '0.7-alpha',
                lastCheck: Date.now() - 2000,
            },
            ipfs: {
                status: 'healthy',
                version: '0.18.1',
                lastCheck: Date.now() - 5000,
            },
            risc0: {
                status: 'healthy',
                version: '1.0.0',
                lastCheck: Date.now() - 1000,
                message: 'Image ID verified',
            },
            executor: {
                status: 'healthy',
                version: '1.0.0',
                lastCheck: Date.now() - 3000,
                message: 'HTTP endpoint ready',
            },
        },
    };
}

function generateMockMetrics(): MetricsSummary {
    return {
        period: {
            start: Date.now() - 24 * 60 * 60 * 1000,
            end: Date.now(),
        },
        decisions: {
            total: 1247,
            allowed: 1189,
            denied: 58,
            change: 12,
        },
        successRate: {
            value: 99.2,
            change: 0.3,
        },
        avgLatencyMs: {
            value: 340,
            change: -15,
        },
        activePolicies: 3,
    };
}

function generateMockAlerts(): Alert[] {
    return [
        {
            id: 'alert-1',
            timestamp: Date.now() - 30 * 60 * 1000,
            severity: 'critical',
            type: 'verification_failure',
            message: 'Verification failure on policy abc123... - hash mismatch detected',
            decisionId: 'dec-001',
            acknowledged: false,
        },
        {
            id: 'alert-2',
            timestamp: Date.now() - 2 * 60 * 60 * 1000,
            severity: 'warning',
            type: 'execution_error',
            message: 'Executor timeout (retry succeeded) - 35s response time',
            decisionId: 'dec-002',
            acknowledged: false,
        },
        {
            id: 'alert-3',
            timestamp: Date.now() - 5 * 60 * 60 * 1000,
            severity: 'info',
            type: 'component_down',
            message: 'IPFS node reconnected after brief outage',
            acknowledged: true,
        },
    ];
}

function generateMockPipelineState(): LivePipelineState {
    return {
        decisionId: `dec-${Date.now()}`,
        policyHash: generateHash(),
        stateHash: generateHash(),
        candidateCount: 3,
        stages: [
            { stage: 'state', status: 'complete', durationMs: 12 },
            { stage: 'propose', status: 'complete', durationMs: 89 },
            { stage: 'evaluate', status: 'complete', durationMs: 45 },
            { stage: 'select', status: 'complete', durationMs: 2 },
            { stage: 'token', status: 'active' },
            { stage: 'attest', status: 'pending' },
            { stage: 'verify', status: 'pending' },
            { stage: 'execute', status: 'pending' },
        ],
    };
}

function generateMockDecisions(count: number): DecisionSummary[] {
    const actionTypes = ['TRANSFER', 'WITHDRAW', 'APPROVE', 'STAKE', 'DELEGATE'];
    const now = Date.now();

    return Array.from({ length: count }, (_, i) => ({
        id: `dec-${now - i * 15000}`,
        timestamp: now - i * 15000,
        policyHash: generateHash(),
        actionType: actionTypes[Math.floor(Math.random() * actionTypes.length)],
        verdict: Math.random() > 0.1 ? 'allowed' as const : 'denied' as const,
        proofStatus: Math.random() > 0.02 ? 'verified' as const : 'failed' as const,
        executionStatus: Math.random() > 0.05 ? 'success' as const : 'failed' as const,
        latencyMs: Math.floor(200 + Math.random() * 400),
    }));
}

function generateMockDecisionDetail(id: string): DecisionDetail {
    const now = Date.now();
    const policyHash = generateHash();
    const stateHash = generateHash();
    const chosenActionHash = generateHash();

    return {
        id,
        timestamp: now,
        policyHash,
        actionType: 'TRANSFER',
        verdict: 'allowed',
        proofStatus: 'verified',
        executionStatus: 'success',
        latencyMs: 342,
        token: {
            policyHash,
            policyEpoch: 42,
            registryRoot: generateHash(),
            stateHash,
            chosenActionHash,
            nonceOrTxHash: generateHash(),
            timestampMs: now,
            signature: generateHash(),
        },
        proof: {
            candidateSetHash: generateHash(),
            limitsHash: generateHash(),
            receiptSize: 12456,
            verifiedAt: now,
        },
        state: {
            fields: {
                balance: 1000,
                owner: '0x123abc456def789...',
                last_action: now - 100000,
            },
            stateHash,
        },
        candidates: [
            {
                index: 0,
                actionType: 'TRANSFER',
                params: { to: '0x456...', amount: 100 },
                score: 100,
                verdict: 'allowed',
                selected: true,
                reasons: ['Within daily limit', 'Approved recipient'],
            },
            {
                index: 1,
                actionType: 'TRANSFER',
                params: { to: '0x789...', amount: 200 },
                score: 80,
                verdict: 'allowed',
                selected: false,
                reasons: ['Within daily limit'],
            },
            {
                index: 2,
                actionType: 'WITHDRAW',
                params: { amount: 500 },
                score: 50,
                verdict: 'denied',
                selected: false,
                reasons: ['Exceeds daily limit'],
            },
        ],
        executionResult: {
            success: true,
            message: 'Transfer completed successfully',
            executor: 'HttpExecutor (http://localhost:8080)',
            durationMs: 45,
        },
    };
}

function generateMockPolicies(): PolicySummary[] {
    return [
        {
            hash: generateHash(),
            name: 'Transfer Policy',
            status: 'active',
            createdAt: Date.now() - 7 * 24 * 60 * 60 * 1000,
            usageCount: 892,
        },
        {
            hash: generateHash(),
            name: 'Withdraw Policy',
            status: 'active',
            createdAt: Date.now() - 5 * 24 * 60 * 60 * 1000,
            usageCount: 234,
        },
        {
            hash: generateHash(),
            name: 'Admin Actions',
            status: 'active',
            createdAt: Date.now() - 2 * 24 * 60 * 60 * 1000,
            usageCount: 21,
        },
        {
            hash: generateHash(),
            name: 'Legacy Policy',
            status: 'deprecated',
            createdAt: Date.now() - 45 * 24 * 60 * 60 * 1000,
            usageCount: 0,
        },
    ];
}

// =============================================================================
// Hooks
// =============================================================================

export function useMockData() {
    const [loading, setLoading] = useState(true);
    const [status, setStatus] = useState<SystemStatus | null>(null);
    const [metrics, setMetrics] = useState<MetricsSummary | null>(null);
    const [alerts, setAlerts] = useState<Alert[]>([]);
    const [pipelineState, setPipelineState] = useState<LivePipelineState | null>(null);

    useEffect(() => {
        // Simulate loading
        const timer = setTimeout(() => {
            setStatus(generateMockSystemStatus());
            setMetrics(generateMockMetrics());
            setAlerts(generateMockAlerts());
            setPipelineState(generateMockPipelineState());
            setLoading(false);
        }, 500);

        return () => clearTimeout(timer);
    }, []);

    return {
        status,
        metrics,
        alerts,
        pipelineState,
        loading,
        error: null as Error | null,
        errorStatus: null as number | null,
        isOffline: false,
        refetch: async () => {},
    };
}

export function useMockDecisions(page: number, pageSize: number, filter: DecisionFilter) {
    const [loading, setLoading] = useState(true);
    const [decisions, setDecisions] = useState<DecisionSummary[]>([]);
    const [selectedDecision, setSelectedDecision] = useState<DecisionDetail | null>(null);
    const total = 1247;
    const hasMore = page * pageSize < total;
    const verifying = false;
    const lastVerifyError: string | null = null;

    useEffect(() => {
        const startTimer = setTimeout(() => setLoading(true), 0);
        const timer = setTimeout(() => {
            setDecisions(generateMockDecisions(pageSize));
            setLoading(false);
        }, 300);

        return () => {
            clearTimeout(startTimer);
            clearTimeout(timer);
        };
    }, [page, pageSize, filter]);

    function loadDecision(id: string) {
        setSelectedDecision(generateMockDecisionDetail(id));
    }

    function verifyDecision(id: string) {
        // In mock mode, "re-verify" just refreshes the mock detail.
        setSelectedDecision(generateMockDecisionDetail(id));
    }

    return {
        decisions,
        total,
        hasMore,
        loading,
        error: null as string | null,
        selectedDecision,
        loadDecision,
        verifyDecision,
        verifying,
        lastVerifyError,
    };
}

export function useMockPolicies() {
    const [loading, setLoading] = useState(true);
    const [policies, setPolicies] = useState<PolicySummary[]>([]);

    useEffect(() => {
        const timer = setTimeout(() => {
            setPolicies(generateMockPolicies());
            setLoading(false);
        }, 300);

        return () => clearTimeout(timer);
    }, []);

    return { policies, loading, error: null as string | null };
}

export function useMockAlerts() {
    const [alerts, setAlerts] = useState<Alert[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const timer = setTimeout(() => {
            setAlerts(generateMockAlerts());
            setLoading(false);
        }, 300);

        return () => clearTimeout(timer);
    }, []);

    function acknowledge(id: string) {
        setAlerts(prev => prev.map(a =>
            a.id === id ? { ...a, acknowledged: true } : a
        ));
    }

    return { alerts, loading, error: null as string | null, acknowledge };
}

export function useMockIncidents(limit = 50, unacknowledgedOnly = false, includeSnoozed = false) {
    void includeSnoozed;
    const [alerts, setAlerts] = useState<Alert[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const timer = setTimeout(() => {
            setAlerts(generateMockAlerts());
            setLoading(false);
        }, 300);

        return () => clearTimeout(timer);
    }, []);

    const incidentsAll = clusterAlerts(alerts)
        .map((inc): IncidentSummary => ({
            id: inc.id,
            severity: inc.severity,
            title: inc.title,
            primaryAlertId: inc.primary.id,
            alertIds: [inc.primary.id],
            unacked: inc.unacked,
            firstSeen: inc.firstSeen,
            lastSeen: inc.lastSeen,
            count: inc.count,
            flapping: false,
            recommendedAction: undefined,
        }))
        .filter((i) => (unacknowledgedOnly ? i.unacked : true))
        .slice(0, limit);

    function acknowledge(id: string) {
        setAlerts((prev) =>
            prev.map((a) => (a.id === id ? { ...a, acknowledged: true } : a)),
        );
    }

    function snooze(_id: string, _ttlMs: number, _reason?: string) {
        // No-op in mock mode.
        void _id;
        void _ttlMs;
        void _reason;
    }

    return {
        incidents: incidentsAll,
        loading,
        error: null as string | null,
        acknowledge,
        snooze,
        snoozeResult: null as { snoozedUntil: number } | null,
    };
}
