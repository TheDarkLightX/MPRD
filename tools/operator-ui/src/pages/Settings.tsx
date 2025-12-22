/**
 * Settings Page
 * 
 * Configuration view and component paths.
 * Per spec Section 4 (Information Architecture).
 * Enhanced with Autopilot mode controls.
 */

import { useEffect, useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Card, CardHeader } from '../components/ui';
import { apiClient } from '../api/client';
import { clearApiConfig, getApiBaseUrl, getApiKey, normalizeApiBaseUrl, setApiConfig, USE_MOCK_DATA } from '../config';
import { useAutopilot } from '../context/AutopilotContext';
import { AutopilotStatusBadge, ModeTransitionModal } from '../components/autopilot';
import { CheckCircle, XCircle, AlertTriangle, Zap, User, Bot } from 'lucide-react';
import type { AutopilotMode, SecurityPosture, IncidentExtended, OperatorSettingsUpdate } from '../api/types';

// Precondition check display
function PreconditionItem({ label, met }: { label: string; met: boolean }) {
    return (
        <div className="flex items-center gap-2 text-sm">
            {met ? (
                <CheckCircle className="w-4 h-4 text-healthy" />
            ) : (
                <XCircle className="w-4 h-4 text-critical" />
            )}
            <span className={met ? 'text-dark-300' : 'text-gray-100'}>{label}</span>
        </div>
    );
}

// Mode button component
function ModeButton({
    mode,
    currentMode,
    onClick,
    disabled,
}: {
    mode: AutopilotMode;
    currentMode: AutopilotMode;
    onClick: () => void;
    disabled: boolean;
}) {
    const isActive = mode === currentMode;
    const config = {
        manual: { icon: User, label: 'Manual', desc: 'All decisions require human action' },
        assisted: { icon: Zap, label: 'Assisted', desc: 'Auto-correlate, suggest actions' },
        autopilot: { icon: Bot, label: 'Autopilot', desc: 'Auto-dismiss, auto-execute low-risk' },
    };
    const { icon: Icon, label, desc } = config[mode];

    return (
        <button
            type="button"
            onClick={onClick}
            disabled={disabled || isActive}
            className={`mode-button flex-1 p-4 rounded-lg border transition-all ${isActive
                ? 'mode-button-active bg-accent-500/10 border-accent-500/50 ring-2 ring-accent-500/30'
                : disabled
                    ? 'mode-button-disabled bg-dark-800/50 border-dark-700 opacity-50 cursor-not-allowed'
                    : 'mode-button-inactive bg-dark-800/50 border-dark-700 hover:border-dark-600 hover:bg-dark-800'
                }`}
        >
            <div className="flex items-center gap-2 mb-2">
                <Icon className={`w-5 h-5 ${isActive ? 'text-accent-400' : 'text-dark-400'}`} />
                <span className={`font-medium ${isActive ? 'text-accent-400' : 'text-gray-100'}`}>
                    {label}
                </span>
            </div>
            <p className="text-xs text-dark-400 text-left">{desc}</p>
        </button>
    );
}

export function SettingsPage() {
    const [modalOpen, setModalOpen] = useState(false);
    const [targetMode, setTargetMode] = useState<AutopilotMode>('manual');
    const [violations, setViolations] = useState<string[]>([]);
    const [apiBaseUrl, setApiBaseUrlState] = useState(() => getApiBaseUrl());
    const [apiKey, setApiKeyState] = useState(() => getApiKey());
    const [now, setNow] = useState<number>(() => Date.now());
    const [retentionDaysDraft, setRetentionDaysDraft] = useState<string | null>(null);
    const [decisionMaxDraft, setDecisionMaxDraft] = useState<string | null>(null);
    const [retentionStatus, setRetentionStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
    const [pruneStatus, setPruneStatus] = useState<'idle' | 'pruning' | 'done' | 'error'>('idle');
    const [prunedCount, setPrunedCount] = useState<number | null>(null);
    const [connTest, setConnTest] = useState<{
        status: 'idle' | 'testing' | 'ok' | 'error';
        healthOk?: boolean;
        apiOk?: boolean;
        message?: string;
        suggestion?: string;
    }>({ status: 'idle' });

    const { state: autopilotState, requestModeTransition, checkModeTransition, recentActions } = useAutopilot();

    useEffect(() => {
        const interval = window.setInterval(() => setNow(Date.now()), 60_000);
        return () => window.clearInterval(interval);
    }, []);

    const settingsQuery = useQuery({
        queryKey: ['settings'],
        queryFn: () => apiClient.getSettings(),
        enabled: !USE_MOCK_DATA,
        refetchInterval: 10_000,
    });

    const settings = settingsQuery.data ?? null;
    const retentionDays = retentionDaysDraft ?? String(settings?.decisionRetentionDays ?? 0);
    const decisionMax = decisionMaxDraft ?? String(settings?.decisionMax ?? 0);

    useEffect(() => {
        if (pruneStatus !== 'done') return;
        const t = window.setTimeout(() => setPruneStatus('idle'), 3000);
        return () => window.clearTimeout(t);
    }, [pruneStatus]);

    // Mock security posture and incidents for demo
    const mockPosture: SecurityPosture = useMemo(() => ({
        trustLevel: 'healthy',
        availabilityLevel: 'healthy',
        reasons: [],
        metrics: { failRate: 0.01, verifyFailRate: 0.005, execFailRate: 0.005, decisionRate: 2.5 },
    }), []);

    const mockIncidents: IncidentExtended[] = [];

    const handleModeClick = (mode: AutopilotMode) => {
        if (mode === autopilotState.mode) return;
        setTargetMode(mode);

        // Check preconditions before showing modal (preview only, no transition yet)
        const result = checkModeTransition(mode, mockPosture, mockIncidents);
        if (!result.success) {
            setViolations(result.violations ?? [result.error ?? 'Unknown error']);
        } else {
            setViolations([]);
        }
        setModalOpen(true);
    };

    const handleConfirm = () => {
        // Actually perform the transition
        const result = requestModeTransition(targetMode, mockPosture, mockIncidents);
        if (result.success) {
            setModalOpen(false);
        }
    };

    const handleRetentionSave = async () => {
        if (USE_MOCK_DATA) return;
        const update: OperatorSettingsUpdate = {};
        const days = Number.parseInt(retentionDays, 10);
        const max = Number.parseInt(decisionMax, 10);
        if (!Number.isNaN(days)) {
            update.decisionRetentionDays = Math.max(0, days);
        }
        if (!Number.isNaN(max)) {
            update.decisionMax = Math.max(0, max);
        }
        if (update.decisionRetentionDays === undefined && update.decisionMax === undefined) {
            return;
        }
        setRetentionStatus('saving');
        try {
            await apiClient.updateSettings(update);
            await settingsQuery.refetch();
            setRetentionStatus('saved');
            setRetentionDaysDraft(null);
            setDecisionMaxDraft(null);
        } catch {
            setRetentionStatus('error');
        }
    };

    const handlePruneNow = async () => {
        if (USE_MOCK_DATA) return;
        setPruneStatus('pruning');
        try {
            const result = await apiClient.pruneDecisions();
            setPrunedCount(result.removed);
            setPruneStatus('done');
            await settingsQuery.refetch();
        } catch {
            setPruneStatus('error');
        }
    };

    // Preconditions status
    const preconditions = [
        { label: 'Trust anchors configured', met: mockPosture.trustLevel !== 'critical' },
        { label: 'Verification failure rate < 5%', met: mockPosture.metrics.verifyFailRate < 0.05 },
        { label: 'No unacked critical incidents', met: mockIncidents.filter(i => i.severity === 'critical' && i.unacked).length === 0 },
        { label: 'Recent human acknowledgment', met: now - autopilotState.lastHumanAck < 4 * 60 * 60 * 1000 },
    ];

    return (
        <div className="space-y-6">
            {/* Page header */}
            <div>
                <h1 className="text-2xl font-bold text-gray-100">Settings</h1>
                <p className="text-dark-400">Configuration and component paths</p>
            </div>

            {/* Autopilot Mode */}
            <Card className="relative overflow-hidden">
                <div className="absolute top-0 right-0 p-4">
                    <AutopilotStatusBadge mode={autopilotState.mode} pendingReview={autopilotState.pendingReviewCount} />
                </div>
                <CardHeader
                    title="Autopilot Mode"
                    subtitle="Control automation level for incident handling"
                />

                {/* Mode selector */}
                <div className="flex gap-3 mb-4">
                    <ModeButton mode="manual" currentMode={autopilotState.mode} onClick={() => handleModeClick('manual')} disabled={false} />
                    <ModeButton mode="assisted" currentMode={autopilotState.mode} onClick={() => handleModeClick('assisted')} disabled={false} />
                    <ModeButton mode="autopilot" currentMode={autopilotState.mode} onClick={() => handleModeClick('autopilot')} disabled={autopilotState.mode === 'manual'} />
                </div>

                {/* Preconditions for Autopilot */}
                <div className="p-3 rounded-lg bg-dark-800/50 border border-dark-700">
                    <div className="flex items-center gap-2 mb-2">
                        <AlertTriangle className="w-4 h-4 text-degraded" />
                        <span className="text-sm font-medium text-gray-100">Autopilot Preconditions</span>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                        {preconditions.map((p) => (
                            <PreconditionItem key={p.label} label={p.label} met={p.met} />
                        ))}
                    </div>
                </div>

                {/* Recent activity */}
                {recentActions.length > 0 && (
                    <div className="mt-4 pt-4 border-t border-dark-700">
                        <p className="text-sm text-dark-400 mb-2">Recent auto-actions: {recentActions.length} in last 24h</p>
                    </div>
                )}
            </Card>

            {/* Configuration */}
            <Card>
                <CardHeader
                    title="Configuration"
                    subtitle="Current MPRD configuration"
                />
                <div className="space-y-3">
                    <div className="flex items-center justify-between py-2 border-b border-dark-700">
                        <span className="text-dark-400">API Endpoint</span>
                        <span className="font-mono text-gray-200">
                            {getApiBaseUrl()}
                        </span>
                    </div>
                    <div className="py-2 border-b border-dark-700">
                        <div className="flex items-center justify-between">
                            <span className="text-dark-400">Connection</span>
                            <span className="font-mono text-gray-200">
                                {USE_MOCK_DATA ? 'Mock mode' : (settings?.apiKeyRequired ? 'API key required' : 'No API key')}
                            </span>
                        </div>
                        <div className="mt-3 grid grid-cols-1 gap-3">
                            <label className="block">
                                <span className="text-xs text-dark-400">API Base URL</span>
                                <input
                                    className="mt-1 w-full rounded-lg bg-dark-900 border border-dark-700 px-3 py-2 text-sm text-gray-100"
                                    value={apiBaseUrl}
                                    onChange={(e) => setApiBaseUrlState(e.target.value)}
                                    placeholder="http://localhost:8080"
                                    spellCheck={false}
                                />
                            </label>
                            <label className="block">
                                <span className="text-xs text-dark-400">API Key</span>
                                <input
                                    className="mt-1 w-full rounded-lg bg-dark-900 border border-dark-700 px-3 py-2 text-sm text-gray-100"
                                    value={apiKey}
                                    onChange={(e) => setApiKeyState(e.target.value)}
                                    placeholder="(optional)"
                                    spellCheck={false}
                                />
                            </label>
                            <div className="flex items-center gap-2">
                                <button
                                    type="button"
                                    className="btn-secondary"
                                    onClick={() => {
                                        setApiConfig({ apiBaseUrl, apiKey });
                                        window.location.reload();
                                    }}
                                    disabled={USE_MOCK_DATA}
                                >
                                    Save & Reload
                                </button>
                                <button
                                    type="button"
                                    className="btn-ghost"
                                    onClick={async () => {
                                        if (USE_MOCK_DATA) return;

                                        setConnTest({ status: 'testing' });
                                        const base = normalizeApiBaseUrl(apiBaseUrl);
                                        try {
                                            const health = await fetch(`${base}/health`, {
                                                method: 'GET',
                                                headers: { 'Content-Type': 'application/json' },
                                            });
                                            const healthOk = health.ok;

                                            const api = await fetch(`${base}/api/status`, {
                                                method: 'GET',
                                                headers: apiKey
                                                    ? { 'Content-Type': 'application/json', 'X-API-Key': apiKey }
                                                    : { 'Content-Type': 'application/json' },
                                            });
                                            const apiOk = api.ok;

                                            let suggestion: string | undefined;
                                            if (!healthOk && base.endsWith('/api')) {
                                                suggestion = "Try removing the trailing `/api` from the base URL.";
                                            } else if (healthOk && api.status === 401) {
                                                suggestion = 'Set the API key (server has MPRD_OPERATOR_API_KEY enabled).';
                                            } else if (!healthOk) {
                                                suggestion = 'Check the host/port and that `mprd serve` is running.';
                                            }

                                            setConnTest({
                                                status: healthOk && apiOk ? 'ok' : 'error',
                                                healthOk,
                                                apiOk,
                                                message: `Health: ${health.status} • API: ${api.status}`,
                                                suggestion,
                                            });
                                        } catch (e) {
                                            setConnTest({
                                                status: 'error',
                                                message: e instanceof Error ? e.message : 'Connection test failed',
                                                suggestion: base.endsWith('/api')
                                                    ? "Try removing the trailing `/api` from the base URL."
                                                    : 'Check the host/port and that `mprd serve` is running.',
                                            });
                                        }
                                    }}
                                    disabled={USE_MOCK_DATA || connTest.status === 'testing'}
                                >
                                    {connTest.status === 'testing' ? 'Testing…' : 'Test Connection'}
                                </button>
                                <button
                                    type="button"
                                    className="btn-ghost"
                                    onClick={() => {
                                        clearApiConfig();
                                        window.location.reload();
                                    }}
                                    disabled={USE_MOCK_DATA}
                                >
                                    Clear
                                </button>
                            </div>
                            <p className="text-xs text-dark-500">
                                Stored locally in your browser. Useful when the backend requires `MPRD_OPERATOR_API_KEY` and you don’t want to rebuild the UI.
                            </p>
                            {connTest.status !== 'idle' && (
                                <div className={`mt-2 rounded-lg border px-3 py-2 text-xs ${connTest.status === 'ok'
                                    ? 'border-healthy/30 bg-healthy/10 text-healthy'
                                    : connTest.status === 'testing'
                                        ? 'border-degraded/30 bg-degraded/10 text-degraded'
                                        : 'border-critical/30 bg-critical/10 text-critical'
                                    }`}>
                                    <div className="font-mono">{connTest.message ?? ''}</div>
                                    {connTest.suggestion && <div className="mt-1">{connTest.suggestion}</div>}
                                </div>
                            )}
                        </div>
                    </div>
                    <div className="flex items-center justify-between py-2 border-b border-dark-700">
                        <span className="text-dark-400">Mock Mode</span>
                        <span className="font-mono text-gray-200">
                            {USE_MOCK_DATA ? 'Enabled' : 'Disabled'}
                        </span>
                    </div>
                    <div className="flex items-center justify-between py-2 border-b border-dark-700">
                        <span className="text-dark-400">Sensitive Store</span>
                        <span className="font-mono text-gray-200">
                            {settings?.storeSensitiveEnabled ? 'Enabled' : (USE_MOCK_DATA ? 'Mock mode' : 'Disabled')}
                        </span>
                    </div>
                    <div className="flex items-center justify-between py-2">
                        <span className="text-dark-400">Backend Version</span>
                        <span className="font-mono text-gray-200">
                            {settings?.version ?? (settingsQuery.isLoading ? 'Loading…' : 'Unavailable')}
                        </span>
                    </div>
                </div>
            </Card>

            {/* Retention */}
            <Card>
                <CardHeader
                    title="Retention"
                    subtitle="Control how long decision history is kept"
                />
                <div className="space-y-3">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <label className="block">
                            <span className="text-xs text-dark-400">Retention (days)</span>
                            <input
                                className="mt-1 w-full rounded-lg bg-dark-900 border border-dark-700 px-3 py-2 text-sm text-gray-100"
                                type="number"
                                min={0}
                                step={1}
                                value={retentionDays}
                                onChange={(e) => {
                                    setRetentionDaysDraft(e.target.value);
                                    setRetentionStatus('idle');
                                }}
                                disabled={USE_MOCK_DATA || !settings}
                            />
                            <p className="text-xs text-dark-500 mt-1">Set to 0 to disable time-based pruning.</p>
                        </label>
                        <label className="block">
                            <span className="text-xs text-dark-400">Max decisions</span>
                            <input
                                className="mt-1 w-full rounded-lg bg-dark-900 border border-dark-700 px-3 py-2 text-sm text-gray-100"
                                type="number"
                                min={0}
                                step={1}
                                value={decisionMax}
                                onChange={(e) => {
                                    setDecisionMaxDraft(e.target.value);
                                    setRetentionStatus('idle');
                                }}
                                disabled={USE_MOCK_DATA || !settings}
                            />
                            <p className="text-xs text-dark-500 mt-1">Set to 0 to disable the cap.</p>
                        </label>
                    </div>
                    <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                        <span className="text-xs text-dark-500">
                            Changes apply immediately and will prune old records in the background.
                        </span>
                        <div className="flex flex-wrap items-center gap-2">
                            {retentionStatus === 'saved' && (
                                <span className="text-xs text-healthy">Saved</span>
                            )}
                            {retentionStatus === 'error' && (
                                <span className="text-xs text-critical">Failed to save</span>
                            )}
                            {pruneStatus === 'done' && (
                                <span className="text-xs text-healthy">
                                    Pruned {prunedCount ?? 0}
                                </span>
                            )}
                            {pruneStatus === 'error' && (
                                <span className="text-xs text-critical">Prune failed</span>
                            )}
                            <button
                                type="button"
                                className="btn-ghost"
                                onClick={handlePruneNow}
                                disabled={USE_MOCK_DATA || !settings || pruneStatus === 'pruning'}
                            >
                                {pruneStatus === 'pruning' ? 'Pruning…' : 'Prune now'}
                            </button>
                            <button
                                type="button"
                                className="btn-primary"
                                onClick={handleRetentionSave}
                                disabled={USE_MOCK_DATA || !settings || retentionStatus === 'saving'}
                            >
                                {retentionStatus === 'saving' ? 'Saving…' : 'Save'}
                            </button>
                        </div>
                    </div>
                </div>
            </Card>

            {/* Paths */}
            <Card>
                <CardHeader
                    title="Paths"
                    subtitle="Operator storage and local policy artifacts"
                />
                <div className="space-y-3">
                    <div className="flex items-center justify-between py-2 border-b border-dark-700">
                        <span className="text-dark-400">Operator Store</span>
                        <span className="font-mono text-sm text-gray-200">
                            {settings?.storeDir ?? (USE_MOCK_DATA ? 'Mock mode' : 'Unavailable')}
                        </span>
                    </div>
                    <div className="flex items-center justify-between py-2 border-b border-dark-700">
                        <span className="text-dark-400">Policy Directory</span>
                        <span className="font-mono text-sm text-gray-200">
                            {settings?.policyDir ?? (USE_MOCK_DATA ? 'Mock mode' : 'Unavailable')}
                        </span>
                    </div>
                    <div className="flex items-center justify-between py-2">
                        <span className="text-dark-400">API Key</span>
                        <span className="font-mono text-gray-200">
                            {settings?.apiKeyRequired ? 'Required' : 'Not required'}
                        </span>
                    </div>
                </div>
            </Card>

            {/* Trust anchors */}
            <Card>
                <CardHeader
                    title="Trust Anchors"
                    subtitle="Fail-closed verification configuration"
                />
                <div className="space-y-3">
                    <div className="flex items-center justify-between py-2 border-b border-dark-700">
                        <span className="text-dark-400">Registry State</span>
                        <span className="font-mono text-sm text-gray-200">
                            {settings?.trustAnchors.registryStatePath ?? 'Not configured'}
                        </span>
                    </div>
                    <div className="flex items-center justify-between py-2 border-b border-dark-700">
                        <span className="text-dark-400">Registry Key FP</span>
                        <span className="font-mono text-gray-200">
                            {settings?.trustAnchors.registryKeyFingerprint ?? 'Not configured'}
                        </span>
                    </div>
                    <div className="flex items-center justify-between py-2">
                        <span className="text-dark-400">Manifest Key FP</span>
                        <span className="font-mono text-gray-200">
                            {settings?.trustAnchors.manifestKeyFingerprint ?? 'Not configured'}
                        </span>
                    </div>
                </div>
            </Card>

            {/* Mode Transition Modal */}
            <ModeTransitionModal
                isOpen={modalOpen}
                currentMode={autopilotState.mode}
                targetMode={targetMode}
                violations={violations}
                onConfirm={handleConfirm}
                onCancel={() => setModalOpen(false)}
            />
        </div>
    );
}
