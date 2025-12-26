/**
 * Dashboard Page (Home)
 *
 * Main operator dashboard showing system status, metrics, alerts, and live pipeline.
 * Per spec Section 6.1: At-a-glance health, metrics summary, alert feed, live pipeline.
 * Enhanced with Algorithm 12: GlanceablePostureRenderer for 1-3s comprehension.
 * 
 * REDESIGNED: Premium UI with gradients, animations, and modern aesthetic.
 */

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { SystemStatusGrid } from '../components/health';
import { LivePipeline } from '../components/pipeline';
import { AlertFeed } from '../components/alerts';
import { LoadingCard, NoticeCard, MetricCard } from '../components/ui';
import { IncidentQueue } from '../components/incidents';
import { GlanceableHeader } from '../components/glanceable';
import {
    FileCheck,
    PercentCircle,
    Timer,
    FileCode,
    Zap,
} from 'lucide-react';

import { useOperatorAlerts, useOperatorDashboard, useOperatorIncidents } from '../hooks';
import { useNavigate } from 'react-router-dom';
import { USE_MOCK_DATA } from '../config';
import { useLiveEvents } from '../context/LiveEventsContext';
import { useAutopilot } from '../context/AutopilotContext';
import { AutopilotActivitySidebar } from '../components/autopilot';
import { SecurityPosturePanel } from '../components/security';
import { CeoStatusCard } from '../components/ceo';
import { renderGlanceable, createLoadingGlanceableView } from '../algorithms/glanceableRenderer';
import { computeSecurityPosture } from '../algorithms/securityPosture';
import { apiClient } from '../api/client';
import type { IncidentExtended, SecurityPosture } from '../api/types';

// =============================================================================
// Mock sparkline data generator
// =============================================================================

function mulberry32(seed: number): () => number {
    let t = seed >>> 0;
    return () => {
        t += 0x6D2B79F5;
        let x = t;
        x = Math.imul(x ^ (x >>> 15), x | 1);
        x ^= x + Math.imul(x ^ (x >>> 7), x | 61);
        return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
    };
}

function sparklineFromValue(value: number, length = 12, variance = 20): number[] {
    const seed = Math.floor((value + 1) * 1_000_003) ^ (length * 97) ^ (variance * 7919);
    const rand = mulberry32(seed);
    const base = Number.isFinite(value) ? value : 0;
    const spread = Math.max(1, variance);
    return Array.from({ length }, (_, i) => {
        const phase = (i / Math.max(1, length - 1)) * Math.PI * 2;
        const wobble = (Math.sin(phase) * 0.25 + (rand() - 0.5) * 0.75) * spread;
        return Math.max(0, base + wobble);
    });
}

// =============================================================================
// Section Header Component
// =============================================================================

function SectionHeader({ title, action }: { title: string; action?: React.ReactNode }) {
    return (
        <div className="section-header">
            <h2>{title}</h2>
            {action && <div className="ml-auto">{action}</div>}
        </div>
    );
}

// =============================================================================
// Main Dashboard Component
// =============================================================================

export function DashboardPage() {
    const { status, metrics, pipelineState: mockPipelineState, loading, error, errorStatus, isOffline, refetch } = useOperatorDashboard();
    const { alerts, acknowledge: acknowledgeAlert } = useOperatorAlerts();
    const { incidents: incidentSummaries, acknowledge: acknowledgeIncident, snooze: snoozeIncident } = useOperatorIncidents(50, false, true);
    const { pipelineState: livePipelineState, connected: liveConnected } = useLiveEvents();
    const { state: autopilotState, recentActions } = useAutopilot();
    const pipelineState = USE_MOCK_DATA ? mockPipelineState : livePipelineState;
    const navigate = useNavigate();

    const settingsQuery = useQuery({
        queryKey: ['settings'],
        queryFn: () => apiClient.getSettings(),
        enabled: !USE_MOCK_DATA,
        refetchInterval: 10_000,
    });

    const recentDecisionsQuery = useQuery({
        queryKey: ['decisions_recent'],
        queryFn: () => apiClient.listDecisions(1, 200, { startDate: Date.now() - 60 * 60 * 1000 }),
        enabled: !USE_MOCK_DATA,
        refetchInterval: 10_000,
    });

    // Generate mock sparkline data (in real app, would come from metrics history)
    const sparklines = useMemo(() => ({
        decisions: sparklineFromValue(metrics?.decisions.total ? metrics.decisions.total / 100 : 50, 12, 20),
        successRate: sparklineFromValue(metrics?.successRate.value ?? 95, 12, 5),
        latency: sparklineFromValue(metrics?.avgLatencyMs.value ?? 45, 12, 15),
        policies: sparklineFromValue(metrics?.activePolicies ?? 12, 12, 3),
    }), [metrics]);

    // Compute incidents for glanceable view based on backend summaries (best-effort mapping)
    const incidents = useMemo((): IncidentExtended[] => {
        return incidentSummaries.map((s) => ({
            id: s.id,
            severity: s.severity,
            title: s.title,
            count: s.count,
            unacked: s.unacked,
            firstSeen: s.firstSeen,
            lastSeen: s.lastSeen,
            primary: {
                id: s.primaryAlertId,
                timestamp: s.lastSeen,
                severity: s.severity,
                type: 'anomaly',
                message: s.title,
                acknowledged: !s.unacked,
            },
            state: s.unacked ? 'open' : 'acknowledged',
            flapping: s.flapping ?? false,
            priority:
                (s.severity === 'critical' ? 1_000_000 : s.severity === 'warning' ? 100_000 : 10_000) +
                (s.unacked ? 50_000 : 0) +
                s.lastSeen,
        }));
    }, [incidentSummaries]);

    const posture = useMemo((): SecurityPosture => {
        if (USE_MOCK_DATA) {
            return {
                trustLevel: status?.overall === 'critical' ? 'critical' : status?.overall === 'degraded' ? 'degraded' : 'healthy',
                availabilityLevel: status?.overall === 'critical' ? 'critical' : status?.overall === 'degraded' ? 'degraded' : 'healthy',
                reasons: [],
                metrics: {
                    failRate: metrics ? (1 - metrics.successRate.value / 100) : 0,
                    verifyFailRate: 0,
                    execFailRate: 0,
                    decisionRate: metrics ? metrics.decisions.total / (24 * 60) : 0,
                },
            };
        }

        if (!status || !settingsQuery.data) {
            return {
                trustLevel: 'critical',
                availabilityLevel: 'critical',
                reasons: ['Backend data unavailable - FAIL-CLOSED'],
                metrics: { failRate: 1.0, verifyFailRate: 1.0, execFailRate: 1.0, decisionRate: 0 },
            };
        }

        const decisions = recentDecisionsQuery.data?.data ?? [];
        return computeSecurityPosture({
            deploymentMode: settingsQuery.data.deploymentMode,
            trustAnchors: settingsQuery.data.trustAnchors,
            trustAnchorsConfigured: settingsQuery.data.trustAnchorsConfigured,
            status,
            decisions,
        });
    }, [metrics, recentDecisionsQuery.data?.data, settingsQuery.data, status]);

    const glanceableView = useMemo(() => {
        if (loading || !status) {
            return createLoadingGlanceableView();
        }

        return renderGlanceable({
            posture,
            incidents,
            autopilot: autopilotState,
            previousMetrics: undefined,
            previousIncidentCount: 0,
            previousCriticalCount: 3,
        });
    }, [autopilotState, incidents, loading, posture, status]);

    if (loading) {
        return (
            <div className="flex items-center justify-center min-h-[60vh]">
                <LoadingCard message="Loading dashboard..." />
            </div>
        );
    }

    if (error) {
        if (isOffline) {
            return (
                <div className="max-w-2xl mx-auto mt-12">
                    <NoticeCard
                        variant="error"
                        title="Backend unreachable"
                        message="The Operator UI cannot reach the backend. Check the API base URL and that `mprd serve` is running."
                        actions={
                            <div className="flex flex-wrap gap-2 mt-4">
                                <button className="btn-secondary" onClick={() => navigate('/settings')}>
                                    Open Settings
                                </button>
                                <button className="btn-ghost" onClick={() => { void refetch(); }}>
                                    Retry
                                </button>
                            </div>
                        }
                    />
                </div>
            );
        }
        if (errorStatus === 401) {
            return (
                <div className="max-w-2xl mx-auto mt-12">
                    <NoticeCard
                        variant="error"
                        title="Authentication required"
                        message="The backend requires an API key. Set it in Settings (or unset `MPRD_OPERATOR_API_KEY` on the server for localhost-only development)."
                        actions={
                            <button
                                className="btn-secondary mt-4"
                                onClick={() => navigate('/settings')}
                            >
                                Open Settings
                            </button>
                        }
                    />
                </div>
            );
        }
        return (
            <div className="max-w-2xl mx-auto mt-12">
                <NoticeCard
                    variant="error"
                    title="Backend unavailable"
                    message={`Failed to load operator data: ${error.message}`}
                    actions={
                        <button
                            className="btn-secondary mt-4"
                            onClick={() => navigate('/settings')}
                        >
                            Check Settings
                        </button>
                    }
                />
            </div>
        );
    }

    return (
        <div className="space-y-8">
            {/* Hero: Glanceable Header */}
            <div className="animate-in fade-in duration-500">
                <GlanceableHeader
                    view={glanceableView}
                    onNextActionClick={() => navigate('/security')}
                />
            </div>

            {/* Main Grid Layout */}
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                {/* Main Content Area - 3 columns */}
                <div className="lg:col-span-3 space-y-8">

                    {/* Metrics Summary - Premium Cards */}
                    {metrics && (
                        <section>
                            <SectionHeader title="Performance Metrics" />
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                                <MetricCard
                                    title="Decisions"
                                    value={metrics.decisions.total}
                                    change={metrics.decisions.change}
                                    changeLabel="vs yesterday"
                                    icon={<FileCheck className="w-5 h-5" />}
                                    sparklineData={sparklines.decisions}
                                    variant="default"
                                    subtitle="Last 24 hours"
                                />
                                <MetricCard
                                    title="Success Rate"
                                    value={`${metrics.successRate.value.toFixed(1)}%`}
                                    change={metrics.successRate.change}
                                    icon={<PercentCircle className="w-5 h-5" />}
                                    sparklineData={sparklines.successRate}
                                    variant={metrics.successRate.value >= 99 ? 'healthy' : metrics.successRate.value >= 95 ? 'default' : 'warning'}
                                    animateValue={false}
                                />
                                <MetricCard
                                    title="Avg Latency"
                                    value={`${metrics.avgLatencyMs.value}ms`}
                                    change={metrics.avgLatencyMs.change}
                                    icon={<Timer className="w-5 h-5" />}
                                    sparklineData={sparklines.latency}
                                    variant={metrics.avgLatencyMs.value <= 50 ? 'healthy' : metrics.avgLatencyMs.value <= 100 ? 'default' : 'warning'}
                                    animateValue={false}
                                />
                                <MetricCard
                                    title="Active Policies"
                                    value={metrics.activePolicies}
                                    icon={<FileCode className="w-5 h-5" />}
                                    sparklineData={sparklines.policies}
                                />
                            </div>
                        </section>
                    )}

                    {/* System Status Grid */}
                    <section className="animate-in fade-in-up delay-100">
                        <SectionHeader title="System Components" />
                        {status && <SystemStatusGrid status={status} />}
                    </section>

                    {/* Live Pipeline Visualization */}
                    <section className="animate-in fade-in-up delay-200">
                        <LivePipeline
                            state={pipelineState}
                            connected={USE_MOCK_DATA ? null : liveConnected}
                        />
                    </section>

                    {/* Work Queue (Incidents) */}
                    <section className="animate-in fade-in-up delay-300">
                        <IncidentQueue
                            incidents={incidentSummaries}
                            onOpenSecurity={() => navigate('/security')}
                            onAcknowledge={(id) => acknowledgeIncident(id)}
                            onSnooze={(id, ttlMs) => snoozeIncident(id, ttlMs)}
                        />
                    </section>
                </div>

                {/* Sidebar - 1 column */}
                <div className="space-y-6">
                    {/* Security Posture Panel */}
                    <div className="animate-in slide-in-right delay-100">
                        <SecurityPosturePanel
                            posture={posture}
                            onConfigureTrust={() => navigate('/settings')}
                        />
                    </div>

                    {/* Controller (CEO) Status */}
                    <div className="animate-in slide-in-right delay-150">
                        <CeoStatusCard />
                    </div>

                    {/* Alert Feed */}
                    <div className="animate-in slide-in-right delay-200">
                        <AlertFeed
                            alerts={alerts}
                            onAcknowledge={(id) => acknowledgeAlert(id)}
                            onViewAll={() => navigate('/security')}
                        />
                    </div>

                    {/* Autopilot Activity */}
                    <div className="animate-in slide-in-right delay-300">
                        <AutopilotActivitySidebar
                            actions={recentActions}
                            onOverride={(id) => console.log('Override', id)}
                        />
                    </div>

                    {/* Quick Stats */}
                    <div className="glass-card p-4 animate-in slide-in-right delay-400">
                        <div className="flex items-center justify-between mb-3">
                            <span className="text-sm font-medium text-dark-400">Autopilot Mode</span>
                            <Zap className={`w-4 h-4 ${autopilotState.mode === 'autopilot' ? 'text-accent-400' : 'text-dark-500'}`} />
                        </div>
                        <div className="flex items-center gap-2">
                            <span className={`text-lg font-semibold capitalize ${autopilotState.mode === 'autopilot' ? 'text-accent-400' :
                                autopilotState.mode === 'assisted' ? 'text-healthy-400' : 'text-dark-300'
                                }`}>
                                {autopilotState.mode}
                            </span>
                            {autopilotState.pendingReviewCount > 0 && (
                                <span className="px-2 py-0.5 text-xs bg-accent-500/20 text-accent-400 rounded-full animate-pulse">
                                    {autopilotState.pendingReviewCount} pending
                                </span>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
