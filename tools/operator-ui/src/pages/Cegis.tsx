/**
 * CEGIS Page - Counterexample-Guided Inductive Synthesis Metrics
 *
 * Displays proposer metrics, counterexamples, and failure analysis.
 */

import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { LoadingCard, NoticeCard, MetricCard, Card } from '../components/ui';
import {
    GitBranch,
    CheckCircle2,
    XCircle,
    Clock,
    AlertTriangle,
    ChevronDown,
    ChevronRight,
    FileX,
    Zap,
    Target,
} from 'lucide-react';
import { USE_MOCK_DATA } from '../config';

// Mock data for development
const MOCK_CEGIS_METRICS = {
    proposer: {
        proposals_total: 1247,
        proposals_valid: 1189,
        proposals_invalid: 58,
        counterexamples_captured: 42,
        time_to_first_valid_ms: 12,
    },
    counterexamples: [
        {
            id: 'cx-001',
            policy_hash: '0xabc123...def456',
            state_hash: '0x789abc...123def',
            action: 'SetBurnRate(+1)',
            failed_atom: 'cooldown_elapsed_ok',
            timestamp_epoch: 42,
            trace: [
                { atom: 'opi_healthy_ok', value: true },
                { atom: 'reserve_runway_ok', value: true },
                { atom: 'cooldown_elapsed_ok', value: false },
            ],
        },
        {
            id: 'cx-002',
            policy_hash: '0xabc123...def456',
            state_hash: '0x456def...789ghi',
            action: 'SetAuctionRate(-1)',
            failed_atom: 'delta_bounded_ok',
            timestamp_epoch: 41,
            trace: [
                { atom: 'opi_healthy_ok', value: true },
                { atom: 'delta_bounded_ok', value: false },
            ],
        },
        {
            id: 'cx-003',
            policy_hash: '0xabc123...def456',
            state_hash: '0x111222...333444',
            action: 'SetDripRate(+2)',
            failed_atom: 'emergency_freeze',
            timestamp_epoch: 40,
            trace: [
                { atom: 'opi_healthy_ok', value: true },
                { atom: 'emergency_freeze', value: true },
            ],
        },
    ],
    failure_taxonomy: {
        'cooldown_elapsed_ok': 18,
        'delta_bounded_ok': 12,
        'reserve_runway_ok': 8,
        'emergency_freeze': 4,
    },
};

type CegisMetrics = typeof MOCK_CEGIS_METRICS;
type Counterexample = CegisMetrics['counterexamples'][0];

function CounterexampleRow({ cx, isExpanded, onToggle }: {
    cx: Counterexample;
    isExpanded: boolean;
    onToggle: () => void;
}) {
    return (
        <div className="border-b border-dark-800 last:border-0">
            <button
                onClick={onToggle}
                className="w-full px-4 py-3 flex items-center gap-4 hover:bg-dark-800/50 transition-colors text-left"
            >
                {isExpanded ? (
                    <ChevronDown className="w-4 h-4 text-dark-400" />
                ) : (
                    <ChevronRight className="w-4 h-4 text-dark-400" />
                )}
                <div className="flex-1 grid grid-cols-4 gap-4 items-center">
                    <div className="font-mono text-sm text-dark-300">{cx.action}</div>
                    <div className="text-sm text-critical flex items-center gap-1">
                        <XCircle className="w-4 h-4" />
                        {cx.failed_atom}
                    </div>
                    <div className="text-sm text-dark-400">Epoch {cx.timestamp_epoch}</div>
                    <div className="text-xs font-mono text-dark-500 truncate">{cx.policy_hash}</div>
                </div>
            </button>

            {isExpanded && (
                <div className="px-4 pb-4 pl-12 bg-dark-800/30">
                    <div className="text-xs text-dark-400 mb-2">Evaluation Trace:</div>
                    <div className="space-y-1">
                        {cx.trace.map((entry, i) => (
                            <div key={i} className="flex items-center gap-2 text-sm font-mono">
                                {entry.value ? (
                                    <CheckCircle2 className="w-4 h-4 text-healthy-400" />
                                ) : (
                                    <XCircle className="w-4 h-4 text-critical" />
                                )}
                                <span className={entry.value ? 'text-dark-300' : 'text-critical'}>
                                    {entry.atom}
                                </span>
                                <span className="text-dark-500">= {entry.value ? 'true' : 'false'}</span>
                            </div>
                        ))}
                    </div>
                    <div className="mt-3 pt-3 border-t border-dark-700 grid grid-cols-2 gap-4 text-xs">
                        <div>
                            <span className="text-dark-500">State Hash: </span>
                            <span className="font-mono text-dark-400">{cx.state_hash}</span>
                        </div>
                        <div>
                            <span className="text-dark-500">Policy Hash: </span>
                            <span className="font-mono text-dark-400">{cx.policy_hash}</span>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

function FailureTaxonomy({ data }: { data: Record<string, number> }) {
    const total = Object.values(data).reduce((a, b) => a + b, 0);
    const sorted = Object.entries(data).sort(([, a], [, b]) => b - a);

    return (
        <Card className="p-6">
            <h3 className="text-sm text-dark-400 mb-4 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" />
                Failure Taxonomy
            </h3>
            <div className="space-y-3">
                {sorted.map(([atom, count]) => {
                    const percentage = (count / total) * 100;
                    return (
                        <div key={atom}>
                            <div className="flex justify-between text-sm mb-1">
                                <span className="font-mono text-dark-300">{atom}</span>
                                <span className="text-dark-400">{count} ({percentage.toFixed(0)}%)</span>
                            </div>
                            <div className="h-2 bg-dark-800 rounded-full overflow-hidden">
                                <div
                                    className="h-full bg-critical/60 rounded-full transition-all duration-500"
                                    style={{ width: `${percentage}%` }}
                                />
                            </div>
                        </div>
                    );
                })}
            </div>
        </Card>
    );
}

export function CegisPage() {
    const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

    const { data: metrics, isLoading, error } = useQuery<CegisMetrics>({
        queryKey: ['cegis_metrics'],
        queryFn: async () => {
            if (USE_MOCK_DATA) return MOCK_CEGIS_METRICS;
            const response = await fetch('/api/cegis/metrics');
            if (!response.ok) throw new Error('Failed to fetch CEGIS metrics');
            return response.json();
        },
        refetchInterval: 5000,
    });

    const toggleRow = (id: string) => {
        setExpandedRows(prev => {
            const next = new Set(prev);
            if (next.has(id)) {
                next.delete(id);
            } else {
                next.add(id);
            }
            return next;
        });
    };

    if (isLoading) {
        return (
            <div className="flex items-center justify-center min-h-[60vh]">
                <LoadingCard message="Loading CEGIS metrics..." />
            </div>
        );
    }

    if (error || !metrics) {
        return (
            <div className="max-w-2xl mx-auto mt-12">
                <NoticeCard
                    variant="warning"
                    title="CEGIS Metrics Unavailable"
                    message="Could not fetch CEGIS metrics. The endpoint may not be implemented yet."
                />
            </div>
        );
    }

    const validRate = metrics.proposer.proposals_total > 0
        ? ((metrics.proposer.proposals_valid / metrics.proposer.proposals_total) * 100).toFixed(1)
        : '0';

    return (
        <div className="space-y-8">
            {/* Header */}
            <div className="flex items-center gap-4">
                <div className="p-3 rounded-xl bg-accent-500/20">
                    <GitBranch className="w-8 h-8 text-accent-400" />
                </div>
                <div>
                    <h1 className="text-2xl font-bold text-white">CEGIS Loop</h1>
                    <p className="text-dark-400">Counterexample-Guided Inductive Synthesis metrics</p>
                </div>
            </div>

            {/* Metrics Row */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
                <MetricCard
                    title="Total Proposals"
                    value={metrics.proposer.proposals_total.toLocaleString()}
                    icon={<Target className="w-5 h-5" />}
                    variant="default"
                />
                <MetricCard
                    title="Valid"
                    value={metrics.proposer.proposals_valid.toLocaleString()}
                    icon={<CheckCircle2 className="w-5 h-5" />}
                    variant="healthy"
                />
                <MetricCard
                    title="Invalid"
                    value={metrics.proposer.proposals_invalid.toLocaleString()}
                    icon={<XCircle className="w-5 h-5" />}
                    variant={metrics.proposer.proposals_invalid > 100 ? 'warning' : 'default'}
                />
                <MetricCard
                    title="Valid Rate"
                    value={`${validRate}%`}
                    icon={<Zap className="w-5 h-5" />}
                    variant={parseFloat(validRate) >= 95 ? 'healthy' : parseFloat(validRate) >= 80 ? 'default' : 'warning'}
                />
                <MetricCard
                    title="Time to Valid"
                    value={`${metrics.proposer.time_to_first_valid_ms}ms`}
                    icon={<Clock className="w-5 h-5" />}
                    variant={metrics.proposer.time_to_first_valid_ms <= 50 ? 'healthy' : 'default'}
                />
            </div>

            {/* Main Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Counterexamples Table */}
                <div className="lg:col-span-2">
                    <Card className="overflow-hidden">
                        <div className="px-4 py-3 border-b border-dark-800 flex items-center gap-2">
                            <FileX className="w-5 h-5 text-critical" />
                            <h3 className="font-medium text-white">Counterexamples</h3>
                            <span className="ml-auto text-sm text-dark-400">
                                {metrics.counterexamples.length} captured
                            </span>
                        </div>
                        <div className="divide-y divide-dark-800">
                            {metrics.counterexamples.length === 0 ? (
                                <div className="px-4 py-8 text-center text-dark-400">
                                    No counterexamples captured
                                </div>
                            ) : (
                                metrics.counterexamples.map(cx => (
                                    <CounterexampleRow
                                        key={cx.id}
                                        cx={cx}
                                        isExpanded={expandedRows.has(cx.id)}
                                        onToggle={() => toggleRow(cx.id)}
                                    />
                                ))
                            )}
                        </div>
                    </Card>
                </div>

                {/* Failure Taxonomy */}
                <FailureTaxonomy data={metrics.failure_taxonomy} />
            </div>

            {/* Info Card */}
            <Card className="p-4 bg-dark-800/30 border-dark-700">
                <div className="flex items-start gap-3">
                    <div className="p-2 rounded-lg bg-info/20">
                        <GitBranch className="w-4 h-4 text-info" />
                    </div>
                    <div className="text-sm text-dark-400">
                        <p className="font-medium text-dark-300 mb-1">What is CEGIS?</p>
                        <p>
                            Counterexample-Guided Inductive Synthesis: the proposer generates candidates,
                            the verifier checks them, and counterexamples are captured for regression testing.
                            This is the "Model Proposes, Rules Decide" pattern in action.
                        </p>
                    </div>
                </div>
            </Card>
        </div>
    );
}
