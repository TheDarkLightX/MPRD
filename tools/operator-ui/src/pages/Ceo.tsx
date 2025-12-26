/**
 * CEO Page - Algorithmic CEO Dashboard
 *
 * Displays the Algorithmic CEO state, objective regime, and control knobs.
 */

import { useQuery } from '@tanstack/react-query';
import { LoadingCard, NoticeCard, MetricCard, Card } from '../components/ui';
import {
    Brain,
    Target,
    Gauge,
    TrendingUp,
    Flame,
    Coins,
    Droplets,
    Activity,
} from 'lucide-react';
import { USE_MOCK_DATA } from '../config';

// Mock data for development
const MOCK_CEO_STATE = {
    objective: {
        id: 'ProfitUtility',
        risk_tolerance_bps: 5000,
        churn_penalty_bps: 1000,
        reserve_floor_epochs: 3,
    },
    knobs: {
        burn_bps: 4000,
        auction_bps: 3500,
        drip_bps: 2500,
    },
    metrics: {
        opi: 9500,
        netWorth: 4200000,
        reserve: 850000,
        volatility: 4.34,
    },
    position: {
        burn_idx: 8,
        auction_idx: 7,
        drip_idx: 5,
    },
};

type CeoState = typeof MOCK_CEO_STATE;

function KnobGauge({ label, value, max = 10000, icon, color }: {
    label: string;
    value: number;
    max?: number;
    icon: React.ReactNode;
    color: string;
}) {
    const percentage = (value / max) * 100;
    const displayValue = (value / 100).toFixed(1);

    return (
        <div className="glass-card p-4">
            <div className="flex items-center gap-3 mb-3">
                <div className={`p-2 rounded-lg ${color}`}>
                    {icon}
                </div>
                <div>
                    <span className="text-sm text-dark-400">{label}</span>
                    <div className="text-xl font-semibold text-white">{displayValue}%</div>
                </div>
            </div>
            <div className="h-2 bg-dark-800 rounded-full overflow-hidden">
                <div
                    className={`h-full rounded-full transition-all duration-500 ${color.replace('bg-opacity-20', '')}`}
                    style={{ width: `${percentage}%` }}
                />
            </div>
            <div className="flex justify-between mt-1 text-xs text-dark-500">
                <span>0%</span>
                <span>100%</span>
            </div>
        </div>
    );
}

function ObjectiveCard({ objective }: { objective: CeoState['objective'] }) {
    const getObjectiveInfo = (id: string) => {
        switch (id) {
            case 'ProfitUtility':
                return {
                    label: 'Profit Utility',
                    description: 'Optimizing for operator treasury net worth',
                    color: 'text-accent-400',
                    bgColor: 'bg-accent-500/20',
                };
            case 'OpiFirst':
                return {
                    label: 'OPI First',
                    description: 'Prioritizing network quality (OPI)',
                    color: 'text-healthy-400',
                    bgColor: 'bg-healthy-500/20',
                };
            case 'Hybrid':
                return {
                    label: 'Hybrid',
                    description: 'Weighted balance of profit and OPI',
                    color: 'text-degraded-400',
                    bgColor: 'bg-degraded-500/20',
                };
            default:
                return {
                    label: id,
                    description: 'Unknown objective',
                    color: 'text-dark-400',
                    bgColor: 'bg-dark-800',
                };
        }
    };

    const info = getObjectiveInfo(objective.id);

    return (
        <Card className="p-6">
            <div className="flex items-start gap-4">
                <div className={`p-3 rounded-xl ${info.bgColor}`}>
                    <Target className={`w-6 h-6 ${info.color}`} />
                </div>
                <div className="flex-1">
                    <h3 className="text-sm text-dark-400 mb-1">Objective Regime</h3>
                    <div className={`text-2xl font-bold ${info.color}`}>{info.label}</div>
                    <p className="text-sm text-dark-400 mt-1">{info.description}</p>
                </div>
            </div>

            <div className="grid grid-cols-3 gap-4 mt-6 pt-4 border-t border-dark-800">
                <div>
                    <span className="text-xs text-dark-500">Risk Tolerance</span>
                    <div className="text-lg font-semibold">{(objective.risk_tolerance_bps / 100).toFixed(0)}%</div>
                </div>
                <div>
                    <span className="text-xs text-dark-500">Churn Penalty</span>
                    <div className="text-lg font-semibold">{(objective.churn_penalty_bps / 100).toFixed(0)}%</div>
                </div>
                <div>
                    <span className="text-xs text-dark-500">Reserve Floor</span>
                    <div className="text-lg font-semibold">{objective.reserve_floor_epochs} epochs</div>
                </div>
            </div>
        </Card>
    );
}

function LatticePosition({ position }: { position: CeoState['position'] }) {
    const gridSize = 11; // 0-10 steps

    return (
        <Card className="p-6">
            <h3 className="text-sm text-dark-400 mb-4 flex items-center gap-2">
                <Activity className="w-4 h-4" />
                Menu Graph Position
            </h3>
            <div className="relative aspect-square bg-dark-800/50 rounded-lg p-4">
                {/* Grid lines */}
                <div className="absolute inset-4 grid grid-cols-10 grid-rows-10 opacity-20">
                    {Array.from({ length: 100 }).map((_, i) => (
                        <div key={i} className="border border-dark-600" />
                    ))}
                </div>

                {/* Current position indicator */}
                <div
                    className="absolute w-4 h-4 bg-accent-500 rounded-full shadow-lg shadow-accent-500/50 transform -translate-x-1/2 -translate-y-1/2 animate-pulse"
                    style={{
                        left: `${(position.burn_idx / (gridSize - 1)) * 100}%`,
                        top: `${(1 - position.auction_idx / (gridSize - 1)) * 100}%`,
                    }}
                />

                {/* Axis labels */}
                <div className="absolute -bottom-6 left-1/2 transform -translate-x-1/2 text-xs text-dark-400">
                    Burn →
                </div>
                <div className="absolute -left-6 top-1/2 transform -translate-y-1/2 -rotate-90 text-xs text-dark-400">
                    Auction →
                </div>
            </div>
            <div className="mt-4 grid grid-cols-3 gap-2 text-center text-xs text-dark-400">
                <div>Burn: {position.burn_idx}</div>
                <div>Auction: {position.auction_idx}</div>
                <div>Drip: {position.drip_idx}</div>
            </div>
        </Card>
    );
}

export function CeoPage() {
    const { data: ceoState, isLoading, error } = useQuery<CeoState>({
        queryKey: ['ceo_state'],
        queryFn: async () => {
            if (USE_MOCK_DATA) return MOCK_CEO_STATE;
            const response = await fetch('/api/ceo/state');
            if (!response.ok) throw new Error('Failed to fetch CEO state');
            return response.json();
        },
        refetchInterval: 5000,
    });

    if (isLoading) {
        return (
            <div className="flex items-center justify-center min-h-[60vh]">
                <LoadingCard message="Loading CEO state..." />
            </div>
        );
    }

    if (error || !ceoState) {
        return (
            <div className="max-w-2xl mx-auto mt-12">
                <NoticeCard
                    variant="warning"
                    title="CEO State Unavailable"
                    message="Could not fetch Algorithmic CEO state. The endpoint may not be implemented yet."
                />
            </div>
        );
    }

    return (
        <div className="space-y-8">
            {/* Header */}
            <div className="flex items-center gap-4">
                <div className="p-3 rounded-xl bg-accent-500/20">
                    <Brain className="w-8 h-8 text-accent-400" />
                </div>
                <div>
                    <h1 className="text-2xl font-bold text-white">Algorithmic CEO</h1>
                    <p className="text-dark-400">Autonomous tokenomics controller with safety rails</p>
                </div>
            </div>

            {/* Metrics Row */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <MetricCard
                    title="OPI"
                    value={ceoState.metrics?.opi?.toLocaleString() ?? 'N/A'}
                    icon={<Gauge className="w-5 h-5" />}
                    variant={(ceoState.metrics?.opi ?? 0) >= 9000 ? 'healthy' : (ceoState.metrics?.opi ?? 0) >= 7000 ? 'default' : 'warning'}
                    subtitle="Operating Performance Index"
                />
                <MetricCard
                    title="Net Worth"
                    value={ceoState.metrics?.netWorth != null ? `${(ceoState.metrics.netWorth / 1_000_000).toFixed(2)}M` : 'N/A'}
                    icon={<Coins className="w-5 h-5" />}
                    variant="default"
                    subtitle="AGRS"
                />
                <MetricCard
                    title="Reserve"
                    value={ceoState.metrics?.reserve != null ? `${(ceoState.metrics.reserve / 1_000_000).toFixed(2)}M` : 'N/A'}
                    icon={<TrendingUp className="w-5 h-5" />}
                    variant="default"
                    subtitle="AGRS"
                />
                <MetricCard
                    title="Volatility"
                    value={ceoState.metrics?.volatility != null ? `${ceoState.metrics.volatility.toFixed(2)}%` : 'N/A'}
                    icon={<Activity className="w-5 h-5" />}
                    variant={(ceoState.metrics?.volatility ?? 0) < 5 ? 'healthy' : (ceoState.metrics?.volatility ?? 0) < 10 ? 'default' : 'warning'}
                    subtitle="Rolling average"
                />
            </div>

            {/* Main Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Objective Card */}
                <div className="lg:col-span-2">
                    <ObjectiveCard objective={ceoState.objective} />
                </div>

                {/* Lattice Position */}
                <LatticePosition position={ceoState.position} />
            </div>

            {/* Control Knobs */}
            <div>
                <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <Gauge className="w-5 h-5 text-accent-400" />
                    Current Setpoints
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <KnobGauge
                        label="Burn Rate"
                        value={ceoState.knobs.burn_bps}
                        icon={<Flame className="w-5 h-5 text-critical" />}
                        color="bg-critical/20"
                    />
                    <KnobGauge
                        label="Auction Rate"
                        value={ceoState.knobs.auction_bps}
                        icon={<Coins className="w-5 h-5 text-accent-400" />}
                        color="bg-accent-500/20"
                    />
                    <KnobGauge
                        label="Drip Rate"
                        value={ceoState.knobs.drip_bps}
                        icon={<Droplets className="w-5 h-5 text-info" />}
                        color="bg-info/20"
                    />
                </div>
            </div>
        </div>
    );
}
