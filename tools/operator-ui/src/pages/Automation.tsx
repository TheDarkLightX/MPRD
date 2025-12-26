/**
 * Automation Page
 *
 * Central hub for autonomous MPRD components:
 * - Autopilot Mode (operator workflow: manual/assisted/autopilot)
 * - Algorithmic CEO (tokenomics controller)
 * - CEGIS Loop (counterexamples, accessible via link)
 */

import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Card, LoadingCard, Glossary } from '../components/ui';
import type { GlossaryTerm } from '../components/ui';
import {
    Bot,
    Brain,
    Zap,
    TrendingUp,
    TrendingDown,
    Minus,
    GitBranch,
    ChevronRight,
    Flame,
    Coins,
    Droplets,
} from 'lucide-react';
import { USE_MOCK_DATA } from '../config';
import { useAutopilot } from '../context/AutopilotContext';

// Mock data
const MOCK_CEO_STATE = {
    objective: { id: 'ProfitUtility', risk_tolerance_bps: 5000 },
    knobs: { burn_bps: 4000, auction_bps: 3500, drip_bps: 2500 },
    metrics: { opi: 9500, netWorth: 4200000 },
    trend: 'up' as const,
    lastAction: 'SetBurnRate(+1)',
    lastActionEpoch: 42,
};

const MOCK_CEGIS_SUMMARY = {
    proposals_total: 1247,
    proposals_valid: 1189,
    counterexamples: 42,
};

type CeoState = typeof MOCK_CEO_STATE;
type CegisSummary = typeof MOCK_CEGIS_SUMMARY;

// Glossary definitions
const AUTOPILOT_GLOSSARY: GlossaryTerm[] = [
    { term: 'Manual', definition: 'Operator must approve every action. Maximum control.' },
    { term: 'Assisted', definition: 'Low-risk decisions auto-approved; high-risk requires operator.' },
    { term: 'Autopilot', definition: 'Full autonomous operation within policy bounds.' },
];

const CEO_GLOSSARY: GlossaryTerm[] = [
    { term: 'Objective', definition: 'The optimization goal guiding tokenomics decisions (Profit, OPI, or Hybrid).' },
    { term: 'OPI', definition: 'Operating Performance Index: network quality score (0-10,000).' },
    { term: 'Net Worth', definition: 'Total treasury value in AGRS tokens.' },
    { term: 'Burn', definition: 'Percentage of fees permanently burned (deflationary pressure).' },
    { term: 'Auction', definition: 'Percentage sent to Dutch auction for redistribution.' },
    { term: 'Drip', definition: 'Percentage dripped as staking rewards.' },
];

const CEGIS_GLOSSARY: GlossaryTerm[] = [
    { term: 'Proposals', definition: 'Total actions proposed by the model for rule verification.' },
    { term: 'Valid Rate', definition: 'Percentage of proposals that passed rule verification.' },
    { term: 'Counterexamples', definition: 'Proposals rejected by rules (useful for debugging and regression).' },
];

function TrendIcon({ trend }: { trend: 'up' | 'down' | 'flat' }) {
    switch (trend) {
        case 'up': return <TrendingUp className="w-4 h-4 text-healthy-400" />;
        case 'down': return <TrendingDown className="w-4 h-4 text-critical" />;
        default: return <Minus className="w-4 h-4 text-dark-400" />;
    }
}

function KnobMini({ label, value, icon, color }: {
    label: string;
    value: number;
    icon: React.ReactNode;
    color: string;
}) {
    return (
        <div className="flex items-center gap-2">
            <div className={`p-1.5 rounded ${color}`}>{icon}</div>
            <div>
                <div className="text-xs text-dark-500">{label}</div>
                <div className="text-sm font-medium">{(value / 100).toFixed(1)}%</div>
            </div>
        </div>
    );
}

export function AutomationPage() {
    const navigate = useNavigate();
    const { state: autopilotState, requestModeTransition } = useAutopilot();

    const { data: ceoState, isLoading: ceoLoading } = useQuery<CeoState>({
        queryKey: ['ceo_state'],
        queryFn: async () => {
            if (USE_MOCK_DATA) return MOCK_CEO_STATE;
            const response = await fetch('/api/ceo/state');
            if (!response.ok) return MOCK_CEO_STATE;
            return response.json();
        },
        refetchInterval: 5000,
    });

    const { data: cegisSummary } = useQuery<CegisSummary>({
        queryKey: ['cegis_summary'],
        queryFn: async () => {
            if (USE_MOCK_DATA) return MOCK_CEGIS_SUMMARY;
            const response = await fetch('/api/cegis/summary');
            if (!response.ok) return MOCK_CEGIS_SUMMARY;
            return response.json();
        },
        refetchInterval: 5000,
    });

    if (ceoLoading) {
        return (
            <div className="flex items-center justify-center min-h-[60vh]">
                <LoadingCard message="Loading automation state..." />
            </div>
        );
    }

    const validRate = cegisSummary && cegisSummary.proposals_total > 0
        ? ((cegisSummary.proposals_valid / cegisSummary.proposals_total) * 100).toFixed(1)
        : '0';

    return (
        <div className="space-y-8">
            {/* Header */}
            <div className="flex items-center gap-4">
                <div className="p-3 rounded-xl bg-accent-500/20">
                    <Bot className="w-8 h-8 text-accent-400" />
                </div>
                <div>
                    <h1 className="text-2xl font-bold text-white">Automation</h1>
                    <p className="text-dark-400">Operator workflow and autonomous tokenomics control</p>
                </div>
            </div>

            {/* Autopilot Mode */}
            <Card className="p-6">
                <div className="flex items-center gap-3 mb-4">
                    <Zap className="w-5 h-5 text-accent-400" />
                    <h2 className="text-lg font-semibold text-white">Autopilot Mode</h2>
                </div>
                <div className="grid grid-cols-3 gap-3">
                    {(['manual', 'assisted', 'autopilot'] as const).map((mode) => {
                        const isSelected = autopilotState.mode === mode;
                        return (
                            <button
                                key={mode}
                                onClick={() => {
                                    if (!isSelected) {
                                        const mockPosture = {
                                            trustLevel: 'healthy' as const,
                                            availabilityLevel: 'healthy' as const,
                                            reasons: [],
                                            metrics: {
                                                failRate: 0,
                                                verifyFailRate: 0,
                                                execFailRate: 0,
                                                decisionRate: 1.0,
                                            },
                                        };
                                        const mockIncidents: never[] = [];
                                        const result = requestModeTransition(mode, mockPosture, mockIncidents);
                                        if (!result.success) {
                                            console.warn('Mode transition failed:', result.error, result.violations);
                                        }
                                    }
                                }}
                                className={`p-4 rounded-lg border text-left transition-all ${isSelected
                                    ? mode === 'autopilot'
                                        ? 'bg-accent-500/20 border-accent-500 text-accent-400'
                                        : mode === 'assisted'
                                            ? 'bg-healthy-500/20 border-healthy-500 text-healthy-400'
                                            : 'bg-dark-700 border-dark-600 text-dark-200'
                                    : 'bg-dark-800/50 border-dark-700 text-dark-500 hover:bg-dark-700/50 hover:border-dark-600 cursor-pointer'
                                    }`}
                            >
                                <div className="text-lg font-semibold capitalize">{mode}</div>
                                <div className="text-xs mt-1 opacity-70">
                                    {mode === 'manual' && 'All decisions require approval'}
                                    {mode === 'assisted' && 'Low-risk decisions auto-approved'}
                                    {mode === 'autopilot' && 'Full autonomous operation'}
                                </div>
                            </button>
                        );
                    })}
                </div>
                {autopilotState.pendingReviewCount > 0 && (
                    <div className="mt-4 p-3 bg-accent-500/10 rounded-lg text-sm text-accent-400">
                        {autopilotState.pendingReviewCount} decisions pending review
                    </div>
                )}
                <Glossary terms={AUTOPILOT_GLOSSARY} title="Mode Definitions" />
            </Card>

            {/* Algorithmic CEO */}
            <Card className="p-6">
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                        <Brain className="w-5 h-5 text-accent-400" />
                        <h2 className="text-lg font-semibold text-white">Algorithmic CEO</h2>
                    </div>
                    <button
                        onClick={() => navigate('/ceo')}
                        className="text-sm text-dark-400 hover:text-accent-400 flex items-center gap-1"
                    >
                        Full Dashboard <ChevronRight className="w-4 h-4" />
                    </button>
                </div>

                {ceoState && (
                    <>
                        {/* Metrics Row */}
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                            <div className="glass-card p-3">
                                <div className="text-xs text-dark-500 mb-1">Objective</div>
                                <div className="text-lg font-semibold text-accent-400">
                                    {ceoState.objective.id === 'ProfitUtility' ? 'Profit' :
                                        ceoState.objective.id === 'OpiFirst' ? 'OPI' : 'Hybrid'}
                                </div>
                            </div>
                            <div className="glass-card p-3">
                                <div className="text-xs text-dark-500 mb-1">OPI</div>
                                <div className="flex items-center gap-1">
                                    <span className="text-lg font-semibold">{ceoState.metrics.opi.toLocaleString()}</span>
                                    <TrendIcon trend={ceoState.trend} />
                                </div>
                            </div>
                            <div className="glass-card p-3">
                                <div className="text-xs text-dark-500 mb-1">Net Worth</div>
                                <div className="text-lg font-semibold">
                                    {(ceoState.metrics.netWorth / 1_000_000).toFixed(2)}M
                                </div>
                            </div>
                            <div className="glass-card p-3">
                                <div className="text-xs text-dark-500 mb-1">Last Action</div>
                                <div className="text-sm font-mono text-dark-300 truncate">
                                    {ceoState.lastAction}
                                </div>
                            </div>
                        </div>

                        {/* Knobs */}
                        <div className="flex gap-6">
                            <KnobMini
                                label="Burn"
                                value={ceoState.knobs.burn_bps}
                                icon={<Flame className="w-3 h-3 text-critical" />}
                                color="bg-critical/20"
                            />
                            <KnobMini
                                label="Auction"
                                value={ceoState.knobs.auction_bps}
                                icon={<Coins className="w-3 h-3 text-accent-400" />}
                                color="bg-accent-500/20"
                            />
                            <KnobMini
                                label="Drip"
                                value={ceoState.knobs.drip_bps}
                                icon={<Droplets className="w-3 h-3 text-info" />}
                                color="bg-info/20"
                            />
                        </div>
                    </>
                )}
                <Glossary terms={CEO_GLOSSARY} title="Metrics & Knobs" />
            </Card>

            {/* CEGIS Summary */}
            <Card className="p-6">
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                        <GitBranch className="w-5 h-5 text-accent-400" />
                        <h2 className="text-lg font-semibold text-white">Verification Loop (CEGIS)</h2>
                    </div>
                    <button
                        onClick={() => navigate('/cegis')}
                        className="text-sm text-dark-400 hover:text-accent-400 flex items-center gap-1"
                    >
                        View Counterexamples <ChevronRight className="w-4 h-4" />
                    </button>
                </div>

                {cegisSummary && (
                    <div className="grid grid-cols-3 gap-4">
                        <div className="glass-card p-3 text-center">
                            <div className="text-2xl font-bold text-white">
                                {cegisSummary.proposals_total.toLocaleString()}
                            </div>
                            <div className="text-xs text-dark-500">Total Proposals</div>
                        </div>
                        <div className="glass-card p-3 text-center">
                            <div className="text-2xl font-bold text-healthy-400">{validRate}%</div>
                            <div className="text-xs text-dark-500">Valid Rate</div>
                        </div>
                        <div className="glass-card p-3 text-center">
                            <div className={`text-2xl font-bold ${cegisSummary.counterexamples > 0 ? 'text-degraded-400' : 'text-dark-300'}`}>
                                {cegisSummary.counterexamples}
                            </div>
                            <div className="text-xs text-dark-500">Counterexamples</div>
                        </div>
                    </div>
                )}
                <Glossary terms={CEGIS_GLOSSARY} title="Term Definitions" />
            </Card>
        </div>
    );
}
