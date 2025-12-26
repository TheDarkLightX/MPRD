/**
 * CEO Status Card - Glanceable summary of Algorithmic CEO state
 *
 * Designed for 1-3 second comprehension. Progressive disclosure via "View Details" link.
 */

import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Brain, TrendingUp, TrendingDown, Minus, ExternalLink } from 'lucide-react';
import { USE_MOCK_DATA } from '../../config';

const MOCK_CEO_SUMMARY = {
    objective: 'ProfitUtility',
    status: 'healthy' as const,
    opi: 9500,
    lastAction: 'SetBurnRate(+1)',
    lastActionEpoch: 42,
    trend: 'up' as const,
};

type CeoSummary = typeof MOCK_CEO_SUMMARY;

function getStatusColor(status: string) {
    switch (status) {
        case 'healthy': return 'text-healthy-400 bg-healthy-500/20';
        case 'degraded': return 'text-degraded-400 bg-degraded-500/20';
        case 'critical': return 'text-critical bg-critical/20';
        default: return 'text-dark-400 bg-dark-800';
    }
}

function TrendIcon({ trend }: { trend: 'up' | 'down' | 'flat' }) {
    switch (trend) {
        case 'up': return <TrendingUp className="w-4 h-4 text-healthy-400" />;
        case 'down': return <TrendingDown className="w-4 h-4 text-critical" />;
        default: return <Minus className="w-4 h-4 text-dark-400" />;
    }
}

export function CeoStatusCard() {
    const navigate = useNavigate();

    const { data: summary } = useQuery<CeoSummary>({
        queryKey: ['ceo_summary'],
        queryFn: async () => {
            if (USE_MOCK_DATA) return MOCK_CEO_SUMMARY;
            const response = await fetch('/api/ceo/summary');
            if (!response.ok) return MOCK_CEO_SUMMARY; // Fallback gracefully
            return response.json();
        },
        refetchInterval: 5000,
    });

    if (!summary) return null;

    const statusColors = getStatusColor(summary.status);

    return (
        <div className="glass-card p-4 hover:bg-dark-800/50 transition-colors">
            {/* Header */}
            <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                    <div className={`p-1.5 rounded-lg ${statusColors}`}>
                        <Brain className="w-4 h-4" />
                    </div>
                    <span className="text-sm font-medium text-white">Controller</span>
                </div>
                <button
                    onClick={() => navigate('/ceo')}
                    className="text-xs text-dark-400 hover:text-accent-400 flex items-center gap-1 transition-colors"
                >
                    Details
                    <ExternalLink className="w-3 h-3" />
                </button>
            </div>

            {/* Glanceable Stats */}
            <div className="grid grid-cols-2 gap-3">
                <div>
                    <div className="text-xs text-dark-500 mb-0.5">Objective</div>
                    <div className="text-sm font-medium text-dark-200">
                        {summary.objective === 'ProfitUtility' ? 'Profit' :
                            summary.objective === 'OpiFirst' ? 'OPI' : 'Hybrid'}
                    </div>
                </div>
                <div>
                    <div className="text-xs text-dark-500 mb-0.5">OPI</div>
                    <div className="flex items-center gap-1">
                        <span className="text-sm font-medium text-dark-200">
                            {summary.opi.toLocaleString()}
                        </span>
                        <TrendIcon trend={summary.trend} />
                    </div>
                </div>
            </div>

            {/* Last Action */}
            <div className="mt-3 pt-2 border-t border-dark-800">
                <div className="text-xs text-dark-500">
                    Last: <span className="font-mono text-dark-400">{summary.lastAction}</span>
                    <span className="text-dark-600 ml-1">(epoch {summary.lastActionEpoch})</span>
                </div>
            </div>
        </div>
    );
}
