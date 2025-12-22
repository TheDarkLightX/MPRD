/**
 * Glanceable Header Component
 * 
 * Top-of-page summary using Algorithm 12 output.
 * Designed for 1-3 second comprehension.
 * 
 * REDESIGNED: Premium gradients, enhanced animations, attention progress bar.
 * 
 * @design No numbers in primary view, single headline answers "Do I need to do anything?"
 */

import { useNavigate } from 'react-router-dom';
import {
    ArrowUp,
    ArrowDown,
    Minus,
    AlertCircle,
    AlertTriangle,
    Info,
    CheckCircle,
    Zap,
    Clock,
    TrendingUp,
    TrendingDown,
    Activity,
} from 'lucide-react';
import type { GlanceableView, TrendDirection, Severity } from '../../api/types';
import { Button } from '../ui';

// =============================================================================
// Gradient & Style Maps
// =============================================================================

const severityGradients: Record<Severity, string> = {
    critical: 'from-critical-500/20 via-critical-600/10 to-transparent',
    warning: 'from-degraded-500/15 via-degraded-600/5 to-transparent',
    info: 'from-accent-500/10 via-accent-600/5 to-transparent',
    ok: 'from-healthy-500/10 via-healthy-600/5 to-transparent',
};

const severityBorders: Record<Severity, string> = {
    critical: 'border-critical-500/40',
    warning: 'border-degraded-500/30',
    info: 'border-accent-500/30',
    ok: 'border-healthy-500/30',
};

const severityGlows: Record<Severity, string> = {
    critical: 'shadow-glow-critical',
    warning: 'shadow-glow-degraded',
    info: 'shadow-glow-accent',
    ok: 'shadow-glow-healthy',
};

const severityIconColors: Record<Severity, string> = {
    critical: 'text-critical-400',
    warning: 'text-degraded-400',
    info: 'text-accent-400',
    ok: 'text-healthy-400',
};

// =============================================================================
// Sub-components
// =============================================================================

function SeverityIcon({ severity }: { severity: Severity }) {
    const colorClass = severityIconColors[severity];
    const animationClass = severity === 'critical' ? 'animate-pulse' : '';
    const baseClass = `w-6 h-6 ${colorClass} ${animationClass}`;

    switch (severity) {
        case 'critical':
            return (
                <div className="relative">
                    <AlertCircle className={baseClass} />
                    <div className="absolute inset-0 rounded-full animate-ping opacity-30 bg-critical-500" />
                </div>
            );
        case 'warning':
            return <AlertTriangle className={baseClass} />;
        case 'info':
            return <Info className={baseClass} />;
        case 'ok':
            return <CheckCircle className={baseClass} />;
    }
}

function TrendArrow({ direction, inverted = false }: { direction: TrendDirection; inverted?: boolean }) {
    const isGood = inverted ? direction === 'down' : direction === 'up';
    const isBad = inverted ? direction === 'up' : direction === 'down';

    if (direction === 'stable') {
        return <Minus className="w-4 h-4 text-dark-400" />;
    }

    const colorClass = isGood ? 'text-healthy-400' : isBad ? 'text-critical-400' : 'text-dark-400';
    const Icon = direction === 'up' ? ArrowUp : ArrowDown;

    return <Icon className={`w-4 h-4 ${colorClass} transition-colors duration-300`} />;
}

function TrendBadge({ label, direction, inverted = false }: { label: string; direction: TrendDirection; inverted?: boolean }) {
    const isGood = inverted ? direction === 'down' : direction === 'up';
    const isBad = inverted ? direction === 'up' : direction === 'down';

    const bgClass = direction === 'stable'
        ? 'bg-dark-800/50'
        : isGood
            ? 'bg-healthy-500/10'
            : isBad
                ? 'bg-critical-500/10'
                : 'bg-dark-800/50';

    return (
        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full ${bgClass} transition-all duration-300 hover:scale-105`}>
            <span className="text-xs text-dark-300">{label}</span>
            <TrendArrow direction={direction} inverted={inverted} />
        </div>
    );
}

function AutopilotBadgeDisplay({ badge }: { badge: GlanceableView['autopilotBadge'] }) {
    if (!badge) return null;

    const isAutopilot = badge.mode === 'autopilot';
    const modeLabel = isAutopilot ? 'Autopilot' : 'Assisted';
    const modeColor = isAutopilot ? 'text-accent-400' : 'text-dark-300';
    const bgColor = isAutopilot ? 'bg-accent-500/10 border-accent-500/30' : 'bg-dark-800/50 border-dark-700';

    return (
        <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border ${bgColor} transition-all duration-300 hover:scale-105`}>
            <Zap className={`w-4 h-4 ${modeColor} ${isAutopilot ? 'animate-pulse' : ''}`} />
            <span className={`text-sm font-medium ${modeColor}`}>{modeLabel}</span>
            {badge.pendingReview > 0 && (
                <span className="text-xs bg-accent-500/20 text-accent-400 px-2 py-0.5 rounded-full animate-pulse">
                    {badge.pendingReview}
                </span>
            )}
        </div>
    );
}

function AttentionProgressBar({ demand }: { demand: GlanceableView['attentionDemand'] }) {
    const percentage = Math.min((demand.itemsNeedingAction / 10) * 100, 100);
    const isOverBudget = !demand.withinBudget;

    return (
        <div className="w-full max-w-xs">
            <div className="flex items-center justify-between text-xs mb-1">
                <span className="text-dark-400">Attention Load</span>
                <span className={isOverBudget ? 'text-degraded-400' : 'text-dark-400'}>
                    {demand.itemsNeedingAction} items
                </span>
            </div>
            <div className="h-1.5 bg-dark-800 rounded-full overflow-hidden">
                <div
                    className={`h-full rounded-full transition-all duration-500 ${isOverBudget
                            ? 'bg-gradient-to-r from-degraded-500 to-critical-500'
                            : 'bg-gradient-to-r from-accent-500 to-purple-500'
                        }`}
                    style={{ width: `${percentage}%` }}
                />
            </div>
        </div>
    );
}

// =============================================================================
// Main Component
// =============================================================================

interface GlanceableHeaderProps {
    view: GlanceableView;
    onNextActionClick?: () => void;
}

export function GlanceableHeader({ view, onNextActionClick }: GlanceableHeaderProps) {
    const navigate = useNavigate();

    const handleNextAction = () => {
        if (onNextActionClick) {
            onNextActionClick();
        } else if (view.nextAction) {
            navigate(view.nextAction.route);
        }
    };

    const isCritical = view.headlineSeverity === 'critical';

    return (
        <div
            className={`
                relative overflow-hidden rounded-2xl border p-5
                bg-gradient-to-br ${severityGradients[view.headlineSeverity]}
                ${severityBorders[view.headlineSeverity]}
                ${isCritical ? severityGlows.critical : ''}
                transition-all duration-500 animate-in fade-in
            `}
        >
            {/* Animated background shimmer for critical */}
            {isCritical && (
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-critical-500/5 to-transparent animate-shimmer" />
            )}

            {/* Top Row: Headline + Actions */}
            <div className="relative flex items-start justify-between gap-4 mb-4">
                {/* Left: Icon + Headline */}
                <div className="flex items-start gap-4 min-w-0">
                    <div className={`flex-shrink-0 p-2 rounded-xl ${view.headlineSeverity === 'critical' ? 'bg-critical-500/10' :
                            view.headlineSeverity === 'warning' ? 'bg-degraded-500/10' :
                                view.headlineSeverity === 'ok' ? 'bg-healthy-500/10' :
                                    'bg-accent-500/10'
                        }`}>
                        <SeverityIcon severity={view.headlineSeverity} />
                    </div>
                    <div className="min-w-0">
                        <h2 className="text-xl font-semibold text-gray-100 truncate">
                            {view.headline}
                        </h2>
                        {view.trendNarrative && (
                            <p className={`text-sm mt-1 ${view.trendNarrative.startsWith('Improving') ? 'text-healthy-400' :
                                    view.trendNarrative.startsWith('Degrading') ? 'text-critical-400' :
                                        'text-dark-300'
                                }`}>
                                {view.trendNarrative.startsWith('Improving') && <TrendingUp className="w-4 h-4 inline mr-1" />}
                                {view.trendNarrative.startsWith('Degrading') && <TrendingDown className="w-4 h-4 inline mr-1" />}
                                {view.trendNarrative}
                            </p>
                        )}
                        {view.nextAction && (
                            <p className="text-sm text-dark-400 flex items-center gap-1.5 mt-2">
                                <Clock className="w-3.5 h-3.5" />
                                <span>~{view.attentionDemand.estimatedMinutes} min to resolve</span>
                            </p>
                        )}
                    </div>
                </div>

                {/* Right: Autopilot + CTA */}
                <div className="flex items-center gap-3 flex-shrink-0">
                    <AutopilotBadgeDisplay badge={view.autopilotBadge} />
                    {view.nextAction && (
                        <Button
                            variant={view.headlineSeverity === 'critical' ? 'danger' : 'primary'}
                            size="sm"
                            onClick={handleNextAction}
                            className="whitespace-nowrap"
                        >
                            {view.nextAction.label}
                        </Button>
                    )}
                </div>
            </div>

            {/* Bottom Row: Trends + Attention Bar */}
            <div className="relative flex items-center justify-between gap-6 pt-4 border-t border-dark-700/30">
                {/* Trend badges */}
                <div className="flex items-center gap-3">
                    <TrendBadge label="Decisions" direction={view.trends.decisions} />
                    <TrendBadge label="Success" direction={view.trends.success} />
                    <TrendBadge label="Latency" direction={view.trends.latency} inverted />

                    {/* Live indicator */}
                    <div className="flex items-center gap-1.5 text-xs text-dark-500 ml-2">
                        <Activity className="w-3.5 h-3.5 text-accent-400 animate-pulse" />
                        <span>Live</span>
                    </div>
                </div>

                {/* Attention progress bar */}
                {view.attentionDemand.itemsNeedingAction > 0 && (
                    <AttentionProgressBar demand={view.attentionDemand} />
                )}
            </div>
        </div>
    );
}
