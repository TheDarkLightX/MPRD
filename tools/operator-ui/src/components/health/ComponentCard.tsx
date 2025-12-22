/**
 * Component Health Card
 * 
 * Displays the status of a single MPRD component.
 * Per spec Section 5.1: "Failures are LOUD"
 * 
 * REDESIGNED: Radial health indicator, gradient backgrounds, smooth animations.
 */

import type { ComponentHealth, HealthLevel } from '../../api/types';
import { CheckCircle2, AlertTriangle, XCircle, Clock, Activity } from 'lucide-react';
import { Badge } from '../ui';

// =============================================================================
// Types & Config
// =============================================================================

interface ComponentCardProps {
    name: string;
    health: ComponentHealth;
    icon?: React.ReactNode;
}

const statusConfig: Record<HealthLevel, {
    icon: typeof CheckCircle2;
    color: string;
    bgGradient: string;
    borderColor: string;
    glowClass: string;
    ringColor: string;
}> = {
    healthy: {
        icon: CheckCircle2,
        color: 'text-healthy-400',
        bgGradient: 'from-healthy-500/5 to-transparent',
        borderColor: 'border-healthy-500/20 hover:border-healthy-500/40',
        glowClass: '',
        ringColor: 'stroke-healthy-500',
    },
    degraded: {
        icon: AlertTriangle,
        color: 'text-degraded-400',
        bgGradient: 'from-degraded-500/5 to-transparent',
        borderColor: 'border-degraded-500/20 hover:border-degraded-500/40',
        glowClass: '',
        ringColor: 'stroke-degraded-500',
    },
    unavailable: {
        icon: XCircle,
        color: 'text-critical-400',
        bgGradient: 'from-critical-500/10 to-transparent',
        borderColor: 'border-critical-500/30 hover:border-critical-500/50',
        glowClass: 'shadow-glow-critical',
        ringColor: 'stroke-critical-500',
    },
};

// =============================================================================
// Ring Indicator
// =============================================================================

function HealthRing({ status, size = 40 }: { status: HealthLevel; size?: number }) {
    const config = statusConfig[status];
    const strokeWidth = 3;
    const radius = (size - strokeWidth) / 2;
    const circumference = 2 * Math.PI * radius;

    // Full ring for healthy, less for degraded/unavailable
    const progress = status === 'healthy' ? 1 : status === 'degraded' ? 0.7 : 0.3;
    const dashOffset = circumference * (1 - progress);

    return (
        <div className="relative" style={{ width: size, height: size }}>
            <svg className="w-full h-full -rotate-90">
                {/* Background ring */}
                <circle
                    cx={size / 2}
                    cy={size / 2}
                    r={radius}
                    fill="none"
                    className="stroke-dark-700/50"
                    strokeWidth={strokeWidth}
                />
                {/* Progress ring */}
                <circle
                    cx={size / 2}
                    cy={size / 2}
                    r={radius}
                    fill="none"
                    className={`${config.ringColor} transition-all duration-700 ease-out`}
                    strokeWidth={strokeWidth}
                    strokeLinecap="round"
                    strokeDasharray={circumference}
                    strokeDashoffset={dashOffset}
                />
            </svg>
            {/* Center icon */}
            <div className="absolute inset-0 flex items-center justify-center">
                <config.icon className={`w-4 h-4 ${config.color}`} />
            </div>
        </div>
    );
}

// =============================================================================
// Utilities
// =============================================================================

function formatLastCheck(timestamp: number): string {
    const now = Date.now();
    const diff = now - timestamp;

    if (diff < 5000) return 'just now';
    if (diff < 60000) return `${Math.floor(diff / 1000)}s ago`;
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    return `${Math.floor(diff / 3600000)}h ago`;
}

// =============================================================================
// Main Component
// =============================================================================

export function ComponentCard({ name, health, icon }: ComponentCardProps) {
    const config = statusConfig[health.status];
    const isUnhealthy = health.status !== 'healthy';

    return (
        <div className={`
            group relative overflow-hidden rounded-xl p-4
            bg-gradient-to-br ${config.bgGradient} bg-dark-900/50
            border ${config.borderColor}
            ${config.glowClass}
            transition-all duration-300 hover:translate-y-[-2px]
            animate-in fade-in-up
        `}>
            {/* Shimmer on unhealthy */}
            {isUnhealthy && (
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/[0.02] to-transparent animate-shimmer" />
            )}

            <div className="relative flex items-start justify-between gap-3">
                {/* Left: Icon + Name */}
                <div className="flex items-center gap-3 min-w-0">
                    {icon && (
                        <div className={`p-2 rounded-lg bg-dark-800/50 ${config.color} transition-colors duration-200`}>
                            {icon}
                        </div>
                    )}
                    <div className="min-w-0">
                        <h4 className="font-medium text-gray-100 truncate">{name}</h4>
                        {health.version && (
                            <p className="text-xs text-dark-500">v{health.version}</p>
                        )}
                    </div>
                </div>

                {/* Right: Health Ring */}
                <HealthRing status={health.status} size={40} />
            </div>

            {/* Error message */}
            {health.message && health.status !== 'healthy' && (
                <p className={`mt-3 text-sm ${config.color} truncate`}>
                    {health.message}
                </p>
            )}

            {/* Footer: Last check */}
            <div className="mt-3 pt-3 border-t border-dark-700/30 flex items-center justify-between text-xs text-dark-500">
                <div className="flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {formatLastCheck(health.lastCheck)}
                </div>
                {health.status === 'healthy' && (
                    <div className="flex items-center gap-1 text-healthy-500">
                        <Activity className="w-3 h-3" />
                        <span>Active</span>
                    </div>
                )}
            </div>
        </div>
    );
}

// =============================================================================
// System Status Header
// =============================================================================

export function SystemStatusHeader({ status }: { status: 'operational' | 'degraded' | 'critical' }) {
    const config = {
        operational: {
            variant: 'healthy' as const,
            label: 'OPERATIONAL',
            bgClass: 'bg-healthy-500/10',
        },
        degraded: {
            variant: 'degraded' as const,
            label: 'DEGRADED',
            bgClass: 'bg-degraded-500/10',
        },
        critical: {
            variant: 'critical' as const,
            label: 'CRITICAL',
            bgClass: 'bg-critical-500/10',
        },
    };

    const { variant, label, bgClass } = config[status];

    return (
        <div className={`flex items-center justify-between p-3 rounded-lg ${bgClass} mb-4`}>
            <h2 className="text-lg font-semibold text-gray-100">System Status</h2>
            <Badge variant={variant} size="md" dot>
                {label}
            </Badge>
        </div>
    );
}
