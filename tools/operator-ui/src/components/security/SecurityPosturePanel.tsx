/**
 * Security Posture Panel
 * 
 * Displays trust and availability posture from Algorithm 1 output.
 * Located in Dashboard sidebar for quick visibility.
 * 
 * REDESIGNED: Shield visualization with animated rings, gradient progress bars.
 */

import { Shield, CheckCircle, AlertTriangle, XCircle, Settings, Activity } from 'lucide-react';
import type { SecurityPosture, TrustLevel, AvailabilityLevel } from '../../api/types';
import { Card, CardHeader, Button } from '../ui';

// =============================================================================
// Types & Config
// =============================================================================

interface SecurityPosturePanelProps {
    posture: SecurityPosture;
    onConfigureTrust?: () => void;
}

const levelConfig: Record<TrustLevel | AvailabilityLevel, {
    color: string;
    bgColor: string;
    icon: typeof CheckCircle;
    label: string;
    glowClass: string;
}> = {
    healthy: {
        color: 'text-healthy-400',
        bgColor: 'bg-healthy-500',
        icon: CheckCircle,
        label: 'Healthy',
        glowClass: 'shadow-glow-healthy',
    },
    degraded: {
        color: 'text-degraded-400',
        bgColor: 'bg-degraded-500',
        icon: AlertTriangle,
        label: 'Degraded',
        glowClass: 'shadow-glow-degraded',
    },
    critical: {
        color: 'text-critical-400',
        bgColor: 'bg-critical-500',
        icon: XCircle,
        label: 'Critical',
        glowClass: 'shadow-glow-critical',
    },
};

// =============================================================================
// Shield Visualization
// =============================================================================

function ShieldViz({ trustLevel, availabilityLevel }: { trustLevel: TrustLevel; availabilityLevel: AvailabilityLevel }) {
    const trustConfig = levelConfig[trustLevel];
    const availConfig = levelConfig[availabilityLevel];
    const isHealthy = trustLevel === 'healthy' && availabilityLevel === 'healthy';
    const isCritical = trustLevel === 'critical' || availabilityLevel === 'critical';

    return (
        <div className="relative w-20 h-20 mx-auto mb-4">
            {/* Outer glow ring */}
            <div className={`
                absolute inset-0 rounded-full opacity-30 blur-md
                ${isHealthy ? 'bg-healthy-500' : isCritical ? 'bg-critical-500' : 'bg-degraded-500'}
            `} />

            {/* Animated rings */}
            <svg className="absolute inset-0 w-full h-full -rotate-90">
                {/* Availability ring (outer) */}
                <circle
                    cx="40"
                    cy="40"
                    r="36"
                    fill="none"
                    className="stroke-dark-700/30"
                    strokeWidth="4"
                />
                <circle
                    cx="40"
                    cy="40"
                    r="36"
                    fill="none"
                    className={`${availConfig.color.replace('text-', 'stroke-')} transition-all duration-700`}
                    strokeWidth="4"
                    strokeLinecap="round"
                    strokeDasharray={`${226 * (availabilityLevel === 'healthy' ? 1 : availabilityLevel === 'degraded' ? 0.7 : 0.3)} 226`}
                />

                {/* Trust ring (inner) */}
                <circle
                    cx="40"
                    cy="40"
                    r="28"
                    fill="none"
                    className="stroke-dark-700/30"
                    strokeWidth="4"
                />
                <circle
                    cx="40"
                    cy="40"
                    r="28"
                    fill="none"
                    className={`${trustConfig.color.replace('text-', 'stroke-')} transition-all duration-700`}
                    strokeWidth="4"
                    strokeLinecap="round"
                    strokeDasharray={`${176 * (trustLevel === 'healthy' ? 1 : trustLevel === 'degraded' ? 0.7 : 0.3)} 176`}
                />
            </svg>

            {/* Center shield icon */}
            <div className="absolute inset-0 flex items-center justify-center">
                <Shield className={`w-8 h-8 ${isHealthy ? 'text-healthy-400' : isCritical ? 'text-critical-400 animate-pulse' : 'text-degraded-400'}`} />
            </div>
        </div>
    );
}

// =============================================================================
// Progress Bar
// =============================================================================

function PostureBar({ label, level, value }: { label: string; level: TrustLevel | AvailabilityLevel; value: number }) {
    const config = levelConfig[level];
    const percentage = Math.min(Math.max(value * 100, 0), 100);

    return (
        <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs">
                <span className="text-dark-400">{label}</span>
                <div className="flex items-center gap-1.5">
                    <config.icon className={`w-3 h-3 ${config.color}`} />
                    <span className={config.color}>{config.label}</span>
                </div>
            </div>
            <div className="h-2 bg-dark-800 rounded-full overflow-hidden">
                <div
                    className={`h-full rounded-full ${config.bgColor} transition-all duration-700 ease-out`}
                    style={{ width: `${percentage}%` }}
                />
            </div>
        </div>
    );
}

// =============================================================================
// Metrics Display
// =============================================================================

function MetricRow({ label, value, unit, warning = false }: { label: string; value: number; unit?: string; warning?: boolean }) {
    return (
        <div className="flex items-center justify-between py-1.5 text-xs">
            <span className="text-dark-400">{label}</span>
            <span className={`font-mono ${warning ? 'text-degraded-400' : 'text-gray-300'}`}>
                {(value * 100).toFixed(1)}{unit || '%'}
            </span>
        </div>
    );
}

// =============================================================================
// Main Component
// =============================================================================

export function SecurityPosturePanel({ posture, onConfigureTrust }: SecurityPosturePanelProps) {
    const { trustLevel, availabilityLevel, metrics } = posture;
    const trustScore = trustLevel === 'healthy' ? 1 : trustLevel === 'degraded' ? 0.7 : 0.3;
    const availScore = availabilityLevel === 'healthy' ? 1 : availabilityLevel === 'degraded' ? 0.7 : 0.3;

    return (
        <Card className="animate-in slide-in-right">
            <CardHeader
                title="Security Posture"
                action={
                    <div className="flex items-center gap-1 text-xs text-dark-500">
                        <Activity className="w-3 h-3 text-accent-400" />
                        <span>Live</span>
                    </div>
                }
            />

            {/* Shield visualization */}
            <ShieldViz trustLevel={trustLevel} availabilityLevel={availabilityLevel} />

            {/* Progress bars */}
            <div className="space-y-3">
                <PostureBar label="Trust Level" level={trustLevel} value={trustScore} />
                <PostureBar label="Availability" level={availabilityLevel} value={availScore} />
            </div>

            {/* Metrics breakdown */}
            <div className="mt-4 pt-4 border-t border-dark-700/50">
                <p className="text-xs text-dark-500 uppercase tracking-wide mb-2">Metrics</p>
                <MetricRow label="Fail Rate" value={metrics.failRate} warning={metrics.failRate > 0.05} />
                <MetricRow label="Verify Fail" value={metrics.verifyFailRate} warning={metrics.verifyFailRate > 0.01} />
                <MetricRow label="Exec Fail" value={metrics.execFailRate} warning={metrics.execFailRate > 0.01} />
                <MetricRow
                    label="Rate"
                    value={metrics.decisionRate}
                    unit="/min"
                />
            </div>

            {/* Configure button */}
            {onConfigureTrust && (
                <Button
                    variant="ghost"
                    size="sm"
                    className="w-full mt-4 justify-center"
                    onClick={onConfigureTrust}
                >
                    <Settings className="w-4 h-4 mr-2" />
                    Configure Trust
                </Button>
            )}
        </Card>
    );
}
