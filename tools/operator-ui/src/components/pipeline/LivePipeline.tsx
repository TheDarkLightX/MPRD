/**
 * Live Pipeline Visualization
 * 
 * Shows the 8-stage MPRD pipeline with real-time status updates.
 * Per spec Section 5.3: "Show every stage... Indicate current stage... Show timing per stage"
 * 
 * REDESIGNED: Connected node track with animated flow, glowing active stage.
 */

import { useMemo } from 'react';
import type { LivePipelineState, PipelineStage, PipelineStageInfo, StageStatus } from '../../api/types';
import { Card, CardHeader, HashBadge } from '../ui';
import {
    Database,
    Lightbulb,
    Scale,
    Target,
    Ticket,
    ShieldCheck,
    CheckCircle2,
    Play,
    Activity,
} from 'lucide-react';

// =============================================================================
// Pipeline Configuration
// =============================================================================

const PIPELINE_STAGES: {
    stage: PipelineStage;
    label: string;
    icon: typeof Database;
}[] = [
        { stage: 'state', label: 'State', icon: Database },
        { stage: 'propose', label: 'Propose', icon: Lightbulb },
        { stage: 'evaluate', label: 'Evaluate', icon: Scale },
        { stage: 'select', label: 'Select', icon: Target },
        { stage: 'token', label: 'Token', icon: Ticket },
        { stage: 'attest', label: 'Attest', icon: ShieldCheck },
        { stage: 'verify', label: 'Verify', icon: CheckCircle2 },
        { stage: 'execute', label: 'Execute', icon: Play },
    ];

// =============================================================================
// Styles & Colors
// =============================================================================

const statusStyles: Record<StageStatus, {
    nodeClass: string;
    iconClass: string;
    connectorClass: string;
    labelClass: string;
}> = {
    pending: {
        nodeClass: 'bg-dark-800/50 border-dark-700',
        iconClass: 'text-dark-500',
        connectorClass: 'bg-dark-700',
        labelClass: 'text-dark-500',
    },
    active: {
        nodeClass: 'bg-accent-500/20 border-accent-500 shadow-glow-accent',
        iconClass: 'text-accent-400',
        connectorClass: 'bg-gradient-to-r from-accent-500 to-accent-500/20',
        labelClass: 'text-accent-400 font-medium',
    },
    complete: {
        nodeClass: 'bg-healthy-500/10 border-healthy-500/50',
        iconClass: 'text-healthy-400',
        connectorClass: 'bg-healthy-500',
        labelClass: 'text-healthy-400',
    },
    failed: {
        nodeClass: 'bg-critical-500/10 border-critical-500/50 shadow-glow-critical',
        iconClass: 'text-critical-400',
        connectorClass: 'bg-critical-500',
        labelClass: 'text-critical-400',
    },
};

// =============================================================================
// Pipeline Node Component
// =============================================================================

function PipelineNode({
    label,
    icon: Icon,
    info,
    isLast = false,
    index,
}: {
    stage: PipelineStage;
    label: string;
    icon: typeof Database;
    info?: PipelineStageInfo;
    isLast?: boolean;
    index: number;
}) {
    const status = info?.status || 'pending';
    const styles = statusStyles[status];
    const isActive = status === 'active';

    return (
        <div
            className="flex items-center animate-in fade-in-up"
            style={{ animationDelay: `${index * 50}ms` }}
        >
            {/* Node */}
            <div className="relative flex flex-col items-center">
                {/* Circle node */}
                <div className={`
                    relative w-12 h-12 rounded-xl flex items-center justify-center
                    border-2 transition-all duration-300
                    ${styles.nodeClass}
                    ${isActive ? 'animate-breathe' : ''}
                `}>
                    <Icon className={`w-5 h-5 ${styles.iconClass}`} />

                    {/* Pulse ring for active */}
                    {isActive && (
                        <div className="absolute inset-0 rounded-xl border-2 border-accent-500 animate-ping opacity-30" />
                    )}

                    {/* Duration badge */}
                    {info?.durationMs !== undefined && status !== 'pending' && (
                        <div className="absolute -bottom-1 -right-1 px-1.5 py-0.5 rounded text-[10px] bg-dark-800 border border-dark-700 text-dark-300">
                            {info.durationMs}ms
                        </div>
                    )}
                </div>

                {/* Label */}
                <span className={`mt-2 text-xs ${styles.labelClass} transition-colors duration-200`}>
                    {label}
                </span>

                {/* Progress indicator for active */}
                {isActive && (
                    <div className="absolute -bottom-4 flex items-center gap-0.5">
                        <span className="w-1 h-1 rounded-full bg-accent-400 animate-bounce" style={{ animationDelay: '0ms' }} />
                        <span className="w-1 h-1 rounded-full bg-accent-400 animate-bounce" style={{ animationDelay: '150ms' }} />
                        <span className="w-1 h-1 rounded-full bg-accent-400 animate-bounce" style={{ animationDelay: '300ms' }} />
                    </div>
                )}
            </div>

            {/* Connector line */}
            {!isLast && (
                <div className="relative w-8 h-0.5 mx-1">
                    {/* Base line */}
                    <div className="absolute inset-0 bg-dark-700 rounded-full" />
                    {/* Progress overlay */}
                    {(status === 'complete' || status === 'active') && (
                        <div
                            className={`absolute inset-y-0 left-0 rounded-full ${styles.connectorClass} transition-all duration-500`}
                            style={{ width: status === 'complete' ? '100%' : '50%' }}
                        />
                    )}
                    {/* Flow animation for active */}
                    {isActive && (
                        <div className="absolute inset-0 overflow-hidden rounded-full">
                            <div className="w-2 h-full bg-gradient-to-r from-transparent via-accent-400 to-transparent animate-shimmer" />
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

// =============================================================================
// Compact Pipeline View
// =============================================================================

function CompactPipeline({ stageMap }: { stageMap: Map<PipelineStage, PipelineStageInfo> }) {
    return (
        <div className="flex items-center gap-1">
            {PIPELINE_STAGES.map((s) => {
                const info = stageMap.get(s.stage);
                const status = info?.status || 'pending';

                const dotClass = {
                    pending: 'bg-dark-600',
                    active: 'bg-accent-400 animate-pulse',
                    complete: 'bg-healthy-400',
                    failed: 'bg-critical-400',
                }[status];

                return (
                    <div
                        key={s.stage}
                        className={`w-2 h-2 rounded-full ${dotClass} transition-colors duration-200`}
                        title={`${s.label}: ${status}`}
                    />
                );
            })}
        </div>
    );
}

// =============================================================================
// Main Component
// =============================================================================

interface LivePipelineProps {
    state: LivePipelineState | null;
    compact?: boolean;
    connected?: boolean | null;
}

export function LivePipeline({ state, compact = false, connected = null }: LivePipelineProps) {
    // Create a map of stage status
    const stageMap = useMemo(() => {
        const map = new Map<PipelineStage, PipelineStageInfo>();
        if (state?.stages) {
            for (const info of state.stages) {
                map.set(info.stage, info);
            }
        }
        return map;
    }, [state]);

    // Check if pipeline is idle
    const isIdle = !state || state.stages.length === 0;
    const hasError = state?.stages.some(s => s.status === 'failed');
    const activeStage = state?.stages.find(s => s.status === 'active');

    if (compact) {
        return <CompactPipeline stageMap={stageMap} />;
    }

    return (
        <Card className={hasError ? 'border-critical-500/30' : ''}>
            <CardHeader
                title="Live Pipeline"
                subtitle={
                    isIdle
                        ? 'Waiting for next decision...'
                        : activeStage
                            ? `Processing: ${activeStage.stage}`
                            : 'Processing decision'
                }
                action={
                    connected === false ? (
                        <div className="flex items-center gap-2 text-xs">
                            <Activity className="w-4 h-4 text-degraded" />
                            <span className="text-dark-400">Disconnected</span>
                        </div>
                    ) : connected === true && (
                        <div className="flex items-center gap-2 text-xs">
                            <Activity className="w-4 h-4 text-accent-400 animate-pulse" />
                            <span className="text-dark-400">Live</span>
                        </div>
                    )
                }
            />

            {/* Stage visualization */}
            <div className="flex items-start justify-center py-4 overflow-x-auto">
                <div className="flex items-start gap-1">
                    {PIPELINE_STAGES.map((s, i) => (
                        <PipelineNode
                            key={s.stage}
                            stage={s.stage}
                            label={s.label}
                            icon={s.icon}
                            info={stageMap.get(s.stage)}
                            isLast={i === PIPELINE_STAGES.length - 1}
                            index={i}
                        />
                    ))}
                </div>
            </div>

            {/* Current context */}
            {state && !isIdle && (
                <div className="mt-4 pt-4 border-t border-dark-700/50 flex flex-wrap gap-4 text-sm">
                    {state.policyHash && (
                        <div className="flex items-center gap-2">
                            <span className="text-dark-500 text-xs uppercase tracking-wide">Policy</span>
                            <HashBadge hash={state.policyHash} />
                        </div>
                    )}
                    {state.stateHash && (
                        <div className="flex items-center gap-2">
                            <span className="text-dark-500 text-xs uppercase tracking-wide">State</span>
                            <HashBadge hash={state.stateHash} />
                        </div>
                    )}
                    {state.candidateCount !== undefined && (
                        <div className="flex items-center gap-2 text-dark-300">
                            <span className="text-dark-500 text-xs uppercase tracking-wide">Candidates</span>
                            <span className="font-mono">{state.candidateCount}</span>
                        </div>
                    )}
                </div>
            )}

            {/* Error display */}
            {hasError && (
                <div className="mt-4 p-3 bg-critical-500/10 border border-critical-500/30 rounded-lg text-sm text-critical-400 flex items-start gap-2">
                    <span className="text-critical-500">⚠</span>
                    <span>{state?.stages.find(s => s.status === 'failed')?.error || 'Pipeline failed'}</span>
                </div>
            )}
        </Card>
    );
}
