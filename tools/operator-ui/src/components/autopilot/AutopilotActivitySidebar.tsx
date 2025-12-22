/**
 * Autopilot Activity Sidebar
 * 
 * List of recent autopilot actions with explanations from Algorithm 11.
 */

import { Clock, ChevronRight, Undo2 } from 'lucide-react';
import type { AutoAction } from '../../api/types';
import { Card, CardHeader, Button } from '../ui';

interface AutopilotActivitySidebarProps {
    actions: AutoAction[];
    onOverride?: (actionId: string) => void;
    maxItems?: number;
}

function formatTimeAgo(timestamp: number): string {
    const now = Date.now();
    const diff = now - timestamp;

    if (diff < 60_000) return 'just now';
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return new Date(timestamp).toLocaleDateString();
}

function ActionTypeIcon({ type }: { type: AutoAction['type'] }) {
    const colors = {
        auto_dismiss: 'text-dark-400',
        auto_correlate: 'text-accent-400',
        auto_execute: 'text-healthy',
        auto_degrade: 'text-degraded',
    };

    return (
        <div className={`w-2 h-2 rounded-full ${colors[type].replace('text-', 'bg-')}`} />
    );
}

export function AutopilotActivitySidebar({
    actions,
    onOverride,
    maxItems = 10,
}: AutopilotActivitySidebarProps) {
    const displayedActions = actions.slice(0, maxItems);

    return (
        <Card className="w-full max-w-sm">
            <CardHeader
                title="Autopilot Activity"
                subtitle={`${actions.length} actions`}
            />

            {displayedActions.length === 0 ? (
                <p className="text-sm text-dark-400 py-4">No recent autopilot actions</p>
            ) : (
                <div className="space-y-3">
                    {displayedActions.map((action) => (
                        <div
                            key={action.id}
                            className="p-3 rounded-lg bg-dark-800/50 border border-dark-700 hover:border-dark-600 transition-colors"
                        >
                            <div className="flex items-start justify-between gap-2">
                                <div className="flex items-start gap-2 min-w-0">
                                    <ActionTypeIcon type={action.type} />
                                    <div className="min-w-0">
                                        <p className="text-sm font-medium text-gray-100 truncate">
                                            {action.explanation.summary}
                                        </p>
                                        <p className="text-xs text-dark-400 mt-1">
                                            {action.explanation.evidence}
                                        </p>
                                    </div>
                                </div>

                                <div className="flex items-center gap-1 text-xs text-dark-500 whitespace-nowrap">
                                    <Clock className="w-3 h-3" />
                                    {formatTimeAgo(action.timestamp)}
                                </div>
                            </div>

                            {/* Confidence and override */}
                            <div className="flex items-center justify-between mt-2 pt-2 border-t border-dark-700/50">
                                <span className="text-xs text-dark-500">
                                    {Math.round(action.explanation.confidence * 100)}% confidence
                                </span>

                                <div className="flex items-center gap-2">
                                    {action.reversible && onOverride && (
                                        <button
                                            type="button"
                                            className="flex items-center gap-1 text-xs text-dark-400 hover:text-gray-100 transition-colors"
                                            onClick={() => onOverride(action.id)}
                                        >
                                            <Undo2 className="w-3 h-3" />
                                            Override
                                        </button>
                                    )}
                                    <button
                                        type="button"
                                        className="flex items-center gap-1 text-xs text-dark-400 hover:text-gray-100 transition-colors"
                                    >
                                        Details
                                        <ChevronRight className="w-3 h-3" />
                                    </button>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {actions.length > maxItems && (
                <div className="mt-3 pt-3 border-t border-dark-700">
                    <Button variant="ghost" size="sm" className="w-full">
                        View all {actions.length} actions
                    </Button>
                </div>
            )}
        </Card>
    );
}
