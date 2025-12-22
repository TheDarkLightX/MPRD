/**
 * Autopilot Status Badge
 * 
 * Compact badge showing current autopilot mode with visual indicator.
 */

import { Zap, User, Bot } from 'lucide-react';
import type { AutopilotMode } from '../../api/types';

interface AutopilotStatusBadgeProps {
    mode: AutopilotMode;
    pendingReview?: number;
    compact?: boolean;
    onClick?: () => void;
}

export function AutopilotStatusBadge({
    mode,
    pendingReview = 0,
    compact = false,
    onClick,
}: AutopilotStatusBadgeProps) {
    const config = {
        manual: {
            icon: User,
            label: 'Manual',
            modeClass: 'autopilot-badge-manual',
            textColor: 'text-dark-300',
        },
        assisted: {
            icon: Zap,
            label: 'Assisted',
            modeClass: 'autopilot-badge-assisted',
            textColor: 'text-accent-400',
        },
        autopilot: {
            icon: Bot,
            label: 'Autopilot',
            modeClass: 'autopilot-badge-autopilot',
            textColor: 'text-healthy',
        },
    };

    const { icon: Icon, label, modeClass, textColor } = config[mode];

    const baseClasses = `autopilot-status-badge flex items-center gap-2 rounded-full border ${modeClass}`;
    const sizeClasses = compact ? 'px-2 py-1' : 'px-3 py-1.5';
    const interactiveClasses = onClick ? 'cursor-pointer hover:opacity-80 transition-opacity' : '';

    return (
        <button
            type="button"
            className={`${baseClasses} ${sizeClasses} ${interactiveClasses}`}
            onClick={onClick}
            disabled={!onClick}
        >
            <Icon className={`w-4 h-4 ${textColor}`} />
            {!compact && (
                <span className={`text-sm font-medium ${textColor}`}>{label}</span>
            )}
            {pendingReview > 0 && (
                <span className="text-xs bg-degraded/20 text-degraded px-1.5 py-0.5 rounded-full">
                    {pendingReview}
                </span>
            )}
        </button>
    );
}

