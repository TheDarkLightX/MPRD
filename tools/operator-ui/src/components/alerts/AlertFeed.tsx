/**
 * Alert Feed Component
 * 
 * Displays recent alerts with severity indicators.
 * Per spec Section 5.1: "Failures are LOUD — Red banners, not subtle icons"
 */

import type { Alert, AlertSeverity } from '../../api/types';
import { Card, CardHeader, Button } from '../ui';
import { AlertTriangle, AlertCircle, Info, ExternalLink, CheckCircle2 } from 'lucide-react';
import { Link } from 'react-router-dom';

const severityConfig: Record<AlertSeverity, {
    icon: typeof AlertCircle;
    bgClass: string;
    borderClass: string;
    textClass: string;
    iconClass: string;
}> = {
    critical: {
        icon: AlertCircle,
        bgClass: 'bg-critical/10',
        borderClass: 'border-critical/30',
        textClass: 'text-critical',
        iconClass: 'text-critical',
    },
    warning: {
        icon: AlertTriangle,
        bgClass: 'bg-degraded/10',
        borderClass: 'border-degraded/30',
        textClass: 'text-degraded',
        iconClass: 'text-degraded',
    },
    info: {
        icon: Info,
        bgClass: 'bg-accent-500/10',
        borderClass: 'border-accent-500/30',
        textClass: 'text-accent-400',
        iconClass: 'text-accent-400',
    },
};

function formatTime(ms: number): string {
    const now = Date.now();
    const diff = now - ms;

    if (diff < 60000) return 'just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return new Date(ms).toLocaleDateString();
}

interface AlertItemProps {
    alert: Alert;
    onAcknowledge?: (id: string) => void;
}

export function AlertItem({ alert, onAcknowledge }: AlertItemProps) {
    const config = severityConfig[alert.severity];
    const Icon = config.icon;

    return (
        <div className={`
      p-3 rounded-lg border
      ${config.bgClass} ${config.borderClass}
      ${alert.acknowledged ? 'opacity-50' : ''}
    `}>
            <div className="flex items-start gap-3">
                <Icon className={`w-5 h-5 mt-0.5 ${config.iconClass}`} />

                <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                        <span className={`text-xs font-medium uppercase ${config.textClass}`}>
                            {alert.type.replace(/_/g, ' ')}
                        </span>
                        <span className="text-xs text-dark-500">
                            {formatTime(alert.timestamp)}
                        </span>
                    </div>

                    <p className="text-sm text-gray-200 mt-1">
                        {alert.message}
                    </p>

                    <div className="flex items-center gap-3 mt-2">
                        {alert.decisionId && (
                            <Link
                                to={`/decisions?id=${alert.decisionId}`}
                                className="text-xs text-accent-400 hover:text-accent-300 flex items-center gap-1"
                            >
                                View Decision <ExternalLink className="w-3 h-3" />
                            </Link>
                        )}

                        {!alert.acknowledged && onAcknowledge && (
                            <button
                                onClick={() => onAcknowledge(alert.id)}
                                className="text-xs text-dark-400 hover:text-gray-200 flex items-center gap-1"
                            >
                                <CheckCircle2 className="w-3 h-3" /> Acknowledge
                            </button>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}

interface AlertFeedProps {
    alerts: Alert[];
    onAcknowledge?: (id: string) => void;
    onViewAll?: () => void;
    compact?: boolean;
    maxItems?: number;
}

export function AlertFeed({
    alerts,
    onAcknowledge,
    onViewAll,
    compact = false,
    maxItems = 5,
}: AlertFeedProps) {
    const displayAlerts = alerts.slice(0, maxItems);
    const unacknowledgedCount = alerts.filter(a => !a.acknowledged).length;

    if (compact) {
        return (
            <div className="space-y-2">
                {displayAlerts.length === 0 ? (
                    <p className="text-sm text-dark-400 py-2">No recent alerts</p>
                ) : (
                    displayAlerts.map(alert => (
                        <AlertItem
                            key={alert.id}
                            alert={alert}
                            onAcknowledge={onAcknowledge}
                        />
                    ))
                )}
            </div>
        );
    }

    return (
        <Card>
            <CardHeader
                title="Alerts"
                subtitle={unacknowledgedCount > 0
                    ? `${unacknowledgedCount} unresolved`
                    : 'All clear'
                }
                action={
                    onViewAll && (
                        <Button variant="ghost" size="sm" onClick={onViewAll}>
                            View All →
                        </Button>
                    )
                }
            />

            <div className="space-y-2">
                {displayAlerts.length === 0 ? (
                    <p className="text-sm text-dark-400 py-4 text-center">
                        No alerts
                    </p>
                ) : (
                    displayAlerts.map(alert => (
                        <AlertItem
                            key={alert.id}
                            alert={alert}
                            onAcknowledge={onAcknowledge}
                        />
                    ))
                )}
            </div>

            {alerts.length > maxItems && (
                <div className="mt-3 text-center">
                    <button
                        onClick={() => onViewAll?.()}
                        disabled={!onViewAll}
                        className="text-sm text-accent-400 hover:text-accent-300"
                    >
                        View {alerts.length - maxItems} more alerts
                    </button>
                </div>
            )}
        </Card>
    );
}
