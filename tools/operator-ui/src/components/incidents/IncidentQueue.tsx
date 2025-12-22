/**
 * Incident Queue (Work Queue)
 *
 * Attention-first triage surface: grouped alerts → ranked incidents.
 */

import type { IncidentSummary } from '../../api/types';
import { Card, CardHeader, Button, Badge } from '../ui';
import { AlertCircle, AlertTriangle, Info } from 'lucide-react';

function formatTime(ms: number): string {
  const now = Date.now();
  const diff = now - ms;

  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return new Date(ms).toLocaleDateString();
}

function severityIcon(severity: IncidentSummary['severity']) {
  switch (severity) {
    case 'critical':
      return <AlertCircle className="w-5 h-5 text-critical" />;
    case 'warning':
      return <AlertTriangle className="w-5 h-5 text-degraded" />;
    case 'info':
      return <Info className="w-5 h-5 text-accent-400" />;
  }
}

export function IncidentQueue({
  incidents,
  onOpenSecurity,
  onAcknowledge,
  onSnooze,
  maxItems = 3,
}: {
  incidents: IncidentSummary[];
  onOpenSecurity: () => void;
  onAcknowledge?: (incidentId: string) => void;
  onSnooze?: (incidentId: string, ttlMs: number) => void;
  maxItems?: number;
}) {
  const displayIncidents = incidents.slice(0, maxItems);
  const unacked = displayIncidents.filter((i) => i.unacked).length;

  return (
    <Card>
      <CardHeader
        title="Work Queue"
        subtitle={unacked > 0 ? `${unacked} unresolved` : 'All clear'}
        action={
          <Button variant="ghost" size="sm" onClick={onOpenSecurity}>
            Open Security →
          </Button>
        }
      />

      {displayIncidents.length === 0 ? (
        <p className="text-sm text-dark-400 py-2">No incidents</p>
      ) : (
        <div className="space-y-2">
          {displayIncidents.map((incident) => (
            <div
              key={incident.id}
              className={`p-3 rounded-lg border ${
                incident.severity === 'critical'
                  ? 'bg-critical/10 border-critical/30'
                  : incident.severity === 'warning'
                    ? 'bg-degraded/10 border-degraded/30'
                    : 'bg-accent-500/10 border-accent-500/30'
              } ${incident.unacked ? '' : 'opacity-60'}`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-3 min-w-0">
                  {severityIcon(incident.severity)}
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium text-gray-100 truncate">{incident.title}</p>
                      {incident.count > 1 && <Badge variant="default">{incident.count}×</Badge>}
                      {!incident.unacked && <Badge variant="healthy">acked</Badge>}
                    </div>
                    <p className="text-xs text-dark-400 mt-1 truncate">
                      Last seen {formatTime(incident.lastSeen)}
                      {incident.recommendedAction ? ` • ${incident.recommendedAction}` : ''}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {incident.unacked && onAcknowledge && (
                    <Button variant="ghost" size="sm" onClick={() => onAcknowledge(incident.id)}>
                      Ack
                    </Button>
                  )}
                  {incident.unacked && onSnooze && (
                    <Button variant="ghost" size="sm" onClick={() => onSnooze(incident.id, 15 * 60 * 1000)}>
                      Snooze
                    </Button>
                  )}
                  <Button variant="ghost" size="sm" onClick={onOpenSecurity}>
                    Open
                  </Button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
