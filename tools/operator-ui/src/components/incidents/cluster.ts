/**
 * Algorithm 4: IncidentClusteringEngine (Enhanced)
 * 
 * Clusters alerts into incidents with flapping detection.
 * 
 * @complexity O(n log n) for n alerts
 * @invariant I3: Unacked critical always first in queue
 */

import type { Alert, AlertSeverity, IncidentState, IncidentExtended } from '../../api/types';

export interface Incident {
  id: string;
  severity: AlertSeverity;
  title: string;
  count: number;
  unacked: boolean;
  firstSeen: number;
  lastSeen: number;
  primary: Alert;
}

// Flapping detection window (15 minutes)
const FLAPPING_WINDOW_MS = 15 * 60 * 1000;
const FLAPPING_THRESHOLD = 3; // oscillations to trigger flapping

function severityScore(severity: AlertSeverity): number {
  switch (severity) {
    case 'critical':
      return 3;
    case 'warning':
      return 2;
    case 'info':
      return 1;
  }
}

function normalizeMessage(message: string): string {
  return message
    .toLowerCase()
    .replace(/\b0x[0-9a-f]{6,}\b/g, '0x…')
    .replace(/\b[0-9a-f]{16,}\b/g, '…')
    .replace(/\b\d+\b/g, 'n')
    .replace(/\s+/g, ' ')
    .trim();
}

function humanizeType(type: string): string {
  return type.replace(/_/g, ' ');
}

function truncate(text: string, max = 80): string {
  if (text.length <= max) return text;
  return `${text.slice(0, Math.max(0, max - 1))}…`;
}

function incidentPriority(incident: Incident): number {
  const base = severityScore(incident.severity) * 1_000_000;
  const unacked = incident.unacked ? 100_000 : 0;
  const recency = incident.lastSeen;
  const countBonus = Math.min(incident.count, 100) * 100;
  return base + unacked + recency + countBonus;
}

/**
 * Detect flapping by counting state oscillations in window.
 */
function detectFlapping(alerts: Alert[]): boolean {
  if (alerts.length < FLAPPING_THRESHOLD) return false;

  const now = Date.now();
  const recentAlerts = alerts.filter(a => now - a.timestamp < FLAPPING_WINDOW_MS);
  if (recentAlerts.length < FLAPPING_THRESHOLD) return false;

  // Count ack/unack oscillations
  const sorted = [...recentAlerts].sort((a, b) => a.timestamp - b.timestamp);
  let oscillations = 0;
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i].acknowledged !== sorted[i - 1].acknowledged) {
      oscillations++;
    }
  }

  return oscillations >= FLAPPING_THRESHOLD;
}

/**
 * Determine incident state from alerts.
 */
function determineState(alerts: Alert[]): IncidentState {
  const hasUnacked = alerts.some(a => !a.acknowledged);
  if (!hasUnacked) return 'acknowledged';

  const allRecent = alerts.every(
    a => Date.now() - a.timestamp < 5 * 60 * 1000 // last 5 mins
  );

  return allRecent ? 'open' : 'open';
}

export function clusterAlerts(alerts: Alert[]): Incident[] {
  const groups = new Map<string, Alert[]>();

  for (const alert of alerts) {
    const key = `${alert.type}:${normalizeMessage(alert.message)}`;
    const existing = groups.get(key);
    if (existing) existing.push(alert);
    else groups.set(key, [alert]);
  }

  const incidents: Incident[] = [];

  for (const [key, group] of groups.entries()) {
    const sorted = [...group].sort((a, b) => b.timestamp - a.timestamp);
    const primary = sorted.find((a) => !a.acknowledged) ?? sorted[0];
    const severity = group.reduce<AlertSeverity>(
      (max, a) => (severityScore(a.severity) > severityScore(max) ? a.severity : max),
      'info',
    );
    const firstSeen = group.reduce((min, a) => Math.min(min, a.timestamp), Number.POSITIVE_INFINITY);
    const lastSeen = group.reduce((max, a) => Math.max(max, a.timestamp), 0);
    const unacked = group.some((a) => !a.acknowledged);

    incidents.push({
      id: key,
      severity,
      title: `${humanizeType(primary.type)}: ${truncate(primary.message)}`,
      count: group.length,
      unacked,
      firstSeen,
      lastSeen,
      primary,
    });
  }

  incidents.sort((a, b) => incidentPriority(b) - incidentPriority(a));
  return incidents;
}

/**
 * Enhanced clustering with flapping detection and state.
 * Returns IncidentExtended with all algorithm fields.
 */
export function clusterAlertsExtended(alerts: Alert[]): IncidentExtended[] {
  const groups = new Map<string, Alert[]>();

  for (const alert of alerts) {
    const key = `${alert.type}:${normalizeMessage(alert.message)}`;
    const existing = groups.get(key);
    if (existing) existing.push(alert);
    else groups.set(key, [alert]);
  }

  const incidents: IncidentExtended[] = [];

  for (const [key, group] of groups.entries()) {
    const sorted = [...group].sort((a, b) => b.timestamp - a.timestamp);
    const primary = sorted.find((a) => !a.acknowledged) ?? sorted[0];
    const severity = group.reduce<AlertSeverity>(
      (max, a) => (severityScore(a.severity) > severityScore(max) ? a.severity : max),
      'info',
    );
    const firstSeen = group.reduce((min, a) => Math.min(min, a.timestamp), Number.POSITIVE_INFINITY);
    const lastSeen = group.reduce((max, a) => Math.max(max, a.timestamp), 0);
    const unacked = group.some((a) => !a.acknowledged);
    const flapping = detectFlapping(group);
    const state = determineState(group);

    const basePriority =
      (severity === 'critical' ? 1_000_000 : severity === 'warning' ? 100_000 : 10_000) +
      (unacked ? 50_000 : 0) +
      lastSeen;

    incidents.push({
      id: key,
      severity,
      title: `${humanizeType(primary.type)}: ${truncate(primary.message)}`,
      count: group.length,
      unacked,
      firstSeen,
      lastSeen,
      primary,
      state,
      flapping,
      priority: basePriority,
    });
  }

  // Sort: critical unacked first (I3), then by priority
  incidents.sort((a, b) => {
    // Critical unacked always first
    const aCritUnacked = a.severity === 'critical' && a.unacked ? 1 : 0;
    const bCritUnacked = b.severity === 'critical' && b.unacked ? 1 : 0;
    if (aCritUnacked !== bCritUnacked) return bCritUnacked - aCritUnacked;

    // Then by priority
    return b.priority - a.priority;
  });

  return incidents;
}


