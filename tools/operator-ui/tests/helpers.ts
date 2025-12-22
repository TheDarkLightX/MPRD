import assert from 'node:assert/strict';

import type { Alert, IncidentExtended, SecurityPosture } from '../src/api/types';

export function withFakeNow<T>(nowMs: number, run: () => T): T {
  const original = Date.now;
  Date.now = () => nowMs;
  try {
    return run();
  } finally {
    Date.now = original;
  }
}

export function posture(
  overrides: (Omit<Partial<SecurityPosture>, 'metrics'> & { metrics?: Partial<SecurityPosture['metrics']> }) = {},
): SecurityPosture {
  const { metrics: metricsOverrides, ...rest } = overrides;
  return {
    trustLevel: 'healthy',
    availabilityLevel: 'healthy',
    reasons: [],
    ...rest,
    metrics: {
      failRate: 0,
      verifyFailRate: 0,
      execFailRate: 0,
      decisionRate: 0,
      ...(metricsOverrides ?? {}),
    },
  };
}

export function alert(overrides?: Partial<Alert>): Alert {
  return {
    id: 'a1',
    timestamp: 0,
    severity: 'info',
    type: 'anomaly',
    message: 'msg',
    acknowledged: false,
    ...overrides,
  };
}

export function incident(overrides: Partial<IncidentExtended> & Pick<IncidentExtended, 'id'>): IncidentExtended {
  const baseAlert = alert({
    id: `alert-${overrides.id}`,
    severity: overrides.severity ?? 'info',
    type: overrides.primary?.type ?? 'anomaly',
    message: overrides.title ?? 'incident',
  });

  return {
    id: overrides.id,
    severity: overrides.severity ?? 'info',
    title: overrides.title ?? 'Incident',
    count: overrides.count ?? 1,
    unacked: overrides.unacked ?? true,
    firstSeen: overrides.firstSeen ?? 0,
    lastSeen: overrides.lastSeen ?? 0,
    primary: overrides.primary ?? baseAlert,
    state: overrides.state ?? 'open',
    flapping: overrides.flapping ?? false,
    priority: overrides.priority ?? 0,
  };
}

export function assertWithin(value: number, min: number, max: number, label: string): void {
  assert.ok(value >= min && value <= max, `${label}: expected ${value} in [${min}, ${max}]`);
}
