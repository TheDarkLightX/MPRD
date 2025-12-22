import { test } from 'node:test';
import assert from 'node:assert/strict';

import type { AutopilotState } from '../src/api/types';
import { renderGlanceable } from '../src/algorithms/glanceableRenderer';
import { incident, posture } from './helpers';

function autopilot(overrides?: Partial<AutopilotState>): AutopilotState {
  return {
    mode: 'manual',
    lastHumanAck: 0,
    pendingReviewCount: 0,
    autoHandled24h: 0,
    canTransitionTo: ['assisted'],
    ...overrides,
  };
}

test('renderGlanceable prioritizes security configuration required headline', () => {
  const view = renderGlanceable({
    posture: posture({ trustLevel: 'critical' }),
    incidents: [],
    autopilot: autopilot(),
  });

  assert.equal(view.headlineSeverity, 'critical');
  assert.ok(view.headline.includes('Security Configuration Required'));
  assert.ok(view.headline.length <= 50);
});

test('renderGlanceable produces critical headline when unacked critical incidents exist', () => {
  const view = renderGlanceable({
    posture: posture(),
    incidents: [
      incident({ id: 'c1', severity: 'critical', unacked: true, title: 'A', priority: 10 }),
      incident({ id: 'c2', severity: 'critical', unacked: true, title: 'B', priority: 9 }),
    ],
    autopilot: autopilot(),
    previousCriticalCount: 0,
  });

  assert.equal(view.headlineSeverity, 'critical');
  assert.ok(view.headline.includes('Critical'));
  assert.ok(view.attentionDemand.itemsNeedingAction > 0);
  assert.ok(view.nextAction !== null);
});

