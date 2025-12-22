import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createDefaultOperatorContext, scheduleAttention } from '../src/algorithms/attentionScheduler';
import { incident, posture, withFakeNow } from './helpers';

test('scheduleAttention prioritizes unacked critical incidents first (I3)', () => {
  const now = 1_000_000;
  const result = withFakeNow(now, () =>
    scheduleAttention({
      posture: posture(),
      operatorContext: createDefaultOperatorContext(),
      incidents: [
        incident({ id: 'w1', severity: 'warning', unacked: true, priority: 100, lastSeen: now - 1 }),
        incident({ id: 'c1', severity: 'critical', unacked: true, priority: 0, lastSeen: now - 10 }),
      ],
    }),
  );

  assert.equal(result.workQueue[0]?.id, 'c1');
});

test('scheduleAttention banner selects the most important unacked critical incident, not input order', () => {
  const now = 2_000_000;
  const result = withFakeNow(now, () =>
    scheduleAttention({
      posture: posture(),
      operatorContext: createDefaultOperatorContext(),
      incidents: [
        incident({ id: 'c-low', severity: 'critical', unacked: true, priority: 1, title: 'Low', lastSeen: now - 5 }),
        incident({ id: 'c-high', severity: 'critical', unacked: true, priority: 99, title: 'High', lastSeen: now - 10 }),
      ],
    }),
  );

  assert.equal(result.bannerSeverity, 'critical');
  assert.ok(result.banner?.includes('High'));
});

test('scheduleAttention enforces toast rate limiting for non-critical items (I6)', () => {
  const now = 3_000_000;
  const operatorContext = createDefaultOperatorContext();
  operatorContext.lastToastTime = now; // just toasted

  const result = withFakeNow(now, () =>
    scheduleAttention({
      posture: posture(),
      operatorContext,
      incidents: [
        incident({ id: 'w1', severity: 'warning', unacked: true, priority: 50, title: 'Warn', lastSeen: now }),
      ],
    }),
  );

  assert.deepEqual(result.toasts, []);
});

