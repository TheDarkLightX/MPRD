import { test } from 'node:test';
import assert from 'node:assert/strict';

import type { DecisionSummary } from '../src/api/types';
import { MetricsAggregator } from '../src/algorithms/metricsAggregator';
import { withFakeNow } from './helpers';

function decision(ts: number, overrides?: Partial<DecisionSummary>): DecisionSummary {
  return {
    id: `d-${ts}`,
    timestamp: ts,
    policyHash: '0'.repeat(64),
    actionType: 'http_call',
    verdict: 'allowed',
    proofStatus: 'verified',
    executionStatus: 'success',
    latencyMs: 10,
    ...overrides,
  };
}

test('MetricsAggregator snapshot only counts decisions inside the window (I4)', () => {
  const now = 10_000;
  const windowMs = 1_000;
  const agg = new MetricsAggregator(100, windowMs);

  agg.addDecision(decision(now - 2_000)); // outside
  agg.addDecision(decision(now - 900)); // inside
  agg.addDecision(decision(now - 1)); // inside

  const snap = withFakeNow(now, () => agg.getSnapshot());
  assert.equal(snap.totalCount, 2);
  assert.equal(snap.allowedCount, 2);
  assert.ok(snap.successRate > 0);
});

test('MetricsAggregator treats denied / failed decisions as lower success', () => {
  const now = 20_000;
  const agg = new MetricsAggregator(100, 10_000);

  agg.addDecision(decision(now - 1, { proofStatus: 'verified', executionStatus: 'success', verdict: 'allowed' }));
  agg.addDecision(decision(now - 1, { proofStatus: 'failed', executionStatus: 'failed', verdict: 'denied' }));

  const snap = withFakeNow(now, () => agg.getSnapshot());
  assert.equal(snap.totalCount, 2);
  assert.ok(snap.successRate < 100);
});

