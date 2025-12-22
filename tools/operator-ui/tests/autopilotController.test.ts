import { test } from 'node:test';
import assert from 'node:assert/strict';

import { checkAutoDegradation, shouldShowAckWarning, transitionMode } from '../src/algorithms/autopilotController';
import { incident, posture, withFakeNow } from './helpers';

test('transitionMode blocks Autopilot when trust anchors are not configured (I9)', () => {
  const now = 1_000_000;
  const result = withFakeNow(now, () =>
    transitionMode(
      { mode: 'assisted', lastHumanAck: now, pendingReviewQueue: [], autoActionsCount24h: 0 },
      'autopilot',
      posture({ trustLevel: 'critical' }),
      [],
    ),
  );

  assert.equal(result.success, false);
  assert.ok(result.violations?.some(v => v.includes('Trust anchors')));
});

test('transitionMode blocks Autopilot when verification failure rate is too high', () => {
  const now = 2_000_000;
  const result = withFakeNow(now, () =>
    transitionMode(
      { mode: 'assisted', lastHumanAck: now, pendingReviewQueue: [], autoActionsCount24h: 0 },
      'autopilot',
      posture({ metrics: { verifyFailRate: 0.06 } }),
      [],
    ),
  );

  assert.equal(result.success, false);
  assert.ok(result.violations?.some(v => v.includes('Verification failure rate')));
});

test('transitionMode allows Assisted -> Autopilot when preconditions are met', () => {
  const now = 3_000_000;
  const result = withFakeNow(now, () =>
    transitionMode(
      { mode: 'assisted', lastHumanAck: now, pendingReviewQueue: [], autoActionsCount24h: 0 },
      'autopilot',
      posture(),
      [],
    ),
  );

  assert.equal(result.success, true);
});

test('checkAutoDegradation degrades to manual on high verification failure rate (I10)', () => {
  const now = 4_000_000;
  const result = withFakeNow(now, () =>
    checkAutoDegradation(
      { mode: 'assisted', lastHumanAck: now, pendingReviewQueue: [], autoActionsCount24h: 0 },
      posture({ metrics: { verifyFailRate: 0.21 } }),
      [],
    ),
  );

  assert.equal(result?.degraded, true);
  assert.equal(result?.toMode, 'manual');
});

test('checkAutoDegradation degrades Autopilot -> Assisted after 8h without ack (I11)', () => {
  const now = 5_000_000;
  const eightHoursMs = 8 * 60 * 60 * 1000;
  const result = withFakeNow(now, () =>
    checkAutoDegradation(
      { mode: 'autopilot', lastHumanAck: now - (eightHoursMs + 1), pendingReviewQueue: [], autoActionsCount24h: 0 },
      posture(),
      [],
    ),
  );

  assert.equal(result?.degraded, true);
  assert.equal(result?.fromMode, 'autopilot');
  assert.equal(result?.toMode, 'assisted');
});

test('shouldShowAckWarning triggers after 4h and reports minutes-until-degrade', () => {
  const now = 6_000_000;
  const fourHoursMs = 4 * 60 * 60 * 1000;
  const lastAck = now - (fourHoursMs + 10_000);

  const result = withFakeNow(now, () => shouldShowAckWarning(lastAck));

  assert.equal(result.show, true);
  assert.ok(result.minutesUntilDegrade > 0);
});

test('checkAutoDegradation degrades Autopilot -> Assisted when attention budget exceeded (I12)', () => {
  const now = 7_000_000;
  const incidents = Array.from({ length: 6 }).map((_, i) =>
    incident({ id: `c${i}`, severity: 'critical', unacked: true, priority: 1 }),
  );

  const result = withFakeNow(now, () =>
    checkAutoDegradation(
      { mode: 'autopilot', lastHumanAck: now, pendingReviewQueue: [], autoActionsCount24h: 0 },
      posture(),
      incidents,
    ),
  );

  assert.equal(result?.degraded, true);
  assert.equal(result?.toMode, 'assisted');
});
