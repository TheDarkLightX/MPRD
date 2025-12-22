import { test } from 'node:test';
import assert from 'node:assert/strict';

import { computeBackendBannerFlags } from '../src/algorithms/backendConnectivity';

test('backend banner: network error shows offline (not auth required)', () => {
  const flags = computeBackendBannerFlags({
    healthIsError: true,
    healthIsSuccess: false,
    healthStatus: 0,
    healthIsNetworkError: true,
    statusIsNetworkError: true,
    statusErrorStatus: 401,
  });

  assert.equal(flags.showWrongBaseUrl, false);
  assert.equal(flags.showOffline, true);
  assert.equal(flags.showAuthRequired, false);
});

test('backend banner: 401 shows auth required only when backend reachable', () => {
  const flags = computeBackendBannerFlags({
    healthIsError: false,
    healthIsSuccess: true,
    healthStatus: 200,
    healthIsNetworkError: false,
    statusIsNetworkError: false,
    statusErrorStatus: 401,
  });

  assert.equal(flags.showOffline, false);
  assert.equal(flags.showAuthRequired, true);
});

test('backend banner: wrong base URL overrides other states', () => {
  const flags = computeBackendBannerFlags({
    healthIsError: true,
    healthIsSuccess: false,
    healthStatus: 404,
    healthIsNetworkError: false,
    statusIsNetworkError: false,
    statusErrorStatus: 401,
  });

  assert.equal(flags.showWrongBaseUrl, true);
  assert.equal(flags.showOffline, false);
  assert.equal(flags.showAuthRequired, false);
});

