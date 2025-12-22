import { USE_MOCK_DATA } from '../config';
import { useMockAlerts, useMockData, useMockDecisions, useMockPolicies, useMockIncidents } from './useMockData';
import { useAlerts, useDashboardData, useDecisions, useIncidents, usePolicies } from './useOperatorData';

const useDashboardHook = USE_MOCK_DATA ? useMockData : useDashboardData;
const useDecisionsHook = USE_MOCK_DATA ? useMockDecisions : useDecisions;
const usePoliciesHook = USE_MOCK_DATA ? useMockPolicies : usePolicies;
const useAlertsHook = USE_MOCK_DATA ? useMockAlerts : useAlerts;
const useIncidentsHook = USE_MOCK_DATA ? useMockIncidents : useIncidents;

export function useOperatorDashboard() {
  return useDashboardHook();
}

export function useOperatorDecisions(page: number, pageSize: number, filter: import('../api/types').DecisionFilter) {
  return useDecisionsHook(page, pageSize, filter);
}

export function useOperatorPolicies() {
  return usePoliciesHook();
}

export function useOperatorAlerts() {
  return useAlertsHook();
}

export function useOperatorIncidents(limit = 50, unacknowledgedOnly = false, includeSnoozed = false) {
  return useIncidentsHook(limit, unacknowledgedOnly, includeSnoozed);
}

export { useMockData, useMockDecisions, useMockPolicies, useMockAlerts, useMockIncidents };

// Performance utilities
export {
  useDebounce,
  useIntersectionObserver,
} from './usePerformance';
