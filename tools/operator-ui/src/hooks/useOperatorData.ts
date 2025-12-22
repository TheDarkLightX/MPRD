import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../api/client';
import { ApiError } from '../api/client';
import type {
  Alert,
  DecisionDetail,
  DecisionFilter,
  DecisionSummary,
  IncidentSummary,
  MetricsSummary,
  PaginatedResponse,
  PolicySummary,
  SnoozeResult,
  SystemStatus,
} from '../api/types';

export function useDashboardData() {
  const statusQuery = useQuery<SystemStatus>({
    queryKey: ['status'],
    queryFn: () => apiClient.getStatus(),
    refetchInterval: 5000,
  });

  const metricsQuery = useQuery<MetricsSummary>({
    queryKey: ['metrics'],
    queryFn: () => apiClient.getMetrics(),
    refetchInterval: 10_000,
  });

  const error = statusQuery.error || metricsQuery.error || null;
  const errorStatus = error instanceof ApiError ? error.status : null;

  return {
    status: statusQuery.data ?? null,
    metrics: metricsQuery.data ?? null,
    pipelineState: null,
    loading: statusQuery.isLoading || metricsQuery.isLoading,
    error: error instanceof Error ? error : null,
    errorStatus,
    isOffline: errorStatus === 0,
    refetch: async () => {
      await Promise.all([statusQuery.refetch(), metricsQuery.refetch()]);
    },
  };
}

export function useDecisions(page: number, pageSize: number, filter: DecisionFilter) {
  const queryClient = useQueryClient();
  const [selectedDecision, setSelectedDecision] = useState<DecisionDetail | null>(null);
  const [lastVerifyError, setLastVerifyError] = useState<string | null>(null);

  const listQuery = useQuery<PaginatedResponse<DecisionSummary>>({
    queryKey: ['decisions', page, pageSize, filter],
    queryFn: () => apiClient.listDecisions(page, pageSize, filter),
    refetchInterval: 5000,
  });

  const verifyMutation = useMutation({
    mutationFn: async (id: string) => apiClient.verifyDecision(id),
    onSuccess: async (_result, id) => {
      setLastVerifyError(_result.verified ? null : (_result.error ?? 'Verification failed'));
      await queryClient.invalidateQueries({ queryKey: ['decisions'] });
      const updated = await apiClient.getDecision(id);
      setSelectedDecision(updated);
    },
    onError: (e) => {
      setLastVerifyError(e instanceof Error ? e.message : 'Verification failed');
    },
  });

  async function loadDecision(id: string) {
    const detail = await queryClient.fetchQuery({
      queryKey: ['decision', id],
      queryFn: () => apiClient.getDecision(id),
      staleTime: 0,
    });
    setSelectedDecision(detail);
  }

  const data = listQuery.data;

  return {
    decisions: data?.data ?? [],
    total: data?.total ?? 0,
    hasMore: data?.hasMore ?? false,
    loading: listQuery.isLoading,
    error: listQuery.error instanceof Error ? listQuery.error.message : null,
    selectedDecision,
    loadDecision,
    verifyDecision: (id: string) => verifyMutation.mutate(id),
    verifying: verifyMutation.isPending,
    lastVerifyError,
  };
}

export function usePolicies() {
  const query = useQuery<PolicySummary[]>({
    queryKey: ['policies'],
    queryFn: () => apiClient.listPolicies(),
    refetchInterval: 10_000,
  });

  return {
    policies: query.data ?? [],
    loading: query.isLoading,
    error: query.error instanceof Error ? query.error.message : null,
  };
}

export function useAlerts() {
  const queryClient = useQueryClient();
  const alertsQuery = useQuery<Alert[]>({
    queryKey: ['alerts'],
    queryFn: () => apiClient.listAlerts(50, false),
    refetchInterval: 10_000,
  });

  const ackMutation = useMutation({
    mutationFn: async (id: string) => apiClient.acknowledgeAlert(id),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
  });

  return useMemo(
    () => ({
      alerts: alertsQuery.data ?? [],
      acknowledge: (id: string) => ackMutation.mutate(id),
      loading: alertsQuery.isLoading,
      error: alertsQuery.error instanceof Error ? alertsQuery.error.message : null,
    }),
    [ackMutation, alertsQuery.data, alertsQuery.error, alertsQuery.isLoading],
  );
}

export function useIncidents(limit = 50, unacknowledgedOnly = false, includeSnoozed = false) {
  const queryClient = useQueryClient();

  const incidentsQuery = useQuery<IncidentSummary[]>({
    queryKey: ['incidents', limit, unacknowledgedOnly, includeSnoozed],
    queryFn: () => apiClient.listIncidents(limit, unacknowledgedOnly, includeSnoozed),
    refetchInterval: 10_000,
  });

  const ackMutation = useMutation({
    mutationFn: async (id: string) => apiClient.acknowledgeIncident(id),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['incidents'] });
      await queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
  });

  const snoozeMutation = useMutation({
    mutationFn: async ({ id, ttlMs, reason }: { id: string; ttlMs: number; reason?: string }) =>
      apiClient.snoozeIncident(id, { ttlMs, reason }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['incidents'] });
    },
  });

  return useMemo(
    () => ({
      incidents: incidentsQuery.data ?? [],
      acknowledge: (id: string) => ackMutation.mutate(id),
      snooze: (id: string, ttlMs: number, reason?: string): void =>
        snoozeMutation.mutate({ id, ttlMs, reason }),
      loading: incidentsQuery.isLoading,
      error: incidentsQuery.error instanceof Error ? incidentsQuery.error.message : null,
      snoozeResult: snoozeMutation.data ?? (null as SnoozeResult | null),
    }),
    [
      ackMutation,
      incidentsQuery.data,
      incidentsQuery.error,
      incidentsQuery.isLoading,
      snoozeMutation,
    ],
  );
}
