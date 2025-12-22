/**
 * MPRD Operator UI - React Query Hooks
 * 
 * Provides data fetching hooks with caching, automatic refetching, and error handling.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from './client';
import type { DecisionFilter } from './types';

// =============================================================================
// Query Keys
// =============================================================================

export const queryKeys = {
    status: ['status'] as const,
    decisions: (page: number, pageSize: number, filter?: DecisionFilter) =>
        ['decisions', page, pageSize, filter] as const,
    decision: (id: string) => ['decision', id] as const,
    policies: ['policies'] as const,
    alerts: (limit: number, unacknowledgedOnly: boolean) =>
        ['alerts', limit, unacknowledgedOnly] as const,
    metrics: ['metrics'] as const,
    incidents: (limit: number, unacknowledgedOnly: boolean, includeSnoozed: boolean) =>
        ['incidents', limit, unacknowledgedOnly, includeSnoozed] as const,
    incident: (id: string) => ['incident', id] as const,
};

// =============================================================================
// Status Hook
// =============================================================================

export function useSystemStatus() {
    return useQuery({
        queryKey: queryKeys.status,
        queryFn: () => apiClient.getStatus(),
        refetchInterval: 5000, // Poll every 5 seconds
        staleTime: 3000,
    });
}

// =============================================================================
// Incident Hooks
// =============================================================================

export function useIncidents(limit = 50, unacknowledgedOnly = false, includeSnoozed = false) {
    return useQuery({
        queryKey: queryKeys.incidents(limit, unacknowledgedOnly, includeSnoozed),
        queryFn: () => apiClient.listIncidents(limit, unacknowledgedOnly, includeSnoozed),
        refetchInterval: 10_000,
    });
}

export function useIncident(id: string | null) {
    return useQuery({
        queryKey: queryKeys.incident(id || ''),
        queryFn: () => apiClient.getIncident(id!),
        enabled: !!id,
    });
}

export function useAcknowledgeIncident() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: (id: string) => apiClient.acknowledgeIncident(id),
        onSuccess: (_, id) => {
            queryClient.invalidateQueries({ queryKey: ['incidents'] });
            queryClient.invalidateQueries({ queryKey: queryKeys.incident(id) });
            queryClient.invalidateQueries({ queryKey: ['alerts'] });
        },
    });
}

export function useSnoozeIncident() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: ({ id, ttlMs, reason }: { id: string; ttlMs: number; reason?: string }) =>
            apiClient.snoozeIncident(id, { ttlMs, reason }),
        onSuccess: (_, variables) => {
            queryClient.invalidateQueries({ queryKey: ['incidents'] });
            queryClient.invalidateQueries({ queryKey: queryKeys.incident(variables.id) });
        },
    });
}

// =============================================================================
// Decision Hooks
// =============================================================================

export function useDecisions(page = 1, pageSize = 50, filter?: DecisionFilter) {
    return useQuery({
        queryKey: queryKeys.decisions(page, pageSize, filter),
        queryFn: () => apiClient.listDecisions(page, pageSize, filter),
        staleTime: 10000,
    });
}

export function useDecision(id: string | null) {
    return useQuery({
        queryKey: queryKeys.decision(id || ''),
        queryFn: () => apiClient.getDecision(id!),
        enabled: !!id,
    });
}

export function useVerifyDecision() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: (id: string) => apiClient.verifyDecision(id),
        onSuccess: (_, id) => {
            // Invalidate the decision to refetch
            queryClient.invalidateQueries({ queryKey: queryKeys.decision(id) });
        },
    });
}

// =============================================================================
// Policy Hooks
// =============================================================================

export function usePolicies() {
    return useQuery({
        queryKey: queryKeys.policies,
        queryFn: () => apiClient.listPolicies(),
        staleTime: 30000, // Policies change less frequently
    });
}

// =============================================================================
// Alert Hooks
// =============================================================================

export function useAlerts(limit = 50, unacknowledgedOnly = false) {
    return useQuery({
        queryKey: queryKeys.alerts(limit, unacknowledgedOnly),
        queryFn: () => apiClient.listAlerts(limit, unacknowledgedOnly),
        refetchInterval: 10000, // Poll every 10 seconds
    });
}

export function useAcknowledgeAlert() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: (id: string) => apiClient.acknowledgeAlert(id),
        onSuccess: () => {
            // Invalidate alerts to refetch
            queryClient.invalidateQueries({ queryKey: ['alerts'] });
        },
    });
}

// =============================================================================
// Metrics Hook
// =============================================================================

export function useMetrics() {
    return useQuery({
        queryKey: queryKeys.metrics,
        queryFn: () => apiClient.getMetrics(),
        refetchInterval: 30000, // Poll every 30 seconds
        staleTime: 20000,
    });
}
