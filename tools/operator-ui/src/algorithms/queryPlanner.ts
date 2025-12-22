/**
 * Algorithm 6: DecisionQueryPlanner
 * 
 * Plans decision queries with safe defaults and pagination.
 * 
 * @complexity O(1) for planning, query execution is O(n log n)
 * 
 * @postcondition Returns plan with safe defaults applied
 */

import type { DecisionFilter } from '../api/types';

// =============================================================================
// Configuration Constants
// =============================================================================

const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 100;
const DEFAULT_DATE_RANGE_MS = 24 * 60 * 60 * 1000; // 24 hours

// =============================================================================
// Types
// =============================================================================

export interface CursorPagination {
    beforeTs: number;
    beforeId: string;
}

export interface QueryPlan {
    filters: DecisionFilter;
    sortField: 'timestamp';
    sortDirection: 'desc';
    pageSize: number;
    cursor: CursorPagination | null;
    useOffsetPagination: boolean;
    warnings: string[];
}

export interface QueryCapabilities {
    supportsCursor: boolean;
    maxPageSize: number;
    maxDateRangeMs: number;
}

// =============================================================================
// Pure Functions
// =============================================================================

/**
 * Apply safe defaults to filters.
 */
function applySafeDefaults(filter: Partial<DecisionFilter> | undefined): DecisionFilter {
    const now = Date.now();

    return {
        // Default: last 24 hours
        startDate: filter?.startDate ?? (now - DEFAULT_DATE_RANGE_MS),
        endDate: filter?.endDate ?? now,
        // Default: failures first (no explicit filter, but see sortDefaults)
        proofStatus: filter?.proofStatus,
        executionStatus: filter?.executionStatus,
        verdict: filter?.verdict,
        policyHash: filter?.policyHash,
        actionType: filter?.actionType,
        query: filter?.query,
    };
}

/**
 * Check for expensive query patterns.
 */
function detectExpensivePatterns(filter: DecisionFilter): string[] {
    const warnings: string[] = [];

    // Unbounded text search
    if (filter.query && filter.query.length < 3) {
        warnings.push('Short search queries may be slow — consider more specific terms');
    }

    // Very large date range
    const dateRange = (filter.endDate ?? Date.now()) - (filter.startDate ?? 0);
    const maxRange = 30 * 24 * 60 * 60 * 1000; // 30 days
    if (dateRange > maxRange) {
        warnings.push('Large date range may result in slow queries');
    }

    // No filters at all
    const hasFilters = filter.proofStatus || filter.executionStatus ||
        filter.verdict || filter.policyHash || filter.actionType;
    if (!hasFilters && !filter.query) {
        warnings.push('Consider adding filters to narrow results');
    }

    return warnings;
}

/**
 * Cap page size to maximum.
 */
function capPageSize(requested: number | undefined): number {
    if (!requested) return DEFAULT_PAGE_SIZE;
    return Math.min(requested, MAX_PAGE_SIZE);
}

// =============================================================================
// Main Algorithm
// =============================================================================

export interface QueryInput {
    filter?: Partial<DecisionFilter>;
    pageSize?: number;
    cursor?: CursorPagination;
    offset?: number;
    capabilities?: QueryCapabilities;
}

/**
 * Plan a decision query with safe defaults.
 * 
 * Algorithm 6: DecisionQueryPlanner
 * 
 * @complexity O(1)
 */
export function planQuery(input: QueryInput): QueryPlan {
    const capabilities = input.capabilities ?? {
        supportsCursor: true,
        maxPageSize: MAX_PAGE_SIZE,
        maxDateRangeMs: 30 * 24 * 60 * 60 * 1000,
    };

    // Step 1: Apply safe defaults
    const filters = applySafeDefaults(input.filter);

    // Step 2: Cap page size
    const pageSize = capPageSize(input.pageSize);

    // Step 3: Prefer cursor pagination
    const useCursor = capabilities.supportsCursor && input.cursor !== undefined;

    // Step 4: Detect expensive patterns
    const warnings = detectExpensivePatterns(filters);

    return {
        filters,
        sortField: 'timestamp',
        sortDirection: 'desc',
        pageSize,
        cursor: useCursor ? input.cursor! : null,
        useOffsetPagination: !useCursor && input.offset !== undefined,
        warnings,
    };
}

/**
 * Create a cursor from a decision for pagination.
 */
export function createCursorFromDecision(
    decisionId: string,
    timestamp: number
): CursorPagination {
    return {
        beforeTs: timestamp,
        beforeId: decisionId,
    };
}

/**
 * Build URL query string from plan.
 */
export function buildQueryString(plan: QueryPlan, page = 1): string {
    const params = new URLSearchParams();

    params.set('pageSize', String(plan.pageSize));

    if (plan.filters.startDate) {
        params.set('startDate', String(plan.filters.startDate));
    }
    if (plan.filters.endDate) {
        params.set('endDate', String(plan.filters.endDate));
    }
    if (plan.filters.proofStatus) {
        params.set('proofStatus', plan.filters.proofStatus);
    }
    if (plan.filters.executionStatus) {
        params.set('executionStatus', plan.filters.executionStatus);
    }
    if (plan.filters.verdict) {
        params.set('verdict', plan.filters.verdict);
    }
    if (plan.filters.policyHash) {
        params.set('policyHash', plan.filters.policyHash);
    }
    if (plan.filters.query) {
        params.set('q', plan.filters.query);
    }

    if (plan.cursor) {
        params.set('beforeTs', String(plan.cursor.beforeTs));
        params.set('beforeId', plan.cursor.beforeId);
    } else if (plan.useOffsetPagination) {
        params.set('page', String(page));
    }

    return params.toString();
}

/**
 * Get failure-first filter for default view.
 */
export function getFailureFirstFilter(): Partial<DecisionFilter> {
    return {
        // Show failures first by filtering to failures
        // In a real implementation, this would be a sort preference
    };
}
