/**
 * Algorithm 3: IncrementalMetricsAggregator
 * 
 * Windowed metrics computation with error budgets.
 * Uses circular buffer for O(1) amortized updates.
 * 
 * @complexity O(1) amortized per decision, O(k) for window size k
 * @invariant I4: Metrics only count decisions in window
 * 
 * @postcondition Returns accurate metrics for the time window
 */

import type { DecisionSummary, TrendDirection } from '../api/types';

// =============================================================================
// Configuration
// =============================================================================

const DEFAULT_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const DEFAULT_FAIL_RATE_TARGET = 0.01; // 1% error budget target

// =============================================================================
// Types
// =============================================================================

export interface MetricsSnapshot {
    successRate: number;
    avgLatencyMs: number;
    verificationRate: number;
    decisionRate: number; // per minute
    errorBudget: number; // 1 - (fail_rate / target)
    totalCount: number;
    allowedCount: number;
    deniedCount: number;
}

export interface MetricsTrends {
    successRate: TrendDirection;
    avgLatency: TrendDirection;
    decisionRate: TrendDirection;
}

interface CacheEntry {
    timestamp: number;
    latencyMs: number;
    proofVerified: boolean;
    executionSuccess: boolean;
    verdict: 'allowed' | 'denied';
}

// =============================================================================
// Circular Buffer Implementation
// =============================================================================

class CircularBuffer<T> {
    private buffer: (T | undefined)[];
    private head = 0;
    private tail = 0;
    private count = 0;
    private capacity: number;

    constructor(capacity: number) {
        this.capacity = capacity;
        this.buffer = new Array(capacity);
    }

    push(item: T): T | undefined {
        const evicted = this.buffer[this.tail];
        this.buffer[this.tail] = item;
        this.tail = (this.tail + 1) % this.capacity;

        if (this.count < this.capacity) {
            this.count++;
        } else {
            this.head = (this.head + 1) % this.capacity;
        }

        return this.count <= this.capacity ? undefined : evicted;
    }

    *entries(): Generator<T> {
        for (let i = 0; i < this.count; i++) {
            const idx = (this.head + i) % this.capacity;
            const item = this.buffer[idx];
            if (item !== undefined) {
                yield item;
            }
        }
    }

    clear(): void {
        this.buffer = new Array(this.capacity);
        this.head = 0;
        this.tail = 0;
        this.count = 0;
    }

    size(): number {
        return this.count;
    }
}

// =============================================================================
// Aggregator Class
// =============================================================================

export class MetricsAggregator {
    private cache: CircularBuffer<CacheEntry>;
    private windowMs: number;
    private failRateTarget: number;

    // Running totals for O(1) queries
    private totals = {
        count: 0,
        allowed: 0,
        denied: 0,
        verified: 0,
        execSuccess: 0,
        latencySum: 0,
    };

    constructor(
        maxEntries = 10000,
        windowMs = DEFAULT_WINDOW_MS,
        failRateTarget = DEFAULT_FAIL_RATE_TARGET
    ) {
        this.cache = new CircularBuffer(maxEntries);
        this.windowMs = windowMs;
        this.failRateTarget = failRateTarget;
    }

    /**
     * Add a decision to the aggregator.
     * 
     * @complexity O(1) amortized
     */
    addDecision(decision: DecisionSummary): void {
        const entry: CacheEntry = {
            timestamp: decision.timestamp,
            latencyMs: decision.latencyMs,
            proofVerified: decision.proofStatus === 'verified',
            executionSuccess: decision.executionStatus === 'success',
            verdict: decision.verdict,
        };

        // Add to buffer, handle eviction
        const evicted = this.cache.push(entry);

        // Update totals for new entry
        this.totals.count++;
        if (entry.verdict === 'allowed') this.totals.allowed++;
        else this.totals.denied++;
        if (entry.proofVerified) this.totals.verified++;
        if (entry.executionSuccess) this.totals.execSuccess++;
        this.totals.latencySum += entry.latencyMs;

        // Subtract evicted entry from totals
        if (evicted) {
            this.totals.count--;
            if (evicted.verdict === 'allowed') this.totals.allowed--;
            else this.totals.denied--;
            if (evicted.proofVerified) this.totals.verified--;
            if (evicted.executionSuccess) this.totals.execSuccess--;
            this.totals.latencySum -= evicted.latencyMs;
        }
    }

    /**
     * Get current metrics snapshot.
     * Evicts expired entries before computing.
     * 
     * @complexity O(k) where k = expired entries to evict
     */
    getSnapshot(): MetricsSnapshot {
        // Recompute from entries within window (handles time-based expiry)
        const now = Date.now();
        const cutoff = now - this.windowMs;

        let count = 0;
        let allowed = 0;
        let denied = 0;
        let verified = 0;
        let execSuccess = 0;
        let latencySum = 0;

        for (const entry of this.cache.entries()) {
            if (entry.timestamp >= cutoff) {
                count++;
                if (entry.verdict === 'allowed') allowed++;
                else denied++;
                if (entry.proofVerified) verified++;
                if (entry.executionSuccess) execSuccess++;
                latencySum += entry.latencyMs;
            }
        }

        const total = Math.max(1, count);
        const windowMinutes = this.windowMs / (60 * 1000);

        const successRate = (verified + execSuccess) / (total * 2) * 100;
        const failRate = 1 - (successRate / 100);

        return {
            successRate,
            avgLatencyMs: latencySum / total,
            verificationRate: (verified / total) * 100,
            decisionRate: count / windowMinutes,
            errorBudget: 1 - (failRate / this.failRateTarget),
            totalCount: count,
            allowedCount: allowed,
            deniedCount: denied,
        };
    }

    /**
     * Compare current metrics to previous period for trends.
     */
    computeTrends(previousSnapshot: MetricsSnapshot): MetricsTrends {
        const current = this.getSnapshot();

        return {
            successRate: compareTrend(current.successRate, previousSnapshot.successRate),
            avgLatency: compareTrend(previousSnapshot.avgLatencyMs, current.avgLatencyMs), // inverted
            decisionRate: compareTrend(current.decisionRate, previousSnapshot.decisionRate),
        };
    }

    /**
     * Reset all metrics.
     */
    reset(): void {
        this.cache.clear();
        this.totals = {
            count: 0,
            allowed: 0,
            denied: 0,
            verified: 0,
            execSuccess: 0,
            latencySum: 0,
        };
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

function compareTrend(current: number, previous: number, threshold = 0.05): TrendDirection {
    const change = (current - previous) / Math.max(1, Math.abs(previous));

    if (change > threshold) return 'up';
    if (change < -threshold) return 'down';
    return 'stable';
}

/**
 * Create a metrics aggregator with decisions pre-loaded.
 */
export function createAggregatorWithDecisions(
    decisions: DecisionSummary[],
    windowMs = DEFAULT_WINDOW_MS
): MetricsAggregator {
    const aggregator = new MetricsAggregator(decisions.length + 1000, windowMs);

    // Sort by timestamp and add all
    const sorted = [...decisions].sort((a, b) => a.timestamp - b.timestamp);
    for (const decision of sorted) {
        aggregator.addDecision(decision);
    }

    return aggregator;
}
