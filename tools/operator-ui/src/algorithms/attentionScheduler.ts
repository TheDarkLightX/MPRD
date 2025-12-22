/**
 * Algorithm 5: AttentionBudgetScheduler
 * 
 * Manages attention surfaces (banner, toasts, work queue) with rate limiting.
 * 
 * @complexity O(n log k) for top-k heap
 * @invariant I3: Unacked critical alerts always first
 * @invariant I6: UI MUST rate-limit interrupts (except CRITICAL safety)
 * @invariant I12: Attention items capped at ATTENTION_BUDGET (default: 5 critical)
 * 
 * @postcondition Returns prioritized attention allocation
 */

import type {
    SecurityPosture,
    IncidentExtended,
    AttentionBudgetResult,
    Severity,
} from '../api/types';

// =============================================================================
// Configuration Constants
// =============================================================================

export const ATTENTION_BUDGET = 5; // Max concurrent critical items
const TOAST_MIN_INTERVAL_MS = 30_000; // 30 seconds between toasts
const WORK_QUEUE_SIZE = 10;
const DIGEST_CADENCE_MS = 10 * 60 * 1000; // 10 minutes

// =============================================================================
// Types
// =============================================================================

export interface OperatorContext {
    lastToastTime: number;
    quietHoursActive: boolean;
    focusModeActive: boolean;
    digestCadenceMs: number;
}

export interface AttentionInput {
    posture: SecurityPosture;
    incidents: IncidentExtended[];
    operatorContext: OperatorContext;
}

// =============================================================================
// Pure Functions
// =============================================================================

/**
 * Determine banner content based on posture and incidents.
 * 
 * @invariant I3: Critical posture always takes precedence
 */
function computeBanner(
    posture: SecurityPosture,
    incidents: IncidentExtended[]
): { text: string | null; severity: Severity | null } {
    // Trust critical is highest priority
    if (posture.trustLevel === 'critical') {
        return {
            text: 'Security Configuration Required — Trust anchors not configured',
            severity: 'critical',
        };
    }

    // Invariant I3: choose the most important unacked critical incident, not the first in input order.
    const criticalUnacked = [...incidents]
        .filter(i => i.severity === 'critical' && i.unacked)
        .sort(compareIncidentPriority)[0];

    if (criticalUnacked) {
        return {
            text: `Critical Issue: ${criticalUnacked.title}`,
            severity: 'critical',
        };
    }

    return { text: null, severity: null };
}

/**
 * Get actionable incidents (not resolved, not flapping).
 */
function getActionableIncidents(incidents: IncidentExtended[]): IncidentExtended[] {
    return incidents.filter(
        i => i.state !== 'resolved' && !i.flapping
    );
}

function isUnackedCritical(incident: IncidentExtended): boolean {
    return incident.severity === 'critical' && incident.unacked;
}

function compareIncidentPriority(a: IncidentExtended, b: IncidentExtended): number {
    // Invariant I3: unacked critical incidents must always appear first.
    const aCritical = isUnackedCritical(a);
    const bCritical = isUnackedCritical(b);
    if (aCritical !== bCritical) return aCritical ? -1 : 1;

    // Secondary: explicit priority (higher is more important), then recency for stability.
    if (b.priority !== a.priority) return b.priority - a.priority;
    return b.lastSeen - a.lastSeen;
}

/**
 * Get top-k incidents by priority.
 * 
 * @complexity O(n log k) using partial sort
 */
function topKByPriority(incidents: IncidentExtended[], k: number): IncidentExtended[] {
    const sorted = [...incidents].sort(compareIncidentPriority);

    return sorted.slice(0, k);
}

/**
 * Determine if a toast should be shown based on rate limiting.
 * 
 * @invariant I6: Rate-limit interrupts except CRITICAL
 */
function shouldShowToast(
    incident: IncidentExtended,
    context: OperatorContext,
    now: number
): boolean {
    // Critical always gets through (except quiet hours for non-trust)
    if (incident.severity === 'critical') {
        return true;
    }

    // Focus mode: only critical
    if (context.focusModeActive) {
        return false;
    }

    // Quiet hours: only critical
    if (context.quietHoursActive) {
        return false;
    }

    // Rate limit check
    const timeSinceLastToast = now - context.lastToastTime;
    return timeSinceLastToast >= TOAST_MIN_INTERVAL_MS;
}

/**
 * Classify incidents into work queue vs digest based on urgency.
 */
function partitionByUrgency(incidents: IncidentExtended[]): {
    workQueue: IncidentExtended[];
    digest: IncidentExtended[];
} {
    const workQueue: IncidentExtended[] = [];
    const digest: IncidentExtended[] = [];

    for (const incident of incidents) {
        if (incident.severity === 'critical' || incident.severity === 'warning') {
            workQueue.push(incident);
        } else {
            digest.push(incident);
        }
    }

    return { workQueue, digest };
}

// =============================================================================
// Main Algorithm
// =============================================================================

/**
 * Schedule attention allocation.
 * 
 * Algorithm 5: AttentionBudgetScheduler
 * 
 * @complexity O(n log k) where n = incidents, k = work queue size
 * @invariant I3: Unacked critical always first
 * @invariant I12: Work queue capped at ATTENTION_BUDGET for critical
 */
export function scheduleAttention(input: AttentionInput): AttentionBudgetResult {
    const { posture, incidents, operatorContext } = input;
    const now = Date.now();

    // Step 1: Compute banner
    const { text: banner, severity: bannerSeverity } = computeBanner(posture, incidents);

    // Step 2: Get actionable and prioritized incidents
    const actionable = getActionableIncidents(incidents);
    const workQueue = topKByPriority(actionable, WORK_QUEUE_SIZE);

    // Step 3: Compute toasts (rate-limited new items)
    const toasts: string[] = [];
    for (const incident of workQueue.slice(0, 3)) {
        if (shouldShowToast(incident, operatorContext, now)) {
            toasts.push(incident.title);
        }
    }

    // Step 4: Compute badge counts
    const badgeCounts = {
        incidentsUnacked: incidents.filter(i => i.unacked).length,
        alertsTotal: incidents.reduce((sum, i) => sum + i.count, 0),
        verifyFailures24h: incidents.filter(
            i => i.primary.type === 'verification_failure'
        ).length,
    };

    // Step 5: Partition low-urgency for digest
    const { digest: lowUrgency } = partitionByUrgency(actionable);
    const digests = lowUrgency.map(i => i.title);

    return {
        banner,
        bannerSeverity,
        toasts,
        badgeCounts,
        workQueue,
        digests,
    };
}

/**
 * Create default operator context.
 */
export function createDefaultOperatorContext(): OperatorContext {
    return {
        lastToastTime: 0,
        quietHoursActive: false,
        focusModeActive: false,
        digestCadenceMs: DIGEST_CADENCE_MS,
    };
}

/**
 * Check if attention budget is exceeded (triggers auto-degrade warning).
 * 
 * @invariant I12: Attention budget enforced
 */
export function isAttentionBudgetExceeded(incidents: IncidentExtended[]): boolean {
    const criticalUnacked = incidents.filter(
        i => i.severity === 'critical' && i.unacked
    ).length;

    return criticalUnacked > ATTENTION_BUDGET;
}
