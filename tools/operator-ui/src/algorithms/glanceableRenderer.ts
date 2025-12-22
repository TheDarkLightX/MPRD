/**
 * Algorithm 12: GlanceablePostureRenderer
 * 
 * Renders system state for 1-3 second comprehension.
 * 
 * @complexity O(c) where c = active incidents
 * @design No numbers in primary view, single headline answers "Do I need to do anything?"
 * 
 * @postcondition Returns GlanceableView ready for UI rendering
 */

import type {
    SecurityPosture,
    IncidentExtended,
    AutopilotState,
    GlanceableView,
    Severity,
    AttentionDemand,
    PrescriptiveAction,
    TrendSet,
    TrendDirection,
    AutopilotBadge,
} from '../api/types';
import { ATTENTION_BUDGET } from './attentionScheduler';

// =============================================================================
// Constants
// =============================================================================

const MAX_HEADLINE_LENGTH = 50;
const ESTIMATED_RESOLUTION_MINUTES = {
    critical: 15,
    warning: 5,
    info: 2,
};

// =============================================================================
// Headline Generation
// =============================================================================

interface HeadlineResult {
    text: string;
    severity: Severity;
}

/**
 * Generate headline (max 8 words) and severity.
 */
function generateHeadline(
    posture: SecurityPosture,
    incidents: IncidentExtended[],
    autopilot: AutopilotState
): HeadlineResult {
    // Count active incidents
    const activeCritical = incidents.filter(
        i => i.severity === 'critical' && i.unacked
    ).length;
    const activeWarning = incidents.filter(
        i => i.severity === 'warning' && i.unacked
    ).length;

    // Priority 1: Security configuration critical
    if (posture.trustLevel === 'critical') {
        return {
            text: 'Security Configuration Required',
            severity: 'critical',
        };
    }

    // Priority 2: Critical incidents
    if (activeCritical > 0) {
        const plural = activeCritical > 1 ? 's' : '';
        return {
            text: `${activeCritical} Critical Issue${plural} Need Attention`,
            severity: 'critical',
        };
    }

    // Priority 3: Multiple warnings
    if (activeWarning > 3) {
        return {
            text: 'Multiple Warnings - Review Needed',
            severity: 'warning',
        };
    }

    // Priority 4: Some warnings
    if (activeWarning > 0) {
        const plural = activeWarning > 1 ? 's' : '';
        return {
            text: `${activeWarning} Warning${plural} to Review`,
            severity: 'warning',
        };
    }

    // Priority 5: Autopilot pending review
    if (autopilot.pendingReviewCount > 0) {
        return {
            text: 'Autopilot Actions Pending Review',
            severity: 'info',
        };
    }

    // Default: All clear
    return {
        text: 'All Systems Normal',
        severity: 'ok',
    };
}

// =============================================================================
// Attention Demand
// =============================================================================

function computeAttentionDemand(
    incidents: IncidentExtended[],
    previousCount?: number
): AttentionDemand {
    const actionable = incidents.filter(i => i.unacked);
    const itemsNeedingAction = actionable.length;

    // Estimate resolution time
    const estimatedMinutes = actionable.reduce((sum, i) => {
        return sum + (ESTIMATED_RESOLUTION_MINUTES[i.severity] ?? 5);
    }, 0);

    // Check budget
    const criticalCount = actionable.filter(i => i.severity === 'critical').length;
    const withinBudget = criticalCount <= ATTENTION_BUDGET;

    // Compute trend vs previous hour
    let trend: TrendDirection = 'stable';
    if (previousCount !== undefined) {
        if (itemsNeedingAction > previousCount * 1.2) trend = 'up';
        else if (itemsNeedingAction < previousCount * 0.8) trend = 'down';
    }

    return {
        itemsNeedingAction,
        estimatedMinutes,
        withinBudget,
        trend,
    };
}

// =============================================================================
// Next Action
// =============================================================================

function computeNextAction(
    incidents: IncidentExtended[]
): PrescriptiveAction | null {
    // Get highest priority unacked incident
    const actionable = incidents
        .filter(i => i.unacked)
        .sort((a, b) => b.priority - a.priority);

    if (actionable.length === 0) {
        return null;
    }

    const top = actionable[0];

    return {
        label: truncate(`Review: ${top.title}`, 40),
        route: `/security`, // Would be /incidents/${top.id} if we had that route
        urgency: top.severity as Severity,
        estimatedTimeMinutes: ESTIMATED_RESOLUTION_MINUTES[top.severity] ?? 5,
    };
}

function truncate(text: string, max: number): string {
    if (text.length <= max) return text;
    return `${text.slice(0, max - 1)}…`;
}

// =============================================================================
// Trends
// =============================================================================

function computeTrends(
    currentMetrics: SecurityPosture['metrics'],
    previousMetrics?: SecurityPosture['metrics']
): TrendSet {
    if (!previousMetrics) {
        return {
            decisions: 'stable',
            success: 'stable',
            latency: 'stable',
        };
    }

    const decisionsTrend = compareTrend(
        currentMetrics.decisionRate,
        previousMetrics.decisionRate
    );

    // For success, we use inverse of fail rate
    const successTrend = compareTrend(
        1 - currentMetrics.failRate,
        1 - previousMetrics.failRate
    );

    // For latency, down is good
    const latencyTrend = compareTrend(
        previousMetrics.decisionRate, // placeholder - would need actual latency
        currentMetrics.decisionRate
    );

    return {
        decisions: decisionsTrend,
        success: successTrend,
        latency: latencyTrend,
    };
}

function compareTrend(current: number, previous: number): TrendDirection {
    const threshold = 0.05;
    const change = (current - previous) / Math.max(0.001, Math.abs(previous));

    if (change > threshold) return 'up';
    if (change < -threshold) return 'down';
    return 'stable';
}

// =============================================================================
// Autopilot Badge
// =============================================================================

function computeAutopilotBadge(autopilot: AutopilotState): AutopilotBadge | null {
    if (autopilot.mode === 'manual') {
        return null;
    }

    const ACK_INTERVAL_MS = 4 * 60 * 60 * 1000; // 4 hours

    return {
        mode: autopilot.mode,
        autoHandled24h: autopilot.autoHandled24h,
        pendingReview: autopilot.pendingReviewCount,
        nextAckRequired: autopilot.lastHumanAck + ACK_INTERVAL_MS,
    };
}

// =============================================================================
// Main Algorithm
// =============================================================================

// =============================================================================
// Trend Narrative (v1.2)
// =============================================================================

function computeTrendNarrative(
    currentCritical: number,
    previousCritical?: number
): string {
    if (previousCritical === undefined) {
        if (currentCritical === 0) return '';
        return `Stable: ${currentCritical} critical (unchanged)`;
    }

    if (currentCritical < previousCritical) {
        return `Improving: ${previousCritical}→${currentCritical} critical in last hour`;
    }

    if (currentCritical > previousCritical) {
        return `Worsening: ${previousCritical}→${currentCritical} critical in last hour`;
    }

    if (currentCritical === 0) {
        return ''; // No narrative needed when all clear
    }

    return `Stable: ${currentCritical} critical (unchanged)`;
}

// =============================================================================
// Main Algorithm
// =============================================================================

export interface GlanceableInput {
    posture: SecurityPosture;
    incidents: IncidentExtended[];
    autopilot: AutopilotState;
    previousMetrics?: SecurityPosture['metrics'];
    previousIncidentCount?: number;
    previousCriticalCount?: number; // Added for trend narrative
}

/**
 * Render glanceable posture view.
 * 
 * Algorithm 12: GlanceablePostureRenderer.render_glanceable
 * 
 * @complexity O(c) where c = active incidents
 * @design Operator should understand system state in ONE GLANCE
 */
export function renderGlanceable(input: GlanceableInput): GlanceableView {
    const { posture, incidents, autopilot, previousMetrics, previousIncidentCount, previousCriticalCount } = input;

    // Step 1: Generate headline
    const { text, severity } = generateHeadline(posture, incidents, autopilot);

    // Step 2: Compute attention demand
    const attentionDemand = computeAttentionDemand(incidents, previousIncidentCount);

    // Step 3: Compute next action
    const nextAction = attentionDemand.itemsNeedingAction > 0
        ? computeNextAction(incidents)
        : null;

    // Step 4: Compute trends
    const trends = computeTrends(posture.metrics, previousMetrics);

    // Compute sparkline (mock data for now as history isn't fully available)
    // In a real implementation this would come from the metrics aggregator history
    trends.autopilotActivity = [0, 0, 1, 0, 2, 1, 0, 0, 0, 3, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, autopilot.autoHandled24h > 5 ? 1 : 0];

    // Step 5: Compute autopilot badge
    const autopilotBadge = computeAutopilotBadge(autopilot);

    // Step 6: Compute trend narrative
    const currentCritical = incidents.filter(i => i.severity === 'critical' && i.unacked).length;
    const trendNarrative = computeTrendNarrative(currentCritical, previousCriticalCount);

    return {
        headline: truncate(text, MAX_HEADLINE_LENGTH),
        headlineSeverity: severity,
        trendNarrative,
        attentionDemand,
        nextAction,
        trends,
        autopilotBadge,
    };
}

/**
 * Create a minimal glanceable view for loading/error states.
 */
export function createLoadingGlanceableView(): GlanceableView {
    return {
        headline: 'Loading…',
        headlineSeverity: 'info',
        trendNarrative: '',
        attentionDemand: {
            itemsNeedingAction: 0,
            estimatedMinutes: 0,
            withinBudget: true,
            trend: 'stable',
        },
        nextAction: null,
        trends: {
            decisions: 'stable',
            success: 'stable',
            latency: 'stable',
            autopilotActivity: [],
        },
        autopilotBadge: null,
    };
}
