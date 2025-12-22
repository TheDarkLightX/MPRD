/**
 * Algorithm 1: SecurityPostureComputation
 * 
 * Computes trust and availability posture from system state.
 * 
 * @complexity O(n) where n = decisions in window
 * @invariant I1: Missing trust anchors in trustless/private → CRITICAL
 * 
 * @precondition trust_anchors, components, and decisions are valid
 * @postcondition Returns SecurityPosture with trust_level and availability_level
 */

import type {
    SystemStatus,
    DecisionSummary,
    TrustAnchors,
    SecurityPosture,
    TrustLevel,
    AvailabilityLevel,
} from '../api/types';

// =============================================================================
// Configuration Constants
// =============================================================================

const VERIFY_FAIL_DEGRADED_THRESHOLD = 0.05;
const EXEC_FAIL_DEGRADED_THRESHOLD = 0.05;
const TOTAL_FAIL_DEGRADED_THRESHOLD = 0.10;
const DEFAULT_WINDOW_MS = 60 * 60 * 1000; // 1 hour

// =============================================================================
// Pure Functions
// =============================================================================

/**
 * Check if trust anchors are fully configured.
 * 
 * @precondition anchors is a valid TrustAnchors object
 * @postcondition Returns true iff all three anchor fields are present
 */
function areAnchorsConfigured(anchors: TrustAnchors): boolean {
    return Boolean(
        anchors.registryStatePath &&
        anchors.registryKeyFingerprint &&
        anchors.manifestKeyFingerprint
    );
}

/**
 * Check if all components are healthy.
 * 
 * @precondition status is a valid SystemStatus object
 * @postcondition Returns true iff all components have status 'healthy'
 */
function areComponentsHealthy(status: SystemStatus): boolean {
    const components = Object.values(status.components);
    return components.every(c => c.status === 'healthy');
}

/**
 * Filter decisions within the time window.
 * 
 * @precondition decisions is an array of valid DecisionSummary
 * @postcondition Returns only decisions with timestamp >= (now - windowMs)
 */
function filterRecentDecisions(
    decisions: DecisionSummary[],
    windowMs: number = DEFAULT_WINDOW_MS
): DecisionSummary[] {
    const cutoff = Date.now() - windowMs;
    return decisions.filter(d => d.timestamp >= cutoff);
}

/**
 * Compute failure rates from decisions.
 * 
 * @precondition decisions is a non-empty array
 * @postcondition Returns rates in [0, 1] range
 */
function computeFailureRates(decisions: DecisionSummary[]): {
    verifyFailRate: number;
    execFailRate: number;
    failRate: number;
} {
    const total = Math.max(1, decisions.length);

    const verifyFailed = decisions.filter(d => d.proofStatus === 'failed').length;
    const execFailed = decisions.filter(d => d.executionStatus === 'failed').length;
    const totalFailed = decisions.filter(
        d => d.proofStatus === 'failed' || d.executionStatus === 'failed'
    ).length;

    return {
        verifyFailRate: verifyFailed / total,
        execFailRate: execFailed / total,
        failRate: totalFailed / total,
    };
}

/**
 * Determine trust level based on anchor configuration and verification rate.
 * 
 * @invariant I1: Missing anchors → critical
 */
function computeTrustLevel(
    anchorsConfigured: boolean,
    verifyFailRate: number
): TrustLevel {
    if (!anchorsConfigured) {
        return 'critical';
    }
    if (verifyFailRate > VERIFY_FAIL_DEGRADED_THRESHOLD) {
        return 'degraded';
    }
    return 'healthy';
}

/**
 * Determine availability level based on component health and failure rates.
 */
function computeAvailabilityLevel(
    componentsHealthy: boolean,
    execFailRate: number,
    failRate: number
): AvailabilityLevel {
    if (!componentsHealthy) {
        return 'critical';
    }
    if (execFailRate > EXEC_FAIL_DEGRADED_THRESHOLD || failRate > TOTAL_FAIL_DEGRADED_THRESHOLD) {
        return 'degraded';
    }
    return 'healthy';
}

/**
 * Generate human-readable reasons for the posture.
 */
function generateReasons(
    trustLevel: TrustLevel,
    availabilityLevel: AvailabilityLevel,
    anchorsConfigured: boolean,
    componentsHealthy: boolean,
    rates: { verifyFailRate: number; execFailRate: number; failRate: number }
): string[] {
    const reasons: string[] = [];

    if (!anchorsConfigured) {
        reasons.push('Trust anchors not configured - FAIL-CLOSED');
    }

    if (!componentsHealthy) {
        reasons.push('One or more components unhealthy');
    }

    if (rates.verifyFailRate > VERIFY_FAIL_DEGRADED_THRESHOLD) {
        reasons.push(`Verification failure rate ${(rates.verifyFailRate * 100).toFixed(1)}% exceeds threshold`);
    }

    if (rates.execFailRate > EXEC_FAIL_DEGRADED_THRESHOLD) {
        reasons.push(`Execution failure rate ${(rates.execFailRate * 100).toFixed(1)}% exceeds threshold`);
    }

    if (trustLevel === 'healthy' && availabilityLevel === 'healthy' && reasons.length === 0) {
        reasons.push('All systems operating normally');
    }

    return reasons;
}

// =============================================================================
// Main Algorithm
// =============================================================================

export interface SecurityPostureInput {
    trustAnchors: TrustAnchors;
    status: SystemStatus;
    decisions: DecisionSummary[];
    windowMs?: number;
}

/**
 * Compute security posture from system state.
 * 
 * Algorithm 1: SecurityPostureComputation
 * 
 * @complexity O(n) where n = |decisions|
 * @invariant I1: Missing trust anchors → trust_level = critical
 */
export function computeSecurityPosture(input: SecurityPostureInput): SecurityPosture {
    const { trustAnchors, status, decisions, windowMs = DEFAULT_WINDOW_MS } = input;

    // Step 1-2: Check anchor and component configuration
    const anchorsConfigured = areAnchorsConfigured(trustAnchors);
    const componentsHealthy = areComponentsHealthy(status);

    // Step 3: Filter to recent decisions
    const recentDecisions = filterRecentDecisions(decisions, windowMs);

    // Step 4-6: Compute failure rates
    const rates = computeFailureRates(recentDecisions);

    // Step 7: Compute decision rate (per minute)
    const windowMinutes = windowMs / (60 * 1000);
    const decisionRate = recentDecisions.length / Math.max(1, windowMinutes);

    // Step 8-9: Determine trust and availability levels
    const trustLevel = computeTrustLevel(anchorsConfigured, rates.verifyFailRate);
    const availabilityLevel = computeAvailabilityLevel(
        componentsHealthy,
        rates.execFailRate,
        rates.failRate
    );

    // Step 10: Generate reasons
    const reasons = generateReasons(
        trustLevel,
        availabilityLevel,
        anchorsConfigured,
        componentsHealthy,
        rates
    );

    return {
        trustLevel,
        availabilityLevel,
        reasons,
        metrics: {
            failRate: rates.failRate,
            verifyFailRate: rates.verifyFailRate,
            execFailRate: rates.execFailRate,
            decisionRate,
        },
    };
}

/**
 * Check if posture requires immediate attention.
 */
export function isPostureCritical(posture: SecurityPosture): boolean {
    return posture.trustLevel === 'critical' || posture.availabilityLevel === 'critical';
}

/**
 * Get the overall severity from posture.
 */
export function getPostureSeverity(posture: SecurityPosture): 'critical' | 'degraded' | 'healthy' {
    if (posture.trustLevel === 'critical' || posture.availabilityLevel === 'critical') {
        return 'critical';
    }
    if (posture.trustLevel === 'degraded' || posture.availabilityLevel === 'degraded') {
        return 'degraded';
    }
    return 'healthy';
}
