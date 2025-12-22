/**
 * Algorithm 10: AutopilotController
 * 
 * State machine managing automation levels with security guardrails.
 * 
 * @complexity O(1)
 * @invariant I9: Autopilot requires trust_anchors.configured = true
 * @invariant I10: Autopilot auto-degrades on >20% verification failure rate
 * @invariant I11: Autopilot: WARNING at 4h without ack, AUTO-DEGRADE at 8h
 * @invariant I12: Attention budget enforcement triggers degradation
 * 
 * @postcondition Mode transitions are logged and validated
 */

import type {
    AutopilotMode,
    AutopilotState,
    SecurityPosture,
    IncidentExtended,
} from '../api/types';
import { ATTENTION_BUDGET } from './attentionScheduler';

// =============================================================================
// Configuration Constants
// =============================================================================

const ACK_WARNING_THRESHOLD_MS = 4 * 60 * 60 * 1000; // 4 hours
const ACK_DEGRADE_THRESHOLD_MS = 8 * 60 * 60 * 1000; // 8 hours
const VERIFY_FAIL_DEGRADE_THRESHOLD = 0.20; // 20%
const VERIFY_FAIL_ASSISTED_THRESHOLD = 0.05; // 5%

// =============================================================================
// Types
// =============================================================================

export interface ModeTransitionResult {
    success: boolean;
    error?: string;
    violations?: string[];
}

export interface AutoDegradeResult {
    degraded: boolean;
    fromMode: AutopilotMode;
    toMode: AutopilotMode;
    reason: string;
}

export interface TransitionPreconditions {
    anchorsConfigured: boolean;
    recentAck: boolean;
    lowFailRate: boolean;
    noCriticalIncidents: boolean;
}

// =============================================================================
// Precondition Checks
// =============================================================================

/**
 * Check all preconditions for transitioning to Autopilot mode.
 * 
 * @invariant I9: Autopilot requires anchors
 */
function checkAutopilotPreconditions(
    posture: SecurityPosture,
    incidents: IncidentExtended[],
    lastHumanAck: number
): { met: boolean; violations: string[] } {
    const now = Date.now();
    const violations: string[] = [];

    // I9: Trust anchors must be configured
    if (posture.trustLevel === 'critical') {
        violations.push('Trust anchors not configured (I9 violation)');
    }

    // Recent human acknowledgment required
    const timeSinceAck = now - lastHumanAck;
    if (timeSinceAck > ACK_WARNING_THRESHOLD_MS) {
        violations.push(`No human acknowledgment in ${Math.floor(timeSinceAck / 3600000)}h (requires < 4h)`);
    }

    // Low verification failure rate
    if (posture.metrics.verifyFailRate > VERIFY_FAIL_ASSISTED_THRESHOLD) {
        violations.push(`Verification failure rate ${(posture.metrics.verifyFailRate * 100).toFixed(1)}% exceeds 5% threshold`);
    }

    // No active critical incidents
    const criticalUnacked = incidents.filter(
        i => i.severity === 'critical' && i.unacked
    ).length;
    if (criticalUnacked > 0) {
        violations.push(`${criticalUnacked} unacked critical incident(s) exist`);
    }

    return {
        met: violations.length === 0,
        violations,
    };
}

/**
 * Get valid transition targets for current mode.
 */
function getValidTransitions(mode: AutopilotMode): AutopilotMode[] {
    switch (mode) {
        case 'manual':
            return ['assisted'];
        case 'assisted':
            return ['manual', 'autopilot'];
        case 'autopilot':
            return ['manual', 'assisted'];
    }
}

// =============================================================================
// Main Algorithm
// =============================================================================

export interface AutopilotControllerState {
    mode: AutopilotMode;
    lastHumanAck: number;
    pendingReviewQueue: string[];
    autoActionsCount24h: number;
}

/**
 * Attempt to transition autopilot mode.
 * 
 * Algorithm 10: AutopilotController.transition_mode
 * 
 * @complexity O(1)
 * @invariant I9: Autopilot requires anchors
 */
export function transitionMode(
    currentState: AutopilotControllerState,
    targetMode: AutopilotMode,
    posture: SecurityPosture,
    incidents: IncidentExtended[]
): ModeTransitionResult {
    // Check if transition is valid
    const validTargets = getValidTransitions(currentState.mode);
    if (!validTargets.includes(targetMode)) {
        return {
            success: false,
            error: `Cannot transition from ${currentState.mode} to ${targetMode}`,
        };
    }

    // Check preconditions for Autopilot
    if (targetMode === 'autopilot') {
        const { met, violations } = checkAutopilotPreconditions(
            posture,
            incidents,
            currentState.lastHumanAck
        );

        if (!met) {
            return {
                success: false,
                error: 'Preconditions not met for Autopilot mode',
                violations,
            };
        }
    }

    return { success: true };
}

/**
 * Check if a transition is valid without performing it.
 * Used for UI preview/validation before user confirms.
 */
export function checkTransition(
    currentState: AutopilotControllerState,
    targetMode: AutopilotMode,
    posture: SecurityPosture,
    incidents: IncidentExtended[]
): ModeTransitionResult {
    // Same logic as transitionMode - just validation
    return transitionMode(currentState, targetMode, posture, incidents);
}

/**
 * Check for automatic degradation conditions.
 * 
 * Algorithm 10: AutopilotController.auto_degrade
 * 
 * @invariant I10: Auto-degrade on >20% failure rate
 * @invariant I11: Auto-degrade on 8h without ack
 * @invariant I12: Auto-degrade on attention budget exceeded
 */
export function checkAutoDegradation(
    currentState: AutopilotControllerState,
    posture: SecurityPosture,
    incidents: IncidentExtended[]
): AutoDegradeResult | null {
    if (currentState.mode === 'manual') {
        return null; // Can't degrade from manual
    }

    const now = Date.now();

    // I10: High verification failure rate → Manual
    if (posture.metrics.verifyFailRate > VERIFY_FAIL_DEGRADE_THRESHOLD) {
        return {
            degraded: true,
            fromMode: currentState.mode,
            toMode: 'manual',
            reason: `Auto-degraded to Manual: verification failure rate ${(posture.metrics.verifyFailRate * 100).toFixed(1)}% exceeds 20%`,
        };
    }

    // I11: No ack for 8h → Assisted (from Autopilot)
    if (currentState.mode === 'autopilot') {
        const timeSinceAck = now - currentState.lastHumanAck;
        if (timeSinceAck > ACK_DEGRADE_THRESHOLD_MS) {
            return {
                degraded: true,
                fromMode: 'autopilot',
                toMode: 'assisted',
                reason: 'Auto-degraded to Assisted: no human acknowledgment in 8 hours',
            };
        }
    }

    // I12: Attention budget exceeded → Assisted (from Autopilot)
    if (currentState.mode === 'autopilot') {
        const criticalUnacked = incidents.filter(
            i => i.severity === 'critical' && i.unacked
        ).length;

        if (criticalUnacked > ATTENTION_BUDGET) {
            return {
                degraded: true,
                fromMode: 'autopilot',
                toMode: 'assisted',
                reason: `Auto-degraded to Assisted: ${criticalUnacked} critical incidents exceed attention budget of ${ATTENTION_BUDGET}`,
            };
        }
    }

    return null;
}

/**
 * Check if ack warning should be shown.
 * 
 * @invariant I11: Warning at 4h
 */
export function shouldShowAckWarning(lastHumanAck: number): {
    show: boolean;
    minutesUntilDegrade: number;
} {
    const now = Date.now();
    const timeSinceAck = now - lastHumanAck;

    if (timeSinceAck > ACK_WARNING_THRESHOLD_MS) {
        const timeUntilDegrade = ACK_DEGRADE_THRESHOLD_MS - timeSinceAck;
        return {
            show: true,
            minutesUntilDegrade: Math.max(0, Math.floor(timeUntilDegrade / 60000)),
        };
    }

    return { show: false, minutesUntilDegrade: 0 };
}

/**
 * Create initial autopilot state.
 */
export function createInitialAutopilotState(): AutopilotControllerState {
    return {
        mode: 'manual',
        lastHumanAck: Date.now(),
        pendingReviewQueue: [],
        autoActionsCount24h: 0,
    };
}

/**
 * Convert internal state to API state type.
 */
export function toAutopilotState(state: AutopilotControllerState): AutopilotState {
    return {
        mode: state.mode,
        lastHumanAck: state.lastHumanAck,
        pendingReviewCount: state.pendingReviewQueue.length,
        autoHandled24h: state.autoActionsCount24h,
        canTransitionTo: getValidTransitions(state.mode),
    };
}
