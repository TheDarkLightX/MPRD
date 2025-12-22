/**
 * Algorithm 8: AutomationActionPlanner
 * 
 * Suggests actions for incidents with risk classification.
 * 
 * @complexity O(r) where r = number of rules
 * @invariant I7: UI MUST NOT auto-run actions that change trust/authorization
 * @invariant I8: All operator actions MUST be audit-logged
 * 
 * @postcondition Actions sorted by risk ASC, time-to-signal ASC
 */

import type {
    IncidentExtended,
    SuggestedAction,
    ActionRisk,
} from '../api/types';

// =============================================================================
// Action Templates
// =============================================================================

const SAFE_ACTIONS = {
    checkStatus: (target: string): SuggestedAction => ({
        id: `check-status-${Date.now()}`,
        label: 'Check Status',
        description: `Verify current status of ${target}`,
        risk: 'low',
        dryRun: true,
        requiresConfirmation: false,
        estimatedTimeSeconds: 5,
    }),

    viewLogs: (target: string): SuggestedAction => ({
        id: `view-logs-${Date.now()}`,
        label: 'View Logs',
        description: `View recent logs for ${target}`,
        risk: 'low',
        dryRun: true,
        requiresConfirmation: false,
        estimatedTimeSeconds: 10,
    }),

    reverifyDecision: (decisionId: string): SuggestedAction => ({
        id: `reverify-${decisionId}`,
        label: 'Re-verify Decision',
        description: 'Re-run proof verification on the decision',
        risk: 'low',
        dryRun: true,
        requiresConfirmation: false,
        estimatedTimeSeconds: 30,
    }),

    checkTrustAnchors: (): SuggestedAction => ({
        id: `check-anchors-${Date.now()}`,
        label: 'Check Trust Anchors',
        description: 'Verify trust anchor configuration',
        risk: 'low',
        dryRun: true,
        requiresConfirmation: false,
        estimatedTimeSeconds: 5,
    }),

    compareRegistryRoot: (): SuggestedAction => ({
        id: `compare-registry-${Date.now()}`,
        label: 'Compare Registry Root',
        description: 'Compare local registry root with expected value',
        risk: 'low',
        dryRun: true,
        requiresConfirmation: false,
        estimatedTimeSeconds: 10,
    }),
};

const CONFIRMED_ACTIONS = {
    restartService: (service: string, runbookLink?: string): SuggestedAction => ({
        id: `restart-${service}-${Date.now()}`,
        label: `Restart ${service}`,
        description: `Restart the ${service} service`,
        risk: 'medium',
        dryRun: false,
        requiresConfirmation: true,
        runbookLink,
        estimatedTimeSeconds: 60,
    }),

    reloadPolicy: (policyHash: string): SuggestedAction => ({
        id: `reload-policy-${policyHash.slice(0, 8)}`,
        label: 'Reload Policy',
        description: 'Reload policy from disk',
        risk: 'medium',
        dryRun: false,
        requiresConfirmation: true,
        estimatedTimeSeconds: 15,
    }),
};

// =============================================================================
// Risk Scoring
// =============================================================================

function getRiskScore(risk: ActionRisk): number {
    switch (risk) {
        case 'low': return 0;
        case 'medium': return 1;
        case 'high': return 2;
    }
}

function sortByRiskAndTime(actions: SuggestedAction[]): SuggestedAction[] {
    return [...actions].sort((a, b) => {
        const riskDiff = getRiskScore(a.risk) - getRiskScore(b.risk);
        if (riskDiff !== 0) return riskDiff;
        return a.estimatedTimeSeconds - b.estimatedTimeSeconds;
    });
}

// =============================================================================
// Main Algorithm
// =============================================================================

/**
 * Plan automation actions for an incident.
 * 
 * Algorithm 8: AutomationActionPlanner
 * 
 * @complexity O(r) where r = number of rules checked
 * @invariant I7: Never auto-run trust/authorization changes
 */
export function planActions(incident: IncidentExtended): SuggestedAction[] {
    const actions: SuggestedAction[] = [];
    const alertType = incident.primary.type;

    switch (alertType) {
        case 'component_down':
            actions.push(
                SAFE_ACTIONS.checkStatus(incident.primary.message),
                SAFE_ACTIONS.viewLogs(incident.primary.message),
                CONFIRMED_ACTIONS.restartService(
                    extractComponentName(incident.primary.message),
                    'https://docs.mprd.dev/runbooks/component-restart'
                )
            );
            break;

        case 'verification_failure':
            if (incident.primary.decisionId) {
                actions.push(
                    SAFE_ACTIONS.reverifyDecision(incident.primary.decisionId)
                );
            }
            actions.push(
                SAFE_ACTIONS.checkTrustAnchors(),
                SAFE_ACTIONS.compareRegistryRoot()
            );
            break;

        case 'execution_error':
            actions.push(
                SAFE_ACTIONS.viewLogs('executor')
            );
            break;

        case 'anomaly':
            actions.push(
                SAFE_ACTIONS.viewLogs('system'),
                SAFE_ACTIONS.checkStatus('all')
            );
            break;
    }

    return sortByRiskAndTime(actions);
}

/**
 * Extract component name from alert message.
 */
function extractComponentName(message: string): string {
    const components = ['tau', 'ipfs', 'risc0', 'executor'];
    const lowerMsg = message.toLowerCase();

    for (const comp of components) {
        if (lowerMsg.includes(comp)) {
            return comp;
        }
    }

    return 'service';
}

/**
 * Check if an action requires confirmation.
 * 
 * @invariant I7: Trust/auth changes always require confirmation
 */
export function requiresConfirmation(action: SuggestedAction): boolean {
    // All non-low risk actions require confirmation
    if (action.risk !== 'low') return true;

    // Explicit flag
    return action.requiresConfirmation;
}

/**
 * Create an audit log entry for an action.
 * 
 * @invariant I8: All actions must be logged
 */
export function createAuditEntry(
    action: SuggestedAction,
    operatorId: string,
    result: 'success' | 'failed' | 'cancelled'
): {
    timestamp: number;
    actionId: string;
    operatorId: string;
    actionType: string;
    result: string;
} {
    return {
        timestamp: Date.now(),
        actionId: action.id,
        operatorId,
        actionType: action.label,
        result,
    };
}
