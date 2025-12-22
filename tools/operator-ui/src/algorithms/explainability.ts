/**
 * Algorithm 11: ExplainabilityGenerator
 * 
 * Generates human-readable explanations for autopilot actions.
 * 
 * @complexity O(1)
 * @invariant All auto-actions MUST have an explanation with audit_id
 * 
 * @postcondition Returns explanation with all required fields
 */

import type {
    AutoActionType,
    Explanation,
    AutoAction,
} from '../api/types';

// =============================================================================
// Template Definitions
// =============================================================================

interface ExplanationTemplate {
    summaryTemplate: string;
    evidenceTemplate: string;
    counterfactualTemplate: string;
}

const TEMPLATES: Record<AutoActionType, ExplanationTemplate> = {
    auto_dismiss: {
        summaryTemplate: 'Auto-dismissed: {alertType} from {alertSource}',
        evidenceTemplate: "Matched pattern '{patternName}' (seen {occurrenceCount}×, 0 incidents)",
        counterfactualTemplate: 'If wrong: would have missed {potentialImpact}',
    },
    auto_correlate: {
        summaryTemplate: 'Grouped {alertCount} alerts into Incident #{incidentId}',
        evidenceTemplate: 'Common factors: {sharedAttributes}',
        counterfactualTemplate: 'If separate issues: split via incident detail view',
    },
    auto_execute: {
        summaryTemplate: 'Auto-executed: {actionType} on {target}',
        evidenceTemplate: "Playbook '{playbookName}' matched ({confidence}% confidence)",
        counterfactualTemplate: 'Rollback: {rollbackProcedure}',
    },
    auto_degrade: {
        summaryTemplate: 'Auto-degraded mode: {oldMode} → {newMode}',
        evidenceTemplate: 'Trigger: {triggerCondition}',
        counterfactualTemplate: 'To restore: {restorationSteps}',
    },
};

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Generate a unique audit ID.
 */
function generateAuditId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 10);
    return `AUD-${timestamp}-${random}`.toUpperCase();
}

/**
 * Interpolate template with context values.
 */
function interpolate(template: string, context: Record<string, string | number>): string {
    return template.replace(/\{(\w+)\}/g, (_, key) => {
        const value = context[key];
        return value !== undefined ? String(value) : `{${key}}`;
    });
}

// =============================================================================
// Context Types for Each Action
// =============================================================================

export interface AutoDismissContext {
    alertType: string;
    alertSource: string;
    patternName: string;
    occurrenceCount: number;
    potentialImpact: string;
    confidence: number;
}

export interface AutoCorrelateContext {
    alertCount: number;
    incidentId: string;
    sharedAttributes: string;
    confidence: number;
}

export interface AutoExecuteContext {
    actionType: string;
    target: string;
    playbookName: string;
    confidence: number;
    rollbackProcedure: string;
}

export interface AutoDegradeContext {
    oldMode: string;
    newMode: string;
    triggerCondition: string;
    restorationSteps: string;
}

export type ActionContext =
    | { type: 'auto_dismiss'; data: AutoDismissContext }
    | { type: 'auto_correlate'; data: AutoCorrelateContext }
    | { type: 'auto_execute'; data: AutoExecuteContext }
    | { type: 'auto_degrade'; data: AutoDegradeContext };

// =============================================================================
// Main Algorithm
// =============================================================================

/**
 * Generate explanation for an auto-action.
 * 
 * Algorithm 11: ExplainabilityGenerator.generate
 * 
 * @complexity O(1)
 * @invariant Every action gets a unique audit_id
 */
export function generateExplanation(context: ActionContext): Explanation {
    const template = TEMPLATES[context.type];
    const data = context.data as unknown as Record<string, string | number>;

    const explanation: Explanation = {
        summary: interpolate(template.summaryTemplate, data),
        evidence: interpolate(template.evidenceTemplate, data),
        confidence: 'confidence' in data ? Number(data.confidence) / 100 : 1.0,
        counterfactual: interpolate(template.counterfactualTemplate, data),
        auditId: generateAuditId(),
        timestamp: Date.now(),
        operatorCanOverride: context.type !== 'auto_degrade', // Deterministic rules can't be overridden
    };

    return explanation;
}

/**
 * Create a full AutoAction with explanation.
 */
export function createAutoAction(
    type: AutoActionType,
    target: string,
    context: ActionContext,
    reversible = true
): AutoAction {
    return {
        id: `action-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
        type,
        target,
        timestamp: Date.now(),
        explanation: generateExplanation(context),
        reversible,
    };
}

/**
 * Generate explanation for auto-dismiss action.
 */
export function explainAutoDismiss(
    alertType: string,
    alertSource: string,
    patternName: string,
    occurrenceCount: number,
    confidence: number
): Explanation {
    return generateExplanation({
        type: 'auto_dismiss',
        data: {
            alertType,
            alertSource,
            patternName,
            occurrenceCount,
            potentialImpact: `${alertType} event requiring attention`,
            confidence,
        },
    });
}

/**
 * Generate explanation for auto-correlate action.
 */
export function explainAutoCorrelate(
    alertCount: number,
    incidentId: string,
    sharedAttributes: string[],
    confidence: number
): Explanation {
    return generateExplanation({
        type: 'auto_correlate',
        data: {
            alertCount,
            incidentId,
            sharedAttributes: sharedAttributes.join(', '),
            confidence,
        },
    });
}

/**
 * Generate explanation for auto-execute action.
 */
export function explainAutoExecute(
    actionType: string,
    target: string,
    playbookName: string,
    confidence: number,
    rollbackProcedure: string
): Explanation {
    return generateExplanation({
        type: 'auto_execute',
        data: {
            actionType,
            target,
            playbookName,
            confidence,
            rollbackProcedure,
        },
    });
}

/**
 * Generate explanation for auto-degrade action.
 */
export function explainAutoDegrade(
    oldMode: string,
    newMode: string,
    triggerCondition: string,
    restorationSteps: string
): Explanation {
    return generateExplanation({
        type: 'auto_degrade',
        data: {
            oldMode,
            newMode,
            triggerCondition,
            restorationSteps,
        },
    });
}
