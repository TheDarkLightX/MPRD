/**
 * Generated kernel for ui_mode_adaptive_gates.
 * IR hash: 5b341afd57beaa56
 * DO NOT EDIT - regenerate from model.
 */

export type ModeMode = 'Local' | 'Trustless' | 'Private';

export interface State {
    anchors_configured: boolean;
    mode: ModeMode;
    run_pipeline_disabled: boolean;
    trust_anchor_warning: boolean;
    zk_actions_disabled: boolean;
}

export function initState(): State {
    return {
        mode: 'Local',
        anchors_configured: false,
        run_pipeline_disabled: false,
        zk_actions_disabled: true,
        trust_anchor_warning: false,
    };
}

export type Command =
    | { type: 'configure_anchors' }
    | { type: 'go_local' }
    | { type: 'go_private' }
    | { type: 'go_trustless' }
;

export interface InvariantViolation {
    id: string;
    message: string;
}

export function checkInvariants(state: State): InvariantViolation[] {
    const violations: InvariantViolation[] = [];

    // I1_TrustlessRequiresAnchors
    if (!(((!(('Local' !== state.mode) && (!state.anchors_configured))) || (state.run_pipeline_disabled && state.trust_anchor_warning)))) {
        violations.push({ id: 'I1_TrustlessRequiresAnchors', message: 'I1_TrustlessRequiresAnchors violated' });
    }

    // I2_LocalDisablesZK
    if (!(((!('Local' === state.mode)) || state.zk_actions_disabled))) {
        violations.push({ id: 'I2_LocalDisablesZK', message: 'I2_LocalDisablesZK violated' });
    }

    return violations;
}

export interface StepResult {
    success: boolean;
    state?: State;
    error?: string;
    violations?: InvariantViolation[];
}

export function step(state: State, cmd: Command): StepResult {
    // Pre-check invariants
    const preViolations = checkInvariants(state);
    if (preViolations.length > 0) {
        return { success: false, error: 'Pre-invariant violated', violations: preViolations };
    }

    let next: State;

    switch (cmd.type) {
        case 'configure_anchors': {
            if (!(true)) {
                return { success: false, error: 'Guard failed: configure_anchors' };
            }
            next = {
                anchors_configured: true,
                mode: state.mode,
                run_pipeline_disabled: false,
                trust_anchor_warning: false,
                zk_actions_disabled: state.zk_actions_disabled,
            };
            break;
        }
        case 'go_local': {
            if (!(('Local' !== state.mode))) {
                return { success: false, error: 'Guard failed: go_local' };
            }
            next = {
                anchors_configured: state.anchors_configured,
                mode: 'Local',
                run_pipeline_disabled: false,
                trust_anchor_warning: false,
                zk_actions_disabled: true,
            };
            break;
        }
        case 'go_private': {
            if (!(('Private' !== state.mode))) {
                return { success: false, error: 'Guard failed: go_private' };
            }
            next = {
                anchors_configured: state.anchors_configured,
                mode: 'Private',
                run_pipeline_disabled: (state.anchors_configured ? false : true),
                trust_anchor_warning: (state.anchors_configured ? false : true),
                zk_actions_disabled: false,
            };
            break;
        }
        case 'go_trustless': {
            if (!(('Trustless' !== state.mode))) {
                return { success: false, error: 'Guard failed: go_trustless' };
            }
            next = {
                anchors_configured: state.anchors_configured,
                mode: 'Trustless',
                run_pipeline_disabled: (state.anchors_configured ? false : true),
                trust_anchor_warning: (state.anchors_configured ? false : true),
                zk_actions_disabled: false,
            };
            break;
        }
        default:
            return { success: false, error: 'Unknown command' };
    }

    // Post-check invariants
    const postViolations = checkInvariants(next);
    if (postViolations.length > 0) {
        return { success: false, error: 'Post-invariant violated', violations: postViolations };
    }

    return { success: true, state: next };
}
