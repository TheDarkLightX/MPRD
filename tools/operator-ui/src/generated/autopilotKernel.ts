/**
 * Generated kernel for autopilot_controller.
 * IR hash: 779e48bb60132318
 * DO NOT EDIT - regenerate from model.
 */

export type ModeMode = 'Off' | 'Assisted' | 'Autopilot';

export interface State {
    anchors_configured: boolean;
    attention_budget: number;
    critical_incidents: number;
    failure_rate_pct: number;
    hours_since_ack: number;
    mode: ModeMode;
}

export function initState(): State {
    return {
        mode: 'Off',
        anchors_configured: false,
        hours_since_ack: 0,
        failure_rate_pct: 0,
        critical_incidents: 0,
        attention_budget: 5,
    };
}

export type Command =
    | { type: 'add_critical' }
    | { type: 'auto_degrade' }
    | { type: 'configure_anchors' }
    | { type: 'go_assisted' }
    | { type: 'go_autopilot' }
    | { type: 'go_off' }
    | { type: 'human_ack' }
    | { type: 'resolve_critical' }
    | { type: 'tick_hour' }
    | { type: 'update_failure_rate'; new_rate: number }
;

export interface InvariantViolation {
    id: string;
    message: string;
}

export function checkInvariants(state: State): InvariantViolation[] {
    const violations: InvariantViolation[] = [];

    // I10_FailRateDegrades
    if (!(((!(state.failure_rate_pct > 20)) || ('Autopilot' !== state.mode)))) {
        violations.push({ id: 'I10_FailRateDegrades', message: 'I10_FailRateDegrades violated' });
    }

    // I11_AckTimeout
    if (!(((!(state.hours_since_ack >= 8)) || ('Autopilot' !== state.mode)))) {
        violations.push({ id: 'I11_AckTimeout', message: 'I11_AckTimeout violated' });
    }

    // I12_AttentionBudget
    if (!(((!(state.critical_incidents > state.attention_budget)) || ('Autopilot' !== state.mode)))) {
        violations.push({ id: 'I12_AttentionBudget', message: 'I12_AttentionBudget violated' });
    }

    // I9_AnchorRequired
    if (!(((!('Autopilot' === state.mode)) || state.anchors_configured))) {
        violations.push({ id: 'I9_AnchorRequired', message: 'I9_AnchorRequired violated' });
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
        case 'add_critical': {
            if (!((state.critical_incidents < 20))) {
                return { success: false, error: 'Guard failed: add_critical' };
            }
            next = {
                anchors_configured: state.anchors_configured,
                attention_budget: state.attention_budget,
                critical_incidents: (1 + state.critical_incidents),
                failure_rate_pct: state.failure_rate_pct,
                hours_since_ack: state.hours_since_ack,
                mode: ((('Autopilot' === state.mode) && ((1 + state.critical_incidents) > state.attention_budget)) ? 'Assisted' : state.mode),
            };
            break;
        }
        case 'auto_degrade': {
            if (!((('Autopilot' === state.mode) && ((state.critical_incidents > state.attention_budget) || (state.failure_rate_pct > 20) || (state.hours_since_ack >= 8))))) {
                return { success: false, error: 'Guard failed: auto_degrade' };
            }
            next = {
                anchors_configured: state.anchors_configured,
                attention_budget: state.attention_budget,
                critical_incidents: state.critical_incidents,
                failure_rate_pct: state.failure_rate_pct,
                hours_since_ack: state.hours_since_ack,
                mode: 'Assisted',
            };
            break;
        }
        case 'configure_anchors': {
            if (!(true)) {
                return { success: false, error: 'Guard failed: configure_anchors' };
            }
            next = {
                anchors_configured: true,
                attention_budget: state.attention_budget,
                critical_incidents: state.critical_incidents,
                failure_rate_pct: state.failure_rate_pct,
                hours_since_ack: state.hours_since_ack,
                mode: state.mode,
            };
            break;
        }
        case 'go_assisted': {
            if (!((('Autopilot' === state.mode) || ('Off' === state.mode)))) {
                return { success: false, error: 'Guard failed: go_assisted' };
            }
            next = {
                anchors_configured: state.anchors_configured,
                attention_budget: state.attention_budget,
                critical_incidents: state.critical_incidents,
                failure_rate_pct: state.failure_rate_pct,
                hours_since_ack: state.hours_since_ack,
                mode: 'Assisted',
            };
            break;
        }
        case 'go_autopilot': {
            if (!(((state.hours_since_ack < 8) && (state.critical_incidents <= state.attention_budget) && (state.failure_rate_pct <= 20) && ('Assisted' === state.mode) && state.anchors_configured))) {
                return { success: false, error: 'Guard failed: go_autopilot' };
            }
            next = {
                anchors_configured: state.anchors_configured,
                attention_budget: state.attention_budget,
                critical_incidents: state.critical_incidents,
                failure_rate_pct: state.failure_rate_pct,
                hours_since_ack: state.hours_since_ack,
                mode: 'Autopilot',
            };
            break;
        }
        case 'go_off': {
            if (!(true)) {
                return { success: false, error: 'Guard failed: go_off' };
            }
            next = {
                anchors_configured: state.anchors_configured,
                attention_budget: state.attention_budget,
                critical_incidents: state.critical_incidents,
                failure_rate_pct: state.failure_rate_pct,
                hours_since_ack: state.hours_since_ack,
                mode: 'Off',
            };
            break;
        }
        case 'human_ack': {
            if (!(true)) {
                return { success: false, error: 'Guard failed: human_ack' };
            }
            next = {
                anchors_configured: state.anchors_configured,
                attention_budget: state.attention_budget,
                critical_incidents: state.critical_incidents,
                failure_rate_pct: state.failure_rate_pct,
                hours_since_ack: 0,
                mode: state.mode,
            };
            break;
        }
        case 'resolve_critical': {
            if (!((state.critical_incidents > 0))) {
                return { success: false, error: 'Guard failed: resolve_critical' };
            }
            next = {
                anchors_configured: state.anchors_configured,
                attention_budget: state.attention_budget,
                critical_incidents: (state.critical_incidents - 1),
                failure_rate_pct: state.failure_rate_pct,
                hours_since_ack: state.hours_since_ack,
                mode: state.mode,
            };
            break;
        }
        case 'tick_hour': {
            if (!((state.hours_since_ack < 48))) {
                return { success: false, error: 'Guard failed: tick_hour' };
            }
            next = {
                anchors_configured: state.anchors_configured,
                attention_budget: state.attention_budget,
                critical_incidents: state.critical_incidents,
                failure_rate_pct: state.failure_rate_pct,
                hours_since_ack: (1 + state.hours_since_ack),
                mode: ((('Autopilot' === state.mode) && ((1 + state.hours_since_ack) >= 8)) ? 'Assisted' : state.mode),
            };
            break;
        }
        case 'update_failure_rate': {
            if (!(true)) {
                return { success: false, error: 'Guard failed: update_failure_rate' };
            }
            next = {
                anchors_configured: state.anchors_configured,
                attention_budget: state.attention_budget,
                critical_incidents: state.critical_incidents,
                failure_rate_pct: cmd.new_rate,
                hours_since_ack: state.hours_since_ack,
                mode: ((('Autopilot' === state.mode) && (cmd.new_rate > 20)) ? 'Assisted' : state.mode),
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
