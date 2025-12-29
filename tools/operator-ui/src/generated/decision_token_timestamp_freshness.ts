/**
 * Generated kernel for decision_token_timestamp_freshness.
 * IR hash: 8c3ade6f705a7ae2
 * DO NOT EDIT - regenerate from model.
 */

export type AgeClassMode = 'Ok' | 'Expired' | 'Future';

export interface State {
    age_class: AgeClassMode;
    validation_ok: boolean;
}

export function initState(): State {
    return {
        age_class: 'Ok',
        validation_ok: false,
    };
}

export type Command =
    | { type: 'reject' }
    | { type: 'token_expires' }
    | { type: 'token_future' }
    | { type: 'validate_fresh' }
;

export interface InvariantViolation {
    id: string;
    message: string;
}

export function checkInvariants(state: State): InvariantViolation[] {
    const violations: InvariantViolation[] = [];

    // InvalidAgeRejects
    if (!(((!('Ok' !== state.age_class)) || (!state.validation_ok)))) {
        violations.push({ id: 'InvalidAgeRejects', message: 'InvalidAgeRejects violated' });
    }

    // ValidationRequiresOkAge
    if (!(((!state.validation_ok) || ('Ok' === state.age_class)))) {
        violations.push({ id: 'ValidationRequiresOkAge', message: 'ValidationRequiresOkAge violated' });
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
        case 'reject': {
            if (!(('Ok' !== state.age_class))) {
                return { success: false, error: 'Guard failed: reject' };
            }
            next = {
                age_class: state.age_class,
                validation_ok: false,
            };
            break;
        }
        case 'token_expires': {
            if (!(('Ok' === state.age_class))) {
                return { success: false, error: 'Guard failed: token_expires' };
            }
            next = {
                age_class: 'Expired',
                validation_ok: false,
            };
            break;
        }
        case 'token_future': {
            if (!(('Ok' === state.age_class))) {
                return { success: false, error: 'Guard failed: token_future' };
            }
            next = {
                age_class: 'Future',
                validation_ok: false,
            };
            break;
        }
        case 'validate_fresh': {
            if (!((('Ok' === state.age_class) && (!state.validation_ok)))) {
                return { success: false, error: 'Guard failed: validate_fresh' };
            }
            next = {
                age_class: state.age_class,
                validation_ok: true,
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
