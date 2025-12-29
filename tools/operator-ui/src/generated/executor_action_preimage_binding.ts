/**
 * Generated kernel for executor_action_preimage_binding.
 * IR hash: 80489420f425564a
 * DO NOT EDIT - regenerate from model.
 */

export type ResultMode = 'Pending' | 'Executed' | 'Rejected';

export interface State {
    action_hash_matches: boolean;
    limits_binding_ok: boolean;
    preimage_present: boolean;
    result: ResultMode;
    schema_valid: boolean;
}

export function initState(): State {
    return {
        limits_binding_ok: true,
        preimage_present: true,
        action_hash_matches: true,
        schema_valid: true,
        result: 'Pending',
    };
}

export type Command =
    | { type: 'execute' }
    | { type: 'hash_mismatch' }
    | { type: 'limits_binding_fail' }
    | { type: 'preimage_missing' }
    | { type: 'reject' }
    | { type: 'schema_invalid' }
;

export interface InvariantViolation {
    id: string;
    message: string;
}

export function checkInvariants(state: State): InvariantViolation[] {
    const violations: InvariantViolation[] = [];

    // ExecuteRequiresAllBindings
    if (!(((!('Executed' === state.result)) || (state.action_hash_matches && state.limits_binding_ok && state.preimage_present && state.schema_valid)))) {
        violations.push({ id: 'ExecuteRequiresAllBindings', message: 'ExecuteRequiresAllBindings violated' });
    }

    // RejectedImpliesBindingFailed
    if (!(((!('Rejected' === state.result)) || (!(state.action_hash_matches && state.limits_binding_ok && state.preimage_present && state.schema_valid))))) {
        violations.push({ id: 'RejectedImpliesBindingFailed', message: 'RejectedImpliesBindingFailed violated' });
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
        case 'execute': {
            if (!((('Pending' === state.result) && state.action_hash_matches && state.limits_binding_ok && state.preimage_present && state.schema_valid))) {
                return { success: false, error: 'Guard failed: execute' };
            }
            next = {
                action_hash_matches: state.action_hash_matches,
                limits_binding_ok: state.limits_binding_ok,
                preimage_present: state.preimage_present,
                result: 'Executed',
                schema_valid: state.schema_valid,
            };
            break;
        }
        case 'hash_mismatch': {
            if (!(('Pending' === state.result))) {
                return { success: false, error: 'Guard failed: hash_mismatch' };
            }
            next = {
                action_hash_matches: false,
                limits_binding_ok: state.limits_binding_ok,
                preimage_present: state.preimage_present,
                result: state.result,
                schema_valid: state.schema_valid,
            };
            break;
        }
        case 'limits_binding_fail': {
            if (!(('Pending' === state.result))) {
                return { success: false, error: 'Guard failed: limits_binding_fail' };
            }
            next = {
                action_hash_matches: state.action_hash_matches,
                limits_binding_ok: false,
                preimage_present: state.preimage_present,
                result: state.result,
                schema_valid: state.schema_valid,
            };
            break;
        }
        case 'preimage_missing': {
            if (!(('Pending' === state.result))) {
                return { success: false, error: 'Guard failed: preimage_missing' };
            }
            next = {
                action_hash_matches: state.action_hash_matches,
                limits_binding_ok: state.limits_binding_ok,
                preimage_present: false,
                result: state.result,
                schema_valid: state.schema_valid,
            };
            break;
        }
        case 'reject': {
            if (!((('Pending' === state.result) && (!(state.action_hash_matches && state.limits_binding_ok && state.preimage_present && state.schema_valid))))) {
                return { success: false, error: 'Guard failed: reject' };
            }
            next = {
                action_hash_matches: state.action_hash_matches,
                limits_binding_ok: state.limits_binding_ok,
                preimage_present: state.preimage_present,
                result: 'Rejected',
                schema_valid: state.schema_valid,
            };
            break;
        }
        case 'schema_invalid': {
            if (!(('Pending' === state.result))) {
                return { success: false, error: 'Guard failed: schema_invalid' };
            }
            next = {
                action_hash_matches: state.action_hash_matches,
                limits_binding_ok: state.limits_binding_ok,
                preimage_present: state.preimage_present,
                result: state.result,
                schema_valid: false,
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
