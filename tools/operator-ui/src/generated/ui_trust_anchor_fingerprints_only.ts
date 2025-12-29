/**
 * Generated kernel for ui_trust_anchor_fingerprints_only.
 * IR hash: 78e9b32639a5ab22
 * DO NOT EDIT - regenerate from model.
 */

export type DisplayStateMode = 'Hidden' | 'ShowingFingerprint' | 'AttemptedRawLeak';

export interface State {
    display_state: DisplayStateMode;
    key_loaded: boolean;
    leaks_raw: boolean;
}

export function initState(): State {
    return {
        key_loaded: false,
        display_state: 'Hidden',
        leaks_raw: false,
    };
}

export type Command =
    | { type: 'attempt_raw_display' }
    | { type: 'clear_key' }
    | { type: 'display_fingerprint' }
    | { type: 'hide_display' }
    | { type: 'load_key' }
;

export interface InvariantViolation {
    id: string;
    message: string;
}

export function checkInvariants(state: State): InvariantViolation[] {
    const violations: InvariantViolation[] = [];

    // BlockedLeakDoesNotLeak
    if (!(((!('AttemptedRawLeak' === state.display_state)) || (!state.leaks_raw)))) {
        violations.push({ id: 'BlockedLeakDoesNotLeak', message: 'BlockedLeakDoesNotLeak violated' });
    }

    // FingerprintRequiresKey
    if (!(((!('ShowingFingerprint' === state.display_state)) || state.key_loaded))) {
        violations.push({ id: 'FingerprintRequiresKey', message: 'FingerprintRequiresKey violated' });
    }

    // I1_NeverLeakRaw
    if (!((!state.leaks_raw))) {
        violations.push({ id: 'I1_NeverLeakRaw', message: 'I1_NeverLeakRaw violated' });
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
        case 'attempt_raw_display': {
            if (!((('AttemptedRawLeak' !== state.display_state) && state.key_loaded))) {
                return { success: false, error: 'Guard failed: attempt_raw_display' };
            }
            next = {
                display_state: 'AttemptedRawLeak',
                key_loaded: state.key_loaded,
                leaks_raw: false,
            };
            break;
        }
        case 'clear_key': {
            if (!(state.key_loaded)) {
                return { success: false, error: 'Guard failed: clear_key' };
            }
            next = {
                display_state: 'Hidden',
                key_loaded: false,
                leaks_raw: state.leaks_raw,
            };
            break;
        }
        case 'display_fingerprint': {
            if (!((('ShowingFingerprint' !== state.display_state) && state.key_loaded))) {
                return { success: false, error: 'Guard failed: display_fingerprint' };
            }
            next = {
                display_state: 'ShowingFingerprint',
                key_loaded: state.key_loaded,
                leaks_raw: false,
            };
            break;
        }
        case 'hide_display': {
            if (!(('Hidden' !== state.display_state))) {
                return { success: false, error: 'Guard failed: hide_display' };
            }
            next = {
                display_state: 'Hidden',
                key_loaded: state.key_loaded,
                leaks_raw: state.leaks_raw,
            };
            break;
        }
        case 'load_key': {
            if (!((!state.key_loaded))) {
                return { success: false, error: 'Guard failed: load_key' };
            }
            next = {
                display_state: state.display_state,
                key_loaded: true,
                leaks_raw: state.leaks_raw,
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
