/**
 * Generated kernel for tau_attestation_replay_guard.
 * IR hash: 9652e0520d8186cc
 * DO NOT EDIT - regenerate from model.
 */

export type ResultMode = 'Pending' | 'Accepted' | 'Rejected';

export interface State {
    epoch_newer: boolean;
    hash_chain_valid: boolean;
    result: ResultMode;
}

export function initState(): State {
    return {
        epoch_newer: true,
        hash_chain_valid: true,
        result: 'Pending',
    };
}

export type Command =
    | { type: 'accept' }
    | { type: 'chain_breaks' }
    | { type: 'receive_stale' }
    | { type: 'reject' }
;

export interface InvariantViolation {
    id: string;
    message: string;
}

export function checkInvariants(state: State): InvariantViolation[] {
    const violations: InvariantViolation[] = [];

    // AcceptRequiresNewerEpoch
    if (!(((!('Accepted' === state.result)) || state.epoch_newer))) {
        violations.push({ id: 'AcceptRequiresNewerEpoch', message: 'AcceptRequiresNewerEpoch violated' });
    }

    // AcceptRequiresValidChain
    if (!(((!('Accepted' === state.result)) || state.hash_chain_valid))) {
        violations.push({ id: 'AcceptRequiresValidChain', message: 'AcceptRequiresValidChain violated' });
    }

    // RejectedImpliesInvalid
    if (!(((!('Rejected' === state.result)) || (!(state.epoch_newer && state.hash_chain_valid))))) {
        violations.push({ id: 'RejectedImpliesInvalid', message: 'RejectedImpliesInvalid violated' });
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
        case 'accept': {
            if (!((('Pending' === state.result) && state.epoch_newer && state.hash_chain_valid))) {
                return { success: false, error: 'Guard failed: accept' };
            }
            next = {
                epoch_newer: state.epoch_newer,
                hash_chain_valid: state.hash_chain_valid,
                result: 'Accepted',
            };
            break;
        }
        case 'chain_breaks': {
            if (!(('Pending' === state.result))) {
                return { success: false, error: 'Guard failed: chain_breaks' };
            }
            next = {
                epoch_newer: state.epoch_newer,
                hash_chain_valid: false,
                result: state.result,
            };
            break;
        }
        case 'receive_stale': {
            if (!(('Pending' === state.result))) {
                return { success: false, error: 'Guard failed: receive_stale' };
            }
            next = {
                epoch_newer: false,
                hash_chain_valid: state.hash_chain_valid,
                result: state.result,
            };
            break;
        }
        case 'reject': {
            if (!((('Pending' === state.result) && (!(state.epoch_newer && state.hash_chain_valid))))) {
                return { success: false, error: 'Guard failed: reject' };
            }
            next = {
                epoch_newer: state.epoch_newer,
                hash_chain_valid: state.hash_chain_valid,
                result: 'Rejected',
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
