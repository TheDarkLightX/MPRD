/**
 * Generated kernel for artifact_commit_consistency_gate.
 * IR hash: 1ffbd49cea5702be
 * DO NOT EDIT - regenerate from model.
 */

export type ResultMode = 'Pending' | 'Accepted' | 'Rejected';

export interface State {
    checkpoint_ok: boolean;
    checkpoint_required: boolean;
    commit_sig_ok: boolean;
    mst_consistency_ok: boolean;
    result: ResultMode;
}

export function initState(): State {
    return {
        commit_sig_ok: true,
        mst_consistency_ok: true,
        checkpoint_required: false,
        checkpoint_ok: true,
        result: 'Pending',
    };
}

export type Command =
    | { type: 'accept' }
    | { type: 'checkpoint_fails' }
    | { type: 'mst_fails' }
    | { type: 'reject' }
    | { type: 'require_checkpoint' }
    | { type: 'sig_fails' }
;

export interface InvariantViolation {
    id: string;
    message: string;
}

export function checkInvariants(state: State): InvariantViolation[] {
    const violations: InvariantViolation[] = [];

    // AcceptRequiresCheckpoint
    if (!(((!(('Accepted' === state.result) && state.checkpoint_required)) || state.checkpoint_ok))) {
        violations.push({ id: 'AcceptRequiresCheckpoint', message: 'AcceptRequiresCheckpoint violated' });
    }

    // AcceptRequiresMST
    if (!(((!('Accepted' === state.result)) || state.mst_consistency_ok))) {
        violations.push({ id: 'AcceptRequiresMST', message: 'AcceptRequiresMST violated' });
    }

    // AcceptRequiresSig
    if (!(((!('Accepted' === state.result)) || state.commit_sig_ok))) {
        violations.push({ id: 'AcceptRequiresSig', message: 'AcceptRequiresSig violated' });
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
            if (!((('Pending' === state.result) && ((!state.checkpoint_required) || state.checkpoint_ok) && state.commit_sig_ok && state.mst_consistency_ok))) {
                return { success: false, error: 'Guard failed: accept' };
            }
            next = {
                checkpoint_ok: state.checkpoint_ok,
                checkpoint_required: state.checkpoint_required,
                commit_sig_ok: state.commit_sig_ok,
                mst_consistency_ok: state.mst_consistency_ok,
                result: 'Accepted',
            };
            break;
        }
        case 'checkpoint_fails': {
            if (!((('Pending' === state.result) && state.checkpoint_required))) {
                return { success: false, error: 'Guard failed: checkpoint_fails' };
            }
            next = {
                checkpoint_ok: false,
                checkpoint_required: state.checkpoint_required,
                commit_sig_ok: state.commit_sig_ok,
                mst_consistency_ok: state.mst_consistency_ok,
                result: state.result,
            };
            break;
        }
        case 'mst_fails': {
            if (!(('Pending' === state.result))) {
                return { success: false, error: 'Guard failed: mst_fails' };
            }
            next = {
                checkpoint_ok: state.checkpoint_ok,
                checkpoint_required: state.checkpoint_required,
                commit_sig_ok: state.commit_sig_ok,
                mst_consistency_ok: false,
                result: state.result,
            };
            break;
        }
        case 'reject': {
            if (!((('Pending' === state.result) && (!(((!state.checkpoint_required) || state.checkpoint_ok) && state.commit_sig_ok && state.mst_consistency_ok))))) {
                return { success: false, error: 'Guard failed: reject' };
            }
            next = {
                checkpoint_ok: state.checkpoint_ok,
                checkpoint_required: state.checkpoint_required,
                commit_sig_ok: state.commit_sig_ok,
                mst_consistency_ok: state.mst_consistency_ok,
                result: 'Rejected',
            };
            break;
        }
        case 'require_checkpoint': {
            if (!(('Pending' === state.result))) {
                return { success: false, error: 'Guard failed: require_checkpoint' };
            }
            next = {
                checkpoint_ok: state.checkpoint_ok,
                checkpoint_required: true,
                commit_sig_ok: state.commit_sig_ok,
                mst_consistency_ok: state.mst_consistency_ok,
                result: state.result,
            };
            break;
        }
        case 'sig_fails': {
            if (!(('Pending' === state.result))) {
                return { success: false, error: 'Guard failed: sig_fails' };
            }
            next = {
                checkpoint_ok: state.checkpoint_ok,
                checkpoint_required: state.checkpoint_required,
                commit_sig_ok: false,
                mst_consistency_ok: state.mst_consistency_ok,
                result: state.result,
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
