/**
 * Generated kernel for decision_token_anti_replay_race.
 * IR hash: 6530e41646cd5ea7
 * DO NOT EDIT - regenerate from model.
 */

export type PhaseAMode = 'IdleA' | 'ValidatingA' | 'ClaimedA' | 'ExecutedA' | 'RejectedA';
export type PhaseBMode = 'IdleB' | 'ValidatingB' | 'ClaimedB' | 'ExecutedB' | 'RejectedB';

export interface State {
    phase_a: PhaseAMode;
    phase_b: PhaseBMode;
    successes: number;
    token_claimed: boolean;
}

export function initState(): State {
    return {
        phase_a: 'IdleA',
        phase_b: 'IdleB',
        token_claimed: false,
        successes: 0,
    };
}

export type Command =
    | { type: 'a_claim' }
    | { type: 'a_execute' }
    | { type: 'a_reject' }
    | { type: 'a_start_validate' }
    | { type: 'b_claim' }
    | { type: 'b_execute' }
    | { type: 'b_reject' }
    | { type: 'b_start_validate' }
;

export interface InvariantViolation {
    id: string;
    message: string;
}

export function checkInvariants(state: State): InvariantViolation[] {
    const violations: InvariantViolation[] = [];

    // AExecutedImpliesSuccess
    if (!(((!('ExecutedA' === state.phase_a)) || (1 === state.successes)))) {
        violations.push({ id: 'AExecutedImpliesSuccess', message: 'AExecutedImpliesSuccess violated' });
    }

    // BExecutedImpliesSuccess
    if (!(((!('ExecutedB' === state.phase_b)) || (1 === state.successes)))) {
        violations.push({ id: 'BExecutedImpliesSuccess', message: 'BExecutedImpliesSuccess violated' });
    }

    // MutualExclusionOnExecuted
    if (!((!(('ExecutedA' === state.phase_a) && ('ExecutedB' === state.phase_b))))) {
        violations.push({ id: 'MutualExclusionOnExecuted', message: 'MutualExclusionOnExecuted violated' });
    }

    // S4_AtMostOneSuccess
    if (!((state.successes <= 1))) {
        violations.push({ id: 'S4_AtMostOneSuccess', message: 'S4_AtMostOneSuccess violated' });
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
        case 'a_claim': {
            if (!((('ValidatingA' === state.phase_a) && (!state.token_claimed)))) {
                return { success: false, error: 'Guard failed: a_claim' };
            }
            next = {
                phase_a: 'ClaimedA',
                phase_b: state.phase_b,
                successes: state.successes,
                token_claimed: true,
            };
            break;
        }
        case 'a_execute': {
            if (!(((state.successes < 1) && ('ClaimedA' === state.phase_a)))) {
                return { success: false, error: 'Guard failed: a_execute' };
            }
            next = {
                phase_a: 'ExecutedA',
                phase_b: state.phase_b,
                successes: (1 + state.successes),
                token_claimed: state.token_claimed,
            };
            break;
        }
        case 'a_reject': {
            if (!((('ValidatingA' === state.phase_a) && state.token_claimed))) {
                return { success: false, error: 'Guard failed: a_reject' };
            }
            next = {
                phase_a: 'RejectedA',
                phase_b: state.phase_b,
                successes: state.successes,
                token_claimed: state.token_claimed,
            };
            break;
        }
        case 'a_start_validate': {
            if (!(('IdleA' === state.phase_a))) {
                return { success: false, error: 'Guard failed: a_start_validate' };
            }
            next = {
                phase_a: 'ValidatingA',
                phase_b: state.phase_b,
                successes: state.successes,
                token_claimed: state.token_claimed,
            };
            break;
        }
        case 'b_claim': {
            if (!((('ValidatingB' === state.phase_b) && (!state.token_claimed)))) {
                return { success: false, error: 'Guard failed: b_claim' };
            }
            next = {
                phase_a: state.phase_a,
                phase_b: 'ClaimedB',
                successes: state.successes,
                token_claimed: true,
            };
            break;
        }
        case 'b_execute': {
            if (!(((state.successes < 1) && ('ClaimedB' === state.phase_b)))) {
                return { success: false, error: 'Guard failed: b_execute' };
            }
            next = {
                phase_a: state.phase_a,
                phase_b: 'ExecutedB',
                successes: (1 + state.successes),
                token_claimed: state.token_claimed,
            };
            break;
        }
        case 'b_reject': {
            if (!((('ValidatingB' === state.phase_b) && state.token_claimed))) {
                return { success: false, error: 'Guard failed: b_reject' };
            }
            next = {
                phase_a: state.phase_a,
                phase_b: 'RejectedB',
                successes: state.successes,
                token_claimed: state.token_claimed,
            };
            break;
        }
        case 'b_start_validate': {
            if (!(('IdleB' === state.phase_b))) {
                return { success: false, error: 'Guard failed: b_start_validate' };
            }
            next = {
                phase_a: state.phase_a,
                phase_b: 'ValidatingB',
                successes: state.successes,
                token_claimed: state.token_claimed,
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
