/**
 * Generated kernel for executor_circuit_breaker.
 * IR hash: 2e37ba431252acc0
 * DO NOT EDIT - regenerate from model.
 */

export type StateMode = 'Closed' | 'Open' | 'HalfOpen';

export interface State {
    state: StateMode;
    consecutive_failures: number;
    consecutive_successes: number;
    cooldown_remaining: number;
}

export function initState(): State {
    return {
        state: 'Closed',
        consecutive_failures: 0,
        consecutive_successes: 0,
        cooldown_remaining: 0,
    };
}

export type Command =
    | { type: 'record_success' }
    | { type: 'record_failure' }
    | { type: 'tick' }
    | { type: 'try_half_open' }
    | { type: 'manual_reset' }
;

export interface InvariantViolation {
    id: string;
    message: string;
}

export function checkInvariants(state: State): InvariantViolation[] {
    const violations: InvariantViolation[] = [];

    // FailureThresholdOpens
    if (!(((!(state.consecutive_failures >= 5)) || (state.state !== 'Closed')))) {
        violations.push({ id: 'FailureThresholdOpens', message: 'FailureThresholdOpens violated' });
    }

    // HalfOpenRequiresCooldown
    if (!(((!(state.state === 'HalfOpen')) || (state.cooldown_remaining === 0)))) {
        violations.push({ id: 'HalfOpenRequiresCooldown', message: 'HalfOpenRequiresCooldown violated' });
    }

    // ClosedMeansRecovered
    if (!(((!(state.state === 'Closed')) || (state.consecutive_failures < 5)))) {
        violations.push({ id: 'ClosedMeansRecovered', message: 'ClosedMeansRecovered violated' });
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
        case 'record_success': {
            if (!((state.state !== 'Open'))) {
                return { success: false, error: 'Guard failed: record_success' };
            }
            next = {
                state: (((state.state === 'HalfOpen') && ((state.consecutive_successes + 1) >= 3)) ? 'Closed' : state.state),
                consecutive_failures: 0,
                consecutive_successes: Math.min((state.consecutive_successes + 1), 5),
                cooldown_remaining: state.cooldown_remaining,
            };
            break;
        }
        case 'record_failure': {
            if (!((state.state !== 'Open'))) {
                return { success: false, error: 'Guard failed: record_failure' };
            }
            next = {
                state: (((state.consecutive_failures + 1) >= 5) ? 'Open' : state.state),
                consecutive_failures: Math.min((state.consecutive_failures + 1), 10),
                consecutive_successes: 0,
                cooldown_remaining: (((state.consecutive_failures + 1) >= 5) ? 30 : state.cooldown_remaining),
            };
            break;
        }
        case 'tick': {
            if (!((state.cooldown_remaining > 0))) {
                return { success: false, error: 'Guard failed: tick' };
            }
            next = {
                state: state.state,
                consecutive_failures: state.consecutive_failures,
                consecutive_successes: state.consecutive_successes,
                cooldown_remaining: (state.cooldown_remaining - 1),
            };
            break;
        }
        case 'try_half_open': {
            if (!(((state.state === 'Open') && (state.cooldown_remaining === 0)))) {
                return { success: false, error: 'Guard failed: try_half_open' };
            }
            next = {
                state: 'HalfOpen',
                consecutive_failures: state.consecutive_failures,
                consecutive_successes: 0,
                cooldown_remaining: state.cooldown_remaining,
            };
            break;
        }
        case 'manual_reset': {
            if (!(true)) {
                return { success: false, error: 'Guard failed: manual_reset' };
            }
            next = {
                state: 'Closed',
                consecutive_failures: 0,
                consecutive_successes: 0,
                cooldown_remaining: 0,
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
