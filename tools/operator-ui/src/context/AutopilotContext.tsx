/**
 * Autopilot Context
 * 
 * React context for autopilot state management with mode transitions,
 * acknowledgment tracking, and security invariant enforcement.
 * 
 * @invariant I9: Autopilot requires trust anchors
 * @invariant I10-I12: Auto-degradation rules
 */
/* eslint-disable react-refresh/only-export-components */

import {
    createContext,
    useContext,
    useEffect,
    useMemo,
    useReducer,
    useCallback,
} from 'react';
import type { ReactNode } from 'react';
import type {
    AutopilotMode,
    AutopilotState,
    SecurityPosture,
    IncidentExtended,
    AutoAction,
} from '../api/types';
import {
    createInitialAutopilotState,
    toAutopilotState,
    transitionMode,
    checkTransition,
    checkAutoDegradation,
    shouldShowAckWarning,
} from '../algorithms/autopilotController';
import type { AutopilotControllerState } from '../algorithms/autopilotController';

// =============================================================================
// Context Types
// =============================================================================

interface AutopilotContextValue {
    state: AutopilotState;
    recentActions: AutoAction[];
    ackWarning: { show: boolean; minutesUntilDegrade: number };

    // Actions
    requestModeTransition: (
        targetMode: AutopilotMode,
        posture: SecurityPosture,
        incidents: IncidentExtended[]
    ) => { success: boolean; error?: string; violations?: string[] };

    // Check without transitioning (for UI preview)
    checkModeTransition: (
        targetMode: AutopilotMode,
        posture: SecurityPosture,
        incidents: IncidentExtended[]
    ) => { success: boolean; error?: string; violations?: string[] };

    acknowledgePresence: () => void;
    addAutoAction: (action: AutoAction) => void;
    checkForDegradation: (
        posture: SecurityPosture,
        incidents: IncidentExtended[]
    ) => void;
}

const AutopilotContext = createContext<AutopilotContextValue | null>(null);

// =============================================================================
// Reducer
// =============================================================================

type AutopilotAction =
    | { type: 'SET_MODE'; mode: AutopilotMode }
    | { type: 'ACKNOWLEDGE' }
    | { type: 'ADD_ACTION'; action: AutoAction }
    | { type: 'PRUNE_OLD_ACTIONS' };

interface AutopilotReducerState {
    controllerState: AutopilotControllerState;
    recentActions: AutoAction[];
}

function autopilotReducer(
    state: AutopilotReducerState,
    action: AutopilotAction
): AutopilotReducerState {
    switch (action.type) {
        case 'SET_MODE':
            return {
                ...state,
                controllerState: {
                    ...state.controllerState,
                    mode: action.mode,
                },
            };

        case 'ACKNOWLEDGE':
            return {
                ...state,
                controllerState: {
                    ...state.controllerState,
                    lastHumanAck: Date.now(),
                },
            };

        case 'ADD_ACTION':
            return {
                ...state,
                recentActions: [action.action, ...state.recentActions].slice(0, 50),
                controllerState: {
                    ...state.controllerState,
                    autoActionsCount24h: state.controllerState.autoActionsCount24h + 1,
                },
            };

        case 'PRUNE_OLD_ACTIONS': {
            const cutoff = Date.now() - 24 * 60 * 60 * 1000;
            return {
                ...state,
                recentActions: state.recentActions.filter(a => a.timestamp >= cutoff),
            };
        }

        default:
            return state;
    }
}

// =============================================================================
// Provider
// =============================================================================

export function AutopilotProvider({ children }: { children: ReactNode }) {
    const [reducerState, dispatch] = useReducer(autopilotReducer, {
        controllerState: createInitialAutopilotState(),
        recentActions: [],
    });

    // Prune old actions periodically
    useEffect(() => {
        const interval = setInterval(() => {
            dispatch({ type: 'PRUNE_OLD_ACTIONS' });
        }, 60 * 60 * 1000); // Every hour

        return () => clearInterval(interval);
    }, []);

    // Request mode transition with validation
    const requestModeTransition = useCallback((
        targetMode: AutopilotMode,
        posture: SecurityPosture,
        incidents: IncidentExtended[]
    ) => {
        const result = transitionMode(
            reducerState.controllerState,
            targetMode,
            posture,
            incidents
        );

        if (result.success) {
            dispatch({ type: 'SET_MODE', mode: targetMode });
        }

        return result;
    }, [reducerState.controllerState]);

    // Acknowledge presence
    const acknowledgePresence = useCallback(() => {
        dispatch({ type: 'ACKNOWLEDGE' });
    }, []);

    // Add auto action
    const addAutoAction = useCallback((action: AutoAction) => {
        dispatch({ type: 'ADD_ACTION', action });
    }, []);

    // Check for degradation
    const checkForDegradation = useCallback((
        posture: SecurityPosture,
        incidents: IncidentExtended[]
    ) => {
        const degradeResult = checkAutoDegradation(
            reducerState.controllerState,
            posture,
            incidents
        );

        if (degradeResult) {
            dispatch({ type: 'SET_MODE', mode: degradeResult.toMode });
            // In a real app, we'd also log this and show a notification
        }
    }, [reducerState.controllerState]);

    // Check mode transition (preview only, no dispatch)
    const checkModeTransition = useCallback((
        targetMode: AutopilotMode,
        posture: SecurityPosture,
        incidents: IncidentExtended[]
    ) => {
        return checkTransition(
            reducerState.controllerState,
            targetMode,
            posture,
            incidents
        );
    }, [reducerState.controllerState]);

    // Compute ack warning
    const ackWarning = useMemo(() => {
        return shouldShowAckWarning(reducerState.controllerState.lastHumanAck);
    }, [reducerState.controllerState.lastHumanAck]);

    // Build context value
    const value = useMemo<AutopilotContextValue>(() => ({
        state: toAutopilotState(reducerState.controllerState),
        recentActions: reducerState.recentActions,
        ackWarning,
        requestModeTransition,
        checkModeTransition,
        acknowledgePresence,
        addAutoAction,
        checkForDegradation,
    }), [
        reducerState,
        ackWarning,
        requestModeTransition,
        checkModeTransition,
        acknowledgePresence,
        addAutoAction,
        checkForDegradation,
    ]);

    return (
        <AutopilotContext.Provider value={value}>
            {children}
        </AutopilotContext.Provider>
    );
}

// =============================================================================
// Hook
// =============================================================================

export function useAutopilot(): AutopilotContextValue {
    const context = useContext(AutopilotContext);
    if (!context) {
        throw new Error('useAutopilot must be used within AutopilotProvider');
    }
    return context;
}

/**
 * Hook to get just the autopilot state (for components that only need to read).
 */
export function useAutopilotState(): AutopilotState {
    return useAutopilot().state;
}
