/**
 * Mode Transition Modal
 * 
 * Confirmation dialog for autopilot mode changes with precondition display.
 * 
 * @invariant I7: UI MUST NOT auto-run actions that change trust/authorization state
 */

import { useState } from 'react';
import { AlertTriangle, CheckCircle, XCircle, Info } from 'lucide-react';
import type { AutopilotMode } from '../../api/types';
import { Button } from '../ui';

interface ModeTransitionModalProps {
    isOpen: boolean;
    currentMode: AutopilotMode;
    targetMode: AutopilotMode;
    violations: string[];
    onConfirm: () => void;
    onCancel: () => void;
}

const MODE_DESCRIPTIONS = {
    manual: {
        title: 'Manual Mode',
        description: 'All decisions require human action. No auto-dismiss or auto-correlate.',
        color: 'text-dark-300',
    },
    assisted: {
        title: 'Assisted Mode',
        description: 'Auto-correlate alerts into incidents. Suggest actions, wait for approval.',
        color: 'text-accent-400',
    },
    autopilot: {
        title: 'Autopilot Mode',
        description: 'Auto-dismiss known patterns, auto-execute low-impact actions. Queue high-impact for review.',
        color: 'text-healthy',
    },
};

export function ModeTransitionModal({
    isOpen,
    currentMode,
    targetMode,
    violations,
    onConfirm,
    onCancel,
}: ModeTransitionModalProps) {
    const [justification, setJustification] = useState('');

    if (!isOpen) return null;

    const targetInfo = MODE_DESCRIPTIONS[targetMode];
    const hasViolations = violations.length > 0;
    const canConfirm = !hasViolations && (targetMode !== 'autopilot' || justification.length > 0);

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
            {/* Backdrop */}
            <div
                className="absolute inset-0 bg-black/60 backdrop-blur-sm"
                onClick={onCancel}
            />

            {/* Modal */}
            <div className="relative bg-dark-900 rounded-lg border border-dark-700 shadow-xl max-w-md w-full mx-4 p-6">
                {/* Header */}
                <div className="flex items-start gap-3 mb-4">
                    <div className={`p-2 rounded-lg ${hasViolations ? 'bg-critical/10' : 'bg-accent-500/10'}`}>
                        {hasViolations ? (
                            <XCircle className="w-6 h-6 text-critical" />
                        ) : (
                            <Info className="w-6 h-6 text-accent-400" />
                        )}
                    </div>
                    <div>
                        <h3 className="text-lg font-semibold text-gray-100">
                            {hasViolations ? 'Cannot Enable Mode' : 'Confirm Mode Change'}
                        </h3>
                        <p className="text-sm text-dark-400">
                            {MODE_DESCRIPTIONS[currentMode].title} → {targetInfo.title}
                        </p>
                    </div>
                </div>

                {/* Target mode description */}
                <div className="p-3 rounded-lg bg-dark-800/50 border border-dark-700 mb-4">
                    <p className={`text-sm font-medium ${targetInfo.color}`}>
                        {targetInfo.title}
                    </p>
                    <p className="text-sm text-dark-400 mt-1">
                        {targetInfo.description}
                    </p>
                </div>

                {/* Violations or preconditions */}
                {hasViolations ? (
                    <div className="space-y-2 mb-4">
                        <p className="text-sm font-medium text-critical flex items-center gap-1">
                            <AlertTriangle className="w-4 h-4" />
                            Preconditions not met:
                        </p>
                        <ul className="space-y-1">
                            {violations.map((v, i) => (
                                <li key={i} className="text-sm text-dark-400 flex items-start gap-2">
                                    <XCircle className="w-4 h-4 text-critical flex-shrink-0 mt-0.5" />
                                    {v}
                                </li>
                            ))}
                        </ul>
                    </div>
                ) : (
                    <div className="space-y-2 mb-4">
                        <p className="text-sm font-medium text-healthy flex items-center gap-1">
                            <CheckCircle className="w-4 h-4" />
                            All preconditions met
                        </p>

                        {targetMode === 'autopilot' && (
                            <div className="mt-3">
                                <label className="block text-sm text-dark-400 mb-1">
                                    Justification (required for Autopilot)
                                </label>
                                <textarea
                                    className="w-full px-3 py-2 bg-dark-800 border border-dark-600 rounded-lg text-gray-100 text-sm resize-none focus:outline-none focus:border-accent-500"
                                    rows={2}
                                    placeholder="e.g., Enabling for overnight operations, reduced staffing..."
                                    value={justification}
                                    onChange={(e) => setJustification(e.target.value)}
                                />
                            </div>
                        )}
                    </div>
                )}

                {/* Actions */}
                <div className="flex justify-end gap-3">
                    <Button variant="ghost" onClick={onCancel}>
                        Cancel
                    </Button>
                    <Button
                        variant={targetMode === 'autopilot' ? 'primary' : 'primary'}
                        onClick={onConfirm}
                        disabled={!canConfirm}
                    >
                        {hasViolations ? 'Close' : 'Confirm Change'}
                    </Button>
                </div>
            </div>
        </div>
    );
}
