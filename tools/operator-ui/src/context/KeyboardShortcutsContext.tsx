/**
 * Keyboard Shortcuts Context
 * 
 * Provides global keyboard shortcuts for power users.
 * 
 * Shortcuts:
 * - g d: Go to Dashboard
 * - g c: Go to Decisions
 * - g p: Go to Policies
 * - g s: Go to Security
 * - g t: Go to Settings
 * - t: Toggle theme (dark/light/system)
 * - ?: Show keyboard shortcuts help
 * - Escape: Close modal/dismiss
 */

import { createContext, useContext, useEffect, useCallback, useState, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTheme } from './ThemeContext';

interface KeyboardShortcutsContextType {
    showHelp: boolean;
    setShowHelp: (show: boolean) => void;
}

const KeyboardShortcutsContext = createContext<KeyboardShortcutsContextType | null>(null);

export function useKeyboardShortcuts() {
    const ctx = useContext(KeyboardShortcutsContext);
    if (!ctx) throw new Error('useKeyboardShortcuts must be used within KeyboardShortcutsProvider');
    return ctx;
}

interface Props {
    children: ReactNode;
}

export function KeyboardShortcutsProvider({ children }: Props) {
    const navigate = useNavigate();
    const { cycleTheme } = useTheme();
    const [showHelp, setShowHelp] = useState(false);
    const [pendingPrefix, setPendingPrefix] = useState<string | null>(null);

    const handleKeyDown = useCallback((e: KeyboardEvent) => {
        // Ignore if typing in an input
        const target = e.target as HTMLElement;
        if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) {
            return;
        }

        const key = e.key.toLowerCase();

        // Handle pending 'g' prefix for navigation
        if (pendingPrefix === 'g') {
            setPendingPrefix(null);
            switch (key) {
                case 'd': navigate('/'); return;
                case 'c': navigate('/decisions'); return;
                case 'p': navigate('/policies'); return;
                case 's': navigate('/security'); return;
                case 't': navigate('/settings'); return;
            }
            return;
        }

        // Single key shortcuts
        switch (key) {
            case 'g':
                setPendingPrefix('g');
                // Clear after 1 second if no follow-up
                setTimeout(() => setPendingPrefix(null), 1000);
                return;
            case 't':
                if (!e.metaKey && !e.ctrlKey) {
                    cycleTheme();
                }
                return;
            case '?':
                setShowHelp(prev => !prev);
                return;
            case 'escape':
                setShowHelp(false);
                return;
        }
    }, [navigate, cycleTheme, pendingPrefix]);

    useEffect(() => {
        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [handleKeyDown]);

    return (
        <KeyboardShortcutsContext.Provider value={{ showHelp, setShowHelp }}>
            {children}
            {showHelp && <KeyboardShortcutsHelp onClose={() => setShowHelp(false)} />}
        </KeyboardShortcutsContext.Provider>
    );
}

function KeyboardShortcutsHelp({ onClose }: { onClose: () => void }) {
    const shortcuts = [
        {
            category: 'Navigation', items: [
                { keys: 'g d', desc: 'Go to Dashboard' },
                { keys: 'g c', desc: 'Go to Decisions' },
                { keys: 'g p', desc: 'Go to Policies' },
                { keys: 'g s', desc: 'Go to Security' },
                { keys: 'g t', desc: 'Go to Settings' },
            ]
        },
        {
            category: 'Actions', items: [
                { keys: 't', desc: 'Toggle theme' },
                { keys: '?', desc: 'Show/hide this help' },
                { keys: 'Esc', desc: 'Close modal' },
            ]
        },
    ];

    return (
        <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm"
            onClick={onClose}
        >
            <div
                className="keyboard-shortcuts-modal bg-dark-900 border border-dark-700 rounded-xl p-6 max-w-md w-full mx-4 shadow-2xl"
                onClick={e => e.stopPropagation()}
            >
                <h2 className="text-lg font-semibold text-gray-100 mb-4">Keyboard Shortcuts</h2>

                {shortcuts.map(group => (
                    <div key={group.category} className="mb-4">
                        <h3 className="text-xs font-medium text-dark-400 uppercase tracking-wider mb-2">
                            {group.category}
                        </h3>
                        <div className="space-y-2">
                            {group.items.map(item => (
                                <div key={item.keys} className="flex items-center justify-between">
                                    <span className="text-sm text-gray-300">{item.desc}</span>
                                    <kbd className="px-2 py-1 bg-dark-800 border border-dark-600 rounded text-xs font-mono text-gray-400">
                                        {item.keys}
                                    </kbd>
                                </div>
                            ))}
                        </div>
                    </div>
                ))}

                <div className="mt-4 pt-4 border-t border-dark-700 text-center">
                    <button
                        onClick={onClose}
                        className="text-sm text-dark-400 hover:text-gray-200 transition-colors"
                    >
                        Press <kbd className="px-1.5 py-0.5 bg-dark-800 border border-dark-600 rounded text-xs">Esc</kbd> to close
                    </button>
                </div>
            </div>
        </div>
    );
}
