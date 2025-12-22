/**
 * ThemeContext - Dark/Light mode and user preferences
 * 
 * Provides theme switching with system preference detection and persistence.
 */

/* eslint-disable react-refresh/only-export-components */

import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';

export type Theme = 'dark' | 'light' | 'system';
export type ResolvedTheme = 'dark' | 'light';

interface UserPreferences {
    theme: Theme;
    compactMode: boolean;
    animationsEnabled: boolean;
    showHashesFull: boolean;
    refreshInterval: number; // seconds
    timezone: 'local' | 'utc';
}

const DEFAULT_PREFERENCES: UserPreferences = {
    theme: 'system',
    compactMode: false,
    animationsEnabled: true,
    showHashesFull: false,
    refreshInterval: 5,
    timezone: 'local',
};

interface ThemeContextType {
    theme: Theme;
    resolvedTheme: ResolvedTheme;
    setTheme: (theme: Theme) => void;
    cycleTheme: () => void;
    preferences: UserPreferences;
    updatePreferences: (updates: Partial<UserPreferences>) => void;
    resetPreferences: () => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

const STORAGE_KEY = 'mprd_user_preferences';

function getStoredPreferences(): UserPreferences {
    if (typeof window === 'undefined') return DEFAULT_PREFERENCES;
    try {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
            return { ...DEFAULT_PREFERENCES, ...JSON.parse(stored) };
        }
    } catch {
        // Ignore parse errors
    }
    return DEFAULT_PREFERENCES;
}

function storePreferences(prefs: UserPreferences): void {
    if (typeof window === 'undefined') return;
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
    } catch {
        // Ignore storage errors
    }
}

function getSystemTheme(): ResolvedTheme {
    if (typeof window === 'undefined') return 'dark';
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function ThemeProvider({ children }: { children: ReactNode }) {
    const [preferences, setPreferences] = useState<UserPreferences>(getStoredPreferences);
    const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(getSystemTheme);

    // Listen for system theme changes
    useEffect(() => {
        const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
        const handler = (e: MediaQueryListEvent) => {
            setSystemTheme(e.matches ? 'dark' : 'light');
        };

        mediaQuery.addEventListener('change', handler);
        return () => mediaQuery.removeEventListener('change', handler);
    }, []);

    // Apply theme to document
    const resolvedTheme: ResolvedTheme =
        preferences.theme === 'system' ? systemTheme : preferences.theme;

    useEffect(() => {
        const root = document.documentElement;
        root.classList.remove('dark', 'light');
        root.classList.add(resolvedTheme);

        // Set CSS custom property for animations
        if (!preferences.animationsEnabled) {
            root.style.setProperty('--animation-duration', '0s');
        } else {
            root.style.removeProperty('--animation-duration');
        }
    }, [resolvedTheme, preferences.animationsEnabled]);

    // Persist preferences
    useEffect(() => {
        storePreferences(preferences);
    }, [preferences]);

    const setTheme = (theme: Theme) => {
        setPreferences(prev => ({ ...prev, theme }));
    };

    const cycleTheme = () => {
        const order: Theme[] = ['dark', 'light', 'system'];
        const currentIndex = order.indexOf(preferences.theme);
        const nextTheme = order[(currentIndex + 1) % order.length];
        setTheme(nextTheme);
    };

    const updatePreferences = (updates: Partial<UserPreferences>) => {
        setPreferences(prev => ({ ...prev, ...updates }));
    };

    const resetPreferences = () => {
        setPreferences(DEFAULT_PREFERENCES);
    };

    return (
        <ThemeContext.Provider
            value={{
                theme: preferences.theme,
                resolvedTheme,
                setTheme,
                cycleTheme,
                preferences,
                updatePreferences,
                resetPreferences,
            }}
        >
            {children}
        </ThemeContext.Provider>
    );
}

export function useTheme() {
    const context = useContext(ThemeContext);
    if (context === undefined) {
        throw new Error('useTheme must be used within a ThemeProvider');
    }
    return context;
}

export function usePreferences() {
    const { preferences, updatePreferences, resetPreferences } = useTheme();
    return { preferences, updatePreferences, resetPreferences };
}

export default ThemeProvider;
