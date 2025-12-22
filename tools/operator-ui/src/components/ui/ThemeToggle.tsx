/**
 * ThemeToggle - Dark/Light/System mode toggle button
 */

import { Moon, Sun, Monitor } from 'lucide-react';
import { useTheme, type Theme } from '../../context/ThemeContext';
import { Tooltip } from './Tooltip';

const themeIcons: Record<Theme, typeof Moon> = {
    dark: Moon,
    light: Sun,
    system: Monitor,
};

const themeLabels: Record<Theme, string> = {
    dark: 'Dark mode',
    light: 'Light mode',
    system: 'System preference',
};

const themeOrder: Theme[] = ['dark', 'light', 'system'];

export function ThemeToggle({ className = '' }: { className?: string }) {
    const { theme, setTheme } = useTheme();

    const cycleTheme = () => {
        const currentIndex = themeOrder.indexOf(theme);
        const nextIndex = (currentIndex + 1) % themeOrder.length;
        setTheme(themeOrder[nextIndex]);
    };

    const Icon = themeIcons[theme];

    return (
        <Tooltip content={themeLabels[theme]} position="bottom">
            <button
                onClick={cycleTheme}
                className={`
          p-2 rounded-lg transition-all duration-200
          hover:bg-neutral-700/50 
          text-neutral-400 hover:text-neutral-200
          focus:outline-none focus:ring-2 focus:ring-accent-500/50
          ${className}
        `}
                aria-label={`Current: ${themeLabels[theme]}. Click to switch.`}
            >
                <Icon className="w-5 h-5" />
            </button>
        </Tooltip>
    );
}

/**
 * ThemeSwitch - Dropdown-style theme selector
 */
export function ThemeSwitch({ className = '' }: { className?: string }) {
    const { theme, setTheme } = useTheme();

    return (
        <div className={`flex items-center gap-1 p-1 bg-neutral-800/50 rounded-lg ${className}`}>
            {themeOrder.map((t) => {
                const Icon = themeIcons[t];
                const isActive = theme === t;

                return (
                    <button
                        key={t}
                        onClick={() => setTheme(t)}
                        className={`
              p-2 rounded-md transition-all duration-200
              ${isActive
                                ? 'bg-accent-500/20 text-accent-400'
                                : 'text-neutral-500 hover:text-neutral-300 hover:bg-neutral-700/50'
                            }
            `}
                        aria-label={themeLabels[t]}
                        aria-pressed={isActive}
                    >
                        <Icon className="w-4 h-4" />
                    </button>
                );
            })}
        </div>
    );
}

export default ThemeToggle;
