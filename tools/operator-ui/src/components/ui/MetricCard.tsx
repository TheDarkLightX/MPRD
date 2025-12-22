/**
 * Premium Metric Card Component
 * 
 * Displays key metrics with gradient styling, trend indicators,
 * optional sparklines, and smooth animations.
 */

import { useEffect, useState, useRef } from 'react';
import {
    ArrowUpRight,
    ArrowDownRight,
    Minus,
    TrendingUp,
    TrendingDown,
} from 'lucide-react';

// =============================================================================
// Types
// =============================================================================

export interface MetricCardProps {
    title: string;
    value: string | number;
    change?: number;
    changeLabel?: string;
    icon: React.ReactNode;
    sparklineData?: number[];
    variant?: 'default' | 'healthy' | 'warning' | 'critical';
    subtitle?: string;
    animateValue?: boolean;
}

// =============================================================================
// Sparkline Component
// =============================================================================

function Sparkline({ data, color = 'accent' }: { data: number[]; color?: string }) {
    if (!data || data.length === 0) return null;

    const max = Math.max(...data);
    const min = Math.min(...data);
    const range = max - min || 1;

    const colorClasses = {
        accent: 'bg-accent-500/40 group-hover:bg-accent-500/60',
        healthy: 'bg-healthy-500/40 group-hover:bg-healthy-500/60',
        warning: 'bg-degraded-500/40 group-hover:bg-degraded-500/60',
        critical: 'bg-critical-500/40 group-hover:bg-critical-500/60',
    };

    return (
        <div className="sparkline-container mt-3">
            {data.map((value, i) => {
                const height = ((value - min) / range) * 100;
                return (
                    <div
                        key={i}
                        className={`sparkline-bar ${colorClasses[color as keyof typeof colorClasses] || colorClasses.accent}`}
                        style={{
                            height: `${Math.max(height, 10)}%`,
                            transitionDelay: `${i * 30}ms`,
                        }}
                    />
                );
            })}
        </div>
    );
}

// =============================================================================
// Animated Number Hook
// =============================================================================

function useAnimatedNumber(target: number, duration = 500): number {
    const [current, setCurrent] = useState(0);
    const startTime = useRef<number | null>(null);
    const animationFrame = useRef<number | undefined>(undefined);

    useEffect(() => {
        const animate = (timestamp: number) => {
            if (!startTime.current) startTime.current = timestamp;
            const progress = Math.min((timestamp - startTime.current) / duration, 1);

            // Easing function (ease-out)
            const eased = 1 - Math.pow(1 - progress, 3);
            setCurrent(Math.round(target * eased));

            if (progress < 1) {
                animationFrame.current = requestAnimationFrame(animate);
            }
        };

        startTime.current = null;
        animationFrame.current = requestAnimationFrame(animate);

        return () => {
            if (animationFrame.current) {
                cancelAnimationFrame(animationFrame.current);
            }
        };
    }, [target, duration]);

    return current;
}

// =============================================================================
// Main Component
// =============================================================================

export function MetricCard({
    title,
    value,
    change,
    changeLabel,
    icon,
    sparklineData,
    variant = 'default',
    subtitle,
    animateValue = true,
}: MetricCardProps) {
    // Parse numeric value for animation
    const numericValue = typeof value === 'number' ? value : parseFloat(String(value).replace(/[^0-9.-]/g, ''));
    const isNumeric = !isNaN(numericValue) && typeof value === 'number';
    const animatedValue = useAnimatedNumber(isNumeric && animateValue ? numericValue : 0);

    // Determine change direction and styling
    const isPositive = change !== undefined && change > 0;
    const isNeutral = change === undefined || change === 0;

    const changeColorClass = isNeutral
        ? 'text-dark-400'
        : isPositive
            ? 'text-healthy-400'
            : 'text-critical-400';

    const ChangeIcon = isNeutral ? Minus : isPositive ? ArrowUpRight : ArrowDownRight;
    const TrendIcon = isPositive ? TrendingUp : TrendingDown;

    // Variant-based glow colors
    const glowStyles: Record<string, string> = {
        default: '--metric-glow: rgba(99, 102, 241, 0.4)',
        healthy: '--metric-glow: rgba(16, 185, 129, 0.4)',
        warning: '--metric-glow: rgba(245, 158, 11, 0.4)',
        critical: '--metric-glow: rgba(239, 68, 68, 0.4)',
    };

    const iconBgClass: Record<string, string> = {
        default: 'bg-accent-500/10 text-accent-400',
        healthy: 'bg-healthy-500/10 text-healthy-400',
        warning: 'bg-degraded-500/10 text-degraded-400',
        critical: 'bg-critical-500/10 text-critical-400',
    };

    return (
        <div
            className="group metric-card animate-in fade-in-up"
            style={{ [glowStyles[variant].split(':')[0]]: glowStyles[variant].split(':')[1] } as React.CSSProperties}
        >
            {/* Shimmer overlay on hover */}
            <div className="shimmer-overlay opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

            {/* Header row */}
            <div className="flex items-center justify-between mb-3 relative z-10">
                <span className="text-sm font-medium text-dark-400 uppercase tracking-wide">
                    {title}
                </span>
                <div className={`p-2 rounded-lg ${iconBgClass[variant]} transition-colors duration-200`}>
                    {icon}
                </div>
            </div>

            {/* Value */}
            <div className="flex items-end justify-between relative z-10">
                <div>
                    <span className="metric-value">
                        {isNumeric && animateValue
                            ? animatedValue.toLocaleString()
                            : value}
                    </span>
                    {subtitle && (
                        <p className="text-xs text-dark-500 mt-1">{subtitle}</p>
                    )}
                </div>

                {/* Change indicator */}
                {change !== undefined && (
                    <div className={`flex items-center gap-1 text-sm font-medium ${changeColorClass}`}>
                        <ChangeIcon className="w-4 h-4" />
                        <span>{Math.abs(change)}%</span>
                        {changeLabel && (
                            <span className="text-dark-500 text-xs ml-1">{changeLabel}</span>
                        )}
                    </div>
                )}
            </div>

            {/* Optional sparkline */}
            {sparklineData && sparklineData.length > 0 && (
                <Sparkline
                    data={sparklineData}
                    color={variant === 'default' ? 'accent' : variant}
                />
            )}

            {/* Trend indicator badge */}
            {change !== undefined && Math.abs(change) >= 5 && (
                <div className={`absolute top-3 right-14 flex items-center gap-1 px-2 py-0.5 rounded-full text-xs ${changeColorClass} bg-dark-800/50`}>
                    <TrendIcon className="w-3 h-3" />
                    {isPositive ? 'Up' : 'Down'}
                </div>
            )}
        </div>
    );
}

export default MetricCard;
