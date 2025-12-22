/**
 * Base UI Components - Badge
 */

import type { ReactNode } from 'react';

type BadgeVariant = 'default' | 'healthy' | 'degraded' | 'critical' | 'accent';

interface BadgeProps {
    children: ReactNode;
    variant?: BadgeVariant;
    size?: 'sm' | 'md';
    dot?: boolean;
}

const variantClasses: Record<BadgeVariant, string> = {
    default: 'bg-dark-700 text-dark-300 border border-dark-600',
    healthy: 'status-healthy',
    degraded: 'status-degraded',
    critical: 'status-critical',
    accent: 'bg-accent-500/20 text-accent-400 border border-accent-500/30',
};

const sizeClasses = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-sm',
};

export function Badge({
    children,
    variant = 'default',
    size = 'sm',
    dot = false
}: BadgeProps) {
    return (
        <span className={`
      inline-flex items-center font-medium rounded-full
      ${variantClasses[variant]}
      ${sizeClasses[size]}
    `}>
            {dot && (
                <span className={`
          w-1.5 h-1.5 rounded-full mr-1.5
          ${variant === 'healthy' ? 'bg-healthy' : ''}
          ${variant === 'degraded' ? 'bg-degraded' : ''}
          ${variant === 'critical' ? 'bg-critical' : ''}
          ${variant === 'default' ? 'bg-dark-400' : ''}
          ${variant === 'accent' ? 'bg-accent-500' : ''}
        `} />
            )}
            {children}
        </span>
    );
}

/**
 * Status badge for verdict/proof/execution status
 */
export function StatusBadge({
    status
}: {
    status: 'allowed' | 'denied' | 'verified' | 'failed' | 'pending' | 'success' | 'skipped'
}) {
    const config: Record<string, { variant: BadgeVariant; label: string }> = {
        allowed: { variant: 'healthy', label: 'Allowed' },
        denied: { variant: 'critical', label: 'Denied' },
        verified: { variant: 'healthy', label: 'Verified' },
        failed: { variant: 'critical', label: 'Failed' },
        pending: { variant: 'degraded', label: 'Pending' },
        success: { variant: 'healthy', label: 'Success' },
        skipped: { variant: 'default', label: 'Skipped' },
    };

    const { variant, label } = config[status] || { variant: 'default', label: status };

    return <Badge variant={variant} dot>{label}</Badge>;
}
