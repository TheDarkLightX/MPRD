/**
 * Base UI Components - Loading States
 * 
 * Premium skeleton loaders with shimmer animation.
 */

interface LoadingSpinnerProps {
    size?: 'sm' | 'md' | 'lg';
    className?: string;
}

const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-8 h-8',
};

function stableSkeletonWidthPct(index: number, columns: number): number {
    // Deterministic (render-pure) “variation” to avoid jitter from Math.random().
    const spread = 41; // 0..40 -> 60..100
    return 60 + ((index * 17 + columns * 7) % spread);
}

export function LoadingSpinner({ size = 'md', className = '' }: LoadingSpinnerProps) {
    return (
        <svg
            className={`animate-spin ${sizeClasses[size]} ${className}`}
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
        >
            <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
            />
            <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
        </svg>
    );
}

interface LoadingCardProps {
    message?: string;
}

export function LoadingCard({ message = 'Loading...' }: LoadingCardProps) {
    return (
        <div className="glass-card p-8 flex flex-col items-center justify-center">
            <LoadingSpinner size="lg" className="text-accent-500" />
            <p className="mt-4 text-dark-400">{message}</p>
        </div>
    );
}

/**
 * Basic skeleton with shimmer animation.
 */
export function LoadingSkeleton({ className = '' }: { className?: string }) {
    return (
        <div
            className={`skeleton-shimmer bg-dark-800 rounded ${className}`}
        />
    );
}

/**
 * Skeleton for stat/metric cards.
 */
export function StatCardSkeleton() {
    return (
        <div className="glass-card p-4 space-y-3">
            <div className="flex items-center justify-between">
                <div className="skeleton-shimmer w-20 h-4 bg-dark-800 rounded" />
                <div className="skeleton-shimmer w-8 h-8 bg-dark-800 rounded-lg" />
            </div>
            <div className="skeleton-shimmer w-24 h-8 bg-dark-800 rounded" />
            <div className="skeleton-shimmer w-16 h-3 bg-dark-800 rounded" />
        </div>
    );
}

/**
 * Skeleton for table rows.
 */
export function TableRowSkeleton({ columns = 5 }: { columns?: number }) {
    return (
        <tr>
            {Array.from({ length: columns }).map((_, i) => (
                <td key={i} className="py-3 px-4">
                    <div
                        className="skeleton-shimmer h-4 bg-dark-800 rounded"
                        style={{ width: `${stableSkeletonWidthPct(i, columns)}%` }}
                    />
                </td>
            ))}
        </tr>
    );
}

/**
 * Skeleton for a full data table.
 */
export function TableSkeleton({ rows = 5, columns = 5 }: { rows?: number; columns?: number }) {
    return (
        <div className="glass-card overflow-hidden">
            {/* Header skeleton */}
            <div className="flex bg-dark-800/50 border-b border-dark-700 p-3 gap-4">
                {Array.from({ length: columns }).map((_, i) => (
                    <div key={i} className="skeleton-shimmer h-3 bg-dark-700 rounded flex-1" />
                ))}
            </div>
            {/* Rows skeleton */}
            <table className="w-full">
                <tbody>
                    {Array.from({ length: rows }).map((_, i) => (
                        <TableRowSkeleton key={i} columns={columns} />
                    ))}
                </tbody>
            </table>
        </div>
    );
}

/**
 * Full page skeleton for dashboard.
 */
export function DashboardSkeleton() {
    return (
        <div className="space-y-6 animate-fade-in">
            {/* Header skeleton */}
            <div className="flex items-center justify-between">
                <div className="skeleton-shimmer w-48 h-8 bg-dark-800 rounded" />
                <div className="skeleton-shimmer w-24 h-8 bg-dark-800 rounded" />
            </div>

            {/* Stats row */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCardSkeleton />
                <StatCardSkeleton />
                <StatCardSkeleton />
                <StatCardSkeleton />
            </div>

            {/* Main content */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="lg:col-span-2">
                    <TableSkeleton rows={6} columns={5} />
                </div>
                <div className="space-y-4">
                    <StatCardSkeleton />
                    <StatCardSkeleton />
                </div>
            </div>
        </div>
    );
}
