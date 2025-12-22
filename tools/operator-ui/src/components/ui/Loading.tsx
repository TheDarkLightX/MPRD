/**
 * Base UI Components - Loading States
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

export function LoadingSkeleton({ className = '' }: { className?: string }) {
    return (
        <div
            className={`animate-pulse bg-dark-800 rounded ${className}`}
        />
    );
}
