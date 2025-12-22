/**
 * ErrorBoundary - Catches React errors and displays fallback UI
 * 
 * Wraps components to prevent full app crashes and provide graceful degradation.
 */

import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
    children: ReactNode;
    fallback?: ReactNode;
    onError?: (error: Error, errorInfo: ErrorInfo) => void;
}

interface State {
    hasError: boolean;
    error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
    constructor(props: Props) {
        super(props);
        this.state = { hasError: false, error: null };
    }

    static getDerivedStateFromError(error: Error): State {
        return { hasError: true, error };
    }

    componentDidCatch(error: Error, errorInfo: ErrorInfo) {
        console.error('[ErrorBoundary] Caught error:', error, errorInfo);
        this.props.onError?.(error, errorInfo);
    }

    handleRetry = () => {
        this.setState({ hasError: false, error: null });
    };

    render() {
        if (this.state.hasError) {
            if (this.props.fallback) {
                return this.props.fallback;
            }

            return (
                <div className="flex flex-col items-center justify-center p-6 bg-red-500/10 border border-red-500/30 rounded-lg">
                    <AlertTriangle className="w-8 h-8 text-red-400 mb-3" />
                    <h3 className="text-sm font-medium text-red-300 mb-1">
                        Something went wrong
                    </h3>
                    <p className="text-xs text-neutral-400 mb-4 text-center max-w-xs">
                        {this.state.error?.message || 'An unexpected error occurred'}
                    </p>
                    <button
                        onClick={this.handleRetry}
                        className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-white bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 rounded transition-colors"
                    >
                        <RefreshCw className="w-3 h-3" />
                        Retry
                    </button>
                </div>
            );
        }

        return this.props.children;
    }
}

/**
 * Compact error fallback for smaller UI elements
 */
export function ErrorFallbackCompact({ message }: { message?: string }) {
    return (
        <div className="flex items-center gap-2 p-3 text-xs text-red-400 bg-red-500/10 rounded">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{message || 'Failed to load'}</span>
        </div>
    );
}

/**
 * Loading skeleton for graceful degradation
 */
export function LoadingSkeleton({
    lines = 3,
    className = ''
}: {
    lines?: number;
    className?: string
}) {
    const widths = [92, 84, 88, 76, 90, 82];
    return (
        <div className={`space-y-2 animate-pulse ${className}`}>
            {Array.from({ length: lines }).map((_, i) => (
                <div
                    key={i}
                    className="h-4 bg-neutral-700/50 rounded"
                    style={{ width: `${widths[i % widths.length]}%` }}
                />
            ))}
        </div>
    );
}

/**
 * Card skeleton for dashboard components
 */
export function CardSkeleton({ className = '' }: { className?: string }) {
    return (
        <div className={`bg-neutral-800/50 border border-neutral-700/50 rounded-lg p-4 animate-pulse ${className}`}>
            <div className="h-4 w-24 bg-neutral-700/50 rounded mb-3" />
            <div className="h-8 w-16 bg-neutral-700/50 rounded mb-2" />
            <div className="h-3 w-32 bg-neutral-700/50 rounded" />
        </div>
    );
}

export default ErrorBoundary;
