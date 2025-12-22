/**
 * Decision List Component
 * 
 * Displays paginated decision history with filtering.
 * Per spec Section 6.2: Searchable, filterable decision log.
 * 
 * @performance Uses VirtualizedTable for 50+ rows
 * @performance Memoized columns and row rendering
 */

import { useMemo, useCallback, memo } from 'react';
import type { DecisionSummary } from '../../api/types';
import { Card, StatusBadge, HashBadge, Button, VirtualizedTable } from '../ui';
import type { Column } from '../ui';
import { ChevronLeft, ChevronRight, Download, Eye } from 'lucide-react';

interface DecisionListProps {
    decisions: DecisionSummary[];
    total: number;
    page: number;
    pageSize: number;
    hasMore: boolean;
    onPageChange: (page: number) => void;
    onViewDecision: (id: string) => void;
    loading?: boolean;
}

// Threshold for switching to virtualized rendering
const VIRTUALIZATION_THRESHOLD = 30;

function formatTimestamp(ms: number): string {
    return new Date(ms).toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
    });
}

function formatLatency(ms: number): string {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
}

// Memoized row component for non-virtualized list
const DecisionRow = memo(function DecisionRow({
    decision,
    onViewDecision,
}: {
    decision: DecisionSummary;
    onViewDecision: (id: string) => void;
}) {
    return (
        <tr
            className="cursor-pointer hover:bg-dark-800/70"
            onClick={() => onViewDecision(decision.id)}
        >
            <td className="font-mono text-sm text-dark-300">
                {formatTimestamp(decision.timestamp)}
            </td>
            <td>
                <HashBadge hash={decision.policyHash} />
            </td>
            <td className="font-medium text-gray-200">
                {decision.actionType}
            </td>
            <td>
                <StatusBadge status={decision.verdict} />
            </td>
            <td>
                <StatusBadge status={decision.proofStatus} />
            </td>
            <td>
                <StatusBadge status={decision.executionStatus} />
            </td>
            <td className="font-mono text-sm text-dark-300">
                {formatLatency(decision.latencyMs)}
            </td>
            <td>
                <button
                    className="p-1.5 rounded hover:bg-dark-700 text-dark-400 hover:text-gray-200"
                    onClick={(e) => {
                        e.stopPropagation();
                        onViewDecision(decision.id);
                    }}
                >
                    <Eye className="w-4 h-4" />
                </button>
            </td>
        </tr>
    );
});

export function DecisionList({
    decisions,
    total,
    page,
    pageSize,
    hasMore,
    onPageChange,
    onViewDecision,
    loading = false,
}: DecisionListProps) {
    const start = (page - 1) * pageSize + 1;
    const end = Math.min(page * pageSize, total);

    // Memoized columns for VirtualizedTable
    const virtualizedColumns = useMemo<Column<DecisionSummary>[]>(() => [
        {
            key: 'timestamp',
            header: 'Time',
            width: '100px',
            render: (d) => (
                <span className="font-mono text-sm text-dark-300">
                    {formatTimestamp(d.timestamp)}
                </span>
            ),
        },
        {
            key: 'policyHash',
            header: 'Policy',
            width: '120px',
            render: (d) => <HashBadge hash={d.policyHash} />,
        },
        {
            key: 'actionType',
            header: 'Action',
            render: (d) => (
                <span className="font-medium text-gray-200">{d.actionType}</span>
            ),
        },
        {
            key: 'verdict',
            header: 'Verdict',
            width: '90px',
            render: (d) => <StatusBadge status={d.verdict} />,
        },
        {
            key: 'proofStatus',
            header: 'Proof',
            width: '90px',
            render: (d) => <StatusBadge status={d.proofStatus} />,
        },
        {
            key: 'executionStatus',
            header: 'Exec',
            width: '90px',
            render: (d) => <StatusBadge status={d.executionStatus} />,
        },
        {
            key: 'latencyMs',
            header: 'Latency',
            width: '80px',
            render: (d) => (
                <span className="font-mono text-sm text-dark-300">
                    {formatLatency(d.latencyMs)}
                </span>
            ),
        },
    ], []);

    const getRowKey = useCallback((d: DecisionSummary) => d.id, []);

    const handleRowClick = useCallback(
        (d: DecisionSummary) => onViewDecision(d.id),
        [onViewDecision]
    );

    function toCsvValue(v: unknown): string {
        const s = String(v ?? '');
        if (/[",\n]/.test(s)) {
            return `"${s.replace(/"/g, '""')}"`;
        }
        return s;
    }

    function exportCsv() {
        const header = [
            'timestamp_ms',
            'decision_id',
            'policy_hash',
            'action_type',
            'verdict',
            'proof_status',
            'execution_status',
            'latency_ms',
        ];

        const lines = [header.join(',')];
        for (const d of decisions) {
            lines.push(
                [
                    d.timestamp,
                    d.id,
                    d.policyHash,
                    d.actionType,
                    d.verdict,
                    d.proofStatus,
                    d.executionStatus,
                    d.latencyMs,
                ]
                    .map(toCsvValue)
                    .join(','),
            );
        }

        const blob = new Blob([lines.join('\n') + '\n'], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        try {
            const a = document.createElement('a');
            a.href = url;
            a.download = `mprd-decisions-page-${page}.csv`;
            document.body.appendChild(a);
            a.click();
            a.remove();
        } finally {
            URL.revokeObjectURL(url);
        }
    }

    // Use VirtualizedTable for large datasets
    const useVirtualized = decisions.length >= VIRTUALIZATION_THRESHOLD;

    return (
        <Card padding="none">
            {useVirtualized ? (
                // Virtualized rendering for large lists
                <VirtualizedTable
                    data={decisions}
                    columns={virtualizedColumns}
                    rowHeight={48}
                    maxHeight={500}
                    onRowClick={handleRowClick}
                    getRowKey={getRowKey}
                    emptyMessage="No decisions found"
                />
            ) : (
                // Standard table for small lists
                <div className="overflow-x-auto">
                    <table className="data-table">
                        <thead>
                            <tr className="bg-dark-800/50">
                                <th>Time</th>
                                <th>Policy</th>
                                <th>Action</th>
                                <th>Verdict</th>
                                <th>Proof</th>
                                <th>Exec</th>
                                <th>Latency</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            {loading ? (
                                // Loading skeleton
                                Array.from({ length: 5 }).map((_, i) => (
                                    <tr key={i}>
                                        <td colSpan={8}>
                                            <div className="h-8 bg-dark-800 rounded animate-pulse"></div>
                                        </td>
                                    </tr>
                                ))
                            ) : decisions.length === 0 ? (
                                <tr>
                                    <td colSpan={8} className="text-center py-8 text-dark-400">
                                        No decisions found
                                    </td>
                                </tr>
                            ) : (
                                decisions.map((decision) => (
                                    <DecisionRow
                                        key={decision.id}
                                        decision={decision}
                                        onViewDecision={onViewDecision}
                                    />
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            )}

            {/* Pagination */}
            <div className="flex items-center justify-between px-4 py-3 border-t border-dark-700">
                <div className="text-sm text-dark-400">
                    Showing {start}-{end} of {total}
                    {useVirtualized && (
                        <span className="ml-2 text-xs text-accent-400">(virtualized)</span>
                    )}
                </div>

                <div className="flex items-center space-x-2">
                    <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => onPageChange(page - 1)}
                        disabled={page <= 1}
                    >
                        <ChevronLeft className="w-4 h-4" />
                    </Button>

                    <span className="text-sm text-dark-300 px-2">
                        Page {page}
                    </span>

                    <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => onPageChange(page + 1)}
                        disabled={!hasMore}
                    >
                        <ChevronRight className="w-4 h-4" />
                    </Button>
                </div>

                <Button
                    variant="secondary"
                    size="sm"
                    icon={<Download className="w-4 h-4" />}
                    onClick={exportCsv}
                    disabled={decisions.length === 0}
                >
                    Export CSV
                </Button>
            </div>
        </Card>
    );
}

