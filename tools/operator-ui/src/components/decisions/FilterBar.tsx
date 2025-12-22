/**
 * Filter Bar Component
 * 
 * Provides filtering controls for the decision list.
 * Per spec Section 6.2: Date Range, Policy, Action Type, Status filters.
 */

import { useState } from 'react';
import type { DecisionFilter } from '../../api/types';
import { Button } from '../ui';
import { Filter, X, Search } from 'lucide-react';

interface FilterBarProps {
    filter: DecisionFilter;
    onFilterChange: (filter: DecisionFilter) => void;
    policyOptions?: { hash: string; name?: string }[];
    actionTypeOptions?: string[];
}

export function FilterBar({
    filter,
    onFilterChange,
    policyOptions = [],
    actionTypeOptions = [],
}: FilterBarProps) {
    const [isExpanded, setIsExpanded] = useState(false);
    const [search, setSearch] = useState(filter.query || '');
    const [selectedRange, setSelectedRange] = useState<'all' | '24h' | '7d' | '30d'>('all');

    const hasActiveFilters = Object.values(filter).some(v => v !== undefined);

    function handleClearFilters() {
        setSearch('');
        setSelectedRange('all');
        onFilterChange({});
    }

    function handleDateRangeChange(range: 'all' | '24h' | '7d' | '30d', nowMs: number) {
        const now = nowMs;
        let startDate: number | undefined;

        switch (range) {
            case '24h':
                startDate = now - 24 * 60 * 60 * 1000;
                break;
            case '7d':
                startDate = now - 7 * 24 * 60 * 60 * 1000;
                break;
            case '30d':
                startDate = now - 30 * 24 * 60 * 60 * 1000;
                break;
            default:
                startDate = undefined;
        }

        onFilterChange({ ...filter, startDate, endDate: undefined });
    }

    return (
        <div className="glass-card p-4 mb-4">
            <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                    {/* Quick date filters */}
                    <div className="flex items-center space-x-1 bg-dark-800 rounded-lg p-1">
                        {(['24h', '7d', '30d', 'all'] as const).map((range) => (
                            <button
                                key={range}
                                onClick={(e) => {
                                    e.preventDefault();
                                    setSelectedRange(range);
                                    handleDateRangeChange(range, Date.now());
                                }}
                                className={`
                  px-3 py-1.5 text-sm rounded-md transition-colors
                  ${(selectedRange === range)
                                        ? 'bg-dark-700 text-gray-200'
                                        : 'text-dark-400 hover:text-gray-200'
                                    }
                `}
                            >
                                {range === 'all' ? 'All' : range === '24h' ? 'Last 24h' : range === '7d' ? 'Last 7d' : 'Last 30d'}
                            </button>
                        ))}
                    </div>

                    {/* Expand filters button */}
                    <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setIsExpanded(!isExpanded)}
                        icon={<Filter className="w-4 h-4" />}
                    >
                        Filters
                    </Button>

                    {/* Clear filters */}
                    {hasActiveFilters && (
                        <Button
                            variant="ghost"
                            size="sm"
                            onClick={handleClearFilters}
                            icon={<X className="w-4 h-4" />}
                        >
                            Clear
                        </Button>
                    )}
                </div>

                {/* Search placeholder */}
                <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
                    <input
                        type="text"
                        placeholder="Search decisions..."
                        value={search}
                        onChange={(e) => {
                            const v = e.target.value;
                            setSearch(v);
                            onFilterChange({ ...filter, query: v.trim() ? v : undefined });
                        }}
                        className="pl-9 pr-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-sm text-gray-200 placeholder-dark-400 focus:outline-none focus:border-accent-500/50"
                    />
                </div>
            </div>

            {/* Expanded filters */}
            {isExpanded && (
                <div className="mt-4 pt-4 border-t border-dark-700 grid grid-cols-4 gap-4">
                    {/* Policy filter */}
                    <div>
                        <label className="block text-xs text-dark-400 mb-1">Policy</label>
                        <select
                            value={filter.policyHash || ''}
                            onChange={(e) => onFilterChange({
                                ...filter,
                                policyHash: e.target.value || undefined
                            })}
                            className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-sm text-gray-200 focus:outline-none focus:border-accent-500/50"
                        >
                            <option value="">All Policies</option>
                            {policyOptions.map((p) => (
                                <option key={p.hash} value={p.hash}>
                                    {p.name || `${p.hash.slice(0, 8)}...`}
                                </option>
                            ))}
                        </select>
                    </div>

                    {/* Action type filter */}
                    <div>
                        <label className="block text-xs text-dark-400 mb-1">Action Type</label>
                        <select
                            value={filter.actionType || ''}
                            onChange={(e) => onFilterChange({
                                ...filter,
                                actionType: e.target.value || undefined
                            })}
                            className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-sm text-gray-200 focus:outline-none focus:border-accent-500/50"
                        >
                            <option value="">All Types</option>
                            {actionTypeOptions.map((t) => (
                                <option key={t} value={t}>{t}</option>
                            ))}
                        </select>
                    </div>

                    {/* Verdict filter */}
                    <div>
                        <label className="block text-xs text-dark-400 mb-1">Verdict</label>
                        <select
                            value={filter.verdict || ''}
                            onChange={(e) => onFilterChange({
                                ...filter,
                                verdict: e.target.value as 'allowed' | 'denied' || undefined
                            })}
                            className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-sm text-gray-200 focus:outline-none focus:border-accent-500/50"
                        >
                            <option value="">All</option>
                            <option value="allowed">Allowed</option>
                            <option value="denied">Denied</option>
                        </select>
                    </div>

                    {/* Proof status filter */}
                    <div>
                        <label className="block text-xs text-dark-400 mb-1">Proof Status</label>
                        <select
                            value={filter.proofStatus || ''}
                            onChange={(e) => onFilterChange({
                                ...filter,
                                proofStatus: e.target.value as 'verified' | 'failed' | 'pending' || undefined
                            })}
                            className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-sm text-gray-200 focus:outline-none focus:border-accent-500/50"
                        >
                            <option value="">All</option>
                            <option value="verified">Verified</option>
                            <option value="failed">Failed</option>
                            <option value="pending">Pending</option>
                        </select>
                    </div>
                </div>
            )}
        </div>
    );
}
