/**
 * Policy List Component
 * 
 * Displays configured policies with usage stats.
 * Per spec Section 6.4: Policy management screen.
 */

import type { PolicySummary, PolicyStatus } from '../../api/types';
import { Card, Badge, Button, HashBadge } from '../ui';
import { Plus, FileCode } from 'lucide-react';

const statusConfig: Record<PolicyStatus, { variant: 'healthy' | 'degraded' | 'critical'; label: string }> = {
    active: { variant: 'healthy', label: 'Active' },
    deprecated: { variant: 'degraded', label: 'Deprecated' },
    invalid: { variant: 'critical', label: 'Invalid' },
};

function formatDate(ms: number): string {
    return new Date(ms).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
    });
}

interface PolicyRowProps {
    policy: PolicySummary;
    onClick?: () => void;
}

export function PolicyRow({ policy, onClick }: PolicyRowProps) {
    const { variant, label } = statusConfig[policy.status];

    return (
        <tr
            className="cursor-pointer hover:bg-dark-800/50"
            onClick={onClick}
        >
            <td>
                <HashBadge hash={policy.hash} />
            </td>
            <td className="font-medium text-gray-200">
                {policy.name || <span className="text-dark-400 italic">Unnamed</span>}
            </td>
            <td>
                <Badge variant={variant} dot>{label}</Badge>
            </td>
            <td className="text-dark-300 font-mono">
                {policy.usageCount.toLocaleString()}
            </td>
            <td className="text-dark-400">
                {formatDate(policy.createdAt)}
            </td>
        </tr>
    );
}

interface PolicyListProps {
    policies: PolicySummary[];
    onAddPolicy?: () => void;
    onViewPolicy?: (hash: string) => void;
    loading?: boolean;
}

export function PolicyList({
    policies,
    onAddPolicy,
    onViewPolicy,
    loading = false,
}: PolicyListProps) {
    const activePolicies = policies.filter(p => p.status === 'active').length;

    return (
        <Card padding="none">
            <div className="px-4 py-3 border-b border-dark-700 flex items-center justify-between">
                <div>
                    <h3 className="text-lg font-semibold text-gray-100">Policies</h3>
                    <p className="text-sm text-dark-400">{activePolicies} active policies</p>
                </div>
                {onAddPolicy && (
                    <Button
                        variant="primary"
                        size="sm"
                        icon={<Plus className="w-4 h-4" />}
                        onClick={onAddPolicy}
                    >
                        Add Policy
                    </Button>
                )}
            </div>

            <div className="overflow-x-auto">
                <table className="data-table">
                    <thead>
                        <tr className="bg-dark-800/50">
                            <th>Hash</th>
                            <th>Name</th>
                            <th>Status</th>
                            <th>Usage</th>
                            <th>Created</th>
                        </tr>
                    </thead>
                    <tbody>
                        {loading ? (
                            Array.from({ length: 3 }).map((_, i) => (
                                <tr key={i}>
                                    <td colSpan={5}>
                                        <div className="h-8 bg-dark-800 rounded animate-pulse"></div>
                                    </td>
                                </tr>
                            ))
                        ) : policies.length === 0 ? (
                            <tr>
                                <td colSpan={5} className="text-center py-8">
                                    <FileCode className="w-8 h-8 text-dark-600 mx-auto mb-2" />
                                    <p className="text-dark-400">No policies configured</p>
                                    {onAddPolicy && (
                                        <Button
                                            variant="secondary"
                                            size="sm"
                                            icon={<Plus className="w-4 h-4" />}
                                            onClick={onAddPolicy}
                                            className="mt-3"
                                        >
                                            Add your first policy
                                        </Button>
                                    )}
                                </td>
                            </tr>
                        ) : (
                            policies.map(policy => (
                                <PolicyRow
                                    key={policy.hash}
                                    policy={policy}
                                    onClick={() => onViewPolicy?.(policy.hash)}
                                />
                            ))
                        )}
                    </tbody>
                </table>
            </div>
        </Card>
    );
}
