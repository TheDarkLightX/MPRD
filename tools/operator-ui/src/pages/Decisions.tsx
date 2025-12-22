/**
 * Decisions Page
 * 
 * Decision history with filtering and detail view.
 * Per spec Section 6.2 and 6.3.
 */

import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { DecisionFilter } from '../api/types';
import { DecisionList, FilterBar, DecisionDetailModal } from '../components/decisions';
import { NoticeCard } from '../components/ui';
import { useOperatorDecisions, useOperatorPolicies } from '../hooks';

export function DecisionsPage() {
    const [searchParams, setSearchParams] = useSearchParams();
    const [filter, setFilter] = useState<DecisionFilter>({});
    const [page, setPage] = useState(1);
    const pageSize = 50;

    // Get decision ID from URL for detail view
    const detailId = searchParams.get('id');

    const {
        decisions,
        total,
        hasMore,
        loading,
        error,
        selectedDecision,
        loadDecision,
        verifyDecision,
        verifying,
        lastVerifyError,
    } = useOperatorDecisions(page, pageSize, filter);

    const { policies } = useOperatorPolicies();

    function handleViewDecision(id: string) {
        setSearchParams({ id });
        loadDecision(id);
    }

    function handleCloseDetail() {
        searchParams.delete('id');
        setSearchParams(searchParams);
    }

    if (error) {
        return (
            <NoticeCard
                variant="error"
                title="Backend unavailable"
                message={`Failed to load decisions: ${error}`}
            />
        );
    }

    return (
        <div className="space-y-4">
            {/* Page header */}
            <div>
                <h1 className="text-2xl font-bold text-gray-100">Decisions</h1>
                <p className="text-dark-400">View and audit decision history</p>
            </div>

            {/* Filters */}
            <FilterBar
                filter={filter}
                onFilterChange={(f) => {
                    setPage(1);
                    setFilter(f);
                }}
                policyOptions={policies}
                actionTypeOptions={[...new Set(decisions.map(d => d.actionType))].sort()}
            />

            {/* Decision List */}
            <DecisionList
                decisions={decisions}
                total={total}
                page={page}
                pageSize={pageSize}
                hasMore={hasMore}
                onPageChange={setPage}
                onViewDecision={handleViewDecision}
                loading={loading}
            />

            {/* Decision Detail Modal */}
            <DecisionDetailModal
                decision={selectedDecision}
                isOpen={!!detailId}
                onClose={handleCloseDetail}
                onVerify={verifyDecision}
                verifying={verifying}
                verifyError={lastVerifyError}
            />
        </div>
    );
}
