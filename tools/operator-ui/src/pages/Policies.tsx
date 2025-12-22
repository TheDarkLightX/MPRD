/**
 * Policies Page
 * 
 * Policy management screen.
 * Per spec Section 6.4.
 */

import { PolicyList } from '../components/policies';
import { NoticeCard } from '../components/ui';
import { useOperatorPolicies } from '../hooks';

export function PoliciesPage() {
    const { policies, loading, error } = useOperatorPolicies();

    if (error) {
        return (
            <NoticeCard
                variant="error"
                title="Backend unavailable"
                message={`Failed to load policies: ${error}`}
            />
        );
    }

    return (
        <div className="space-y-4">
            {/* Page header */}
            <div>
                <h1 className="text-2xl font-bold text-gray-100">Policies</h1>
                <p className="text-dark-400">View policy artifacts used by this node</p>
            </div>

            {/* Policy List */}
            <PolicyList
                policies={policies}
                loading={loading}
                onViewPolicy={(hash) => {
                    // TODO: Navigate to policy detail
                    console.log('View policy:', hash);
                }}
            />
        </div>
    );
}
