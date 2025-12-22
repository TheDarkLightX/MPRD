/**
 * Security Page
 * 
 * Alert history, verification failures, and audit log.
 * Per spec Section 4 (Information Architecture).
 */

import { AlertFeed } from '../components/alerts';
import { Card, CardHeader, NoticeCard } from '../components/ui';
import { useOperatorAlerts } from '../hooks';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../api/client';
import { USE_MOCK_DATA } from '../config';

export function SecurityPage() {
    const { alerts, acknowledge, error } = useOperatorAlerts();
    const settingsQuery = useQuery({
        queryKey: ['settings'],
        queryFn: () => apiClient.getSettings(),
        enabled: !USE_MOCK_DATA,
        refetchInterval: 10_000,
    });
    const settings = settingsQuery.data ?? null;

    if (error) {
        return (
            <NoticeCard
                variant="error"
                title="Backend unavailable"
                message={`Failed to load alerts: ${error}`}
            />
        );
    }

    return (
        <div className="space-y-6">
            {/* Page header */}
            <div>
                <h1 className="text-2xl font-bold text-gray-100">Security</h1>
                <p className="text-dark-400">Alerts, verification failures, and audit</p>
            </div>

            {/* Trust anchors */}
            <Card>
                <CardHeader
                    title="Trust Anchors"
                    subtitle="Verification configuration that must be correct to stay fail-closed"
                />
                <div className="space-y-3">
                    <div className="flex items-center justify-between py-2 border-b border-dark-700">
                        <span className="text-dark-400">Registry State</span>
                        <span className="font-mono text-sm text-gray-200">
                            {settings?.trustAnchors.registryStatePath ?? 'Not configured'}
                        </span>
                    </div>
                    <div className="flex items-center justify-between py-2 border-b border-dark-700">
                        <span className="text-dark-400">Registry Key FP</span>
                        <span className="font-mono text-gray-200">
                            {settings?.trustAnchors.registryKeyFingerprint ?? 'Not configured'}
                        </span>
                    </div>
                    <div className="flex items-center justify-between py-2">
                        <span className="text-dark-400">Manifest Key FP</span>
                        <span className="font-mono text-gray-200">
                            {settings?.trustAnchors.manifestKeyFingerprint ?? 'Not configured'}
                        </span>
                    </div>
                </div>
            </Card>

            {/* Full alert history */}
            <Card>
                <CardHeader
                    title="Alert History"
                    subtitle={`${alerts.filter(a => !a.acknowledged).length} unresolved`}
                />
                <AlertFeed
                    alerts={alerts}
                    compact
                    maxItems={50}
                    onAcknowledge={acknowledge}
                />
            </Card>

            {/* Verification Failures placeholder */}
            <Card>
                <CardHeader
                    title="Verification Failures"
                    subtitle="Recent proof verification failures"
                />
                <p className="text-dark-400 py-4">No verification failures in the last 24 hours.</p>
            </Card>

            {/* Key management */}
            <Card>
                <CardHeader
                    title="Key Management"
                    subtitle="Operator API access control"
                />
                <div className="flex items-center justify-between py-2">
                    <span className="text-dark-400">API Key</span>
                    <span className="font-mono text-gray-200">
                        {settings?.apiKeyRequired ? 'Required' : 'Not required'}
                    </span>
                </div>
                <div className="flex items-center justify-between py-2 border-t border-dark-700">
                    <span className="text-dark-400">Sensitive Store</span>
                    <span className="font-mono text-gray-200">
                        {settings?.storeSensitiveEnabled ? 'Enabled' : 'Disabled'}
                    </span>
                </div>
            </Card>
        </div>
    );
}
