/**
 * Decision Detail Component
 * 
 * Shows full decision information including token, proof, state, and candidates.
 * Per spec Section 6.3: Complete decision detail modal.
 */

import type { DecisionDetail } from '../../api/types';
import { Modal, Button, StatusBadge, HashDisplay } from '../ui';
import { RefreshCw, Download, Star, Eye, EyeOff, FileDown } from 'lucide-react';
import { apiClient } from '../../api/client';
import { useEffect, useState } from 'react';

interface DecisionDetailModalProps {
    decision: DecisionDetail | null;
    isOpen: boolean;
    onClose: () => void;
    onVerify?: (id: string) => void;
    verifying?: boolean;
    verifyError?: string | null;
}

function formatDate(ms: number): string {
    return new Date(ms).toLocaleString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
    });
}

function SectionDivider() {
    return <div className="border-t border-dark-700 my-4" />;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
    return (
        <div>
            <h4 className="text-sm font-semibold text-dark-400 uppercase tracking-wider mb-3">
                {title}
            </h4>
            {children}
        </div>
    );
}

async function downloadBlob(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob);
    try {
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
    } finally {
        URL.revokeObjectURL(url);
    }
}

export function DecisionDetailModal({
    decision,
    isOpen,
    onClose,
    onVerify,
    verifying = false,
    verifyError = null,
}: DecisionDetailModalProps) {
    const [revealPlaintext, setRevealPlaintext] = useState(false);
    const [downloading, setDownloading] = useState<string | null>(null);
    const decisionId = decision?.id ?? '';
    const [downloadError, setDownloadError] = useState<string | null>(null);

    useEffect(() => {
        setRevealPlaintext(false);
        setDownloading(null);
        setDownloadError(null);
    }, [decisionId, isOpen]);

    if (!decision) return null;

    async function handleDownload(name: string) {
        try {
            setDownloading(name);
            setDownloadError(null);
            const blob = await apiClient.downloadDecisionBlob(decisionId, name);
            await downloadBlob(blob, `${decisionId}-${name}`);
        } catch (e) {
            setDownloadError(e instanceof Error ? e.message : 'Download failed');
        } finally {
            setDownloading(null);
        }
    }

    return (
        <Modal
            isOpen={isOpen}
            onClose={onClose}
            title="Decision Detail"
            size="xl"
        >
            {/* Header with ID and time */}
            <div className="flex items-start justify-between mb-6">
                <div>
                    <p className="text-sm text-dark-400">Decision ID</p>
                    <p className="font-mono text-sm text-gray-200">{decision.id}</p>
                </div>
                <div className="text-right">
                    <p className="text-sm text-dark-400">Time</p>
                    <p className="text-sm text-gray-200">{formatDate(decision.timestamp)}</p>
                </div>
            </div>

            <SectionDivider />

            {/* Token */}
            <Section title="Token">
                <div className="bg-dark-800/50 rounded-lg p-4 space-y-3">
                    <HashDisplay hash={decision.token.policyHash} label="policy_hash" fullWidth />
                    <div className="flex items-center">
                        <span className="text-dark-400 text-sm min-w-[120px]">policy_epoch:</span>
                        <span className="text-gray-200">{decision.token.policyEpoch}</span>
                    </div>
                    <HashDisplay hash={decision.token.registryRoot} label="registry_root" fullWidth />
                    <HashDisplay hash={decision.token.stateHash} label="state_hash" fullWidth />
                    <HashDisplay hash={decision.token.chosenActionHash} label="chosen_action" fullWidth />
                    <HashDisplay hash={decision.token.nonceOrTxHash} label="nonce" fullWidth />
                    <div className="flex items-center">
                        <span className="text-dark-400 text-sm min-w-[120px]">timestamp_ms:</span>
                        <span className="font-mono text-sm text-gray-200">{decision.token.timestampMs}</span>
                    </div>
                    <HashDisplay hash={decision.token.signature} label="signature" fullWidth />
                </div>
            </Section>

            <SectionDivider />

            {/* Proof */}
            <Section title="Proof">
                <div className="flex items-center justify-between mb-3">
                    <span className="text-sm text-dark-400">Verification Status</span>
                    <StatusBadge status={decision.proofStatus} />
                </div>
                {verifyError && (
                    <div className="text-xs text-critical mb-2">
                        {verifyError}
                    </div>
                )}
                {downloadError && (
                    <div className="text-xs text-critical mb-2">
                        {downloadError}
                    </div>
                )}
                <div className="bg-dark-800/50 rounded-lg p-4 space-y-3">
                    <HashDisplay hash={decision.proof.candidateSetHash} label="candidate_set" fullWidth />
                    <HashDisplay hash={decision.proof.limitsHash} label="limits_hash" fullWidth />
                    <div className="flex items-center">
                        <span className="text-dark-400 text-sm min-w-[120px]">receipt_size:</span>
                        <span className="text-gray-200">{decision.proof.receiptSize.toLocaleString()} bytes</span>
                    </div>
                    <div className="flex items-center">
                        <span className="text-dark-400 text-sm min-w-[120px]">verified_at:</span>
                        <span className="text-gray-200">{formatDate(decision.proof.verifiedAt)}</span>
                    </div>
                </div>
                <div className="flex items-center space-x-2 mt-3">
                    <Button
                        variant="secondary"
                        size="sm"
                        icon={<RefreshCw className={`w-4 h-4 ${verifying ? 'animate-spin' : ''}`} />}
                        onClick={() => onVerify?.(decision.id)}
                        loading={verifying}
                    >
                        Re-Verify
                    </Button>
                    <Button
                        variant="ghost"
                        size="sm"
                        icon={<Download className="w-4 h-4" />}
                        onClick={() => handleDownload('record.json')}
                        loading={downloading === 'record.json'}
                    >
                        Download record.json
                    </Button>
                    <Button
                        variant="ghost"
                        size="sm"
                        icon={<FileDown className="w-4 h-4" />}
                        onClick={() => handleDownload('receipt.bin')}
                        loading={downloading === 'receipt.bin'}
                    >
                        receipt.bin
                    </Button>
                    <Button
                        variant="ghost"
                        size="sm"
                        icon={<FileDown className="w-4 h-4" />}
                        onClick={() => handleDownload('limits.bin')}
                        loading={downloading === 'limits.bin'}
                    >
                        limits.bin
                    </Button>
                    {revealPlaintext && (
                        <Button
                            variant="ghost"
                            size="sm"
                            icon={<FileDown className="w-4 h-4" />}
                            onClick={() => handleDownload('chosen_action_preimage.bin')}
                            loading={downloading === 'chosen_action_preimage.bin'}
                        >
                            chosen_action_preimage.bin
                        </Button>
                    )}
                </div>
            </Section>

            <SectionDivider />

            {/* State Snapshot */}
            <Section title="State Snapshot">
                <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-dark-400">
                        {revealPlaintext ? 'Plaintext visible in UI' : 'Plaintext hidden'}
                    </span>
                    <Button
                        variant="secondary"
                        size="sm"
                        icon={revealPlaintext ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                        onClick={() => setRevealPlaintext(v => !v)}
                    >
                        {revealPlaintext ? 'Hide' : 'Reveal'}
                    </Button>
                </div>
                {revealPlaintext && (
                    <div className="text-xs text-degraded mb-2">
                        Revealing plaintext may expose sensitive data (state fields, action params). Use only when needed.
                    </div>
                )}
                <div className="bg-dark-800/50 rounded-lg p-4">
                    <pre className="text-sm text-gray-200 font-mono overflow-x-auto">
                        {revealPlaintext
                            ? JSON.stringify(decision.state.fields, null, 2)
                            : '<hidden: enable Reveal to view state fields>'}
                    </pre>
                </div>
            </Section>

            <SectionDivider />

            {/* Candidates */}
            <Section title={`Candidates (${decision.candidates.length})`}>
                <div className="overflow-x-auto">
                    <table className="data-table">
                        <thead>
                            <tr className="bg-dark-800/50">
                                <th>#</th>
                                <th>Type</th>
                                <th>Params</th>
                                <th>Score</th>
                                <th>Verdict</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            {decision.candidates.map((candidate) => (
                                <tr key={candidate.index}>
                                    <td className="font-mono text-dark-400">{candidate.index}</td>
                                    <td className="font-medium">{candidate.actionType}</td>
                                    <td className="font-mono text-sm text-dark-300 max-w-xs truncate">
                                        {revealPlaintext
                                            ? JSON.stringify(candidate.params)
                                            : '<hidden>'}
                                    </td>
                                    <td className="font-mono">{candidate.score}</td>
                                    <td><StatusBadge status={candidate.verdict} /></td>
                                    <td>
                                        {candidate.selected && (
                                            <Star className="w-4 h-4 text-degraded fill-degraded" />
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </Section>

            {/* Execution Result */}
            {decision.executionResult && (
                <>
                    <SectionDivider />
                    <Section title="Execution">
                        <div className="flex items-center justify-between mb-3">
                            <span className="text-sm text-dark-400">Status</span>
                            <StatusBadge status={decision.executionStatus} />
                        </div>
                        <div className="bg-dark-800/50 rounded-lg p-4 space-y-2">
                            <div className="flex items-center">
                                <span className="text-dark-400 text-sm min-w-[80px]">Executor:</span>
                                <span className="text-gray-200">{decision.executionResult.executor}</span>
                            </div>
                            <div className="flex items-center">
                                <span className="text-dark-400 text-sm min-w-[80px]">Duration:</span>
                                <span className="text-gray-200">{decision.executionResult.durationMs}ms</span>
                            </div>
                            {decision.executionResult.message && (
                                <div className="flex items-start">
                                    <span className="text-dark-400 text-sm min-w-[80px]">Message:</span>
                                    <span className="text-gray-200">{decision.executionResult.message}</span>
                                </div>
                            )}
                        </div>
                    </Section>
                </>
            )}
        </Modal>
    );
}
