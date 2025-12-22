/**
 * Base UI Components - HashDisplay
 * 
 * Display cryptographic hashes with copy-to-clipboard functionality.
 * Per spec: "Show cryptographic proof, not just assertions"
 */

import { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface HashDisplayProps {
    hash: string;
    label?: string;
    truncate?: boolean;
    fullWidth?: boolean;
}

export function HashDisplay({
    hash,
    label,
    truncate = true,
    fullWidth = false,
}: HashDisplayProps) {
    const [copied, setCopied] = useState(false);

    const displayHash = truncate && hash.length > 16
        ? `${hash.slice(0, 8)}...${hash.slice(-8)}`
        : hash;

    async function copyToClipboard() {
        try {
            await navigator.clipboard.writeText(hash);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    }

    return (
        <div className={`flex items-center ${fullWidth ? 'w-full' : ''}`}>
            {label && (
                <span className="text-dark-400 text-sm mr-2 min-w-[120px]">{label}:</span>
            )}
            <div className={`flex items-center ${fullWidth ? 'flex-1' : ''}`}>
                <code className={`hash-display ${fullWidth ? 'flex-1' : ''}`}>
                    {displayHash}
                </code>
                <button
                    onClick={copyToClipboard}
                    className="ml-2 p-1 rounded hover:bg-dark-700 text-dark-400 hover:text-gray-200 transition-colors"
                    title="Copy to clipboard"
                >
                    {copied ? (
                        <Check className="w-4 h-4 text-healthy" />
                    ) : (
                        <Copy className="w-4 h-4" />
                    )}
                </button>
            </div>
        </div>
    );
}

/**
 * Compact hash badge for tables
 */
export function HashBadge({ hash }: { hash: string }) {
    const [copied, setCopied] = useState(false);
    const displayHash = `${hash.slice(0, 6)}...`;

    async function copyToClipboard() {
        try {
            await navigator.clipboard.writeText(hash);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch {
            // Silent fail
        }
    }

    return (
        <button
            onClick={copyToClipboard}
            className={`
        font-mono text-xs px-2 py-0.5 rounded 
        bg-dark-800 border border-dark-700 
        hover:bg-dark-700 transition-colors
        ${copied ? 'text-healthy' : 'text-dark-300'}
      `}
            title={hash}
        >
            {copied ? '✓' : displayHash}
        </button>
    );
}
