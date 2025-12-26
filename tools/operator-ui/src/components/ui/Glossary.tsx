/**
 * Glossary Component
 *
 * A collapsible glossary section that displays term definitions.
 * Alternative to tooltips for explaining UI elements.
 */

import { useState } from 'react';
import { ChevronDown, ChevronUp, HelpCircle } from 'lucide-react';

export interface GlossaryTerm {
    term: string;
    definition: string;
}

interface GlossaryProps {
    terms: GlossaryTerm[];
    title?: string;
    defaultExpanded?: boolean;
    className?: string;
}

export function Glossary({
    terms,
    title = 'Glossary',
    defaultExpanded = false,
    className = '',
}: GlossaryProps) {
    const [isExpanded, setIsExpanded] = useState(defaultExpanded);

    if (terms.length === 0) return null;

    return (
        <div className={`mt-4 ${className}`}>
            <button
                onClick={() => setIsExpanded(!isExpanded)}
                className="flex items-center gap-2 text-sm text-dark-400 hover:text-dark-200 transition-colors w-full"
            >
                <HelpCircle className="w-4 h-4" />
                <span>{title}</span>
                {isExpanded ? (
                    <ChevronUp className="w-4 h-4 ml-auto" />
                ) : (
                    <ChevronDown className="w-4 h-4 ml-auto" />
                )}
            </button>

            {isExpanded && (
                <div className="mt-3 p-3 bg-dark-800/50 rounded-lg border border-dark-700/50 animate-in slide-in-from-top-2 duration-200">
                    <dl className="space-y-2 text-sm">
                        {terms.map(({ term, definition }) => (
                            <div key={term} className="flex gap-2">
                                <dt className="font-medium text-dark-300 min-w-[80px] shrink-0">
                                    {term}
                                </dt>
                                <dd className="text-dark-400">{definition}</dd>
                            </div>
                        ))}
                    </dl>
                </div>
            )}
        </div>
    );
}
