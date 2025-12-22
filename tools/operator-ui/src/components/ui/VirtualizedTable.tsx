/**
 * VirtualizedTable - Efficient rendering for large data sets
 * 
 * Uses @tanstack/react-virtual for windowed rendering.
 * Only renders visible rows, dramatically improving performance
 * for tables with 100+ rows.
 * 
 * @performance O(visible_rows) instead of O(total_rows) for rendering
 */

import { useRef, type ReactNode } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';

export interface Column<T> {
    key: keyof T | string;
    header: string;
    width?: string;
    render?: (item: T, index: number) => ReactNode;
}

interface VirtualizedTableProps<T> {
    data: T[];
    columns: Column<T>[];
    rowHeight?: number;
    maxHeight?: number;
    onRowClick?: (item: T, index: number) => void;
    getRowKey: (item: T, index: number) => string;
    emptyMessage?: string;
}

export function VirtualizedTable<T>({
    data,
    columns,
    rowHeight = 48,
    maxHeight = 600,
    onRowClick,
    getRowKey,
    emptyMessage = 'No data available',
}: VirtualizedTableProps<T>) {
    const parentRef = useRef<HTMLDivElement>(null);

    const virtualizer = useVirtualizer({
        count: data.length,
        getScrollElement: () => parentRef.current,
        estimateSize: () => rowHeight,
        overscan: 5, // Render 5 extra rows above/below viewport
    });

    const items = virtualizer.getVirtualItems();

    if (data.length === 0) {
        return (
            <div className="p-8 text-center text-dark-400">
                {emptyMessage}
            </div>
        );
    }

    return (
        <div className="overflow-hidden rounded-lg border border-dark-700">
            {/* Header */}
            <div className="flex bg-dark-800/50 border-b border-dark-700">
                {columns.map((col) => (
                    <div
                        key={String(col.key)}
                        className="px-3 py-2 text-xs font-medium text-dark-400 uppercase tracking-wider"
                        style={{ width: col.width ?? 'auto', flex: col.width ? 'none' : 1 }}
                    >
                        {col.header}
                    </div>
                ))}
            </div>

            {/* Virtualized body */}
            <div
                ref={parentRef}
                className="overflow-auto"
                style={{ maxHeight }}
            >
                <div
                    style={{
                        height: virtualizer.getTotalSize(),
                        width: '100%',
                        position: 'relative',
                    }}
                >
                    {items.map((virtualRow) => {
                        const item = data[virtualRow.index];
                        const rowKey = getRowKey(item, virtualRow.index);

                        return (
                            <div
                                key={rowKey}
                                data-index={virtualRow.index}
                                ref={virtualizer.measureElement}
                                className={`
                  absolute left-0 flex items-center w-full
                  border-b border-dark-700/50
                  ${onRowClick ? 'cursor-pointer hover:bg-dark-800/50' : ''}
                  ${virtualRow.index % 2 === 0 ? 'bg-dark-900/20' : ''}
                `}
                                style={{
                                    height: rowHeight,
                                    transform: `translateY(${virtualRow.start}px)`,
                                }}
                                onClick={() => onRowClick?.(item, virtualRow.index)}
                            >
                                {columns.map((col) => {
                                    const value = col.render
                                        ? col.render(item, virtualRow.index)
                                        : String((item as Record<string, unknown>)[col.key as string] ?? '');

                                    return (
                                        <div
                                            key={String(col.key)}
                                            className="px-3 py-2 text-sm text-gray-200 truncate"
                                            style={{ width: col.width ?? 'auto', flex: col.width ? 'none' : 1 }}
                                        >
                                            {value}
                                        </div>
                                    );
                                })}
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Footer with stats */}
            <div className="px-3 py-2 bg-dark-800/30 border-t border-dark-700 text-xs text-dark-400">
                Showing {items.length} of {data.length} rows
            </div>
        </div>
    );
}
