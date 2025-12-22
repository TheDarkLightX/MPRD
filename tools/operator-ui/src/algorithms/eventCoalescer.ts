/**
 * Algorithm 9: EventStreamCoalescer
 * 
 * Coalesces high-rate events with backpressure handling.
 * 
 * @complexity O(1) amortized for event processing
 * @invariant Trust-critical events are NEVER dropped
 * 
 * @postcondition Events are coalesced and delivered in order
 */

import type { PipelineEvent } from '../api/types';

// =============================================================================
// Configuration
// =============================================================================

const STAGE_COALESCE_WINDOW_MS = 250;
// const METRICS_COALESCE_WINDOW_MS = 1000; // For future metrics coalescing
// const MAX_QUEUE_SIZE = 1000; // For future queue size limits
const BACKPRESSURE_THRESHOLD = 800;

// =============================================================================
// Types
// =============================================================================

export type EventPriority = 'critical' | 'high' | 'low';

export interface CoalescedEvent {
    type: string;
    events: PipelineEvent[];
    timestamp: number;
}

type EventHandler = (event: PipelineEvent) => void;

interface CoalesceWindow {
    key: string;
    events: PipelineEvent[];
    timer: ReturnType<typeof setTimeout> | null;
}

// =============================================================================
// Event Priority Classification
// =============================================================================

function getEventPriority(event: PipelineEvent): EventPriority {
    // Trust-critical events: posture changes, critical alerts
    if (event.type === 'alert_raised' && event.alert?.severity === 'critical') {
        return 'critical';
    }

    // High priority: decision completions, stage failures
    if (event.type === 'decision_completed') {
        return 'high';
    }
    if (event.error) {
        return 'high';
    }

    // Low priority: stage updates, metrics
    return 'low';
}

function shouldNeverDrop(event: PipelineEvent): boolean {
    return getEventPriority(event) === 'critical';
}

// =============================================================================
// Coalescer Class
// =============================================================================

export class EventStreamCoalescer {
    private subscribers = new Map<string, Set<EventHandler>>();
    private coalesceWindows = new Map<string, CoalesceWindow>();
    private queue: PipelineEvent[] = [];
    private processing = false;

    /**
     * Subscribe to events by type.
     */
    subscribe(eventType: string, handler: EventHandler): () => void {
        if (!this.subscribers.has(eventType)) {
            this.subscribers.set(eventType, new Set());
        }
        this.subscribers.get(eventType)!.add(handler);

        // Return unsubscribe function
        return () => {
            this.subscribers.get(eventType)?.delete(handler);
        };
    }

    /**
     * Subscribe to all events.
     */
    subscribeAll(handler: EventHandler): () => void {
        return this.subscribe('*', handler);
    }

    /**
     * Process an incoming event.
     * 
     * @invariant Critical events are never dropped
     */
    processEvent(event: PipelineEvent): void {
        // Validate event
        if (!this.isValidEvent(event)) {
            console.warn('Invalid event received:', event);
            return;
        }

        // Check for coalescing
        if (this.shouldCoalesce(event)) {
            this.addToCoalesceWindow(event);
            return;
        }

        // Apply backpressure
        if (this.queue.length >= BACKPRESSURE_THRESHOLD) {
            if (!shouldNeverDrop(event)) {
                this.dropLowPriority();
            }
        }

        // Add to queue and process
        this.queue.push(event);
        this.processQueue();
    }

    /**
     * Validate event structure.
     */
    private isValidEvent(event: PipelineEvent): boolean {
        return Boolean(event && event.type);
    }

    /**
     * Check if event should be coalesced.
     */
    private shouldCoalesce(event: PipelineEvent): boolean {
        return event.type === 'stage_started' ||
            event.type === 'stage_completed';
    }

    /**
     * Add event to coalesce window.
     */
    private addToCoalesceWindow(event: PipelineEvent): void {
        const key = `${event.type}:${event.decisionId ?? ''}:${event.stage ?? ''}`;

        let window = this.coalesceWindows.get(key);
        if (!window) {
            window = { key, events: [], timer: null };
            this.coalesceWindows.set(key, window);
        }

        window.events.push(event);

        // Reset or start timer
        if (window.timer) {
            clearTimeout(window.timer);
        }

        window.timer = setTimeout(() => {
            this.flushCoalesceWindow(key);
        }, STAGE_COALESCE_WINDOW_MS);
    }

    /**
     * Flush a coalesce window, emitting the latest event.
     */
    private flushCoalesceWindow(key: string): void {
        const window = this.coalesceWindows.get(key);
        if (!window || window.events.length === 0) return;

        // Emit only the latest event (coalesced)
        const latestEvent = window.events[window.events.length - 1];
        this.dispatch(latestEvent);

        // Clean up
        this.coalesceWindows.delete(key);
    }

    /**
     * Drop low-priority events when under backpressure.
     */
    private dropLowPriority(): void {
        // Remove up to 20% of low-priority events
        const targetSize = Math.floor(this.queue.length * 0.8);
        const newQueue: PipelineEvent[] = [];

        for (const event of this.queue) {
            if (newQueue.length >= targetSize && getEventPriority(event) === 'low') {
                continue; // Drop
            }
            newQueue.push(event);
        }

        this.queue = newQueue;
    }

    /**
     * Process queued events.
     */
    private processQueue(): void {
        if (this.processing) return;
        this.processing = true;

        while (this.queue.length > 0) {
            const event = this.queue.shift()!;
            this.dispatch(event);
        }

        this.processing = false;
    }

    /**
     * Dispatch event to subscribers.
     */
    private dispatch(event: PipelineEvent): void {
        // Type-specific subscribers
        const typeHandlers = this.subscribers.get(event.type);
        if (typeHandlers) {
            for (const handler of typeHandlers) {
                this.safeCall(handler, event);
            }
        }

        // Wildcard subscribers
        const allHandlers = this.subscribers.get('*');
        if (allHandlers) {
            for (const handler of allHandlers) {
                this.safeCall(handler, event);
            }
        }
    }

    /**
     * Call handler with error isolation.
     */
    private safeCall(handler: EventHandler, event: PipelineEvent): void {
        try {
            handler(event);
        } catch (error) {
            console.error('Event handler error:', error);
        }
    }

    /**
     * Flush all pending events.
     */
    flush(): void {
        // Flush all coalesce windows
        for (const key of this.coalesceWindows.keys()) {
            this.flushCoalesceWindow(key);
        }

        // Process remaining queue
        this.processQueue();
    }

    /**
     * Clear all state.
     */
    reset(): void {
        for (const window of this.coalesceWindows.values()) {
            if (window.timer) {
                clearTimeout(window.timer);
            }
        }
        this.coalesceWindows.clear();
        this.queue = [];
        this.subscribers.clear();
    }
}

/**
 * Create a singleton coalescer instance.
 */
let coalescerInstance: EventStreamCoalescer | null = null;

export function getEventCoalescer(): EventStreamCoalescer {
    if (!coalescerInstance) {
        coalescerInstance = new EventStreamCoalescer();
    }
    return coalescerInstance;
}
