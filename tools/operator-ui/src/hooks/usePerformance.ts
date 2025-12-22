/**
 * Performance Utilities
 *
 * Keep hooks deterministic and render-pure: no ref reads/writes during render.
 */

import { useEffect, useRef, useState } from 'react';

/**
 * Debounce a value - only update after delay with no changes.
 * Useful for search inputs to avoid excessive API calls.
 */
export function useDebounce<T>(value: T, delay: number): T {
    const [debouncedValue, setDebouncedValue] = useState<T>(value);

    useEffect(() => {
        const timer = setTimeout(() => setDebouncedValue(value), delay);
        return () => clearTimeout(timer);
    }, [value, delay]);

    return debouncedValue;
}

/**
 * Intersection observer hook for lazy loading.
 */
export function useIntersectionObserver(
    options?: IntersectionObserverInit
): [React.RefObject<HTMLDivElement | null>, boolean] {
    const ref = useRef<HTMLDivElement | null>(null);
    const [isIntersecting, setIsIntersecting] = useState(false);

    useEffect(() => {
        const element = ref.current;
        if (!element) return;

        const observer = new IntersectionObserver(([entry]) => {
            setIsIntersecting(entry.isIntersecting);
        }, options);

        observer.observe(element);
        return () => observer.disconnect();
    }, [options]);

    return [ref, isIntersecting];
}
