/**
 * Tooltip - Premium hover tooltips with modern styling
 * 
 * Design based on Apple/Figma/Linear systems:
 * - Font: Inter or system fonts, 13px
 * - Background: #2D2D2D (not pure black for OLED depth)
 * - Text: #EDEDED (off-white for high contrast)
 * - Border-radius: 6px
 * - Shadow: Multi-layer for depth
 * - Animation: 150ms fade + slight slide
 */

import { useState, useRef, useEffect, type ReactNode } from 'react';

interface TooltipProps {
    content: ReactNode;
    children: ReactNode;
    position?: 'top' | 'bottom' | 'left' | 'right';
    delay?: number;
    className?: string;
}

export function Tooltip({
    content,
    children,
    position = 'top',
    delay = 200,
    className = ''
}: TooltipProps) {
    const [isVisible, setIsVisible] = useState(false);
    const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const triggerRef = useRef<HTMLDivElement>(null);

    const showTooltip = () => {
        timeoutRef.current = setTimeout(() => setIsVisible(true), delay);
    };

    const hideTooltip = () => {
        if (timeoutRef.current) clearTimeout(timeoutRef.current);
        setIsVisible(false);
    };

    useEffect(() => {
        return () => {
            if (timeoutRef.current) clearTimeout(timeoutRef.current);
        };
    }, []);

    const positionClasses = {
        top: 'bottom-full left-1/2 -translate-x-1/2 mb-2',
        bottom: 'top-full left-1/2 -translate-x-1/2 mt-2',
        left: 'right-full top-1/2 -translate-y-1/2 mr-2',
        right: 'left-full top-1/2 -translate-y-1/2 ml-2',
    };

    const arrowClasses = {
        top: 'top-full left-1/2 -translate-x-1/2 border-t-[#2D2D2D] border-x-transparent border-b-transparent',
        bottom: 'bottom-full left-1/2 -translate-x-1/2 border-b-[#2D2D2D] border-x-transparent border-t-transparent',
        left: 'left-full top-1/2 -translate-y-1/2 border-l-[#2D2D2D] border-y-transparent border-r-transparent',
        right: 'right-full top-1/2 -translate-y-1/2 border-r-[#2D2D2D] border-y-transparent border-l-transparent',
    };

    return (
        <div
            ref={triggerRef}
            className="relative inline-flex"
            onMouseEnter={showTooltip}
            onMouseLeave={hideTooltip}
            onFocus={showTooltip}
            onBlur={hideTooltip}
        >
            {children}

            {isVisible && content && (
                <div
                    className={`
                        absolute z-50 ${positionClasses[position]}
                        px-3 py-2
                        text-[13px] font-medium leading-relaxed tracking-tight
                        text-[#EDEDED]
                        bg-[#2D2D2D] 
                        border border-[#404040]/50
                        rounded-md
                        shadow-[0_4px_12px_rgba(0,0,0,0.4),0_2px_4px_rgba(0,0,0,0.3)]
                        backdrop-blur-sm
                        animate-tooltip-fade-in
                        whitespace-nowrap pointer-events-none
                        max-w-[250px]
                        ${className}
                    `}
                    style={{
                        fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
                    }}
                    role="tooltip"
                >
                    {content}
                    <div className={`absolute w-0 h-0 border-[5px] ${arrowClasses[position]}`} />
                </div>
            )}
        </div>
    );
}

/**
 * TruncatedText - Text with ellipsis and tooltip on overflow
 */
export function TruncatedText({
    text,
    maxWidth = 200,
    className = ''
}: {
    text: string;
    maxWidth?: number | string;
    className?: string;
}) {
    const [isTruncated, setIsTruncated] = useState(false);
    const textRef = useRef<HTMLSpanElement>(null);

    useEffect(() => {
        if (textRef.current) {
            setIsTruncated(textRef.current.scrollWidth > textRef.current.clientWidth);
        }
    }, [text]);

    const content = (
        <span
            ref={textRef}
            className={`block truncate ${className}`}
            style={{ maxWidth: typeof maxWidth === 'number' ? `${maxWidth}px` : maxWidth }}
        >
            {text}
        </span>
    );

    if (isTruncated) {
        return <Tooltip content={text}>{content}</Tooltip>;
    }

    return content;
}

/**
 * HoverCard - Enhanced card with hover effects
 */
export function HoverCard({
    children,
    className = '',
    onClick,
}: {
    children: ReactNode;
    className?: string;
    onClick?: () => void;
}) {
    return (
        <div
            className={`
        group relative bg-neutral-800/60 border border-neutral-700/50 rounded-lg
        transition-all duration-200 ease-out
        hover:bg-neutral-800/80 hover:border-neutral-600/60 hover:shadow-lg hover:shadow-neutral-900/20
        hover:-translate-y-0.5
        ${onClick ? 'cursor-pointer' : ''}
        ${className}
      `}
            onClick={onClick}
        >
            {children}
        </div>
    );
}

/**
 * Shimmer effect for loading states
 */
export function Shimmer({ className = '' }: { className?: string }) {
    return (
        <div className={`relative overflow-hidden ${className}`}>
            <div className="absolute inset-0 -translate-x-full animate-shimmer bg-gradient-to-r from-transparent via-white/5 to-transparent" />
        </div>
    );
}

export default Tooltip;
