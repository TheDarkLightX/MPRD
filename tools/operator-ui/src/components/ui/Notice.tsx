/**
 * Notice / Error cards
 *
 * Used for production-grade "empty state" and "backend unavailable" UX.
 */
import type { ReactNode } from 'react';
import { Card } from './Card';

type NoticeVariant = 'info' | 'warning' | 'error';

const variantStyles: Record<NoticeVariant, { border: string; bg: string; text: string }> = {
  info: { border: 'border-dark-700', bg: 'bg-dark-900/30', text: 'text-dark-200' },
  warning: { border: 'border-degraded/30', bg: 'bg-degraded/10', text: 'text-degraded' },
  error: { border: 'border-critical/30', bg: 'bg-critical/10', text: 'text-critical' },
};

export function NoticeCard({
  title,
  message,
  variant = 'info',
  actions,
}: {
  title: string;
  message: string;
  variant?: NoticeVariant;
  actions?: ReactNode;
}) {
  const s = variantStyles[variant];
  return (
    <Card className={`${s.border} ${s.bg}`}>
      <div className="space-y-2">
        <div className={`text-sm font-semibold ${s.text}`}>{title}</div>
        <div className="text-sm text-dark-200">{message}</div>
        {actions ? <div className="pt-2">{actions}</div> : null}
      </div>
    </Card>
  );
}
