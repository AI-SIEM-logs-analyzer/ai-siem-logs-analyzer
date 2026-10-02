import type { Severity } from '@/lib/event-filters';
import { cn } from '@/lib/utils';

// Colour carries the level at a glance, the text carries it for everyone; the dot keeps the
// badge distinguishable without colour.
const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: 'border-red-600/40 bg-red-600/15 text-red-700 dark:text-red-300',
  ERROR: 'border-orange-500/40 bg-orange-500/15 text-orange-700 dark:text-orange-300',
  WARNING: 'border-amber-500/40 bg-amber-500/15 text-amber-800 dark:text-amber-300',
  INFO: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  DEBUG: 'border-border bg-muted text-muted-foreground',
};

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity | undefined;
  className?: string;
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap',
        severity ? SEVERITY_STYLES[severity] : SEVERITY_STYLES.DEBUG,
        className,
      )}
    >
      <span aria-hidden className="size-1.5 rounded-full bg-current" />
      {severity ?? 'UNKNOWN'}
    </span>
  );
}
