import type { ReactNode } from 'react';
import { AlertStatusBadge } from '@/components/alerts/alert-status-badge';
import { SeverityBadge } from '@/components/events/severity-badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { ALERT_STATUSES, NO_ALERT_FILTERS, toggle, type AlertFilters } from '@/lib/alert-filters';
import { SEVERITIES } from '@/lib/event-filters';
import { cn } from '@/lib/utils';

interface AlertFilterBarProps {
  filters: AlertFilters;
  onChange: (filters: AlertFilters) => void;
}

/**
 * Severity and status toggles above the alert list. Each applies as it is pressed, combines with
 * the other row by AND and with its own row by OR; a change goes back to the first page.
 */
export function AlertFilterBar({ filters, onChange }: AlertFilterBarProps) {
  const filtered = filters.severity.length > 0 || filters.status.length > 0;
  return (
    <Card className="gap-0 py-0">
      <CardContent className="flex flex-wrap items-start justify-between gap-4 p-4">
        <div className="space-y-3">
          <ToggleRow label="Severity">
            {SEVERITIES.map((severity) => (
              <Toggle
                key={severity}
                on={filters.severity.includes(severity)}
                dimmed={filters.severity.length > 0}
                onClick={() =>
                  onChange({ ...filters, severity: toggle(filters.severity, severity), page: 0 })
                }
              >
                <SeverityBadge
                  severity={severity}
                  className={cn(filters.severity.includes(severity) && 'ring-1 ring-current')}
                />
              </Toggle>
            ))}
          </ToggleRow>
          <ToggleRow label="Status">
            {ALERT_STATUSES.map((status) => (
              <Toggle
                key={status}
                on={filters.status.includes(status)}
                dimmed={filters.status.length > 0}
                onClick={() =>
                  onChange({ ...filters, status: toggle(filters.status, status), page: 0 })
                }
              >
                <AlertStatusBadge status={status} />
              </Toggle>
            ))}
          </ToggleRow>
        </div>
        {filtered && (
          <Button variant="ghost" size="sm" onClick={() => onChange(NO_ALERT_FILTERS)}>
            Clear filters
          </Button>
        )}
      </CardContent>
    </Card>
  );
}

function ToggleRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap items-center gap-2">
      <span className="text-muted-foreground w-16 text-sm">{label}</span>
      {children}
    </div>
  );
}

function Toggle({
  on,
  dimmed,
  onClick,
  children,
}: {
  on: boolean;
  /** Something in the row is picked, so the rest step back. */
  dimmed: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      aria-pressed={on}
      onClick={onClick}
      className={cn(
        'focus-visible:ring-ring/50 rounded-full transition-opacity outline-none focus-visible:ring-[3px]',
        dimmed && !on && 'opacity-45 hover:opacity-80',
      )}
    >
      {children}
    </button>
  );
}
