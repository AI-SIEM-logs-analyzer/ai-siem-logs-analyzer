import type { ReactNode } from 'react';
import { useAttackTactics, useTechniquesInUse } from '@/api/attack';
import { AlertStatusBadge } from '@/components/alerts/alert-status-badge';
import { SeverityBadge } from '@/components/events/severity-badge';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import {
  ALERT_STATUSES,
  hasAlertFilters,
  NO_ALERT_FILTERS,
  toggle,
  type AlertFilters,
} from '@/lib/alert-filters';
import { SEVERITIES } from '@/lib/event-filters';
import { cn } from '@/lib/utils';

interface AlertFilterBarProps {
  filters: AlertFilters;
  onChange: (filters: AlertFilters) => void;
}

export function AlertFilterBar({ filters, onChange }: AlertFilterBarProps) {
  const { data: techniques = [] } = useTechniquesInUse();
  const { data: tactics = [] } = useAttackTactics();
  const served = new Set(
    techniques.flatMap(
      (technique) =>
        technique.tactics?.map((tactic) => tactic.id).filter((id): id is string => Boolean(id)) ??
        [],
    ),
  );
  const tacticOptions = tactics.filter((tactic): tactic is typeof tactic & { id: string } =>
    Boolean(tactic.id && served.has(tactic.id)),
  );
  const techniqueOptions = techniques.filter(
    (technique): technique is typeof technique & { id: string } => Boolean(technique.id),
  );
  const filtered = hasAlertFilters(filters);
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
          {tacticOptions.length > 0 && (
            <ToggleRow label="Tactic">
              {tacticOptions.map((tactic) => (
                <Toggle
                  key={tactic.id}
                  on={filters.tactic.includes(tactic.id)}
                  dimmed={filters.tactic.length > 0}
                  onClick={() =>
                    onChange({ ...filters, tactic: toggle(filters.tactic, tactic.id), page: 0 })
                  }
                >
                  <Badge
                    variant="outline"
                    title={tactic.id}
                    className={cn(filters.tactic.includes(tactic.id) && 'ring-1 ring-current')}
                  >
                    {tactic.name}
                  </Badge>
                </Toggle>
              ))}
            </ToggleRow>
          )}
          {techniqueOptions.length > 0 && (
            <ToggleRow label="Technique">
              {techniqueOptions.map((technique) => (
                <Toggle
                  key={technique.id}
                  on={filters.technique.includes(technique.id)}
                  dimmed={filters.technique.length > 0}
                  onClick={() =>
                    onChange({
                      ...filters,
                      technique: toggle(filters.technique, technique.id),
                      page: 0,
                    })
                  }
                >
                  <Badge
                    variant="outline"
                    title={technique.name ?? undefined}
                    className={cn(
                      'font-mono',
                      filters.technique.includes(technique.id) && 'ring-1 ring-current',
                    )}
                  >
                    {technique.id}
                  </Badge>
                </Toggle>
              ))}
            </ToggleRow>
          )}
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
      <span className="text-muted-foreground w-20 text-sm">{label}</span>
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
