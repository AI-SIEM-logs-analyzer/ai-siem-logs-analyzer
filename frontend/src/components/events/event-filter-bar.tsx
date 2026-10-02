import { useState, type FormEvent } from 'react';
import { Search, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { SeverityBadge } from '@/components/events/severity-badge';
import {
  activeFilterCount,
  EVENT_RANGES,
  eventFiltersToParams,
  isEventRange,
  isStatusFilter,
  MAX_FILTER_VALUES,
  MAX_SUBSTRING_LENGTH,
  NO_FILTERS,
  SEVERITIES,
  splitList,
  type EventFilters,
  type EventRange,
} from '@/lib/event-filters';
import { cn } from '@/lib/utils';

interface EventFilterBarProps {
  filters: EventFilters;
  onChange: (filters: EventFilters) => void;
}

/**
 * The filters above the events table. The time range and the severities apply as they are
 * picked; the text boxes apply together, on Enter or "Apply". The boxes are uncontrolled and
 * remounted whenever the applied filters change, so a drill-down or the back button shows up in
 * them without a draft state to keep in step.
 */
export function EventFilterBar({ filters, onChange }: EventFilterBarProps) {
  return (
    <Card className="gap-0 py-0">
      <CardContent className="space-y-4 p-4">
        <FilterForm
          key={eventFiltersToParams(filters).toString()}
          filters={filters}
          onChange={onChange}
        />
        <SeverityToggles filters={filters} onChange={onChange} />
        <ActiveFilters filters={filters} onChange={onChange} />
      </CardContent>
    </Card>
  );
}

/** "2026-09-30T14:25" in local time, as a datetime-local input shows an ISO instant. */
function toLocalInput(iso: string | undefined): string {
  if (!iso) return '';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

/** The ISO instant a datetime-local value names, or undefined for an empty box. */
function fromLocalInput(value: FormDataEntryValue | null): string | undefined {
  if (typeof value !== 'string' || !value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

function FilterForm({ filters, onChange }: EventFilterBarProps) {
  const [range, setRange] = useState<EventRange>(filters.range);
  const [problem, setProblem] = useState<string | null>(null);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const text = (name: string) => {
      const value = form.get(name);
      return typeof value === 'string' ? value.trim() : '';
    };

    const srcIp = splitList(text('srcIp'));
    const status = splitList(text('status')).map((value) => value.toLowerCase());
    const badStatus = status.filter((value) => !isStatusFilter(value));
    if (badStatus.length > 0) {
      setProblem(
        `${badStatus.join(', ')}: a status is a code from 100 to 599 (404) or a class (5xx).`,
      );
      return;
    }
    if (srcIp.length > MAX_FILTER_VALUES || status.length > MAX_FILTER_VALUES) {
      setProblem(`At most ${MAX_FILTER_VALUES} source IPs and ${MAX_FILTER_VALUES} statuses.`);
      return;
    }
    const from = range === 'custom' ? fromLocalInput(form.get('from')) : undefined;
    const to = range === 'custom' ? fromLocalInput(form.get('to')) : undefined;
    if (from && to && Date.parse(from) >= Date.parse(to)) {
      setProblem('The start of the range must come before its end.');
      return;
    }

    setProblem(null);
    onChange({
      ...filters,
      range,
      from,
      to,
      q: text('q'),
      substring: text('substring'),
      srcIp,
      status,
    });
  }

  function pickRange(next: EventRange) {
    setRange(next);
    // A preset applies at once; a custom range waits for its dates and "Apply".
    if (next !== 'custom') onChange({ ...filters, range: next, from: undefined, to: undefined });
  }

  return (
    <form onSubmit={submit} className="space-y-3" aria-label="Event filters">
      <div className="flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1">
          <Search
            aria-hidden
            className="text-muted-foreground pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2"
          />
          <Input
            name="q"
            type="search"
            defaultValue={filters.q}
            placeholder="Search messages, e.g. failed login"
            aria-label="Search messages"
            className="pl-9"
          />
        </div>
        <select
          aria-label="Time range"
          value={range}
          onChange={(event) => isEventRange(event.target.value) && pickRange(event.target.value)}
          className="border-input dark:bg-input/30 focus-visible:border-ring focus-visible:ring-ring/50 h-9 rounded-md border bg-transparent px-3 text-sm shadow-xs outline-none focus-visible:ring-[3px]"
        >
          {(Object.keys(EVENT_RANGES) as EventRange[]).map((key) => (
            <option key={key} value={key}>
              {EVENT_RANGES[key].label}
            </option>
          ))}
        </select>
        <Button type="submit">Apply</Button>
      </div>

      {range === 'custom' && (
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="space-y-1 text-sm">
            <span className="text-muted-foreground">From</span>
            <Input name="from" type="datetime-local" defaultValue={toLocalInput(filters.from)} />
          </label>
          <label className="space-y-1 text-sm">
            <span className="text-muted-foreground">To</span>
            <Input name="to" type="datetime-local" defaultValue={toLocalInput(filters.to)} />
          </label>
        </div>
      )}

      <div className="grid gap-3 md:grid-cols-3">
        <label className="space-y-1 text-sm">
          <span className="text-muted-foreground">Source IP or CIDR</span>
          <Input
            name="srcIp"
            defaultValue={filters.srcIp.join(', ')}
            placeholder="10.0.0.0/8, 203.0.113.7"
            className="font-mono"
          />
        </label>
        <label className="space-y-1 text-sm">
          <span className="text-muted-foreground">HTTP status</span>
          <Input
            name="status"
            defaultValue={filters.status.join(', ')}
            placeholder="404, 5xx"
            className="font-mono"
          />
        </label>
        <label className="space-y-1 text-sm">
          <span className="text-muted-foreground">Raw line contains</span>
          <Input
            name="substring"
            defaultValue={filters.substring}
            maxLength={MAX_SUBSTRING_LENGTH}
            placeholder="/wp-login.php"
            className="font-mono"
          />
        </label>
      </div>

      {problem && (
        <p role="alert" className="text-destructive text-sm">
          {problem}
        </p>
      )}
    </form>
  );
}

function SeverityToggles({ filters, onChange }: EventFilterBarProps) {
  return (
    <div role="group" aria-label="Severity" className="flex flex-wrap items-center gap-2">
      <span className="text-muted-foreground mr-1 text-sm">Severity</span>
      {SEVERITIES.map((severity) => {
        const on = filters.severity.includes(severity);
        return (
          <button
            key={severity}
            type="button"
            aria-pressed={on}
            onClick={() =>
              onChange({
                ...filters,
                severity: on
                  ? filters.severity.filter((s) => s !== severity)
                  : [...filters.severity, severity],
              })
            }
            className={cn(
              'focus-visible:ring-ring/50 rounded-full transition-opacity outline-none focus-visible:ring-[3px]',
              filters.severity.length > 0 && !on && 'opacity-45 hover:opacity-80',
            )}
          >
            <SeverityBadge severity={severity} className={cn(on && 'ring-1 ring-current')} />
          </button>
        );
      })}
    </div>
  );
}

/** What is filtered on, each removable by itself, and a way back to every event. */
function ActiveFilters({ filters, onChange }: EventFilterBarProps) {
  if (activeFilterCount(filters) === 0) return null;

  const chips: { key: string; label: string; remove: EventFilters }[] = [
    ...(filters.q ? [{ key: 'q', label: `“${filters.q}”`, remove: { ...filters, q: '' } }] : []),
    ...(filters.substring
      ? [
          {
            key: 'substring',
            label: `raw ∋ ${filters.substring}`,
            remove: { ...filters, substring: '' },
          },
        ]
      : []),
    ...filters.severity.map((severity) => ({
      key: `severity:${severity}`,
      label: `severity ${severity}`,
      remove: { ...filters, severity: filters.severity.filter((s) => s !== severity) },
    })),
    ...filters.srcIp.map((ip) => ({
      key: `srcIp:${ip}`,
      label: `IP ${ip}`,
      remove: { ...filters, srcIp: filters.srcIp.filter((value) => value !== ip) },
    })),
    ...filters.status.map((status) => ({
      key: `status:${status}`,
      label: `status ${status}`,
      remove: { ...filters, status: filters.status.filter((value) => value !== status) },
    })),
    ...filters.sourceId.map((id) => ({
      key: `sourceId:${id}`,
      label: `source #${id}`,
      remove: { ...filters, sourceId: filters.sourceId.filter((value) => value !== id) },
    })),
  ];

  return (
    <ul aria-label="Active filters" className="flex flex-wrap items-center gap-2 border-t pt-3">
      {chips.map((chip) => (
        <li key={chip.key}>
          <span className="bg-secondary text-secondary-foreground inline-flex items-center gap-1 rounded-full py-0.5 pr-1 pl-2.5 text-xs">
            <span className="max-w-64 truncate">{chip.label}</span>
            <button
              type="button"
              aria-label={`Remove filter ${chip.label}`}
              onClick={() => onChange(chip.remove)}
              className="hover:bg-background/60 rounded-full p-0.5"
            >
              <X aria-hidden className="size-3" />
            </button>
          </span>
        </li>
      ))}
      <li>
        <Button
          variant="ghost"
          size="sm"
          onClick={() =>
            onChange({
              ...NO_FILTERS,
              range: filters.range,
              from: filters.from,
              to: filters.to,
              order: filters.order,
            })
          }
        >
          Clear filters
        </Button>
      </li>
    </ul>
  );
}
