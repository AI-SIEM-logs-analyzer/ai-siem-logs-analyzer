import { useState } from 'react';
import { Check, ChevronLeft, ChevronRight, Copy, Filter } from 'lucide-react';
import type { EventHit } from '@/api/events';
import { SeverityBadge } from '@/components/events/severity-badge';
import { Button } from '@/components/ui/button';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { fieldGroups, formatEventTime, type FieldRow } from '@/lib/event-fields';
import { hasFilterValue, type DrillField, type EventFilters } from '@/lib/event-filters';
import { cn } from '@/lib/utils';

interface EventDetailsProps {
  /** The event shown; null keeps the panel closed. */
  hit: EventHit | null;
  filters: EventFilters;
  onClose: () => void;
  onDrill: (field: DrillField, value: string | number) => void;
  /** Step to the row above or below in the table; undefined at either end of the page. */
  onPrevious?: () => void;
  onNext?: () => void;
}

/**
 * Everything one event carries, in a panel beside the table: when it happened and was
 * ingested, its message, every parsed field in groups and the raw line as it arrived. Values
 * the search can filter on narrow the table from here too.
 */
export function EventDetails({
  hit,
  filters,
  onClose,
  onDrill,
  onPrevious,
  onNext,
}: EventDetailsProps) {
  return (
    <Sheet open={hit !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full gap-0 overflow-y-auto sm:max-w-xl">
        {hit && (
          <>
            <SheetHeader className="border-b pr-12">
              <div className="flex flex-wrap items-center gap-2">
                <SheetTitle>Event #{hit.eventId ?? '?'}</SheetTitle>
                <SeverityBadge severity={hit.severity} />
              </div>
              <SheetDescription>
                <time dateTime={hit.occurredAt}>{formatEventTime(hit.occurredAt)}</time>
              </SheetDescription>
              <div className="flex gap-2 pt-1">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={onPrevious}
                  disabled={!onPrevious}
                  aria-label="Previous event"
                >
                  <ChevronLeft aria-hidden />
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={onNext}
                  disabled={!onNext}
                  aria-label="Next event"
                >
                  Next
                  <ChevronRight aria-hidden />
                </Button>
              </div>
            </SheetHeader>
            <EventBody hit={hit} filters={filters} onDrill={onDrill} />
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

function EventBody({
  hit,
  filters,
  onDrill,
}: {
  hit: EventHit;
  filters: EventFilters;
  onDrill: EventDetailsProps['onDrill'];
}) {
  const groups = fieldGroups(hit.fields);
  const summary: FieldRow[] = [
    { key: 'eventId', label: 'Event ID', value: String(hit.eventId ?? '—'), mono: true },
    {
      key: 'sourceId',
      label: 'Log source',
      value: hit.sourceId !== undefined ? String(hit.sourceId) : '—',
      ...(hit.sourceId !== undefined && { drill: 'sourceId' as const }),
      mono: true,
    },
    { key: 'severity', label: 'Severity', value: hit.severity ?? '—', drill: 'severity' },
    { key: 'occurredAt', label: 'Occurred', value: hit.occurredAt ?? '—', mono: true },
    { key: 'ingestedAt', label: 'Ingested', value: hit.ingestedAt ?? '—', mono: true },
  ];

  return (
    <div className="space-y-6 p-4">
      <section aria-labelledby="event-message" className="space-y-2">
        <h3 id="event-message" className="text-sm font-medium">
          Message
        </h3>
        <p className="bg-muted/50 rounded-md border p-3 text-sm wrap-anywhere whitespace-pre-wrap">
          {hit.message || <span className="text-muted-foreground">(no message)</span>}
        </p>
      </section>

      <FieldList title="Event" rows={summary} filters={filters} onDrill={onDrill} />
      {groups.map((group) => (
        <FieldList
          key={group.title}
          title={group.title}
          rows={group.rows}
          filters={filters}
          onDrill={onDrill}
        />
      ))}

      <section aria-labelledby="event-raw" className="space-y-2">
        <div className="flex items-center justify-between gap-2">
          <h3 id="event-raw" className="text-sm font-medium">
            Raw line
          </h3>
          {hit.raw && <CopyButton text={hit.raw} label="Copy raw line" />}
        </div>
        <pre className="bg-muted/50 max-h-72 overflow-auto rounded-md border p-3 font-mono text-xs wrap-anywhere whitespace-pre-wrap">
          {hit.raw || '(empty)'}
        </pre>
      </section>

      <details className="text-sm">
        <summary className="text-muted-foreground cursor-pointer select-none">Show as JSON</summary>
        <div className="mt-2 space-y-2">
          <div className="flex justify-end">
            <CopyButton text={JSON.stringify(hit, null, 2)} label="Copy JSON" />
          </div>
          <pre className="bg-muted/50 max-h-96 overflow-auto rounded-md border p-3 font-mono text-xs">
            {JSON.stringify(hit, null, 2)}
          </pre>
        </div>
      </details>
    </div>
  );
}

function FieldList({
  title,
  rows,
  filters,
  onDrill,
}: {
  title: string;
  rows: FieldRow[];
  filters: EventFilters;
  onDrill: EventDetailsProps['onDrill'];
}) {
  return (
    <section className="space-y-2">
      <h3 className="text-sm font-medium">{title}</h3>
      <dl className="divide-y rounded-md border text-sm">
        {rows.map((row) => (
          <div key={row.key} className="grid grid-cols-[9rem_1fr_auto] items-start gap-3 px-3 py-2">
            <dt className="text-muted-foreground">{row.label}</dt>
            <dd className={cn('min-w-0 wrap-anywhere', row.mono && 'font-mono text-xs leading-5')}>
              {row.value}
            </dd>
            {row.drill ? (
              <DrillButton
                field={row.drill}
                value={row.value}
                label={row.label}
                filters={filters}
                onDrill={onDrill}
              />
            ) : (
              <span aria-hidden className="size-7" />
            )}
          </div>
        ))}
      </dl>
    </section>
  );
}

function DrillButton({
  field,
  value,
  label,
  filters,
  onDrill,
}: {
  field: DrillField;
  value: string;
  label: string;
  filters: EventFilters;
  onDrill: EventDetailsProps['onDrill'];
}) {
  const active = hasFilterValue(filters, field, value);
  return (
    <Button
      variant="ghost"
      size="icon"
      className="size-7"
      disabled={active}
      title={
        active
          ? 'Already filtered on this value'
          : `Show only events with this ${label.toLowerCase()}`
      }
      aria-label={`Filter by ${label.toLowerCase()} ${value}`}
      onClick={() => onDrill(field, value)}
    >
      <Filter aria-hidden className="size-3.5" />
    </Button>
  );
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
    >
      {copied ? <Check aria-hidden /> : <Copy aria-hidden />}
      {copied ? 'Copied' : label}
    </Button>
  );
}
