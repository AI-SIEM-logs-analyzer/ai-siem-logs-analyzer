import type { ReactNode } from 'react';
import { ArrowLeft, Filter, ScrollText } from 'lucide-react';
import { Link, useLocation, useParams } from 'react-router';
import { useAlert, type Alert, type AlertEvent } from '@/api/alerts';
import { AlertStatusBadge } from '@/components/alerts/alert-status-badge';
import { SeverityBadge } from '@/components/events/severity-badge';
import { ErrorState } from '@/components/feedback/error-state';
import { LinesSkeleton } from '@/components/feedback/skeletons';
import { PageHeader } from '@/components/page-header';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { alertEvents, alertWindowFilters, groupValueText } from '@/lib/alert-filters';
import { fieldGroups, formatEventTime, type FieldRow } from '@/lib/event-fields';
import { eventFiltersToParams, withFilterValue, type EventFilters } from '@/lib/event-filters';
import { cn } from '@/lib/utils';

const count = new Intl.NumberFormat();

/** The events page showing `filters`. */
function eventsLink(filters: EventFilters): string {
  return `/events?${eventFiltersToParams(filters)}`;
}

export function AlertDetailsPage() {
  const { id: param } = useParams();
  const id = Number(param);
  // The list hands on its query string, so "All alerts" goes back to the same filters and page.
  const { state } = useLocation() as { state: { listSearch?: string } | null };
  const back = state?.listSearch ? `/alerts?${state.listSearch}` : '/alerts';
  const { data: alert, error, isPending, isFetching, refetch } = useAlert(id);
  const valid = Number.isSafeInteger(id) && id > 0;

  return (
    <>
      <div>
        <Button variant="ghost" size="sm" asChild className="-ml-2">
          <Link to={back}>
            <ArrowLeft aria-hidden />
            All alerts
          </Link>
        </Button>
      </div>

      {!valid ? (
        <ErrorState error={null} message={`“${param}” is not an alert number.`} />
      ) : isPending ? (
        <LinesSkeleton label="Loading the alert" lines={6} />
      ) : !alert ? (
        <ErrorState
          error={error}
          what={`alert #${id}`}
          onRetry={() => void refetch()}
          retrying={isFetching}
        />
      ) : (
        <AlertDetails alert={alert} />
      )}
    </>
  );
}

function AlertDetails({ alert }: { alert: Alert }) {
  const { filters, unfiltered } = alertEvents(alert);
  const windowed = alert.windowStart !== undefined && alert.windowEnd !== undefined;
  const group = Object.entries(alert.groupKey ?? {});

  return (
    <>
      <PageHeader
        title={alert.title || `Alert #${alert.id}`}
        description={alert.detail}
        actions={
          <Button asChild>
            <Link to={eventsLink(filters)}>
              <ScrollText aria-hidden />
              {alert.eventCount && alert.eventCount > 1
                ? `View the ${count.format(alert.eventCount)} events`
                : 'View the event'}
            </Link>
          </Button>
        }
      />

      <div className="flex flex-wrap items-center gap-2 text-sm">
        <SeverityBadge severity={alert.severity} />
        <AlertStatusBadge status={alert.status} />
        <span className="text-muted-foreground">
          Alert #{alert.id} · raised{' '}
          <time dateTime={alert.raisedAt}>{formatEventTime(alert.raisedAt)}</time>
        </span>
      </div>

      <div className="grid items-start gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>
              <h2>Detection</h2>
            </CardTitle>
            <CardDescription>What fired, and on which events.</CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="divide-y rounded-md border text-sm">
              <Row label="Rule">
                {alert.ruleName ?? (
                  <span className="text-muted-foreground">None — raised without a rule</span>
                )}
                {alert.ruleId !== undefined && (
                  <span className="text-muted-foreground"> (#{alert.ruleId})</span>
                )}
              </Row>
              {windowed && (
                <Row label="Window">
                  <time dateTime={alert.windowStart}>{formatEventTime(alert.windowStart)}</time>
                  {' – '}
                  <time dateTime={alert.windowEnd}>{formatEventTime(alert.windowEnd)}</time>
                </Row>
              )}
              {alert.eventCount !== undefined && (
                <Row label="Events in window">{count.format(alert.eventCount)}</Row>
              )}
              {alert.aggregateValue !== undefined && (
                <Row label="Aggregate value" mono>
                  {String(alert.aggregateValue)}
                </Row>
              )}
              {group.length > 0 && (
                <Row label="Grouped by">
                  <ul className="flex flex-wrap gap-1.5">
                    {group.map(([key, value]) => (
                      <li
                        key={key}
                        className="bg-secondary text-secondary-foreground rounded-full px-2.5 py-0.5 font-mono text-xs"
                      >
                        {key}={groupValueText(value)}
                      </li>
                    ))}
                  </ul>
                </Row>
              )}
              <Row label="Status changed">
                <time dateTime={alert.statusChangedAt}>
                  {formatEventTime(alert.statusChangedAt)}
                </time>
              </Row>
              {alert.resolvedAt && (
                <Row label="Closed">
                  <time dateTime={alert.resolvedAt}>{formatEventTime(alert.resolvedAt)}</time>
                </Row>
              )}
            </dl>
            {unfiltered.length > 0 && (
              <p className="text-muted-foreground mt-3 text-xs">
                The events page cannot filter on {unfiltered.join(', ')}, so the link shows every
                event in the window, not only this group&apos;s.
              </p>
            )}
          </CardContent>
        </Card>

        {alert.trigger ? (
          <TriggerCard event={alert.trigger} windowFilters={alertWindowFilters(alert)} />
        ) : (
          <Card>
            <CardHeader>
              <CardTitle>
                <h2>Triggering event</h2>
              </CardTitle>
              <CardDescription>The backend sent no event with this alert.</CardDescription>
            </CardHeader>
          </Card>
        )}
      </div>
    </>
  );
}

/**
 * The event whose arrival raised the alert. A value the events page can filter on links to the
 * alert's window narrowed to that value.
 */
function TriggerCard({ event, windowFilters }: { event: AlertEvent; windowFilters: EventFilters }) {
  const summary: FieldRow[] = [
    {
      key: 'source',
      label: 'Log source',
      value: event.sourceName ? `${event.sourceName} (#${event.sourceId})` : `#${event.sourceId}`,
    },
    { key: 'occurredAt', label: 'Occurred', value: formatEventTime(event.occurredAt) },
    { key: 'ingestedAt', label: 'Ingested', value: formatEventTime(event.ingestedAt) },
  ];
  const groups = fieldGroups(event.fields);

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2 className="flex flex-wrap items-center gap-2">
            Triggering event
            <SeverityBadge severity={event.severity} />
          </h2>
        </CardTitle>
        <CardDescription>Event #{event.eventId}, the one that made the rule fire.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="bg-muted/50 rounded-md border p-3 text-sm wrap-anywhere whitespace-pre-wrap">
          {event.message || <span className="text-muted-foreground">(no message)</span>}
        </p>
        <FieldList rows={summary} windowFilters={windowFilters} />
        {groups.map((group) => (
          <section key={group.title} className="space-y-2">
            <h3 className="text-sm font-medium">{group.title}</h3>
            <FieldList rows={group.rows} windowFilters={windowFilters} />
          </section>
        ))}
        <section className="space-y-2">
          <h3 className="text-sm font-medium">Raw line</h3>
          <pre className="bg-muted/50 max-h-60 overflow-auto rounded-md border p-3 font-mono text-xs wrap-anywhere whitespace-pre-wrap">
            {event.raw || '(empty)'}
          </pre>
        </section>
      </CardContent>
    </Card>
  );
}

function FieldList({ rows, windowFilters }: { rows: FieldRow[]; windowFilters: EventFilters }) {
  return (
    <dl className="divide-y rounded-md border text-sm">
      {rows.map((row) => (
        <Row key={row.key} label={row.label} mono={row.mono}>
          {row.drill ? (
            <span className="flex items-start justify-between gap-2">
              <span>{row.value}</span>
              <Link
                to={eventsLink(withFilterValue(windowFilters, row.drill, row.value))}
                aria-label={`Events in the window with ${row.label} ${row.value}`}
                title={`Events in the window with this ${row.label.toLowerCase()}`}
                className="text-muted-foreground hover:text-foreground shrink-0"
              >
                <Filter aria-hidden className="size-3.5" />
              </Link>
            </span>
          ) : (
            row.value
          )}
        </Row>
      ))}
    </dl>
  );
}

function Row({ label, mono, children }: { label: string; mono?: boolean; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[9rem_1fr] items-start gap-3 px-3 py-2">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={cn('min-w-0 wrap-anywhere', mono && 'font-mono text-xs leading-5')}>
        {children}
      </dd>
    </div>
  );
}
