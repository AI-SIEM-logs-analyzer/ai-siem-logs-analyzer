import { useCallback, useMemo } from 'react';
import { RefreshCw } from 'lucide-react';
import { Link, useNavigate, useSearchParams } from 'react-router';
import { ALERT_PAGE_SIZE, useAlertPage, type Alert } from '@/api/alerts';
import { AlertFilterBar } from '@/components/alerts/alert-filter-bar';
import { AlertStatusBadge } from '@/components/alerts/alert-status-badge';
import { TechniqueBadges } from '@/components/alerts/technique-badges';
import { SeverityBadge } from '@/components/events/severity-badge';
import { ErrorState } from '@/components/feedback/error-state';
import { TableSkeleton } from '@/components/feedback/skeletons';
import { PageHeader } from '@/components/page-header';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import {
  alertFiltersToParams,
  hasAlertFilters,
  parseAlertFilters,
  type AlertFilters,
} from '@/lib/alert-filters';
import { formatEventTime } from '@/lib/event-fields';
import { errorMessage } from '@/lib/errors';
import { cn } from '@/lib/utils';

const count = new Intl.NumberFormat();

export function AlertsPage() {
  // The filters and the page live in the URL, so the way back from an alert lands on the same
  // slice of the list.
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => parseAlertFilters(params), [params]);
  const { data, error, isPending, isFetching, isPlaceholderData, refetch } = useAlertPage(filters);

  const applyFilters = useCallback(
    (next: AlertFilters) => setParams(alertFiltersToParams(next)),
    [setParams],
  );

  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / ALERT_PAGE_SIZE));
  const filtered = hasAlertFilters(filters);

  return (
    <>
      <PageHeader
        title="Alerts"
        description="Detections raised against ingested events. Open one for what fired and the events behind it."
        actions={
          <Button variant="outline" size="sm" onClick={() => void refetch()} disabled={isFetching}>
            <RefreshCw className={isFetching ? 'animate-spin' : undefined} aria-hidden />
            Refresh
          </Button>
        }
      />

      <AlertFilterBar filters={filters} onChange={applyFilters} />

      <Card className="gap-0 py-0">
        <div className="flex flex-wrap items-baseline justify-between gap-2 border-b px-4 py-3">
          <h2 className="font-semibold">Alerts</h2>
          {data && (
            <p className="text-muted-foreground text-sm" aria-live="polite">
              {count.format(total)} {total === 1 ? 'alert' : 'alerts'}
              {total > 0 && ` · page ${filters.page + 1} of ${count.format(pages)}`}
            </p>
          )}
        </div>

        {/* A failed refresh keeps the last list on screen and says it may be out of date. */}
        {data && error && (
          <ErrorState
            error={error}
            message={`${errorMessage(error, 'the alerts')} Showing the last list received.`}
            onRetry={() => void refetch()}
            retrying={isFetching}
            className="m-4"
          />
        )}
        {isPending ? (
          <TableSkeleton label="Loading alerts" columns={6} rows={6} />
        ) : !data ? (
          <div className="p-4">
            <ErrorState
              error={error}
              what="the alerts"
              onRetry={() => void refetch()}
              retrying={isFetching}
            />
          </div>
        ) : !data.items?.length ? (
          <p className="text-muted-foreground p-10 text-center text-sm">
            {filtered
              ? `No alerts match these filters${filters.page > 0 ? ' on this page' : ''}.`
              : 'No alerts have been raised yet.'}
          </p>
        ) : (
          <AlertsTable alerts={data.items} stale={isPlaceholderData} search={params.toString()} />
        )}

        {data && total > ALERT_PAGE_SIZE && (
          <nav
            aria-label="Pages"
            className="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-3 text-sm"
          >
            <span className="text-muted-foreground">
              Page {filters.page + 1} of {count.format(pages)}
            </span>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={filters.page === 0 || isPlaceholderData}
                onClick={() => applyFilters({ ...filters, page: filters.page - 1 })}
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={filters.page + 1 >= pages || isPlaceholderData}
                onClick={() => applyFilters({ ...filters, page: filters.page + 1 })}
              >
                Next
              </Button>
            </div>
          </nav>
        )}
      </Card>
    </>
  );
}

function AlertsTable({
  alerts,
  stale,
  search,
}: {
  alerts: readonly Alert[];
  stale: boolean;
  search: string;
}) {
  const navigate = useNavigate();
  const state = { listSearch: search };

  return (
    <div className="overflow-x-auto">
      <table className={cn('w-full text-sm', stale && 'opacity-60')}>
        <thead className="text-muted-foreground border-b text-left">
          <tr>
            <th className="px-4 py-3 font-medium">Severity</th>
            <th className="px-4 py-3 font-medium">Alert</th>
            <th className="px-4 py-3 font-medium">ATT&amp;CK</th>
            <th className="px-4 py-3 font-medium">Status</th>
            <th className="px-4 py-3 text-right font-medium">Events</th>
            <th className="px-4 py-3 font-medium">Raised</th>
          </tr>
        </thead>
        <tbody className="divide-y">
          {alerts.map((alert) => (
            <tr
              key={alert.id}
              onClick={() => void navigate(`/alerts/${alert.id}`, { state })}
              className="hover:bg-muted/50 cursor-pointer"
            >
              <td className="px-4 py-3">
                <SeverityBadge severity={alert.severity} />
              </td>
              <td className="max-w-md px-4 py-3">
                <Link
                  to={`/alerts/${alert.id}`}
                  state={state}
                  onClick={(event) => event.stopPropagation()}
                  className="block truncate font-medium hover:underline"
                  title={alert.title}
                >
                  {alert.title || `Alert #${alert.id}`}
                </Link>
                {alert.detail && (
                  <div className="text-muted-foreground truncate text-xs" title={alert.detail}>
                    {alert.detail}
                  </div>
                )}
              </td>
              <td className="px-4 py-3">
                <TechniqueBadges techniques={alert.techniques ?? []} />
              </td>
              <td className="px-4 py-3">
                <AlertStatusBadge status={alert.status} />
              </td>
              <td className="px-4 py-3 text-right tabular-nums">
                {alert.eventCount !== undefined ? count.format(alert.eventCount) : '—'}
              </td>
              <td className="text-muted-foreground px-4 py-3 whitespace-nowrap">
                <time dateTime={alert.raisedAt}>{formatEventTime(alert.raisedAt)}</time>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
