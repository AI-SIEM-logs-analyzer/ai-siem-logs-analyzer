import { useCallback, useMemo, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { useSearchParams } from 'react-router';
import { EVENT_PAGE_SIZE, useEventPage, type EventCursor, type EventHit } from '@/api/events';
import { EventDetails } from '@/components/events/event-details';
import { EventFilterBar } from '@/components/events/event-filter-bar';
import { EventsTable } from '@/components/events/events-table';
import { PageHeader } from '@/components/page-header';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { ApiError } from '@/lib/api-client';
import {
  eventFiltersToParams,
  parseEventFilters,
  withFilterValue,
  type DrillField,
  type EventFilters,
} from '@/lib/event-filters';

const count = new Intl.NumberFormat();
const clock = new Intl.DateTimeFormat(undefined, { timeStyle: 'medium' });

/**
 * Where the table is in one search. `now` ends a relative range and stays fixed while paging,
 * so the pages chain; `cursors[i]` starts page i + 1. Both belong to the filters named by
 * `key`: a different search starts over on its first page.
 */
interface Paging {
  key: string;
  now: number;
  cursors: EventCursor[];
}

export function EventsPage() {
  // The filters live in the URL, so a reload, the back button or a shared link shows the same
  // search; paging and the open event are this visit's.
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => parseEventFilters(params), [params]);
  const key = eventFiltersToParams(filters).toString();

  const [paging, setPaging] = useState<Paging>(() => ({ key, now: Date.now(), cursors: [] }));
  // Filters reached without going through `applyFilters` (back, forward) start on page one.
  const cursors = paging.key === key ? paging.cursors : [];
  const cursor = cursors.at(-1) ?? null;

  const { data, error, isPending, isFetching, isPlaceholderData } = useEventPage(
    filters,
    paging.now,
    cursor,
  );
  const [selected, setSelected] = useState<EventHit | null>(null);

  const applyFilters = useCallback(
    (next: EventFilters) => {
      const nextParams = eventFiltersToParams(next);
      setParams(nextParams);
      setPaging({ key: nextParams.toString(), now: Date.now(), cursors: [] });
    },
    [setParams],
  );

  const drill = useCallback(
    (field: DrillField, value: string | number) =>
      applyFilters(withFilterValue(filters, field, value)),
    [applyFilters, filters],
  );

  const changeOrder = useCallback(
    (order: EventFilters['order']) => applyFilters({ ...filters, order }),
    [applyFilters, filters],
  );

  const refresh = () => setPaging({ key, now: Date.now(), cursors: [] });

  const hits = data?.hits;
  const index = selected ? (hits?.findIndex((hit) => hit.eventId === selected.eventId) ?? -1) : -1;
  const page = cursors.length;
  const pages = data ? Math.max(1, Math.ceil(data.total / EVENT_PAGE_SIZE)) : 1;

  return (
    <>
      <PageHeader
        title="Events"
        description="Search normalized log events, filter them and open any one for every field."
        actions={
          <div className="flex items-center gap-3">
            <span className="text-muted-foreground text-xs">As of {clock.format(paging.now)}</span>
            <Button variant="outline" size="sm" onClick={refresh} disabled={isFetching}>
              <RefreshCw className={isFetching ? 'animate-spin' : undefined} aria-hidden />
              Refresh
            </Button>
          </div>
        }
      />

      <EventFilterBar filters={filters} onChange={applyFilters} />

      <Card className="gap-0 py-0">
        <div className="flex flex-wrap items-baseline justify-between gap-2 border-b px-4 py-3">
          <h2 className="font-semibold">Results</h2>
          {data && (
            <p className="text-muted-foreground text-sm" aria-live="polite">
              {count.format(data.total)} {data.total === 1 ? 'event' : 'events'}
              {data.total > 0 && ` · page ${page + 1} of ${count.format(pages)}`}
            </p>
          )}
        </div>

        {isPending ? (
          <div className="space-y-2 p-4" aria-label="Loading events">
            <Skeleton className="h-9 w-full" />
            <Skeleton className="h-9 w-full" />
            <Skeleton className="h-9 w-full" />
          </div>
        ) : !data ? (
          <p role="alert" className="text-destructive p-4 text-sm">
            {searchErrorMessage(error)}
          </p>
        ) : data.hits.length === 0 ? (
          <p className="text-muted-foreground p-10 text-center text-sm">
            No events match these filters{page > 0 ? ' on this page' : ''}.
          </p>
        ) : (
          <>
            {error && (
              <p role="alert" className="text-destructive border-b px-4 py-2 text-sm">
                {searchErrorMessage(error)} Showing the last results.
              </p>
            )}
            <EventsTable
              hits={data.hits}
              filters={filters}
              onDrill={drill}
              onOrderChange={changeOrder}
              onSelect={setSelected}
              selectedId={selected?.eventId}
              stale={isPlaceholderData}
            />
          </>
        )}

        {data && (page > 0 || data.next) && (
          <nav
            aria-label="Pages"
            className="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-3 text-sm"
          >
            <Button
              variant="ghost"
              size="sm"
              disabled={page === 0 || isPlaceholderData}
              onClick={() => setPaging({ ...paging, key, cursors: [] })}
            >
              First page
            </Button>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page === 0 || isPlaceholderData}
                onClick={() => setPaging({ ...paging, key, cursors: cursors.slice(0, -1) })}
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={!data.next || isPlaceholderData}
                onClick={() =>
                  data.next && setPaging({ ...paging, key, cursors: [...cursors, data.next] })
                }
              >
                Next
              </Button>
            </div>
          </nav>
        )}
      </Card>

      <EventDetails
        hit={selected}
        filters={filters}
        onClose={() => setSelected(null)}
        onDrill={drill}
        onPrevious={hits && index > 0 ? () => setSelected(hits[index - 1]) : undefined}
        onNext={
          hits && index >= 0 && index < hits.length - 1
            ? () => setSelected(hits[index + 1])
            : undefined
        }
      />
    </>
  );
}

function searchErrorMessage(error: Error | null): string {
  if (error instanceof ApiError && error.status === 503) {
    return 'The search index is unreachable, so events cannot be searched. Ingestion continues.';
  }
  if (error instanceof ApiError && error.status === 400) {
    return 'The backend refused this search: check the source IPs, statuses and time range.';
  }
  return `Could not load events: ${error?.message ?? 'unknown error'}`;
}
