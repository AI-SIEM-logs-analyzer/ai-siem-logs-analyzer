import { lazy, Suspense, useMemo } from 'react';
import { RefreshCw } from 'lucide-react';
import { useEventTimeline } from '@/api/events';
import { eventTimelineOption, formatEvents } from '@/components/dashboard/event-timeline-option';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { ApiError } from '@/lib/api-client';
import { formatBucket, peakBucket, TIMELINE_RANGES, type TimelineRange } from '@/lib/timeline';
import { cn } from '@/lib/utils';

// ECharts is about half of the bundle; it loads with the first chart rather than with the app.
const EChart = lazy(() =>
  import('@/components/charts/echart').then((module) => ({ default: module.EChart })),
);

function timelineErrorMessage(error: Error): string {
  if (error instanceof ApiError && error.status === 503) {
    return 'The search index is unreachable, so events cannot be counted. Ingestion continues.';
  }
  return `Could not load the event timeline: ${error.message}`;
}

/** Events over time across every source, for the range picked above the dashboard. */
export function EventTimelineCard({ range }: { range: TimelineRange }) {
  const { data, error, isPending, isFetching, isPlaceholderData, refetch } =
    useEventTimeline(range);
  const { label, per } = TIMELINE_RANGES[range];

  const option = useMemo(
    () => (data ? eventTimelineOption(data.buckets, data.window) : undefined),
    [data],
  );
  const peak = data ? peakBucket(data.buckets) : undefined;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Event timeline</CardTitle>
        <CardDescription>
          Events per {per}, {label.toLowerCase()}, across all sources.
        </CardDescription>
        <CardAction>
          <Button variant="outline" size="sm" onClick={() => void refetch()} disabled={isFetching}>
            <RefreshCw className={isFetching ? 'animate-spin' : undefined} aria-hidden />
            Refresh
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent>
        {isPending ? (
          <div className="space-y-3" aria-label="Loading event timeline">
            <Skeleton className="h-6 w-40" />
            <Skeleton className="h-64 w-full" />
          </div>
        ) : !data ? (
          <p role="alert" className="text-destructive text-sm">
            {timelineErrorMessage(error)}
          </p>
        ) : data.total === 0 ? (
          <p className="text-muted-foreground flex h-64 items-center justify-center rounded-md border border-dashed text-sm">
            No events in the {label.toLowerCase()}. They appear here once log files are ingested.
          </p>
        ) : (
          // A different range keeps the previous chart, dimmed, until its counts arrive.
          <div
            className={cn('space-y-4 transition-opacity', isPlaceholderData && 'opacity-60')}
            aria-busy={isPlaceholderData}
          >
            <dl className="flex flex-wrap gap-x-8 gap-y-2 text-sm">
              <div>
                <dt className="text-muted-foreground">Total</dt>
                <dd className="text-2xl font-semibold">{formatEvents(data.total)}</dd>
              </div>
              {peak && (
                <div>
                  <dt className="text-muted-foreground">Busiest {per}</dt>
                  <dd className="text-2xl font-semibold">{formatEvents(peak.count)}</dd>
                  <dd className="text-muted-foreground">
                    {formatBucket(peak.start, data.window.bucketMs)}
                  </dd>
                </div>
              )}
            </dl>
            {error && (
              <p role="alert" className="text-destructive text-sm">
                {timelineErrorMessage(error)} Showing the last counts received.
              </p>
            )}
            <Suspense fallback={<Skeleton className="h-64 w-full" />}>
              <EChart
                option={option!}
                label={`Column chart of events per ${per}, ${label.toLowerCase()}`}
                className="h-64 w-full"
              />
            </Suspense>
            <details className="text-sm">
              <summary className="text-muted-foreground cursor-pointer select-none">
                Show as table
              </summary>
              <div className="mt-2 max-h-72 overflow-y-auto rounded-md border">
                <table className="w-full">
                  <thead className="bg-muted/50 sticky top-0">
                    <tr>
                      <th scope="col" className="px-3 py-2 text-left font-medium">
                        Period
                      </th>
                      <th scope="col" className="px-3 py-2 text-right font-medium">
                        Events
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {data.buckets.map((bucket) => (
                      <tr key={bucket.start}>
                        <td className="px-3 py-1.5">
                          {formatBucket(bucket.start, data.window.bucketMs)}
                        </td>
                        <td className="px-3 py-1.5 text-right tabular-nums">
                          {bucket.count.toLocaleString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
