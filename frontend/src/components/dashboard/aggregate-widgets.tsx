import { Suspense, useEffect, useMemo, useRef, useState, type RefObject } from 'react';
import { count } from '@/components/charts/chart-theme';
import { LazyEChart } from '@/components/charts/lazy-echart';
import { AggregateCard, TableView } from '@/components/dashboard/aggregate-card';
import {
  rankedBarOption,
  rankedChartHeight,
  STATUS_CLASS_COLORS,
  statusCodesOption,
} from '@/components/dashboard/aggregate-options';
import { Skeleton } from '@/components/ui/skeleton';
import {
  errorEventCount,
  formatShare,
  STATUS_CLASSES,
  statusBreakdown,
  topEntries,
  type RankedEntry,
} from '@/lib/facets';
import { TIMELINE_RANGES, type TimelineRange } from '@/lib/timeline';

// The aggregate widgets under the timeline. Each reads its facet from the shared overview;
// the chart, its tooltip and the table view show the same numbers.

function rangeLabel(range: TimelineRange): string {
  return TIMELINE_RANGES[range].label.toLowerCase();
}

/** The width of the element `ref` points at, followed as it resizes; `fallback` until measured. */
function useWidth(ref: RefObject<HTMLElement | null>, fallback: number): number {
  const [width, setWidth] = useState(fallback);
  useEffect(() => {
    const element = ref.current;
    if (!element || typeof ResizeObserver === 'undefined') return;
    // Rounded down to 8 px, so a resize redraws the chart in steps rather than every pixel.
    const measure = () => setWidth(Math.floor(element.clientWidth / 8) * 8 || fallback);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => observer.disconnect();
  }, [ref, fallback]);
  return width;
}

/**
 * A ranked bar chart sized to its rows, loaded with ECharts. Labels sit beside the bars, cut
 * at `labelWidth`, or with `labelsAbove` on a line of their own as wide as the chart.
 */
function RankedChart({
  entries,
  label,
  labelWidth = 0,
  labelsAbove = false,
  mono,
}: {
  entries: readonly RankedEntry[];
  label: string;
  labelWidth?: number;
  labelsAbove?: boolean;
  mono?: boolean;
}) {
  const container = useRef<HTMLDivElement>(null);
  // Above its bar, a label may run as far as the count at the end of the longest one.
  const width = useWidth(container, 320) - 64;
  const labels = labelsAbove ? Math.max(width, 120) : labelWidth;
  const option = useMemo(
    () => rankedBarOption(entries, { labelWidth: labels, labelsAbove, mono }),
    [entries, labels, labelsAbove, mono],
  );
  const height = rankedChartHeight(entries.length, labelsAbove);
  return (
    <div ref={container}>
      <Suspense fallback={<Skeleton className="w-full" style={{ height }} />}>
        <LazyEChart option={option} label={label} className="w-full" style={{ height }} />
      </Suspense>
    </div>
  );
}

/** The source addresses behind the most events: scanners, brute force, a noisy client. */
export function TopIpsCard({ range }: { range: TimelineRange }) {
  return (
    <AggregateCard
      title="Top source IPs"
      description={`Addresses with the most events, ${rangeLabel(range)}.`}
      range={range}
      what="the top source IPs"
      isEmpty={(overview) => topEntries(overview.facets.bySrcIp).length === 0}
      empty="No events with a source address in this range."
    >
      {(overview) => (
        <TopIps bySrcIp={overview.facets.bySrcIp} total={overview.total} range={range} />
      )}
    </AggregateCard>
  );
}

function TopIps({
  bySrcIp,
  total,
  range,
}: {
  bySrcIp: Record<string, number> | undefined;
  total: number;
  range: TimelineRange;
}) {
  const entries = useMemo(() => topEntries(bySrcIp), [bySrcIp]);
  return (
    <>
      <RankedChart
        entries={entries}
        label={`Bar chart of the ${entries.length} source IPs with the most events, ${rangeLabel(range)}`}
        labelWidth={136}
        mono
      />
      <TableView
        caption="Source IPs with the most events"
        columns={[
          { label: 'Source IP' },
          { label: 'Events', numeric: true },
          { label: 'Of all events', numeric: true },
        ]}
        rows={entries.map((entry) => ({
          key: entry.key,
          cells: [
            <span className="font-mono">{entry.key}</span>,
            count.format(entry.count),
            formatShare(total ? entry.count / total : 0),
          ],
        }))}
      />
    </>
  );
}

/** The messages ERROR and CRITICAL events repeat most, by exact text. */
export function TopErrorsCard({ range, className }: { range: TimelineRange; className?: string }) {
  return (
    <AggregateCard
      className={className}
      title="Top errors"
      description={`Most frequent messages of ERROR and CRITICAL events, ${rangeLabel(range)}.`}
      range={range}
      what="the top errors"
      isEmpty={(overview) => topEntries(overview.facets.topErrors).length === 0}
      empty="No ERROR or CRITICAL events in this range."
    >
      {(overview) => (
        <TopErrors
          topErrors={overview.facets.topErrors}
          errors={errorEventCount(overview.facets.bySeverity)}
          range={range}
        />
      )}
    </AggregateCard>
  );
}

function TopErrors({
  topErrors,
  errors,
  range,
}: {
  topErrors: Record<string, number> | undefined;
  errors: number;
  range: TimelineRange;
}) {
  const entries = useMemo(() => topEntries(topErrors), [topErrors]);
  const shown = entries.reduce((sum, entry) => sum + entry.count, 0);
  return (
    <>
      <dl className="flex flex-wrap gap-x-8 gap-y-2 text-sm">
        <div>
          <dt className="text-muted-foreground">Error events</dt>
          <dd className="text-2xl font-semibold">{count.format(errors)}</dd>
        </div>
        {errors > 0 && (
          <div>
            <dt className="text-muted-foreground">Covered by these messages</dt>
            <dd className="text-2xl font-semibold">{formatShare(Math.min(1, shown / errors))}</dd>
          </div>
        )}
      </dl>
      <RankedChart
        entries={entries}
        label={`Bar chart of the ${entries.length} most frequent error messages, ${rangeLabel(range)}`}
        labelsAbove
      />
      <TableView
        caption="Most frequent error messages"
        columns={[
          { label: 'Message' },
          { label: 'Events', numeric: true },
          { label: 'Of errors', numeric: true },
        ]}
        rows={entries.map((entry) => ({
          key: entry.key,
          cells: [
            entry.key,
            count.format(entry.count),
            formatShare(errors ? entry.count / errors : 0),
          ],
        }))}
      />
    </>
  );
}

/** HTTP status codes, by code and by class: how much of the traffic failed, and how. */
export function StatusCodesCard({ range }: { range: TimelineRange }) {
  return (
    <AggregateCard
      title="Status codes"
      description={`HTTP responses by status code, ${rangeLabel(range)}.`}
      range={range}
      what="the status codes"
      isEmpty={(overview) => statusBreakdown(overview.facets.byStatus).total === 0}
      empty="No events with an HTTP status in this range."
    >
      {(overview) => <StatusCodes byStatus={overview.facets.byStatus} range={range} />}
    </AggregateCard>
  );
}

function StatusCodes({
  byStatus,
  range,
}: {
  byStatus: Record<string, number> | undefined;
  range: TimelineRange;
}) {
  const breakdown = useMemo(() => statusBreakdown(byStatus), [byStatus]);
  const option = useMemo(() => statusCodesOption(breakdown.codes), [breakdown]);
  return (
    <>
      {/* The classes double as the chart's legend: a swatch, the class and its share. */}
      <ul aria-label="Status classes" className="flex flex-wrap gap-x-6 gap-y-2 text-sm">
        {breakdown.classes.map(({ statusClass, count: events, share }) => (
          <li key={statusClass} className="flex items-baseline gap-2">
            <span
              aria-hidden
              className="inline-block size-2.5 shrink-0 rounded-sm"
              style={{ backgroundColor: STATUS_CLASS_COLORS[statusClass] }}
            />
            <span>
              <span className="font-medium">{statusClass}</span>{' '}
              <span className="text-muted-foreground">{STATUS_CLASSES[statusClass]}</span>
            </span>
            <span className="tabular-nums">{formatShare(share)}</span>
            <span className="text-muted-foreground tabular-nums">({count.format(events)})</span>
          </li>
        ))}
      </ul>
      <Suspense fallback={<Skeleton className="h-56 w-full" />}>
        <LazyEChart
          option={option}
          label={`Column chart of events per HTTP status code, ${rangeLabel(range)}`}
          className="h-56 w-full"
        />
      </Suspense>
      <TableView
        caption="Events per HTTP status code"
        columns={[
          { label: 'Status' },
          { label: 'Class' },
          { label: 'Events', numeric: true },
          { label: 'Share', numeric: true },
        ]}
        rows={breakdown.codes.map((code) => ({
          key: String(code.code),
          cells: [
            code.code,
            STATUS_CLASSES[code.statusClass],
            count.format(code.count),
            formatShare(code.count / breakdown.total),
          ],
        }))}
      />
    </>
  );
}
