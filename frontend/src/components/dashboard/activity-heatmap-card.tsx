import { Suspense, useCallback, useMemo } from 'react';
import { Link, useNavigate } from 'react-router';
import { count, formatEvents } from '@/components/charts/chart-theme';
import type { EChartClick } from '@/components/charts/echart';
import { LazyEChart } from '@/components/charts/lazy-echart';
import {
  activityHeatmapOption,
  heatmapChartHeight,
  heatmapColors,
} from '@/components/dashboard/activity-heatmap-option';
import { AggregateCard, TableView } from '@/components/dashboard/aggregate-card';
import { Skeleton } from '@/components/ui/skeleton';
import { eventFiltersToParams, NO_FILTERS } from '@/lib/event-filters';
import { topEntries } from '@/lib/facets';
import {
  activeCells,
  activityHeatmap,
  densityLevels,
  formatLevel,
  peakCell,
  type ActivityHeatmap,
  type DensityLevel,
} from '@/lib/heatmap';
import {
  formatBucket,
  TIMELINE_RANGES,
  type TimelineRange,
  type TimelineWindow,
} from '@/lib/timeline';

/** Widest an address label gets: a whole IPv4 address in monospace; IPv6 is cut. */
const LABEL_WIDTH = 112;
/** Narrowest a column gets before the chart scrolls sideways inside its card. */
const MIN_COLUMN_PX = 7;

/** The events page, narrowed to `ip` between `from` and `to`. */
function eventsLink(ip: string, from: number, to: number): string {
  const params = eventFiltersToParams({
    ...NO_FILTERS,
    range: 'custom',
    from: new Date(from).toISOString(),
    to: new Date(to).toISOString(),
    srcIp: [ip],
  });
  return `/events?${params}`;
}

/**
 * When the busiest source addresses were active: a row per address, a column per period of the
 * timeline, each cell coloured by how many events the address sent then. A scan or brute force
 * shows as a dark streak, a steady client as an even row.
 */
export function ActivityHeatmapCard({
  range,
  className,
}: {
  range: TimelineRange;
  className?: string;
}) {
  const { label, per } = TIMELINE_RANGES[range];
  return (
    <AggregateCard
      className={className}
      title="Activity by source IP"
      description={`Events per ${per} from the busiest addresses, ${label.toLowerCase()}.`}
      range={range}
      what="the activity heatmap"
      isEmpty={(overview) => topEntries(overview.facets.bySrcIp).length === 0}
      empty="No activity from a source address in this range."
    >
      {(overview) => (
        <ActivityHeatmapView
          bySrcIp={overview.facets.bySrcIp}
          srcIpOverTime={overview.facets.srcIpOverTime}
          window={overview.window}
          range={range}
        />
      )}
    </AggregateCard>
  );
}

function ActivityHeatmapView({
  bySrcIp,
  srcIpOverTime,
  window,
  range,
}: {
  bySrcIp: Record<string, number> | undefined;
  srcIpOverTime: Record<string, { start?: string; count?: number }[]> | undefined;
  window: TimelineWindow;
  range: TimelineRange;
}) {
  const navigate = useNavigate();
  const { label, per } = TIMELINE_RANGES[range];
  const heatmap = useMemo(
    () => activityHeatmap(bySrcIp, srcIpOverTime, window),
    [bySrcIp, srcIpOverTime, window],
  );
  const peak = peakCell(heatmap);
  const levels = useMemo(() => densityLevels(peak?.count ?? 0), [peak?.count]);
  const option = useMemo(
    () => activityHeatmapOption(heatmap, { levels, labelWidth: LABEL_WIDTH }),
    [heatmap, levels],
  );

  // A click on a cell opens the events behind it; the table below is the keyboard path.
  const onClick = useCallback(
    (event: EChartClick) => {
      const [x, y] = (event.value ?? []) as number[];
      const row = heatmap.rows[y];
      const cell = row?.cells[x];
      if (!cell?.count) return;
      void navigate(eventsLink(row.ip, cell.start, cell.start + heatmap.bucketMs));
    },
    [heatmap, navigate],
  );

  const height = heatmapChartHeight(heatmap.rows.length);
  const minWidth = LABEL_WIDTH + heatmap.columns.length * MIN_COLUMN_PX;

  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-x-8 gap-y-3 text-sm">
        {peak && (
          <dl>
            <dt className="text-muted-foreground">Busiest address and period</dt>
            <dd className="text-2xl font-semibold">{formatEvents(peak.count)}</dd>
            <dd className="text-muted-foreground">
              <span className="text-foreground font-mono">{peak.ip}</span>,{' '}
              {formatBucket(peak.start, heatmap.bucketMs)}
            </dd>
          </dl>
        )}
        <DensityLegend levels={levels} per={per} />
      </div>
      <div className="overflow-x-auto">
        <Suspense fallback={<Skeleton className="w-full" style={{ height, minWidth }} />}>
          <LazyEChart
            option={option}
            label={`Heatmap of events per ${per} for the ${heatmap.rows.length} busiest source IPs, ${label.toLowerCase()}`}
            className="w-full"
            style={{ height, minWidth }}
            onClick={onClick}
          />
        </Suspense>
      </div>
      <HeatmapTable heatmap={heatmap} per={per} />
    </>
  );
}

/** The colour bands, faintest first, each with the counts it stands for. */
function DensityLegend({ levels, per }: { levels: readonly DensityLevel[]; per: string }) {
  const fills = heatmapColors(levels.length);
  const entries = [
    { key: 'none', label: '0', color: fills.empty },
    ...levels.map((level, i) => ({
      key: String(level.from),
      label: formatLevel(level, (n) => count.format(n)),
      color: fills.levels[i],
    })),
  ];
  return (
    <ul
      aria-label={`Events per ${per}, by colour`}
      className="flex flex-wrap items-center gap-x-3 gap-y-1"
    >
      {entries.map((entry) => (
        <li key={entry.key} className="flex items-center gap-1.5">
          <span
            aria-hidden
            className="inline-block size-3 shrink-0 rounded-sm border"
            style={{ backgroundColor: entry.color }}
          />
          <span className="text-muted-foreground tabular-nums">{entry.label}</span>
        </li>
      ))}
    </ul>
  );
}

/**
 * Each address's activity summed up: how many events, in how many of the periods, and its
 * busiest one. The address and the busiest period lead to their events.
 */
function HeatmapTable({ heatmap, per }: { heatmap: ActivityHeatmap; per: string }) {
  const { columns, bucketMs } = heatmap;
  const from = columns[0];
  const to = columns[columns.length - 1] + bucketMs;
  return (
    <TableView
      caption={`Events per ${per} for the busiest source IPs`}
      columns={[
        { label: 'Source IP' },
        { label: 'Events', numeric: true },
        { label: 'Active periods', numeric: true },
        { label: 'Busiest period' },
        { label: 'Events then', numeric: true },
      ]}
      rows={heatmap.rows.map((row) => {
        const busiest = row.cells.reduce(
          (best, cell) => (cell.count > best.count ? cell : best),
          row.cells[0],
        );
        return {
          key: row.ip,
          cells: [
            <Link
              to={eventsLink(row.ip, from, to)}
              className="font-mono underline-offset-4 hover:underline"
            >
              {row.ip}
            </Link>,
            count.format(row.total),
            `${activeCells(row)} of ${row.cells.length}`,
            busiest?.count ? (
              <Link
                to={eventsLink(row.ip, busiest.start, busiest.start + bucketMs)}
                className="underline-offset-4 hover:underline"
              >
                {formatBucket(busiest.start, bucketMs)}
              </Link>
            ) : (
              '—'
            ),
            count.format(busiest?.count ?? 0),
          ],
        };
      })}
    />
  );
}
