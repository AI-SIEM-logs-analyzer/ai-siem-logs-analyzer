// The dashboard's activity heatmap: the busiest source addresses' hourly counts folded into the
// timeline's buckets, and the scale the cells are coloured on. Kept free of React and ECharts so
// it is tested alone.

import { TOP_ENTRIES, topEntries } from '@/lib/facets';
import { timelineBuckets, type TimelineBucket, type TimelineWindow } from '@/lib/timeline';

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

/** One source address: a row of the heatmap. */
export interface HeatmapRow {
  ip: string;
  /** Its events in the window, as the source IP facet counted them. */
  total: number;
  /** A cell per timeline bucket, the empty ones included. */
  cells: TimelineBucket[];
}

export interface ActivityHeatmap {
  /** The busiest addresses, busiest first. */
  rows: HeatmapRow[];
  /** Where each column starts, in epoch milliseconds; a column is one timeline bucket. */
  columns: number[];
  bucketMs: number;
}

/**
 * The `limit` addresses with the most events, each with its hourly counts folded into the
 * window's buckets. The rows follow the source IP facet, so the heatmap and the top source IPs
 * name the same addresses in the same order.
 */
export function activityHeatmap(
  bySrcIp: Readonly<Record<string, number>> | undefined,
  srcIpOverTime:
    Readonly<Record<string, readonly { start?: string; count?: number }[]>> | undefined,
  window: TimelineWindow,
  limit = TOP_ENTRIES,
): ActivityHeatmap {
  const rows = topEntries(bySrcIp, limit).map(({ key, count }) => ({
    ip: key,
    total: count,
    cells: timelineBuckets(srcIpOverTime?.[key] ?? [], window),
  }));
  const columns = Array.from(
    { length: Math.ceil((window.to - window.from) / window.bucketMs) },
    (_, i) => window.from + i * window.bucketMs,
  );
  return { rows, columns, bucketMs: window.bucketMs };
}

/** The fullest cell and its address; undefined when every cell is empty. */
export function peakCell(
  heatmap: ActivityHeatmap,
): { ip: string; start: number; count: number } | undefined {
  let peak: { ip: string; start: number; count: number } | undefined;
  for (const row of heatmap.rows) {
    for (const cell of row.cells) {
      if (cell.count > (peak?.count ?? 0)) peak = { ip: row.ip, ...cell };
    }
  }
  return peak;
}

/** How many of a row's cells have events. */
export function activeCells(row: HeatmapRow): number {
  return row.cells.filter((cell) => cell.count > 0).length;
}

/** A band of the colour scale: the cells holding `from` to `to` events, both included. */
export interface DensityLevel {
  from: number;
  to: number;
}

/** How many colours the scale has at most. */
export const DENSITY_STEPS = 5;

/** The largest of 1, 2 and 5 times a power of ten that is no larger than `value` (≥ 1). */
function niceFloor(value: number): number {
  const power = 10 ** Math.floor(Math.log10(value));
  const [nice] = [5, 2, 1].filter((step) => step * power <= value);
  return nice * power;
}

/**
 * The colour bands for cells holding up to `max` events. A handful of addresses usually dwarfs
 * the rest, so the bands grow geometrically (1, 2–9, 10–49, …) rather than evenly: on an even
 * scale one scanner would leave every other cell the palest colour. Bounds are rounded to 1, 2
 * and 5 times a power of ten so the legend reads easily; a small `max` gets a band per count.
 */
export function densityLevels(max: number, steps = DENSITY_STEPS): DensityLevel[] {
  if (!(max >= 1)) return [];
  const starts: number[] = [];
  for (let i = 0; i < steps; i++) {
    const start = max <= steps ? i + 1 : i === 0 ? 1 : niceFloor(max ** (i / steps));
    if (start > max) break;
    if (start > (starts.at(-1) ?? 0)) starts.push(start);
  }
  return starts.map((from, i) => ({ from, to: i + 1 < starts.length ? starts[i + 1] - 1 : max }));
}

/**
 * Which of `colors` (palest first) each of `levels` bands takes: spread over the whole ramp,
 * always ending on the darkest, so the fullest cells look the same however many bands there are.
 */
export function levelColors<T>(levels: number, colors: readonly T[]): T[] {
  return Array.from(
    { length: levels },
    (_, i) => colors[Math.max(0, Math.ceil(((i + 1) * colors.length) / levels) - 1)],
  );
}

/** "1", "2–9". */
export function formatLevel({ from, to }: DensityLevel, format: (n: number) => string): string {
  return from === to ? format(from) : `${format(from)}–${format(to)}`;
}

const hourFormat = new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' });
const dayFormat = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short' });
const weekdayFormat = new Intl.DateTimeFormat(undefined, { weekday: 'short', day: 'numeric' });

/**
 * The label under the column starting at `start`, or null for a column left unlabelled. Hourly
 * columns are labelled every three hours, with the date at midnight; coarser ones only at
 * midnight, every day for 3-hour columns and every fifth day for 12-hour ones.
 */
export function columnLabel(start: number, bucketMs: number): string | null {
  const date = new Date(start);
  const midnight = date.getHours() === 0 && date.getMinutes() === 0;
  if (bucketMs < 3 * HOUR_MS) {
    if (midnight) return dayFormat.format(date);
    return date.getHours() % 3 === 0 && date.getMinutes() === 0 ? hourFormat.format(date) : null;
  }
  if (!midnight) return null;
  if (bucketMs < 12 * HOUR_MS) return weekdayFormat.format(date);
  // Days counted in local time, so the labelled days stay put as the window slides.
  const day = Math.round((start - date.getTimezoneOffset() * 60_000) / DAY_MS);
  return day % 5 === 0 ? dayFormat.format(date) : null;
}
