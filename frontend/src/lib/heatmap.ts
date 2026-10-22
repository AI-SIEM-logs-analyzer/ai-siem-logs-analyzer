import { TOP_ENTRIES, topEntries } from '@/lib/facets';
import { timelineBuckets, type TimelineBucket, type TimelineWindow } from '@/lib/timeline';

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

export interface HeatmapRow {
  ip: string;

  total: number;

  cells: TimelineBucket[];
}

export interface ActivityHeatmap {
  rows: HeatmapRow[];

  columns: number[];
  bucketMs: number;
}

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

export function activeCells(row: HeatmapRow): number {
  return row.cells.filter((cell) => cell.count > 0).length;
}

export interface DensityLevel {
  from: number;
  to: number;
}

export const DENSITY_STEPS = 5;

function niceFloor(value: number): number {
  const power = 10 ** Math.floor(Math.log10(value));
  const [nice] = [5, 2, 1].filter((step) => step * power <= value);
  return nice * power;
}

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

export function levelColors<T>(levels: number, colors: readonly T[]): T[] {
  return Array.from(
    { length: levels },
    (_, i) => colors[Math.max(0, Math.ceil(((i + 1) * colors.length) / levels) - 1)],
  );
}

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
