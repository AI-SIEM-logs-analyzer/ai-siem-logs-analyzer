// The dashboard timeline's time arithmetic: which window a range covers, and how the backend's
// hourly counts fold into the buckets drawn. Kept free of React and ECharts so it is tested alone.

const HOUR_MS = 60 * 60 * 1000;

export const TIMELINE_RANGES = {
  '24h': { label: 'Last 24 hours', per: 'hour', durationMs: 24 * HOUR_MS, bucketMs: HOUR_MS },
  '7d': {
    label: 'Last 7 days',
    per: '3 hours',
    durationMs: 7 * 24 * HOUR_MS,
    bucketMs: 3 * HOUR_MS,
  },
  '30d': {
    label: 'Last 30 days',
    per: '12 hours',
    durationMs: 30 * 24 * HOUR_MS,
    bucketMs: 12 * HOUR_MS,
  },
} as const;

export type TimelineRange = keyof typeof TIMELINE_RANGES;

export const DEFAULT_TIMELINE_RANGE: TimelineRange = '24h';

export function isTimelineRange(value: string | null | undefined): value is TimelineRange {
  return value != null && Object.hasOwn(TIMELINE_RANGES, value);
}

/** A half-open interval [from, to) in epoch milliseconds, cut into buckets of `bucketMs`. */
export interface TimelineWindow {
  from: number;
  to: number;
  bucketMs: number;
}

export interface TimelineBucket {
  /** Epoch milliseconds; the bucket covers [start, start + bucketMs). */
  start: number;
  count: number;
}

/**
 * The window `range` covers at `now`: it ends at the bucket boundary after `now`, so the last
 * bucket is the one still filling, and starts one range earlier.
 *
 * Boundaries fall on the hours the backend counts by (UTC hours) and on multiples of the
 * bucket in local time, so 12-hour buckets start at midnight and noon rather than wherever the
 * UTC offset puts them. A half-hour offset is rounded to the hour: a bucket must never split
 * one of the backend's.
 */
export function timelineWindow(range: TimelineRange, now: number): TimelineWindow {
  const { durationMs, bucketMs } = TIMELINE_RANGES[range];
  const offset = Math.round(-new Date(now).getTimezoneOffset() / 60) * HOUR_MS;
  const to = Math.floor((now + offset) / bucketMs) * bucketMs - offset + bucketMs;
  return { from: to - durationMs, to, bucketMs };
}

/**
 * Folds hourly counts into the window's buckets, with a zero for every bucket nothing fell in
 * (the backend sends only the hours that have events). Counts outside the window are dropped.
 */
export function timelineBuckets(
  hourly: readonly { start?: string; count?: number }[],
  { from, to, bucketMs }: TimelineWindow,
): TimelineBucket[] {
  const buckets = Array.from({ length: Math.ceil((to - from) / bucketMs) }, (_, i) => ({
    start: from + i * bucketMs,
    count: 0,
  }));
  for (const { start, count } of hourly) {
    const time = start ? Date.parse(start) : NaN;
    if (!(time >= from && time < to)) continue;
    buckets[Math.floor((time - from) / bucketMs)].count += count ?? 0;
  }
  return buckets;
}

const bucketFormat = new Intl.DateTimeFormat(undefined, {
  weekday: 'short',
  day: 'numeric',
  month: 'short',
  hour: '2-digit',
  minute: '2-digit',
});

/** "Tue, 30 Sep, 14:00 – 15:00", in the reader's locale and time zone. */
export function formatBucket(start: number, bucketMs: number): string {
  return bucketFormat.formatRange(start, start + bucketMs);
}

/** The bucket with the most events, the earliest on a tie; undefined when all are empty. */
export function peakBucket(buckets: readonly TimelineBucket[]): TimelineBucket | undefined {
  let peak: TimelineBucket | undefined;
  for (const bucket of buckets) {
    if (bucket.count > (peak?.count ?? 0)) peak = bucket;
  }
  return peak;
}
