import { isTimelineRange, peakBucket, timelineBuckets, timelineWindow } from '@/lib/timeline';

const HOUR = 60 * 60 * 1000;
const at = (iso: string) => Date.parse(iso);

describe('timelineWindow', () => {
  // Offsets come from the machine running the tests, so the expectations are built from it too.
  const offset = (now: number) => Math.round(-new Date(now).getTimezoneOffset() / 60) * HOUR;

  it('ends at the hour after now and spans the range', () => {
    const now = at('2026-09-30T14:25:00Z');
    const window = timelineWindow('24h', now);

    expect(window.to).toBe(at('2026-09-30T15:00:00Z'));
    expect(window.to - window.from).toBe(24 * HOUR);
    expect(window.bucketMs).toBe(HOUR);
  });

  it('puts a moment on the hour in the bucket it starts', () => {
    const now = at('2026-09-30T14:00:00Z');

    expect(timelineWindow('24h', now).to).toBe(at('2026-09-30T15:00:00Z'));
  });

  it.each(['7d', '30d'] as const)(
    'aligns %s buckets to local multiples of their size, on UTC hours',
    (range) => {
      const now = at('2026-09-30T14:25:00Z');
      const window = timelineWindow(range, now);

      expect(window.to).toBeGreaterThan(now);
      expect(window.to - window.bucketMs).toBeLessThanOrEqual(now);
      expect((window.to + offset(now)) % window.bucketMs).toBe(0);
      expect(window.from % HOUR).toBe(0);
    },
  );
});

describe('timelineBuckets', () => {
  const window = {
    from: at('2026-09-30T00:00:00Z'),
    to: at('2026-09-30T12:00:00Z'),
    bucketMs: 3 * HOUR,
  };

  it('fills the hours the backend left out with zeros', () => {
    expect(timelineBuckets([], window)).toEqual([
      { start: at('2026-09-30T00:00:00Z'), count: 0 },
      { start: at('2026-09-30T03:00:00Z'), count: 0 },
      { start: at('2026-09-30T06:00:00Z'), count: 0 },
      { start: at('2026-09-30T09:00:00Z'), count: 0 },
    ]);
  });

  it('adds up the hours of each bucket and drops the ones outside the window', () => {
    const buckets = timelineBuckets(
      [
        { start: '2026-09-29T23:00:00Z', count: 99 },
        { start: '2026-09-30T00:00:00Z', count: 1 },
        { start: '2026-09-30T02:00:00Z', count: 2 },
        { start: '2026-09-30T03:00:00Z', count: 4 },
        { start: '2026-09-30T11:00:00Z', count: 8 },
        { start: '2026-09-30T12:00:00Z', count: 99 },
        { count: 99 },
      ],
      window,
    );

    expect(buckets.map((bucket) => bucket.count)).toEqual([3, 4, 0, 8]);
  });
});

describe('peakBucket', () => {
  it('is the earliest of the largest buckets', () => {
    const buckets = [
      { start: 0, count: 1 },
      { start: 1, count: 5 },
      { start: 2, count: 5 },
    ];

    expect(peakBucket(buckets)).toBe(buckets[1]);
  });

  it('is undefined when nothing happened', () => {
    expect(peakBucket([{ start: 0, count: 0 }])).toBeUndefined();
  });
});

describe('isTimelineRange', () => {
  it('accepts the offered ranges only', () => {
    expect(isTimelineRange('7d')).toBe(true);
    expect(isTimelineRange('1y')).toBe(false);
    expect(isTimelineRange('toString')).toBe(false);
    expect(isTimelineRange(null)).toBe(false);
  });
});
