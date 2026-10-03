import {
  activeCells,
  activityHeatmap,
  columnLabel,
  densityLevels,
  formatLevel,
  levelColors,
  peakCell,
} from '@/lib/heatmap';

const HOUR = 60 * 60 * 1000;
const at = (iso: string) => Date.parse(iso);

describe('activityHeatmap', () => {
  const window = {
    from: at('2026-09-30T00:00:00Z'),
    to: at('2026-09-30T06:00:00Z'),
    bucketMs: 3 * HOUR,
  };

  it('gives the busiest addresses a row each, busiest first, folded into the buckets', () => {
    const heatmap = activityHeatmap(
      { '198.51.100.2': 3, '203.0.113.7': 40 },
      {
        '203.0.113.7': [
          { start: '2026-09-30T01:00:00Z', count: 30 },
          { start: '2026-09-30T02:00:00Z', count: 10 },
        ],
        '198.51.100.2': [{ start: '2026-09-30T04:00:00Z', count: 3 }],
      },
      window,
    );

    expect(heatmap.columns).toEqual([window.from, window.from + 3 * HOUR]);
    expect(heatmap.bucketMs).toBe(3 * HOUR);
    expect(heatmap.rows).toEqual([
      {
        ip: '203.0.113.7',
        total: 40,
        cells: [
          { start: window.from, count: 40 },
          { start: window.from + 3 * HOUR, count: 0 },
        ],
      },
      {
        ip: '198.51.100.2',
        total: 3,
        cells: [
          { start: window.from, count: 0 },
          { start: window.from + 3 * HOUR, count: 3 },
        ],
      },
    ]);
  });

  it('keeps an address whose histogram is missing, as an empty row', () => {
    const heatmap = activityHeatmap({ '203.0.113.7': 5 }, undefined, window);

    expect(heatmap.rows[0].cells.map((cell) => cell.count)).toEqual([0, 0]);
    expect(activeCells(heatmap.rows[0])).toBe(0);
    expect(peakCell(heatmap)).toBeUndefined();
  });

  it('shows at most `limit` addresses', () => {
    const bySrcIp = Object.fromEntries(
      Array.from({ length: 20 }, (_, i) => [`10.0.0.${i}`, i + 1]),
    );

    expect(activityHeatmap(bySrcIp, {}, window).rows).toHaveLength(10);
    expect(activityHeatmap(bySrcIp, {}, window, 3).rows.map((row) => row.ip)).toEqual([
      '10.0.0.19',
      '10.0.0.18',
      '10.0.0.17',
    ]);
  });

  it('finds the fullest cell, the earliest on a tie', () => {
    const heatmap = activityHeatmap(
      { a: 4, b: 4 },
      {
        a: [{ start: '2026-09-30T04:00:00Z', count: 4 }],
        b: [{ start: '2026-09-30T00:00:00Z', count: 4 }],
      },
      window,
    );

    expect(peakCell(heatmap)).toEqual({ ip: 'a', start: window.from + 3 * HOUR, count: 4 });
  });
});

describe('densityLevels', () => {
  it('has no bands when every cell is empty', () => {
    expect(densityLevels(0)).toEqual([]);
  });

  it('gives each count its own band when there are few', () => {
    expect(densityLevels(3)).toEqual([
      { from: 1, to: 1 },
      { from: 2, to: 2 },
      { from: 3, to: 3 },
    ]);
  });

  it('grows the bands geometrically, on round bounds', () => {
    expect(densityLevels(1000)).toEqual([
      { from: 1, to: 1 },
      { from: 2, to: 9 },
      { from: 10, to: 49 },
      { from: 50, to: 199 },
      { from: 200, to: 1000 },
    ]);
  });

  it('covers every count from 1 to max without a gap or an overlap', () => {
    for (const max of [6, 7, 12, 99, 250, 12_345]) {
      const levels = densityLevels(max);
      expect(levels[0].from).toBe(1);
      expect(levels.at(-1)!.to).toBe(max);
      for (let i = 1; i < levels.length; i++) expect(levels[i].from).toBe(levels[i - 1].to + 1);
      expect(levels.length).toBeLessThanOrEqual(5);
    }
  });
});

describe('levelColors', () => {
  const ramp = ['c0', 'c1', 'c2', 'c3', 'c4'];

  it('uses the whole ramp for as many bands as colours', () => {
    expect(levelColors(5, ramp)).toEqual(ramp);
  });

  it('spreads fewer bands over the ramp, ending on the darkest', () => {
    expect(levelColors(1, ramp)).toEqual(['c4']);
    expect(levelColors(2, ramp)).toEqual(['c2', 'c4']);
    expect(levelColors(3, ramp)).toEqual(['c1', 'c3', 'c4']);
  });
});

describe('formatLevel', () => {
  it('names a band by its bounds, or by its one count', () => {
    expect(formatLevel({ from: 1, to: 1 }, String)).toBe('1');
    expect(formatLevel({ from: 2, to: 9 }, String)).toBe('2–9');
  });
});

describe('columnLabel', () => {
  // Local time, as the reader sees it: built from the machine running the tests.
  const local = (day: number, hour: number) => new Date(2026, 8, day, hour).getTime();

  it('labels hourly columns every three hours, with the date at midnight', () => {
    expect(columnLabel(local(30, 0), HOUR)).toMatch(/30/);
    expect(columnLabel(local(30, 3), HOUR)).not.toBeNull();
    expect(columnLabel(local(30, 4), HOUR)).toBeNull();
  });

  it('labels 3-hour columns once a day, at midnight', () => {
    expect(columnLabel(local(30, 0), 3 * HOUR)).toMatch(/30/);
    expect(columnLabel(local(30, 3), 3 * HOUR)).toBeNull();
  });

  it('labels 12-hour columns every fifth day', () => {
    const labelled = Array.from({ length: 10 }, (_, i) => local(10 + i, 0)).filter(
      (start) => columnLabel(start, 12 * HOUR) != null,
    );

    expect(labelled).toHaveLength(2);
    expect(labelled[1] - labelled[0]).toBeGreaterThanOrEqual(5 * 24 * HOUR - HOUR);
    expect(columnLabel(local(10, 12), 12 * HOUR)).toBeNull();
  });
});
