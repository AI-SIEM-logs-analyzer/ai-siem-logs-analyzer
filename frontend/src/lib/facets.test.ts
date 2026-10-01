import {
  errorEventCount,
  formatShare,
  statusBreakdown,
  topEntries,
  TOP_ENTRIES,
} from '@/lib/facets';

describe('topEntries', () => {
  it('ranks the largest counts first and keeps the order of a tie', () => {
    expect(topEntries({ '10.0.0.2': 5, '10.0.0.1': 9, '10.0.0.3': 5 })).toEqual([
      { key: '10.0.0.1', count: 9 },
      { key: '10.0.0.2', count: 5 },
      { key: '10.0.0.3', count: 5 },
    ]);
  });

  it(`keeps the top ${TOP_ENTRIES} and drops empty counts`, () => {
    const counts = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`ip-${i}`, 20 - i]));
    counts.zero = 0;

    const top = topEntries(counts);

    expect(top).toHaveLength(TOP_ENTRIES);
    expect(top[0]).toEqual({ key: 'ip-0', count: 20 });
    expect(top.at(-1)).toEqual({ key: 'ip-9', count: 11 });
    expect(topEntries({ zero: 0 })).toEqual([]);
  });

  it('reads a missing facet as empty', () => {
    expect(topEntries(undefined)).toEqual([]);
  });
});

describe('statusBreakdown', () => {
  it('orders codes numerically and adds them up per class', () => {
    const breakdown = statusBreakdown({ '404': 30, '200': 60, '503': 5, '500': 5 });

    expect(breakdown.codes.map((code) => [code.code, code.statusClass])).toEqual([
      [200, '2xx'],
      [404, '4xx'],
      [500, '5xx'],
      [503, '5xx'],
    ]);
    expect(breakdown.total).toBe(100);
    expect(breakdown.classes).toEqual([
      { statusClass: '2xx', count: 60, share: 0.6 },
      { statusClass: '4xx', count: 30, share: 0.3 },
      { statusClass: '5xx', count: 10, share: 0.1 },
    ]);
  });

  it('leaves out what is not an HTTP status', () => {
    const breakdown = statusBreakdown({ '0': 3, '999': 2, abc: 1, '301': 4 });

    expect(breakdown.codes.map((code) => code.code)).toEqual([301]);
    expect(breakdown.total).toBe(4);
  });

  it('is empty without a facet', () => {
    expect(statusBreakdown(undefined)).toEqual({ codes: [], classes: [], total: 0 });
  });
});

describe('errorEventCount', () => {
  it('counts ERROR and CRITICAL only', () => {
    expect(errorEventCount({ INFO: 100, WARNING: 7, ERROR: 12, CRITICAL: 3 })).toBe(15);
    expect(errorEventCount(undefined)).toBe(0);
  });
});

describe('formatShare', () => {
  it('rounds to a tenth of a percent and never shows a real share as zero', () => {
    expect(formatShare(0.125)).toBe(
      new Intl.NumberFormat(undefined, { style: 'percent', maximumFractionDigits: 1 }).format(
        0.125,
      ),
    );
    expect(formatShare(0.00001)).toMatch(/^</);
    expect(formatShare(0)).not.toMatch(/^</);
  });
});
