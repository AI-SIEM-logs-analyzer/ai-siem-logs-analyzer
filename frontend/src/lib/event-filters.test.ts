import {
  activeFilterCount,
  eventFiltersToParams,
  eventSearchQuery,
  hasFilterValue,
  NO_FILTERS,
  parseEventFilters,
  splitList,
  withFilterValue,
} from '@/lib/event-filters';

const NOW = Date.parse('2026-09-30T14:25:00Z');

describe('parseEventFilters', () => {
  it('reads every filter from the URL', () => {
    const filters = parseEventFilters(
      new URLSearchParams(
        'range=7d&q=failed+login&substring=wp-login&severity=error&severity=CRITICAL' +
          '&srcIp=10.0.0.0/8&srcIp=203.0.113.7&status=5XX&status=404&sourceId=3&order=asc',
      ),
    );
    expect(filters).toEqual({
      range: '7d',
      q: 'failed login',
      substring: 'wp-login',
      severity: ['ERROR', 'CRITICAL'],
      srcIp: ['10.0.0.0/8', '203.0.113.7'],
      status: ['5xx', '404'],
      sourceId: [3],
      order: 'asc',
    });
  });

  it('drops what the backend would refuse and falls back to the defaults', () => {
    const filters = parseEventFilters(
      new URLSearchParams(
        'range=1y&severity=LOUD&status=999&status=abc&status=200&sourceId=-1&sourceId=x&order=sideways&from=yesterday',
      ),
    );
    expect(filters).toEqual({ ...NO_FILTERS, status: ['200'] });
  });

  it('round-trips through the URL, leaving defaults out', () => {
    expect(eventFiltersToParams(NO_FILTERS).toString()).toBe('');
    const filters = {
      ...NO_FILTERS,
      range: 'custom' as const,
      from: '2026-09-01T00:00:00.000Z',
      to: '2026-09-02T00:00:00.000Z',
      severity: ['WARNING' as const],
      srcIp: ['192.0.2.1'],
      sourceId: [4],
    };
    expect(parseEventFilters(eventFiltersToParams(filters))).toEqual(filters);
  });
});

describe('eventSearchQuery', () => {
  it('ends a relative range at now', () => {
    expect(eventSearchQuery({ ...NO_FILTERS, range: '1h', status: ['5xx'] }, NOW)).toEqual({
      from: '2026-09-30T13:25:00.000Z',
      to: '2026-09-30T14:25:00.000Z',
      status: ['5xx'],
      order: 'desc',
    });
  });

  it('leaves all time unbounded and a custom range as given', () => {
    expect(eventSearchQuery({ ...NO_FILTERS, range: 'all' }, NOW)).toEqual({ order: 'desc' });
    expect(
      eventSearchQuery(
        { ...NO_FILTERS, range: 'custom', from: '2026-09-01T00:00:00Z', order: 'asc' },
        NOW,
      ),
    ).toEqual({ from: '2026-09-01T00:00:00.000Z', order: 'asc' });
  });
});

describe('drill-down', () => {
  it('adds a value once, and only a valid one', () => {
    const once = withFilterValue(NO_FILTERS, 'srcIp', '203.0.113.7');
    expect(once.srcIp).toEqual(['203.0.113.7']);
    expect(withFilterValue(once, 'srcIp', '203.0.113.7')).toBe(once);
    expect(withFilterValue(NO_FILTERS, 'status', 404).status).toEqual(['404']);
    expect(withFilterValue(NO_FILTERS, 'status', 'teapot')).toBe(NO_FILTERS);
    expect(withFilterValue(NO_FILTERS, 'severity', 'warning').severity).toEqual(['WARNING']);
    expect(withFilterValue(NO_FILTERS, 'sourceId', '7').sourceId).toEqual([7]);
  });

  it('knows what is already filtered on', () => {
    const filters = { ...NO_FILTERS, status: ['5xx'], severity: ['ERROR' as const] };
    expect(hasFilterValue(filters, 'status', '5XX')).toBe(true);
    expect(hasFilterValue(filters, 'status', '500')).toBe(false);
    expect(hasFilterValue(filters, 'severity', 'error')).toBe(true);
    expect(activeFilterCount(filters)).toBe(2);
  });
});

describe('splitList', () => {
  it('splits on commas and whitespace, dropping blanks and repeats', () => {
    expect(splitList(' 10.0.0.1, 10.0.0.2  10.0.0.1,,')).toEqual(['10.0.0.1', '10.0.0.2']);
  });
});
