import {
  alertEvents,
  alertFiltersToParams,
  alertWindowFilters,
  groupValueText,
  NO_ALERT_FILTERS,
  parseAlertFilters,
  toggle,
} from '@/lib/alert-filters';
import { eventFiltersToParams } from '@/lib/event-filters';

const trigger = {
  eventId: 41,
  sourceId: 3,
  occurredAt: '2026-10-01T10:00:05Z',
  severity: 'WARNING' as const,
  message: 'POST /login 401',
};

describe('alert filters', () => {
  it('reads severities, statuses and a one-based page from the URL', () => {
    const filters = parseAlertFilters(
      new URLSearchParams('severity=critical&severity=CRITICAL&status=new&page=3'),
    );
    expect(filters).toEqual({ severity: ['CRITICAL'], status: ['NEW'], page: 2 });
  });

  it('drops what the backend would refuse', () => {
    expect(parseAlertFilters(new URLSearchParams('severity=URGENT&status=OPEN&page=-4'))).toEqual(
      NO_ALERT_FILTERS,
    );
    expect(parseAlertFilters(new URLSearchParams('page=two')).page).toBe(0);
  });

  it('writes the filters back, leaving the first page out', () => {
    expect(alertFiltersToParams(NO_ALERT_FILTERS).toString()).toBe('');
    const params = alertFiltersToParams({
      severity: ['CRITICAL', 'ERROR'],
      status: ['IN_PROGRESS'],
      page: 1,
    });
    expect(params.toString()).toBe('severity=CRITICAL&severity=ERROR&status=IN_PROGRESS&page=2');
    expect(parseAlertFilters(params)).toEqual({
      severity: ['CRITICAL', 'ERROR'],
      status: ['IN_PROGRESS'],
      page: 1,
    });
  });

  it('toggles a value in and out', () => {
    expect(toggle(['A'], 'B')).toEqual(['A', 'B']);
    expect(toggle(['A', 'B'], 'A')).toEqual(['B']);
  });
});

describe('alert drill-down', () => {
  it('narrows the rule window to the group the rule fired for, oldest first', () => {
    const { filters, unfiltered } = alertEvents({
      windowStart: '2026-10-01T10:00:00Z',
      windowEnd: '2026-10-01T10:00:05Z',
      eventCount: 6,
      groupKey: { srcIp: '10.0.0.7', status: 401 },
      trigger,
    });

    expect(unfiltered).toEqual([]);
    expect(eventFiltersToParams(filters).toString()).toBe(
      new URLSearchParams([
        ['range', 'custom'],
        ['from', '2026-10-01T10:00:00.000Z'],
        // The window's end is inclusive and the search's `to` is not.
        ['to', '2026-10-01T10:00:05.001Z'],
        ['srcIp', '10.0.0.7'],
        ['status', '401'],
        ['order', 'asc'],
      ]).toString(),
    );
  });

  it('names the group fields the events page cannot filter on', () => {
    const { filters, unfiltered } = alertEvents({
      windowStart: '2026-10-01T10:00:00Z',
      windowEnd: '2026-10-01T10:00:05Z',
      eventCount: 6,
      groupKey: { user: 'root', SRCIP: '10.0.0.7' },
      trigger,
    });
    expect(unfiltered).toEqual(['user']);
    expect(filters.srcIp).toEqual(['10.0.0.7']);
  });

  it('pins an alert raised on one event to that event and its source', () => {
    const { filters } = alertEvents({
      windowStart: trigger.occurredAt,
      windowEnd: trigger.occurredAt,
      eventCount: 1,
      trigger,
    });
    expect(filters).toMatchObject({
      range: 'custom',
      from: '2026-10-01T10:00:05.000Z',
      to: '2026-10-01T10:00:05.001Z',
      sourceId: [3],
    });
  });

  it('keeps every source for an ungrouped rule over many events', () => {
    const { filters } = alertEvents({
      windowStart: '2026-10-01T10:00:00Z',
      windowEnd: '2026-10-01T10:00:05Z',
      eventCount: 40,
      trigger,
    });
    expect(filters.sourceId).toEqual([]);
  });

  it('falls back to the triggering event when there is no window', () => {
    expect(alertWindowFilters({ trigger })).toMatchObject({
      from: '2026-10-01T10:00:05.000Z',
      to: '2026-10-01T10:00:05.001Z',
    });
    expect(alertWindowFilters({}).range).toBe('all');
  });

  it('shows a group value as text', () => {
    expect(groupValueText('10.0.0.7')).toBe('10.0.0.7');
    expect(groupValueText(401)).toBe('401');
    expect(groupValueText(['a'])).toBe('["a"]');
  });
});
