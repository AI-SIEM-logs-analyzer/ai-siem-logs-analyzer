import {
  alertEvents,
  alertFiltersToParams,
  alertWindowFilters,
  groupValueText,
  hasAlertFilters,
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
    expect(filters).toEqual({
      severity: ['CRITICAL'],
      status: ['NEW'],
      technique: [],
      tactic: [],
      page: 2,
    });
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
      technique: [],
      tactic: [],
      page: 1,
    });
    expect(params.toString()).toBe('severity=CRITICAL&severity=ERROR&status=IN_PROGRESS&page=2');
    expect(parseAlertFilters(params)).toEqual({
      severity: ['CRITICAL', 'ERROR'],
      status: ['IN_PROGRESS'],
      technique: [],
      tactic: [],
      page: 1,
    });
  });

  it('reads ATT&CK techniques and tactics, upper-cased, and drops malformed ones', () => {
    const filters = parseAlertFilters(
      new URLSearchParams(
        'technique=t1110&technique=T1110.001&technique=T1110&technique=T12&tactic=ta0006&tactic=TA6',
      ),
    );
    expect(filters.technique).toEqual(['T1110', 'T1110.001']);
    expect(filters.tactic).toEqual(['TA0006']);
  });

  it('writes ATT&CK filters back before the page', () => {
    expect(
      alertFiltersToParams({
        ...NO_ALERT_FILTERS,
        technique: ['T1110'],
        tactic: ['TA0006'],
        page: 1,
      }).toString(),
    ).toBe('technique=T1110&tactic=TA0006&page=2');
  });

  it('tells a filtered list from the plain one', () => {
    expect(hasAlertFilters(NO_ALERT_FILTERS)).toBe(false);
    expect(hasAlertFilters({ ...NO_ALERT_FILTERS, page: 3 })).toBe(false);
    expect(hasAlertFilters({ ...NO_ALERT_FILTERS, tactic: ['TA0006'] })).toBe(true);
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
