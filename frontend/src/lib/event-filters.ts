// The events page's filters: read from and written to the URL, so a reload, the back button or
// a shared link shows the same slice, and turned into the query /api/events/search takes.
// Kept free of React so it is tested alone.

import type { components, operations } from '@/api/schema';

export type Severity = components['schemas']['Severity'];
export type EventSearchQuery = NonNullable<operations['searchEvents']['parameters']['query']>;

const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;

/** The time ranges the filter bar offers, relative to when the search runs. */
export const EVENT_RANGES = {
  '15m': { label: 'Last 15 minutes', durationMs: 15 * MINUTE_MS },
  '1h': { label: 'Last hour', durationMs: HOUR_MS },
  '24h': { label: 'Last 24 hours', durationMs: 24 * HOUR_MS },
  '7d': { label: 'Last 7 days', durationMs: 7 * 24 * HOUR_MS },
  '30d': { label: 'Last 30 days', durationMs: 30 * 24 * HOUR_MS },
  all: { label: 'All time', durationMs: null },
  custom: { label: 'Custom range', durationMs: null },
} as const;

export type EventRange = keyof typeof EVENT_RANGES;

export const DEFAULT_EVENT_RANGE: EventRange = '24h';

export const SEVERITIES: readonly Severity[] = ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'];

/** Mirrors the backend's EventQuery bounds; the backend still has the final say. */
export const MAX_FILTER_VALUES = 50;
export const MAX_SUBSTRING_LENGTH = 256;

export type SortOrder = 'asc' | 'desc';

export interface EventFilters {
  range: EventRange;
  /** ISO instants, read only when `range` is `custom`; either may be left open. */
  from?: string;
  to?: string;
  /** Full-text search over the message. */
  q: string;
  /** Literal, case-insensitive substring of the raw line. */
  substring: string;
  severity: Severity[];
  /** Addresses or CIDR ranges. */
  srcIp: string[];
  /** Codes (404) or classes (5xx). */
  status: string[];
  sourceId: number[];
  order: SortOrder;
}

/** The filters a field can be narrowed by from a value on screen (drill-down). */
export type DrillField = 'severity' | 'srcIp' | 'status' | 'sourceId';

export const NO_FILTERS: EventFilters = {
  range: DEFAULT_EVENT_RANGE,
  q: '',
  substring: '',
  severity: [],
  srcIp: [],
  status: [],
  sourceId: [],
  order: 'desc',
};

export function isEventRange(value: string | null | undefined): value is EventRange {
  return value != null && Object.hasOwn(EVENT_RANGES, value);
}

function isSeverity(value: string): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value);
}

/** An HTTP status code (100–599) or class (1xx–5xx), as the backend's `status` filter takes. */
export function isStatusFilter(value: string): boolean {
  return /^[1-5](\d\d|xx)$/i.test(value);
}

function isInstant(value: string | null): value is string {
  return value != null && !Number.isNaN(Date.parse(value));
}

function unique<T>(values: Iterable<T>): T[] {
  return [...new Set(values)];
}

/**
 * Splits a list typed into one box: commas or whitespace separate the values, blanks and
 * repeats are dropped.
 */
export function splitList(text: string): string[] {
  return unique(
    text
      .split(/[\s,]+/)
      .map((value) => value.trim())
      .filter(Boolean),
  );
}

/**
 * The filters `params` describe. A value the backend would refuse (an unknown severity, a
 * status that is no code, an unparseable instant) is dropped rather than sent, so a mangled
 * link still opens on a page of events.
 */
export function parseEventFilters(params: URLSearchParams): EventFilters {
  const range = params.get('range');
  const from = params.get('from');
  const to = params.get('to');
  return {
    range: isEventRange(range) ? range : DEFAULT_EVENT_RANGE,
    ...(isInstant(from) && { from }),
    ...(isInstant(to) && { to }),
    q: params.get('q')?.trim() ?? '',
    substring: params.get('substring')?.slice(0, MAX_SUBSTRING_LENGTH) ?? '',
    severity: unique(params.getAll('severity').map((s) => s.toUpperCase())).filter(isSeverity),
    srcIp: unique(params.getAll('srcIp').map((ip) => ip.trim()))
      .filter(Boolean)
      .slice(0, MAX_FILTER_VALUES),
    status: unique(params.getAll('status').map((s) => s.trim().toLowerCase()))
      .filter(isStatusFilter)
      .slice(0, MAX_FILTER_VALUES),
    sourceId: unique(params.getAll('sourceId').map(Number)).filter(
      (id) => Number.isSafeInteger(id) && id > 0,
    ),
    order: params.get('order') === 'asc' ? 'asc' : 'desc',
  };
}

/** The URL parameters for `filters`; defaults are left out so a plain link stays plain. */
export function eventFiltersToParams(filters: EventFilters): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.range !== DEFAULT_EVENT_RANGE) params.set('range', filters.range);
  if (filters.range === 'custom') {
    if (filters.from) params.set('from', filters.from);
    if (filters.to) params.set('to', filters.to);
  }
  if (filters.q) params.set('q', filters.q);
  if (filters.substring) params.set('substring', filters.substring);
  for (const severity of filters.severity) params.append('severity', severity);
  for (const ip of filters.srcIp) params.append('srcIp', ip);
  for (const status of filters.status) params.append('status', status);
  for (const id of filters.sourceId) params.append('sourceId', String(id));
  if (filters.order !== 'desc') params.set('order', filters.order);
  return params;
}

/** The time window `filters` cover at `now`, as ISO instants; an open end is left out. */
export function eventWindow(filters: EventFilters, now: number): { from?: string; to?: string } {
  if (filters.range === 'custom') {
    return {
      ...(filters.from && { from: new Date(filters.from).toISOString() }),
      ...(filters.to && { to: new Date(filters.to).toISOString() }),
    };
  }
  const { durationMs } = EVENT_RANGES[filters.range];
  if (durationMs === null) return {};
  return { from: new Date(now - durationMs).toISOString(), to: new Date(now).toISOString() };
}

/**
 * The search for `filters`, with a relative range ending at `now`. The caller fixes `now` while
 * it pages, so every page of one search covers the same window.
 */
export function eventSearchQuery(filters: EventFilters, now: number): EventSearchQuery {
  return {
    ...eventWindow(filters, now),
    ...(filters.q && { q: filters.q }),
    ...(filters.substring && { substring: filters.substring }),
    ...(filters.severity.length > 0 && { severity: filters.severity }),
    ...(filters.srcIp.length > 0 && { srcIp: filters.srcIp }),
    ...(filters.status.length > 0 && { status: filters.status }),
    ...(filters.sourceId.length > 0 && { sourceId: filters.sourceId }),
    order: filters.order,
  };
}

/**
 * `filters` narrowed to events whose `field` is `value` as well — the drill-down from a value on
 * screen. A value already filtered on leaves the filters as they are.
 */
export function withFilterValue(
  filters: EventFilters,
  field: DrillField,
  value: string | number,
): EventFilters {
  switch (field) {
    case 'severity': {
      const severity = String(value).toUpperCase();
      if (!isSeverity(severity) || filters.severity.includes(severity)) return filters;
      return { ...filters, severity: [...filters.severity, severity] };
    }
    case 'srcIp': {
      const ip = String(value).trim();
      if (!ip || filters.srcIp.includes(ip)) return filters;
      return { ...filters, srcIp: [...filters.srcIp, ip].slice(0, MAX_FILTER_VALUES) };
    }
    case 'status': {
      const status = String(value).toLowerCase();
      if (!isStatusFilter(status) || filters.status.includes(status)) return filters;
      return { ...filters, status: [...filters.status, status].slice(0, MAX_FILTER_VALUES) };
    }
    case 'sourceId': {
      const id = Number(value);
      if (!Number.isSafeInteger(id) || id <= 0 || filters.sourceId.includes(id)) return filters;
      return { ...filters, sourceId: [...filters.sourceId, id] };
    }
  }
}

/** Whether `filters` already narrow `field` to `value`. */
export function hasFilterValue(
  filters: EventFilters,
  field: DrillField,
  value: string | number,
): boolean {
  switch (field) {
    case 'severity':
      return (filters.severity as string[]).includes(String(value).toUpperCase());
    case 'srcIp':
      return filters.srcIp.includes(String(value).trim());
    case 'status':
      return filters.status.includes(String(value).toLowerCase());
    case 'sourceId':
      return filters.sourceId.includes(Number(value));
  }
}

/** How many filters beyond the time range and the order are in effect. */
export function activeFilterCount(filters: EventFilters): number {
  return (
    (filters.q ? 1 : 0) +
    (filters.substring ? 1 : 0) +
    filters.severity.length +
    filters.srcIp.length +
    filters.status.length +
    filters.sourceId.length
  );
}
