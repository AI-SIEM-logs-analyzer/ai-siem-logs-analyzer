// The alerts page's filters, read from and written to the URL like the events page's, and the
// drill-down from an alert to the events behind it. Kept free of React so it is tested alone.

import type { components } from '@/api/schema';
import {
  NO_FILTERS,
  SEVERITIES,
  withFilterValue,
  type DrillField,
  type EventFilters,
  type Severity,
} from '@/lib/event-filters';

export type AlertStatus = components['schemas']['AlertStatus'];
type Alert = components['schemas']['AlertResponse'];

/** The triage statuses, in the order an alert usually moves through them. */
export const ALERT_STATUSES: readonly AlertStatus[] = [
  'NEW',
  'IN_PROGRESS',
  'RESOLVED',
  'FALSE_POSITIVE',
];

export const ALERT_STATUS_LABELS: Record<AlertStatus, string> = {
  NEW: 'New',
  IN_PROGRESS: 'In progress',
  RESOLVED: 'Resolved',
  FALSE_POSITIVE: 'False positive',
};

export interface AlertFilters {
  severity: Severity[];
  status: AlertStatus[];
  /** Zero-based page of the listing. */
  page: number;
}

export const NO_ALERT_FILTERS: AlertFilters = { severity: [], status: [], page: 0 };

function isSeverity(value: string): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value);
}

function isAlertStatus(value: string): value is AlertStatus {
  return (ALERT_STATUSES as readonly string[]).includes(value);
}

/** The filters `params` describe; a value the backend would refuse is dropped, not sent. */
export function parseAlertFilters(params: URLSearchParams): AlertFilters {
  const page = Number(params.get('page') ?? 1) - 1;
  return {
    severity: [...new Set(params.getAll('severity').map((s) => s.toUpperCase()))].filter(
      isSeverity,
    ),
    status: [...new Set(params.getAll('status').map((s) => s.toUpperCase()))].filter(isAlertStatus),
    page: Number.isSafeInteger(page) && page > 0 ? page : 0,
  };
}

/** The URL parameters for `filters`; the page is one-based there, and left out on the first. */
export function alertFiltersToParams(filters: AlertFilters): URLSearchParams {
  const params = new URLSearchParams();
  for (const severity of filters.severity) params.append('severity', severity);
  for (const status of filters.status) params.append('status', status);
  if (filters.page > 0) params.set('page', String(filters.page + 1));
  return params;
}

/** `values` with `value` added, or taken out if it was there. */
export function toggle<T>(values: readonly T[], value: T): T[] {
  return values.includes(value) ? values.filter((v) => v !== value) : [...values, value];
}

/** The group-by fields the events page can filter on, by their lower-cased rule name. */
const DRILL_FIELDS: Readonly<Record<string, DrillField>> = {
  srcip: 'srcIp',
  status: 'status',
  severity: 'severity',
  sourceid: 'sourceId',
};

export interface AlertEvents {
  filters: EventFilters;
  /** Group-by fields the events page cannot filter on, so the window shows more than the group. */
  unfiltered: string[];
}

/**
 * Every event in `alert`'s window, oldest first. The window's end is the newest event's time and
 * the search's `to` is exclusive, so it is pushed a millisecond on. An alert without a window
 * (raised by a model) spans its triggering event alone.
 */
export function alertWindowFilters(alert: Alert): EventFilters {
  const start = alert.windowStart ?? alert.trigger?.occurredAt;
  const end = alert.windowEnd ?? alert.trigger?.occurredAt;
  return {
    ...NO_FILTERS,
    range: start || end ? 'custom' : 'all',
    ...(start && { from: new Date(start).toISOString() }),
    ...(end && { to: new Date(Date.parse(end) + 1).toISOString() }),
    order: 'asc',
  };
}

/**
 * The events behind `alert`: its window, narrowed to the group its rule fired for. An alert
 * raised on one event (no group, one event in the window) is narrowed to that event's source as
 * well, which leaves the window on little but the event.
 */
export function alertEvents(alert: Alert): AlertEvents {
  let filters = alertWindowFilters(alert);
  const unfiltered: string[] = [];
  const group = Object.entries(alert.groupKey ?? {});
  for (const [key, value] of group) {
    const field = DRILL_FIELDS[key.toLowerCase()];
    if (field && (typeof value === 'string' || typeof value === 'number')) {
      filters = withFilterValue(filters, field, value);
    } else {
      unfiltered.push(key);
    }
  }
  if (group.length === 0 && (alert.eventCount ?? 1) <= 1 && alert.trigger?.sourceId) {
    filters = withFilterValue(filters, 'sourceId', alert.trigger.sourceId);
  }
  return { filters, unfiltered };
}

/** A group key's value as text: a string as it is, anything else as JSON. */
export function groupValueText(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value);
}
