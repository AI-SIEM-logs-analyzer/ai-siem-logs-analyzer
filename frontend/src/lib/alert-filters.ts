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

  technique: string[];

  tactic: string[];

  page: number;
}

export const NO_ALERT_FILTERS: AlertFilters = {
  severity: [],
  status: [],
  technique: [],
  tactic: [],
  page: 0,
};

const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/;
const TACTIC_ID = /^TA\d{4}$/;

function attackIds(params: URLSearchParams, name: string, format: RegExp): string[] {
  return [...new Set(params.getAll(name).map((v) => v.trim().toUpperCase()))].filter((v) =>
    format.test(v),
  );
}

export function hasAlertFilters(filters: AlertFilters): boolean {
  return (
    filters.severity.length > 0 ||
    filters.status.length > 0 ||
    filters.technique.length > 0 ||
    filters.tactic.length > 0
  );
}

function isSeverity(value: string): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value);
}

function isAlertStatus(value: string): value is AlertStatus {
  return (ALERT_STATUSES as readonly string[]).includes(value);
}

export function parseAlertFilters(params: URLSearchParams): AlertFilters {
  const page = Number(params.get('page') ?? 1) - 1;
  return {
    severity: [...new Set(params.getAll('severity').map((s) => s.toUpperCase()))].filter(
      isSeverity,
    ),
    status: [...new Set(params.getAll('status').map((s) => s.toUpperCase()))].filter(isAlertStatus),
    technique: attackIds(params, 'technique', TECHNIQUE_ID),
    tactic: attackIds(params, 'tactic', TACTIC_ID),
    page: Number.isSafeInteger(page) && page > 0 ? page : 0,
  };
}

export function alertFiltersToParams(filters: AlertFilters): URLSearchParams {
  const params = new URLSearchParams();
  for (const severity of filters.severity) params.append('severity', severity);
  for (const status of filters.status) params.append('status', status);
  for (const technique of filters.technique) params.append('technique', technique);
  for (const tactic of filters.tactic) params.append('tactic', tactic);
  if (filters.page > 0) params.set('page', String(filters.page + 1));
  return params;
}

export function toggle<T>(values: readonly T[], value: T): T[] {
  return values.includes(value) ? values.filter((v) => v !== value) : [...values, value];
}

const DRILL_FIELDS: Readonly<Record<string, DrillField>> = {
  srcip: 'srcIp',
  status: 'status',
  severity: 'severity',
  sourceid: 'sourceId',
};

export interface AlertEvents {
  filters: EventFilters;

  unfiltered: string[];
}

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

export function groupValueText(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value);
}
