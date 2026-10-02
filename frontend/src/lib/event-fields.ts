// How an event's parsed fields read on screen: the table's columns pick single fields, the
// details panel lays every field out in groups. Kept free of React so it is tested alone.

import type { DrillField } from '@/lib/event-filters';

/** The parsed fields of one hit, as /api/events/search returns them (camelCase). */
export type EventFields = Readonly<Record<string, unknown>>;

const dateTime = new Intl.DateTimeFormat(undefined, {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
});

/** An event time in the reader's locale and zone, to the second; the ISO text if unparseable. */
export function formatEventTime(iso: string | undefined): string {
  if (!iso) return '—';
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : dateTime.format(date);
}

/** A field as text, or undefined when the event does not carry it (or carries an object). */
export function fieldText(fields: EventFields | undefined, key: string): string | undefined {
  const value = fields?.[key];
  if (typeof value === 'string') return value || undefined;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return undefined;
}

export interface FieldRow {
  key: string;
  label: string;
  value: string;
  /** The filter a click on the value adds, for the fields the search can filter on. */
  drill?: DrillField;
  /** Addresses, paths and versions read better in a fixed-width face. */
  mono?: boolean;
}

export interface FieldGroup {
  title: string;
  rows: FieldRow[];
}

interface FieldSpec {
  label: string;
  drill?: DrillField;
  mono?: boolean;
  format?: (value: unknown) => string;
}

const bytes = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });

/** The fields the backend names, in the order and groups the details panel shows them. */
const GROUPS: readonly { title: string; fields: Readonly<Record<string, FieldSpec>> }[] = [
  {
    title: 'Origin',
    fields: {
      host: { label: 'Host', mono: true },
      format: { label: 'Format' },
      user: { label: 'User', mono: true },
      srcIp: { label: 'Source IP', drill: 'srcIp', mono: true },
      srcPort: { label: 'Source port', mono: true },
    },
  },
  {
    title: 'HTTP request',
    fields: {
      method: { label: 'Method', mono: true },
      path: { label: 'Path', mono: true },
      protocol: { label: 'Protocol', mono: true },
      status: { label: 'Status', drill: 'status', mono: true },
      bytes: { label: 'Bytes', format: (value) => bytes.format(Number(value)) },
      referrer: { label: 'Referrer', mono: true },
      userAgent: { label: 'User-Agent', mono: true },
    },
  },
  {
    title: 'Location',
    fields: {
      geoCountryName: { label: 'Country' },
      geoCountryIso: { label: 'Country code', mono: true },
      geoCity: { label: 'City' },
      geoLatitude: { label: 'Latitude', mono: true },
      geoLongitude: { label: 'Longitude', mono: true },
      geoAsn: { label: 'AS number', mono: true, format: (value) => `AS${String(value)}` },
      geoAsOrg: { label: 'AS organisation' },
    },
  },
  {
    title: 'Client',
    fields: {
      uaBrowser: { label: 'Browser' },
      uaBrowserVersion: { label: 'Browser version', mono: true },
      uaOs: { label: 'Operating system' },
      uaOsVersion: { label: 'OS version', mono: true },
      uaDeviceClass: { label: 'Device class' },
      uaAgentClass: { label: 'Agent class' },
      uaBot: { label: 'Bot', format: (value) => (value === true ? 'Yes' : 'No') },
    },
  },
];

/** Turns `geoCountryIso` into "Geo country iso", for a field the backend adds later. */
function labelFor(key: string): string {
  const words = key.replace(/([a-z\d])([A-Z])/g, '$1 $2').toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function display(value: unknown): string | undefined {
  if (typeof value === 'string') return value || undefined;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (value === null || value === undefined) return undefined;
  return JSON.stringify(value);
}

/**
 * Every field the event carries, in groups; empty groups are left out. Fields the groups do
 * not name land under "Other fields", so nothing the backend sends is hidden.
 */
export function fieldGroups(fields: EventFields | undefined): FieldGroup[] {
  const seen = new Set<string>();
  const groups: FieldGroup[] = [];
  for (const group of GROUPS) {
    const rows: FieldRow[] = [];
    for (const [key, spec] of Object.entries(group.fields)) {
      seen.add(key);
      const raw = fields?.[key];
      const value = display(raw);
      if (value === undefined) continue;
      rows.push({
        key,
        label: spec.label,
        value: spec.format ? spec.format(raw) : value,
        ...(spec.drill && { drill: spec.drill }),
        ...(spec.mono && { mono: true }),
      });
    }
    if (rows.length > 0) groups.push({ title: group.title, rows });
  }

  const other: FieldRow[] = [];
  for (const [key, raw] of Object.entries(fields ?? {})) {
    const value = display(raw);
    if (seen.has(key) || value === undefined) continue;
    other.push({ key, label: labelFor(key), value });
  }
  other.sort((a, b) => a.label.localeCompare(b.label));
  if (other.length > 0) groups.push({ title: 'Other fields', rows: other });
  return groups;
}
