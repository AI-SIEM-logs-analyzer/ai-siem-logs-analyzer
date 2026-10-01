// The dashboard's aggregate widgets: the search facets turned into what they draw. Kept free of
// React and ECharts so it is tested alone.

/** One value of a facet and how many events carried it. */
export interface RankedEntry {
  key: string;
  count: number;
}

/** How many entries a ranked widget shows. The backend returns 20 IPs and 10 messages. */
export const TOP_ENTRIES = 10;

/**
 * The `limit` largest counts, largest first. The backend already ranks its facets, but a JSON
 * object is not an ordered contract, so the order is restored here; a tie keeps the order it came in.
 */
export function topEntries(
  counts: Readonly<Record<string, number>> | undefined,
  limit = TOP_ENTRIES,
): RankedEntry[] {
  return Object.entries(counts ?? {})
    .map(([key, count]) => ({ key, count }))
    .filter((entry) => entry.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

export const STATUS_CLASSES = {
  '1xx': 'Informational',
  '2xx': 'Success',
  '3xx': 'Redirection',
  '4xx': 'Client error',
  '5xx': 'Server error',
} as const;

export type StatusClass = keyof typeof STATUS_CLASSES;

export interface StatusCodeCount {
  code: number;
  count: number;
  statusClass: StatusClass;
}

export interface StatusClassCount {
  statusClass: StatusClass;
  count: number;
  /** Of the events with a status, between 0 and 1. */
  share: number;
}

export interface StatusBreakdown {
  /** Every code seen, in numeric order. */
  codes: StatusCodeCount[];
  /** The classes that have events, 1xx to 5xx. */
  classes: StatusClassCount[];
  /** Events that carried a status code from 100 to 599. */
  total: number;
}

/**
 * Splits the per-code counts into codes and classes. A status outside 100–599 (a parser's 0, a
 * proxy's 999) belongs to no class and is left out, so the classes add up to the total.
 */
export function statusBreakdown(
  byStatus: Readonly<Record<string, number>> | undefined,
): StatusBreakdown {
  const codes: StatusCodeCount[] = [];
  for (const [key, count] of Object.entries(byStatus ?? {})) {
    const code = Number(key);
    if (!Number.isInteger(code) || code < 100 || code > 599 || !(count > 0)) continue;
    codes.push({ code, count, statusClass: `${Math.floor(code / 100)}xx` as StatusClass });
  }
  codes.sort((a, b) => a.code - b.code);

  const total = codes.reduce((sum, { count }) => sum + count, 0);
  const classes = (Object.keys(STATUS_CLASSES) as StatusClass[])
    .map((statusClass) => {
      const count = codes
        .filter((code) => code.statusClass === statusClass)
        .reduce((sum, code) => sum + code.count, 0);
      return { statusClass, count, share: total ? count / total : 0 };
    })
    .filter((entry) => entry.count > 0);
  return { codes, classes, total };
}

/** ERROR and CRITICAL events, the population the top error messages are drawn from. */
export function errorEventCount(bySeverity: Readonly<Record<string, number>> | undefined): number {
  return (bySeverity?.ERROR ?? 0) + (bySeverity?.CRITICAL ?? 0);
}

const percent = new Intl.NumberFormat(undefined, { style: 'percent', maximumFractionDigits: 1 });

/** "12.5%", or "<0.1%" for a share too small to round to anything but zero. */
export function formatShare(share: number): string {
  if (share > 0 && share < 0.0005) return `<${percent.format(0.001)}`;
  return percent.format(share);
}
