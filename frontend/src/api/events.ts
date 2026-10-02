import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { api } from '@/api/client';
import type { components } from '@/api/schema';
import { unwrap } from '@/lib/api-client';
import { eventSearchQuery, type EventFilters } from '@/lib/event-filters';
import {
  timelineBuckets,
  timelineWindow,
  type TimelineBucket,
  type TimelineRange,
  type TimelineWindow,
} from '@/lib/timeline';

// /api/events/search: the event timeline and the aggregate widgets on the dashboard, and the
// events page's table.

export type EventSearchResponse = components['schemas']['EventSearchResponse'];
export type EventFacets = components['schemas']['EventFacets'];
export type TimeBucket = components['schemas']['TimeBucket'];
export type EventHit = components['schemas']['EventHit'];

/** How often the dashboard asks again, sliding its window along with the clock. */
export const OVERVIEW_REFRESH_MS = 60_000;

export const eventKeys = {
  all: ['events'] as const,
  overview: (range: TimelineRange) => ['events', 'overview', range] as const,
  search: (filters: EventFilters, now: number, cursor: EventCursor | null) =>
    ['events', 'search', filters, now, cursor] as const,
};

export interface EventOverview {
  window: TimelineWindow;
  buckets: TimelineBucket[];
  /** Events in the window, as the backend counted them. */
  total: number;
  /** Counts across the window: severities, source IPs, status codes, error messages, … */
  facets: EventFacets;
}

/**
 * Everything the dashboard draws for `range`, ending now, from one search with `facets=true`.
 * The backend counts per hour and leaves out the empty hours; the window, the coarser buckets
 * and the zeros are ours. One hit is the smallest page the endpoint serves; only the counts
 * are read.
 */
export async function fetchEventOverview(
  range: TimelineRange,
  now = Date.now(),
): Promise<EventOverview> {
  const window = timelineWindow(range, now);
  const response = await unwrap(
    api.GET('/api/events/search', {
      params: {
        query: {
          from: new Date(window.from).toISOString(),
          to: new Date(window.to).toISOString(),
          facets: true,
          size: 1,
        },
      },
    }),
  );
  return {
    window,
    buckets: timelineBuckets(response.facets?.overTime ?? [], window),
    total: response.totalHits ?? 0,
    facets: response.facets ?? {},
  };
}

/**
 * The overview for `range`, kept on screen while a different range loads. The timeline and
 * every widget share it, so the dashboard costs one request per range and refresh.
 */
export function useEventOverview(range: TimelineRange) {
  return useQuery({
    queryKey: eventKeys.overview(range),
    queryFn: () => fetchEventOverview(range),
    placeholderData: keepPreviousData,
    refetchInterval: OVERVIEW_REFRESH_MS,
  });
}

/** Where a page of results resumes: the last hit of the page before it. */
export interface EventCursor {
  occurredAt: string;
  eventId: number;
}

/** Hits per page on the events page. */
export const EVENT_PAGE_SIZE = 50;

export interface EventPage {
  hits: EventHit[];
  /** Events matching the filters across every page. */
  total: number;
  /** Where the next page starts; null on the last page. */
  next: EventCursor | null;
}

const NO_HITS: EventHit[] = [];

/**
 * One page of the events matching `filters`, a relative range ending at `now`. Pages are
 * chained by cursor, and the backend wants the same filters and order with each, so `now`
 * stays fixed while paging: every page covers the same window.
 */
export async function fetchEventPage(
  filters: EventFilters,
  now: number,
  cursor: EventCursor | null,
  size = EVENT_PAGE_SIZE,
): Promise<EventPage> {
  const response = await unwrap(
    api.GET('/api/events/search', {
      params: {
        query: {
          ...eventSearchQuery(filters, now),
          size,
          ...(cursor && { cursorOccurredAt: cursor.occurredAt, cursorEventId: cursor.eventId }),
        },
      },
    }),
  );
  const { nextCursorOccurredAt: occurredAt, nextCursorEventId: eventId } = response;
  return {
    hits: response.hits ?? NO_HITS,
    total: response.totalHits ?? 0,
    next:
      typeof occurredAt === 'string' && typeof eventId === 'number'
        ? { occurredAt, eventId }
        : null,
  };
}

/** A page of the events table, kept on screen while the next one (or a new filter) loads. */
export function useEventPage(filters: EventFilters, now: number, cursor: EventCursor | null) {
  return useQuery({
    queryKey: eventKeys.search(filters, now, cursor),
    queryFn: () => fetchEventPage(filters, now, cursor),
    placeholderData: keepPreviousData,
  });
}
