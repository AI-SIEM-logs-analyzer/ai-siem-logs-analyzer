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

export type EventSearchResponse = components['schemas']['EventSearchResponse'];
export type EventFacets = components['schemas']['EventFacets'];
export type TimeBucket = components['schemas']['TimeBucket'];
export type EventHit = components['schemas']['EventHit'];

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

  total: number;

  facets: EventFacets;
}

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

export function useEventOverview(range: TimelineRange) {
  return useQuery({
    queryKey: eventKeys.overview(range),
    queryFn: () => fetchEventOverview(range),
    placeholderData: keepPreviousData,
    refetchInterval: OVERVIEW_REFRESH_MS,
  });
}

export interface EventCursor {
  occurredAt: string;
  eventId: number;
}

export const EVENT_PAGE_SIZE = 50;

export interface EventPage {
  hits: EventHit[];

  total: number;

  next: EventCursor | null;
}

const NO_HITS: EventHit[] = [];

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

export function useEventPage(filters: EventFilters, now: number, cursor: EventCursor | null) {
  return useQuery({
    queryKey: eventKeys.search(filters, now, cursor),
    queryFn: () => fetchEventPage(filters, now, cursor),
    placeholderData: keepPreviousData,
  });
}
