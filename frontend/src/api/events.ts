import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { api } from '@/api/client';
import type { components } from '@/api/schema';
import { unwrap } from '@/lib/api-client';
import {
  timelineBuckets,
  timelineWindow,
  type TimelineBucket,
  type TimelineRange,
  type TimelineWindow,
} from '@/lib/timeline';

// /api/events/search: the event timeline and the aggregate widgets on the dashboard.

export type EventSearchResponse = components['schemas']['EventSearchResponse'];
export type EventFacets = components['schemas']['EventFacets'];
export type TimeBucket = components['schemas']['TimeBucket'];

/** How often the dashboard asks again, sliding its window along with the clock. */
export const OVERVIEW_REFRESH_MS = 60_000;

export const eventKeys = {
  all: ['events'] as const,
  overview: (range: TimelineRange) => ['events', 'overview', range] as const,
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
