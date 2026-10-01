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

// /api/events/search: the event timeline on the dashboard.

export type EventSearchResponse = components['schemas']['EventSearchResponse'];
export type TimeBucket = components['schemas']['TimeBucket'];

/** How often the dashboard timeline asks again, sliding its window along with the clock. */
export const TIMELINE_REFRESH_MS = 60_000;

export const eventKeys = {
  all: ['events'] as const,
  timeline: (range: TimelineRange) => ['events', 'timeline', range] as const,
};

export interface EventTimeline {
  window: TimelineWindow;
  buckets: TimelineBucket[];
  /** Events in the window, as the backend counted them. */
  total: number;
}

/**
 * Events per bucket over `range`, ending now. The backend counts per hour (`facets=true`) and
 * leaves out the empty hours; the window, the coarser buckets and the zeros are ours. One hit
 * is the smallest page the endpoint serves; only the counts are read.
 */
export async function fetchEventTimeline(
  range: TimelineRange,
  now = Date.now(),
): Promise<EventTimeline> {
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
  };
}

/** The timeline for `range`, kept on screen while a different range loads. */
export function useEventTimeline(range: TimelineRange) {
  return useQuery({
    queryKey: eventKeys.timeline(range),
    queryFn: () => fetchEventTimeline(range),
    placeholderData: keepPreviousData,
    refetchInterval: TIMELINE_REFRESH_MS,
  });
}
