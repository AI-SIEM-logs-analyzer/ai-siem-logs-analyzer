import { lazy, Suspense } from 'react';
import { PageSkeleton } from '@/components/feedback/skeletons';

// TanStack Table and the details panel load with the events page rather than with the app.
const EventsPage = lazy(() =>
  import('@/pages/events-page').then((module) => ({ default: module.EventsPage })),
);

export function LazyEventsPage() {
  return (
    <Suspense fallback={<PageSkeleton label="Loading events" />}>
      <EventsPage />
    </Suspense>
  );
}
