import { lazy, Suspense } from 'react';
import { Skeleton } from '@/components/ui/skeleton';

// TanStack Table and the details panel load with the events page rather than with the app.
const EventsPage = lazy(() =>
  import('@/pages/events-page').then((module) => ({ default: module.EventsPage })),
);

export function LazyEventsPage() {
  return (
    <Suspense
      fallback={
        <div className="space-y-4" aria-label="Loading events">
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      }
    >
      <EventsPage />
    </Suspense>
  );
}
