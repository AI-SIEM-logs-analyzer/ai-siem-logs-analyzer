import type { RouteObject } from 'react-router';
import { AppLayout } from '@/components/layout/app-layout';
import { AlertsPage } from '@/pages/alerts-page';
import { DashboardPage } from '@/pages/dashboard-page';
import { EventsPage } from '@/pages/events-page';
import { NotFoundPage } from '@/pages/not-found-page';
import { RouteErrorPage } from '@/pages/route-error-page';
import { UploadsPage } from '@/pages/uploads-page';

// Kept apart from the router instance so tests can mount the same tree in a memory router.
export const routes: RouteObject[] = [
  {
    path: '/',
    element: <AppLayout />,
    errorElement: <RouteErrorPage />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: 'events', element: <EventsPage /> },
      { path: 'uploads', element: <UploadsPage /> },
      { path: 'alerts', element: <AlertsPage /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
];
