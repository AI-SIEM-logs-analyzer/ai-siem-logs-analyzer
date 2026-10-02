import type { RouteObject } from 'react-router';
import { RequireAuth } from '@/components/auth/require-auth';
import { RequirePermission } from '@/components/auth/require-permission';
import { AppLayout } from '@/components/layout/app-layout';
import { AlertsPage } from '@/pages/alerts-page';
import { DashboardPage } from '@/pages/dashboard-page';
import { LazyEventsPage } from '@/pages/lazy-events-page';
import { LoginPage } from '@/pages/login-page';
import { NotFoundPage } from '@/pages/not-found-page';
import { RouteErrorPage } from '@/pages/route-error-page';
import { UploadsPage } from '@/pages/uploads-page';
import { UsersPage } from '@/pages/users-page';

// Kept apart from the router instance so tests can mount the same tree in a memory router.
// Every page but /login needs a session (RequireAuth); a page for some roles only also needs the
// matching permission (RequirePermission), and its nav item names the same one.
export const routes: RouteObject[] = [
  { path: '/login', element: <LoginPage />, errorElement: <RouteErrorPage /> },
  {
    path: '/',
    element: (
      <RequireAuth>
        <AppLayout />
      </RequireAuth>
    ),
    errorElement: <RouteErrorPage />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: 'events', element: <LazyEventsPage /> },
      { path: 'uploads', element: <UploadsPage /> },
      { path: 'alerts', element: <AlertsPage /> },
      {
        path: 'users',
        element: (
          <RequirePermission permission="users:manage">
            <UsersPage />
          </RequirePermission>
        ),
      },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
];
