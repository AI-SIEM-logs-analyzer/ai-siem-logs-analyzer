import type { RouteObject } from 'react-router';
import { RequireAuth } from '@/components/auth/require-auth';
import { RequirePermission } from '@/components/auth/require-permission';
import { AppLayout } from '@/components/layout/app-layout';
import { AlertDetailsPage } from '@/pages/alert-details-page';
import { AlertsPage } from '@/pages/alerts-page';
import { AttackMatrixPage } from '@/pages/attack-matrix-page';
import { DashboardPage } from '@/pages/dashboard-page';
import { LazyEventsPage } from '@/pages/lazy-events-page';
import { LoginPage } from '@/pages/login-page';
import { NotFoundPage } from '@/pages/not-found-page';
import { RouteErrorPage } from '@/pages/route-error-page';
import { UploadsPage } from '@/pages/uploads-page';
import { UsersPage } from '@/pages/users-page';

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
      {
        errorElement: <RouteErrorPage variant="page" />,
        children: [
          { index: true, element: <DashboardPage /> },
          { path: 'events', element: <LazyEventsPage /> },
          { path: 'uploads', element: <UploadsPage /> },
          { path: 'alerts', element: <AlertsPage /> },
          { path: 'alerts/:id', element: <AlertDetailsPage /> },
          { path: 'attack', element: <AttackMatrixPage /> },
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
    ],
  },
];
