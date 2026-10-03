import type { ReactNode } from 'react';
import { useCurrentUser } from '@/api/auth';
import { ErrorState } from '@/components/feedback/error-state';
import { PageSkeleton } from '@/components/feedback/skeletons';
import { can, type Permission } from '@/lib/auth/permissions';
import { errorMessage } from '@/lib/errors';
import { ForbiddenPage } from '@/pages/forbidden-page';

/**
 * Renders `children` only for an account allowed `permission`, and a 403 page for anyone else.
 * Sits under RequireAuth, so there is always a session here; what is still unknown until
 * /api/auth/me answers is which roles it carries.
 */
export function RequirePermission({
  permission,
  children,
}: {
  permission: Permission;
  children: ReactNode;
}) {
  const { data: user, error, isPending, isFetching, refetch } = useCurrentUser();

  if (isPending) return <PageSkeleton label="Checking access" />;
  // A 401 that could not be renewed has already ended the session and RequireAuth is leaving;
  // any other failure means the roles are unknown, and unknown is not allowed.
  if (error) {
    return (
      <ErrorState
        error={error}
        what="your access"
        message={`Could not check your access. ${errorMessage(error)}`}
        onRetry={() => void refetch()}
        retrying={isFetching}
      />
    );
  }
  return can(user.roles, permission) ? children : <ForbiddenPage />;
}
