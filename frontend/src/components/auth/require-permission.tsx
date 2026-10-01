import type { ReactNode } from 'react';
import { useCurrentUser } from '@/api/auth';
import { Skeleton } from '@/components/ui/skeleton';
import { can, type Permission } from '@/lib/auth/permissions';
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
  const { data: user, error, isPending } = useCurrentUser();

  if (isPending) {
    return (
      <div className="space-y-3" aria-label="Checking access">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-4 w-full" />
      </div>
    );
  }
  // A 401 that could not be renewed has already ended the session and RequireAuth is leaving;
  // any other failure means the roles are unknown, and unknown is not allowed.
  if (error) {
    return (
      <p role="alert" className="text-destructive text-sm">
        Could not check your access: {error.message}
      </p>
    );
  }
  return can(user.roles, permission) ? children : <ForbiddenPage />;
}
