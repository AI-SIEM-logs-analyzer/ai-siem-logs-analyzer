import type { ReactNode } from 'react';
import { useCurrentUser } from '@/api/auth';
import { ErrorState } from '@/components/feedback/error-state';
import { PageSkeleton } from '@/components/feedback/skeletons';
import { can, type Permission } from '@/lib/auth/permissions';
import { errorMessage } from '@/lib/errors';
import { ForbiddenPage } from '@/pages/forbidden-page';

export function RequirePermission({
  permission,
  children,
}: {
  permission: Permission;
  children: ReactNode;
}) {
  const { data: user, error, isPending, isFetching, refetch } = useCurrentUser();

  if (isPending) return <PageSkeleton label="Checking access" />;

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
