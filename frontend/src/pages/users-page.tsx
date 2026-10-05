import { useUsers } from '@/api/users';
import { ErrorState } from '@/components/feedback/error-state';
import { TableSkeleton } from '@/components/feedback/skeletons';
import { PageHeader } from '@/components/page-header';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { roleLabels } from '@/lib/auth/permissions';

/** Account administration. The route is ADMIN only — see `app/routes.tsx`. */
export function UsersPage() {
  return (
    <>
      <PageHeader title="Users" description="Accounts that can sign in, and what each may do." />
      <UsersTable />
    </>
  );
}

function UsersTable() {
  const { data: users, error, isPending, isFetching, refetch } = useUsers();

  if (isPending) {
    return (
      <Card className="py-0">
        <TableSkeleton label="Loading users" columns={4} rows={4} />
      </Card>
    );
  }
  if (error) {
    return (
      <ErrorState
        error={error}
        what="the users"
        onRetry={() => void refetch()}
        retrying={isFetching}
      />
    );
  }

  return (
    <Card className="py-0">
      <CardContent className="overflow-x-auto px-0">
        <table className="w-full text-sm">
          <thead className="text-muted-foreground border-b text-left">
            <tr>
              <th className="px-4 py-3 font-medium">Username</th>
              <th className="px-4 py-3 font-medium">Email</th>
              <th className="px-4 py-3 font-medium">Roles</th>
              <th className="px-4 py-3 font-medium">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {users.map((user) => (
              <tr key={user.id}>
                <td className="px-4 py-3 font-medium">{user.username}</td>
                <td className="text-muted-foreground px-4 py-3">{user.email ?? '—'}</td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {user.roles?.map((role) => (
                      <Badge key={role} variant="outline">
                        {roleLabels[role]}
                      </Badge>
                    ))}
                  </div>
                </td>
                <td className="px-4 py-3">
                  {user.enabled === false ? (
                    <Badge variant="destructive">Disabled</Badge>
                  ) : (
                    <Badge variant="secondary">Active</Badge>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}
