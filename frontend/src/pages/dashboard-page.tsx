import { RefreshCw } from 'lucide-react';
import { useBackendHealth, type HealthStatus } from '@/api/health';
import { PageHeader } from '@/components/page-header';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';

export function DashboardPage() {
  return (
    <>
      <PageHeader title="Dashboard" description="Overview of ingestion, detections and alerts." />
      <BackendHealthCard />
    </>
  );
}

// The spec leaves every field optional; a status the backend did not report reads as unknown.
function StatusBadge({ status }: { status: HealthStatus | undefined }) {
  if (!status) return <Badge variant="outline">UNKNOWN</Badge>;
  return <Badge variant={status === 'UP' ? 'secondary' : 'destructive'}>{status}</Badge>;
}

function BackendHealthCard() {
  const { data, error, isPending, isFetching, refetch } = useBackendHealth();

  return (
    <Card>
      <CardHeader>
        <CardTitle>Backend health</CardTitle>
        <CardDescription>SmallRye Health checks reported by the Quarkus API.</CardDescription>
        <CardAction>
          <Button variant="outline" size="sm" onClick={() => void refetch()} disabled={isFetching}>
            <RefreshCw className={isFetching ? 'animate-spin' : undefined} aria-hidden />
            Refresh
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent>
        {isPending ? (
          <div className="space-y-2" aria-label="Loading health checks">
            <Skeleton className="h-5 w-24" />
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-2/3" />
          </div>
        ) : error ? (
          <p role="alert" className="text-destructive text-sm">
            Backend unreachable: {error.message}
          </p>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-sm">
              Overall <StatusBadge status={data.status} />
            </div>
            <ul className="divide-y rounded-md border text-sm">
              {data.checks?.map((check) => (
                <li key={check.name} className="flex items-center justify-between px-3 py-2">
                  <span>{check.name}</span>
                  <StatusBadge status={check.status} />
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
