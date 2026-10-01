import { RefreshCw } from 'lucide-react';
import { useSearchParams } from 'react-router';
import { useBackendHealth, type HealthStatus } from '@/api/health';
import { EventTimelineCard } from '@/components/dashboard/event-timeline-card';
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
import {
  DEFAULT_TIMELINE_RANGE,
  isTimelineRange,
  TIMELINE_RANGES,
  type TimelineRange,
} from '@/lib/timeline';

export function DashboardPage() {
  // The range lives in the URL, so a reload or a shared link shows the same slice.
  const [params, setParams] = useSearchParams();
  const requested = params.get('range');
  const range = isTimelineRange(requested) ? requested : DEFAULT_TIMELINE_RANGE;

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Overview of ingestion, detections and alerts."
        actions={
          <RangePicker
            value={range}
            onChange={(next) =>
              setParams(
                (current) => {
                  current.set('range', next);
                  return current;
                },
                { replace: true },
              )
            }
          />
        }
      />
      <EventTimelineCard range={range} />
      <BackendHealthCard />
    </>
  );
}

function RangePicker({
  value,
  onChange,
}: {
  value: TimelineRange;
  onChange: (range: TimelineRange) => void;
}) {
  return (
    <div role="group" aria-label="Time range" className="flex gap-1 rounded-lg border p-1">
      {(Object.keys(TIMELINE_RANGES) as TimelineRange[]).map((range) => (
        <Button
          key={range}
          size="sm"
          variant={range === value ? 'secondary' : 'ghost'}
          aria-pressed={range === value}
          title={TIMELINE_RANGES[range].label}
          onClick={() => onChange(range)}
        >
          {range}
        </Button>
      ))}
    </div>
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
