import type { ReactNode } from 'react';
import { useEventOverview, type EventOverview } from '@/api/events';
import { overviewErrorMessage } from '@/components/dashboard/overview-error';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import type { TimelineRange } from '@/lib/timeline';
import { cn } from '@/lib/utils';

interface AggregateCardProps {
  title: string;
  description: string;
  range: TimelineRange;
  /** Names the card in an error ("the top source IPs"). */
  what: string;
  /** Whether the overview holds nothing for this card. */
  isEmpty: (overview: EventOverview) => boolean;
  /** Shown instead of the chart when `isEmpty`. */
  empty: string;
  children: (overview: EventOverview) => ReactNode;
  className?: string;
}

/**
 * The frame every aggregate widget shares: loading, error and empty states around a chart.
 * The data is the dashboard's overview query, shared with the timeline, so a widget adds no
 * request of its own and changes range, refreshes and dims together with the rest.
 */
export function AggregateCard({
  title,
  description,
  range,
  what,
  isEmpty,
  empty,
  children,
  className,
}: AggregateCardProps) {
  const { data, error, isPending, isPlaceholderData } = useEventOverview(range);

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        {isPending ? (
          <div className="space-y-2" aria-label={`Loading ${what}`}>
            <Skeleton className="h-5 w-full" />
            <Skeleton className="h-5 w-4/5" />
            <Skeleton className="h-5 w-3/5" />
          </div>
        ) : !data ? (
          // Not an alert: the timeline above announces the same failure once for the page.
          <p className="text-destructive text-sm">{overviewErrorMessage(error, what)}</p>
        ) : isEmpty(data) ? (
          <p className="text-muted-foreground flex h-40 items-center justify-center rounded-md border border-dashed px-4 text-center text-sm">
            {empty}
          </p>
        ) : (
          <div
            className={cn('space-y-4 transition-opacity', isPlaceholderData && 'opacity-60')}
            aria-busy={isPlaceholderData}
          >
            {children(data)}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface TableViewProps {
  caption: string;
  columns: readonly { label: string; numeric?: boolean }[];
  rows: readonly { key: string; cells: readonly ReactNode[] }[];
}

/** The chart's data as a table, folded away under "Show as table". */
export function TableView({ caption, columns, rows }: TableViewProps) {
  return (
    <details className="text-sm">
      <summary className="text-muted-foreground cursor-pointer select-none">Show as table</summary>
      <div className="mt-2 max-h-72 overflow-auto rounded-md border">
        <table className="w-full">
          <caption className="sr-only">{caption}</caption>
          <thead className="bg-muted/50 sticky top-0">
            <tr>
              {columns.map((column) => (
                <th
                  key={column.label}
                  scope="col"
                  className={cn(
                    'px-3 py-2 font-medium',
                    column.numeric ? 'text-right' : 'text-left',
                  )}
                >
                  {column.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y">
            {rows.map((row) => (
              <tr key={row.key}>
                {row.cells.map((cell, i) => (
                  <td
                    key={columns[i].label}
                    className={cn(
                      'px-3 py-1.5',
                      columns[i].numeric
                        ? 'text-right whitespace-nowrap tabular-nums'
                        : 'wrap-anywhere',
                    )}
                  >
                    {cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}
