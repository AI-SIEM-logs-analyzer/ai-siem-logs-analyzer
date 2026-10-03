import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';

// Placeholders shaped like what is loading, so the page does not jump when it arrives. Each
// is a `status` region named by `label`, so a screen reader hears what is on its way.

/** Widths cycled across a row's cells, so the placeholder reads as text rather than a grid. */
const CELL_WIDTHS = ['w-3/4', 'w-1/2', 'w-2/3', 'w-1/3', 'w-5/6'];

interface LoadingProps {
  /** What is loading ("Loading users"), read out instead of the placeholder. */
  label: string;
  className?: string;
}

/** A table on its way: a header and `rows` rows of `columns` cells. */
export function TableSkeleton({
  label,
  rows = 5,
  columns = 4,
  className,
}: LoadingProps & { rows?: number; columns?: number }) {
  return (
    <div role="status" aria-label={label} aria-busy className={cn('w-full', className)}>
      <TableRows rows={rows} columns={columns} />
    </div>
  );
}

function TableRows({ rows, columns }: { rows: number; columns: number }) {
  const grid = { gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` };
  return (
    <>
      <div className="grid gap-4 border-b px-4 py-3" style={grid}>
        {Array.from({ length: columns }, (_, column) => (
          <Skeleton key={column} className="h-4 w-1/2" />
        ))}
      </div>
      <div className="divide-y">
        {Array.from({ length: rows }, (_, row) => (
          <div key={row} className="grid items-center gap-4 px-4 py-3" style={grid}>
            {Array.from({ length: columns }, (_, column) => (
              <Skeleton
                key={column}
                className={cn('h-4', CELL_WIDTHS[(row + column) % CELL_WIDTHS.length])}
              />
            ))}
          </div>
        ))}
      </div>
    </>
  );
}

/** A few lines of text on their way, each a little shorter than the last. */
export function LinesSkeleton({ label, lines = 3, className }: LoadingProps & { lines?: number }) {
  return (
    <div role="status" aria-label={label} aria-busy className={cn('space-y-2', className)}>
      {Array.from({ length: lines }, (_, line) => (
        <Skeleton
          key={line}
          className="h-5"
          style={{ width: `${100 - (line * 40) / Math.max(1, lines - 1)}%` }}
        />
      ))}
    </div>
  );
}

/** A chart on its way: a headline figure over the plot area. */
export function ChartSkeleton({ label, className }: LoadingProps) {
  return (
    <div role="status" aria-label={label} aria-busy className="space-y-3">
      <Skeleton className="h-6 w-40" />
      <Skeleton className={cn('h-64 w-full', className)} />
    </div>
  );
}

/** A whole page on its way: its header, a toolbar and a content card. */
export function PageSkeleton({ label, className }: LoadingProps) {
  return (
    <div role="status" aria-label={label} aria-busy className={cn('space-y-6', className)}>
      <div className="space-y-2">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-4 w-80 max-w-full" />
      </div>
      <Skeleton className="h-24 w-full" />
      <div className="rounded-xl border">
        <TableRows rows={6} columns={4} />
      </div>
    </div>
  );
}
